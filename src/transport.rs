/// Threema Transport Layer

// TODO: use some nice abstraction for byte parsing/serialisation.
// at the moment, i just used stdlib stuff like clone_from_slice and to_le_bytes,
// to not lose focus in nice parsing, and it works - but much of the [u8] slicing
// code should just be trashed...

use std::io;
use std::io::Write;
use getrandom::getrandom;
use tokio::io::{AsyncReadExt,AsyncWriteExt};
use std::convert::TryInto;
use tokio;
use crate::{ThreemaID, naclbox, Credentials, Peer, ParseError, pltypes};
use anyhow;

use rand::{self, Rng};

pub const SERVER : &str = "ds.g-00.0.threema.ch:5222";


pub struct NonceCounter{
    prefix: [u8; naclbox::NONCEBYTES-8],
    next_nonce: u64,
}
const PREFIXBYTES : usize = naclbox::NONCEBYTES - 8;
type NoncePrefix = [u8; PREFIXBYTES];
impl NonceCounter {
    fn random() -> Self {
        let mut n = NonceCounter { prefix : NoncePrefix::default(), next_nonce: 1 };
        getrandom(&mut n.prefix).expect("random failed");
        n
    }
    fn with_prefix(prefix: NoncePrefix) -> Self{
        NonceCounter { prefix, next_nonce: 1}
    }

}

impl Iterator for NonceCounter{
    type Item = naclbox::Nonce;
    fn next(&mut self) -> Option<Self::Item>{
        let mut nonce = [0u8; naclbox::NONCEBYTES];
        nonce[..naclbox::NONCEBYTES-8].clone_from_slice(&self.prefix);
        for i in 0..8 {
            nonce[i+naclbox::NONCEBYTES-8] = (self.next_nonce >> (i * 8)) as u8;
        }
        self.next_nonce = self.next_nonce.wrapping_add(1);
        naclbox::Nonce::from_slice(&nonce)
    }
}

pub struct ReadHalf {
    their_nonces: NonceCounter,
    sock: tokio::net::tcp::OwnedReadHalf,
    shared_key: naclbox::PrecomputedKey,
}
pub struct WriteHalf {
    my_nonces: NonceCounter,
    sock: tokio::net::tcp::OwnedWriteHalf,
    shared_key: naclbox::PrecomputedKey,
}

#[derive(Clone, Debug)]
pub struct ThreemaServer {
    pub addr: String,
    pub pk: naclbox::PublicKey,
}

/// Open TCP connection to a Threema Server and do the handshake.
pub async fn connect(addr: &ThreemaServer, creds: &Credentials) -> io::Result<(ReadHalf, WriteHalf)>{
    let my_nonces = NonceCounter::random();
    let (my_epk,my_esk) = naclbox::gen_keypair();
    let mut sock = tokio::net::TcpStream::connect(&addr.addr).await.expect("could not connect :/");
    // client hello, send my epk
    sock.write_all(my_epk.as_ref() ).await?;
    sock.write_all(my_nonces.prefix.as_ref()).await?;
    sock.flush().await?;
    log::trace!("sent client hello");

    // server hello, verify server has its longtime key, receive server epk
    let mut their_nonce_prefix = NoncePrefix::default();
    sock.read_exact(&mut their_nonce_prefix).await?;
    let mut their_nonces = NonceCounter::with_prefix(their_nonce_prefix);
    let mut hellobox = [0u8; naclbox::PUBLICKEYBYTES + PREFIXBYTES + naclbox::MACBYTES];
    sock.read_exact(&mut hellobox).await?;
    log::trace!("received server hello");
    let server_hello = naclbox::open(&hellobox, &their_nonces.next().unwrap(), &addr.pk, &my_esk).
        map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption error in server hello"))?;
    log::trace!("decrypted server hello");
    let their_epk = naclbox::PublicKey::from_slice(&server_hello[..naclbox::PUBLICKEYBYTES]).unwrap();
    let my_nonce_prefix_again = &server_hello[naclbox::PUBLICKEYBYTES .. naclbox::PUBLICKEYBYTES + PREFIXBYTES];
    // TODO what does this proof again?
    if my_nonce_prefix_again != &my_nonces.prefix {
        return Err(io::Error::new(io::ErrorKind::Other, "verification error while checking client nonce"));
    }
    log::trace!("stage 1 connected");

    let shared_key = naclbox::precompute(&their_epk, &my_esk);
    let (rs,ws) = sock.into_split();
    let mut rh = ReadHalf { shared_key: shared_key.clone(), their_nonces, sock: rs};
    let mut wh = WriteHalf { shared_key, my_nonces, sock: ws};
    
    
    // login: tell the server my identity and proof that i own my secret key
    let mut vouchenonce = [0u8; naclbox::NONCEBYTES];
    getrandom(&mut vouchenonce)?;
    let mut vouchbox = naclbox::seal(my_epk.as_ref(), &naclbox::Nonce::from_slice(&vouchenonce).unwrap(), &addr.pk, &creds.sk);

    let mut request = Vec::<u8>::new();
    request.extend_from_slice(creds.id.as_ref());
    let mut version = [0u8; 32];
    let mut version_wr = &mut version[..];
    version_wr.write_all("rustyclient;O;;archlinux".as_bytes())?;
    request.extend_from_slice(&version);
    request.extend_from_slice(&rh.their_nonces.prefix);
    request.extend_from_slice(&vouchenonce);
    request.append(&mut vouchbox);
    wh.encrypt_and_send(&request).await?;
    log::trace!("sent login vouch");

    // verify 
    rh.receive_and_decrypt(16).await?; // reserved bunch of zeros.
    log::trace!("received login ack");
    Ok((rh, wh))
}

impl ReadHalf {
    async fn receive_and_decrypt(&mut self, sz: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; sz + naclbox::MACBYTES];
        self.sock.read_exact(&mut buf).await?;
        log::trace!("received data");
        naclbox::open_precomputed(&buf, &self.their_nonces.next().unwrap(), &self.shared_key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "validation failed in receive"))
    }
    pub async fn receive_frame(&mut self) -> io::Result<Vec<u8>> {
        log::trace!("receiving length");
        let mut lenbuf = [0;2];
        self.sock.read_exact(&mut lenbuf).await?;
        let len = lenbuf[0] as usize + 256 * (lenbuf[1] as usize);
        
        if len < naclbox::MACBYTES {
            return Err(io::Error::new(io::ErrorKind::Other, "received to short length"));
        }
        log::trace!("receiving {} bytes...", len);
        return self.receive_and_decrypt(len-naclbox::MACBYTES).await;
    }
    pub async fn receive_packet(&mut self) -> anyhow::Result<Packet> {
        let f = self.receive_frame().await?;
        if f.len() < 4 {
            return Ok(Packet::Raw(f)); // TODO parse
        }
        let pltype = u32::from_le_bytes(f[0..4].try_into().unwrap());
        let payload = &f[4..];
        let packet = match pltype {
            pltypes::INCOMING_MESSAGE_ACK => (Packet::AckDownload(Ack::from_buf(payload)?)),
            pltypes::OUTGOING_MESSAGE_ACK => (Packet::AckUpload(Ack::from_buf(payload)?)),
            pltypes::INCOMING_MESSAGE => (Packet::BoxedMessageDownload(BoxedMessage::from_slice(payload)?)),
            pltypes::OUTGOING_MESSAGE => (Packet::BoxedMessageUpload(BoxedMessage::from_slice(payload)?)),
            pltypes::ECHO_REPLY => (Packet::EchoReply(u32::from_le_bytes(payload.try_into()?))),
            pltypes::ECHO_REQUEST => (Packet::EchoRequest(u32::from_le_bytes(payload.try_into()?))),
            pltypes::QUEUE_SEND_COMPLETE => (Packet::QueueSendComplete),
            pltypes::ALERT => (Packet::Alert(String::from_utf8_lossy(payload).to_string())),
            pltypes::ERROR => {
                let reconnect_allowed = *payload.get(0).ok_or(ParseError::ToShort{expected:1,got:0})? != 0;
                let message = String::from_utf8_lossy(&payload[1..]).to_string();
                Packet::Error((reconnect_allowed, message))
            }
            // PUSH stuff not implemented
            _unknown => (Packet::Raw(f))
        };
        Ok(packet)
    }
}
impl WriteHalf {
    async fn encrypt_and_send(&mut self, plaintext: &[u8]) -> io::Result<()>{
        let ct = naclbox::seal_precomputed(plaintext, &self.my_nonces.next().unwrap(), &self.shared_key);
        log::trace!("sending encryped data");
        self.sock.write_all(&ct).await
    }
    pub async fn send_frame(&mut self, packet: &[u8]) -> io::Result<()>{
        let n = packet.len() + naclbox::MACBYTES;
        if n > (u16::MAX as usize) {
            return Err(io::Error::new(io::ErrorKind::Other, "Packet too long for 16 bit length field"));
        }
        log::trace!("sending length {}...", n);
        self.sock.write_all(&(n as u16).to_le_bytes()).await?;
        self.encrypt_and_send(packet).await?;
        Ok(())
    }
    pub async fn send_download_ack(&mut self, original_envelope: &Envelope) -> anyhow::Result<()> {
        let mut buf = [0; 4+Ack::SIZE];
        buf[0..4].copy_from_slice(&pltypes::INCOMING_MESSAGE_ACK.to_le_bytes());
        Ack{partner: original_envelope.sender, message_id: original_envelope.id, }.to_buf(&mut buf);
        self.send_frame(&buf).await?;
        Ok(())
    }
    pub async fn send_ack(&mut self, ack: &Ack, direction: Direction) -> io::Result<()>{
        let magic = if direction == ServerToClient {pltypes::OUTGOING_MESSAGE_ACK} else {pltypes::INCOMING_MESSAGE_ACK};
        let mut buf = [0; 4+Ack::SIZE];
        buf[0..4].copy_from_slice(&magic.to_le_bytes());
        ack.to_buf(&mut buf[4..]);
        self.send_frame(&buf).await
    }
    pub async fn send_message(&mut self, msg: &BoxedMessage, direction: Direction) -> io::Result<()> {
        let magic = if direction == ServerToClient {pltypes::INCOMING_MESSAGE} else {pltypes::OUTGOING_MESSAGE};
        let mut buf = vec![0; 4 + msg.size()];
        buf[0..4].copy_from_slice(&magic.to_le_bytes());
        msg.to_buf(&mut buf[4..]);
        self.send_frame(&buf).await
    }
    pub async fn echo_request(&mut self, seq: u32) -> io::Result<()>{
        let mut buf = [0; 8];
        buf[0..4].copy_from_slice(&pltypes::ECHO_REQUEST.to_le_bytes());
        buf[4..8].copy_from_slice(&seq.to_le_bytes());
        self.send_frame(&buf).await
    }
    pub async fn echo_reply(&mut self, seq: u32) -> io::Result<()>{
        let mut buf = [0; 8];
        buf[0..4].copy_from_slice(&pltypes::ECHO_REPLY.to_le_bytes());
        buf[4..8].copy_from_slice(&seq.to_le_bytes());
        self.send_frame(&buf).await
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction{
    ClientToServer, ServerToClient
}
pub use Direction::*;

#[derive(Clone, Debug)]
pub enum Packet{
    Raw(Vec<u8>),
    BoxedMessageUpload(BoxedMessage),
    BoxedMessageDownload(BoxedMessage),
    AckUpload(Ack),
    AckDownload(Ack),
    EchoRequest(u32),
    EchoReply(u32),
    QueueSendComplete,
    Alert(String),
    Error((bool, String)),
}

#[derive(Debug, Clone)]
pub struct Envelope{
    pub sender: ThreemaID,
    pub recipient: ThreemaID,
    pub id: u64,
    pub time: u32,
    pub flags: u32,
    pub nickname: String,
}
impl Envelope{
    pub const SIZE: usize = 64;

    pub fn from_buf(data: &[u8]) -> Result<Envelope, ParseError> {
        if data.len() < Self::SIZE {
            return Err(ParseError::ToShort{expected:Self::SIZE, got: data.len()})
        }
        //let pltype = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let sender = data[0..8].try_into().unwrap();
        let recipient = data[8..16].try_into().unwrap();
        let id = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let time = u32::from_le_bytes(data[24..28].try_into().unwrap());
        let flags = u32::from_le_bytes(data[28..32].try_into().unwrap());
        let nickname_buf = &data[32..64];

        let nickname_len = nickname_buf.iter().take_while(|b| **b != 0).count();
        let nickname = String::from_utf8_lossy(&nickname_buf[0..nickname_len]).to_string();
        return Ok(Envelope{sender, recipient, id, time, flags, nickname});
    }
    pub fn to_buf(&self, data: &mut [u8]) {
        //data[0..4].copy_from_slice(&self.pltype.to_le_bytes());
        data[0..8].copy_from_slice(self.sender.as_ref());
        data[8..16].copy_from_slice(self.recipient.as_ref());
        data[16..24].copy_from_slice(&self.id.to_le_bytes());
        data[24..28].copy_from_slice(&self.time.to_le_bytes());
        data[28..32].copy_from_slice(&self.flags.to_le_bytes());
        data[32..64].fill(0);
        if self.nickname.len() > 32 {
            panic!("nickname to long");
        }
        data[36.. 36+self.nickname.len()].copy_from_slice(self.nickname.as_bytes());
    }
    pub fn recipient_ack(&self) -> Ack {
        Ack{partner: self.recipient, message_id: self.id}
    }
    pub fn sender_ack(&self) -> Ack {
        Ack{partner: self.sender, message_id: self.id}
    }
}

#[derive(Debug, Clone)]
pub struct BoxedMessage{
    pub envelope: Envelope,
    pub payload: Vec<u8>,
}
impl BoxedMessage {
    pub fn from_slice(data: &[u8]) -> Result<BoxedMessage, ParseError>{
        let minlen = Envelope::SIZE + naclbox::NONCEBYTES + naclbox::MACBYTES;
        if data.len() < minlen {
            return Err(ParseError::ToShort{got: data.len(), expected: minlen});
        }
        let envelope = Envelope::from_buf(&data[0..Envelope::SIZE])?;
        let payload = data[Envelope::SIZE..].into();
        Ok(BoxedMessage{envelope, payload})
    }
    pub fn open(&self, pk: &naclbox::PublicKey, sk: &naclbox::SecretKey) -> Result<Vec<u8>, ParseError> {
        let minlen = naclbox::NONCEBYTES + naclbox::MACBYTES;
        if self.payload.len() < minlen {
            return Err(ParseError::ToShort{got: self.payload.len(), expected: minlen});
        }
        let nonce = naclbox::Nonce::from_slice(&self.payload[0..naclbox::NONCEBYTES]).unwrap();
        match naclbox::open(&self.payload[naclbox::NONCEBYTES..], &nonce, &pk, &sk) {
            Err(_) => Err(ParseError::DecryptionError),
            Ok(mut msg) =>{
                if msg.len() < 1 {
                    Ok(vec![])
                }
                else{
                    let padsz = *msg.last().unwrap() as usize;
                    if msg.len() <= padsz {
                        Err(ParseError::InvalidPadding)
                    }
                    else {
                        msg.truncate(msg.len() - padsz);
                        Ok(msg)
                    }
                }
            }
        }
    }
    pub fn size(&self) -> usize {
        Envelope::SIZE + self.payload.len()
    }
    pub fn to_buf(&self, buf: &mut [u8]){
        self.envelope.to_buf(buf);
        buf[Envelope::SIZE..].copy_from_slice(&self.payload);
    }
    /// pad and encrypt a end to end message
    pub fn encrypt(creds: &Credentials, nickname: &str, peer: &Peer, mut plain: Vec<u8>, flags: u32) -> Self {
        // padding
        let npad = rand::thread_rng().gen_range(1u8..=255);
        plain.extend(std::iter::repeat(npad).take(npad as usize));

        // encrypt
        let n = naclbox::gen_nonce();
        let mut encrypted = n.as_ref().to_vec();
        encrypted.append(&mut naclbox::seal(&plain, &n, &peer.pk, &creds.sk));

        let envelope = Envelope{
            sender: creds.id,
            recipient: peer.id,
            id: rand::random(),
            time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32,
            flags,
            nickname: nickname.to_string(),
        };
        BoxedMessage { envelope, payload: encrypted }

    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ack{
//    pltype: u32,
    partner: ThreemaID,
    message_id: u64,
}

impl Ack{
    pub const SIZE: usize = 16;
    pub fn to_buf(&self, data: &mut [u8]){
        data[0..8].copy_from_slice(self.partner.as_ref());
        data[8..16].copy_from_slice(&self.message_id.to_le_bytes());
    }
    pub fn from_buf(data: &[u8]) -> Result<Self, ParseError>{
        if data.len() < Self::SIZE {
            return Err(ParseError::ToShort{expected:Self::SIZE, got: data.len()})
        }
        //let pltype = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let partner = data[0..8].try_into().unwrap();
        let message_id = u64::from_le_bytes(data[8..16].try_into().unwrap());
        Ok(Ack{partner, message_id})
    }
}
