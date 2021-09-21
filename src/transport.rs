/// Threema Transport Layer

use sodiumoxide::crypto::stream::xsalsa20;
use std::io;
use std::io::Write;
use getrandom::getrandom;
use tokio::io::{AsyncReadExt,AsyncWriteExt};
use std::convert::TryInto;
use tokio;
use crate::{ThreemaID, naclbox, Credentials, ParseError, pltypes};

pub const SERVER : &str = "ds.g-00.0.threema.ch:5222";


pub struct NonceCounter{
    prefix: [u8; xsalsa20::NONCEBYTES-8],
    next_nonce: u64,
}
const PREFIXBYTES : usize = xsalsa20::NONCEBYTES - 8;
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
            nonce[i+xsalsa20::NONCEBYTES-8] = (self.next_nonce >> (i * 8)) as u8;
        }
        self.next_nonce = self.next_nonce.wrapping_add(1);
        naclbox::Nonce::from_slice(&nonce)
    }
}



pub struct Connection {
    my_esk: naclbox::SecretKey,
    my_epk: naclbox::PublicKey,
    their_epk: naclbox::PublicKey,
    their_pk: naclbox::PublicKey,
    sock: tokio::net::TcpStream,
    my_nonces: NonceCounter,
    their_nonces: NonceCounter,
}

pub struct ThreemaServer<'a> {
    pub addr: &'a str,
    pub pk: naclbox::PublicKey,
}

impl Connection {
    pub async fn connect<'a>(addr: &ThreemaServer<'a>) -> io::Result<Self>{
        let my_nonces = NonceCounter::random();
        let (my_epk,my_esk) = naclbox::gen_keypair();
        let mut sock = tokio::net::TcpStream::connect(addr.addr).await.expect("could not connect :/");
        // client hello
        sock.write_all(my_epk.as_ref() ).await?;
        sock.write_all(my_nonces.prefix.as_ref()).await?;
        sock.flush().await?;

        // server hello
        let mut their_nonce_prefix = NoncePrefix::default();
        sock.read_exact(&mut their_nonce_prefix).await?;
        let mut their_nonces = NonceCounter::with_prefix(their_nonce_prefix);
        let mut hellobox = [0u8; naclbox::PUBLICKEYBYTES + PREFIXBYTES + naclbox::MACBYTES];
        sock.read_exact(&mut hellobox).await?;
        let server_hello = naclbox::open(&hellobox, &their_nonces.next().unwrap(), &addr.pk, &my_esk).
            map_err(|_| io::Error::new(io::ErrorKind::Other, "decryption error in server hello"))?;
        let their_epk = naclbox::PublicKey::from_slice(&server_hello[..naclbox::PUBLICKEYBYTES]).unwrap();
        let my_nonce_prefix_again = &server_hello[naclbox::PUBLICKEYBYTES .. naclbox::PUBLICKEYBYTES + PREFIXBYTES];
        if my_nonce_prefix_again != &my_nonces.prefix {
            return Err(io::Error::new(io::ErrorKind::Other, "verification error while checking client nonce"));
        }

        Ok(Connection{my_esk, my_epk, their_pk: addr.pk.clone(), their_epk, sock, my_nonces, their_nonces})
    }

    pub async fn login(&mut self, u: &Credentials) -> io::Result<()>{
        let mut vouchenonce = [0u8; naclbox::NONCEBYTES];
        getrandom(&mut vouchenonce)?;
        let mut vouchbox = naclbox::seal(self.my_epk.as_ref(), &naclbox::Nonce::from_slice(&vouchenonce).unwrap(), &self.their_pk, &u.sk);

        let mut request = Vec::<u8>::new();
        request.extend_from_slice(u.id.as_ref());
        let mut version = [0u8; 32];
        let mut version_wr = &mut version[..];
        version_wr.write_all("rustyclient;O;;archlinux".as_bytes())?;
        request.extend_from_slice(&version);
        request.extend_from_slice(&self.their_nonces.prefix);
        request.extend_from_slice(&vouchenonce);
        request.append(&mut vouchbox);
        self.encrypt_and_send(&request).await?;

        self.receive_and_decrypt(16).await?; // reserved bunch of zeros
        Ok(())
    }

    async fn encrypt_and_send(&mut self, plaintext: &[u8]) -> io::Result<()>{
        let ct = naclbox::seal(plaintext, &self.my_nonces.next().unwrap(), &self.their_epk, &self.my_esk);
        self.sock.write_all(&ct).await
    }

    async fn receive_and_decrypt(&mut self, sz: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; sz + naclbox::MACBYTES];
        self.sock.read_exact(&mut buf).await?;
        naclbox::open(&buf, &self.their_nonces.next().unwrap(), &self.their_epk, &self.my_esk)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "validation failed in receive"))
    }
    pub async fn receive_packet(&mut self) -> io::Result<Vec<u8>> {
        let mut lenbuf = [0;2];
        self.sock.read_exact(&mut lenbuf).await?;
        let len = lenbuf[0] as usize + 256 * (lenbuf[1] as usize);
        
        if len < naclbox::MACBYTES {
            return Err(io::Error::new(io::ErrorKind::Other, "received to short length"));
        }
        println!("receiving {} bytes...", len);
        return self.receive_and_decrypt(len-naclbox::MACBYTES).await;
    }
    pub async fn send_packet(&mut self, packet: &[u8]) -> io::Result<()>{
        let n = packet.len() + naclbox::MACBYTES;
        if n > (u16::MAX as usize) {
            return Err(io::Error::new(io::ErrorKind::Other, "Packet too long for 16 bit length field"));
        }
        self.sock.write_all(&(n as u16).to_le_bytes()).await?;
        self.encrypt_and_send(packet).await?;
        Ok(())
    }
    pub async fn send_ack(&mut self, original_envelope: &Envelope) -> anyhow::Result<()> {
        let mut buf = [0; Ack::SIZE];
        Ack{sender: original_envelope.sender, message_id: original_envelope.id, pltype: pltypes::INCOMING_MESSAGE_ACK}.to_buf(&mut buf);
        self.send_packet(&buf).await?;
        Ok(())

    }
}


#[derive(Debug)]
pub struct Envelope{
    pub pltype: u32,
    pub sender: ThreemaID,
    pub recipient: ThreemaID,
    pub id: u64,
    pub time: u32,
    pub flags: u32,
    pub nickname: String,
    pub nonce: naclbox::Nonce,
}
impl Envelope{
    pub const SIZE: usize = 92;

    pub fn from_buf(data: &[u8]) -> Result<Envelope, ParseError> {
        if data.len() < Self::SIZE {
            return Err(ParseError::ToShort{expected:Self::SIZE, got: data.len()})
        }
        let pltype = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let sender = data[4..12].try_into().unwrap();
        let recipient = data[12..20].try_into().unwrap();
        let id = u64::from_le_bytes(data[20..28].try_into().unwrap());
        let time = u32::from_le_bytes(data[28..32].try_into().unwrap());
        let flags = u32::from_le_bytes(data[32..36].try_into().unwrap());
        let nickname_buf = &data[36..68];
        let nonce = naclbox::Nonce::from_slice(&data[68..92]).unwrap();

        let nickname_len = nickname_buf.iter().take_while(|b| **b != 0).count();
        let nickname = String::from_utf8_lossy(&nickname_buf[0..nickname_len]).to_string();
        return Ok(Envelope{pltype, sender, recipient, id, time, flags, nickname, nonce});
    }
    pub fn to_buf(&self, data: &mut [u8]) {
        data[0..4].copy_from_slice(&self.pltype.to_le_bytes());
        data[4..12].copy_from_slice(self.sender.as_ref());
        data[12..20].copy_from_slice(self.recipient.as_ref());
        data[20..28].copy_from_slice(&self.id.to_le_bytes());
        data[28..32].copy_from_slice(&self.time.to_le_bytes());
        data[32..36].copy_from_slice(&self.flags.to_le_bytes());
        data[36..68].fill(0);
        if self.nickname.len() > 32 {
            panic!("nickname to long");
        }
        data[36.. 36+self.nickname.len()].copy_from_slice(self.nickname.as_bytes());
        data[68..92].copy_from_slice(self.nonce.as_ref());
    }
}

pub struct Ack{
    pltype: u32,
    sender: ThreemaID,
    message_id: u64,
}

impl Ack{
    pub const SIZE: usize = 20;
    pub fn to_buf(&self, data: &mut [u8]){
        data[0..4].copy_from_slice(&self.pltype.to_le_bytes());
        data[4..12].copy_from_slice(self.sender.as_ref());
        data[12..20].copy_from_slice(&self.message_id.to_le_bytes());
    }
    pub fn from_buf(data: &[u8]) -> Result<Self, ParseError>{
        if data.len() < Self::SIZE {
            return Err(ParseError::ToShort{expected:Self::SIZE, got: data.len()})
        }
        let pltype = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let sender = data[4..12].try_into().unwrap();
        let message_id = u64::from_le_bytes(data[12..20].try_into().unwrap());
        Ok(Ack{pltype, sender, message_id})
    }
}
