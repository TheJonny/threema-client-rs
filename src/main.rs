use anyhow::Context;
pub(crate) use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as naclbox;
use tokio;
use std::convert::TryInto;

pub mod import;
pub mod directory_api;
mod threema_id;
pub use threema_id::{ThreemaID, InvalidID};



pub mod pltypes{
    pub const ECHO_REQUEST : u32 =  0x00;
    pub const ECHO_REPLY : u32 =  0x80;
    pub const OUTGOING_MESSAGE : u32 =  0x01;
    pub const OUTGOING_MESSAGE_ACK : u32 =  0x81;
    pub const INCOMING_MESSAGE : u32 =  0x02;
    pub const INCOMING_MESSAGE_ACK : u32 =  0x82;
    pub const PUSH_NOTIFICATION_TOKEN : u32 =  0x20;
    pub const PUSH_ALLOWED_IDENTITIES : u32 =  0x21;
    pub const VOIP_PUSH_NOTIFICATION_TOKEN : u32 =  0x24;
    pub const QUEUE_SEND_COMPLETE : u32 =  0xd0;
    pub const ERROR : u32 =  0xe0;
    pub const ALERT : u32 =  0xe1;
}
pub mod transport;

pub struct Credentials{
    pub id: ThreemaID,
    pub sk: naclbox::SecretKey,
}


impl Credentials{
    pub fn new(id: &str, sk: naclbox::SecretKey) -> Result<Self, InvalidID>{
        Ok(Credentials{id: id.try_into()?, sk})
    }
}




pub mod msg_types{
    pub const TEXT: u8 = 0x01;
    pub const IMAGE: u8 = 0x02;
    pub const LOCATION: u8 = 0x10;
    pub const VIDEO: u8 = 0x13;
    pub const AUDIO: u8 = 0x14;
    pub const BALLOT_CREATE: u8 = 0x15;
    pub const BALLOT_VOTE: u8 = 0x16;
    pub const FILE: u8 = 0x17;
    pub const CONTACT_SET_PHOTO: u8 = 0x18;     
    pub const CONTACT_DELETE_PHOTO: u8 = 0x19;  
    pub const CONTACT_REQUEST_PHOTO: u8 = 0x1a; 
    pub const GROUP_TEXT: u8 = 0x41;            
    pub const GROUP_LOCATION: u8 = 0x42;        
    pub const GROUP_IMAGE: u8 = 0x43;           
    pub const GROUP_VIDEO: u8 = 0x44;           
    pub const GROUP_AUDIO: u8 = 0x45;           
    pub const GROUP_FILE: u8 = 0x46;            
    pub const GROUP_CREATE: u8 = 0x4a;          
    pub const GROUP_RENAME: u8 = 0x4b;          
    pub const GROUP_LEAVE: u8 = 0x4c;           
    pub const GROUP_ADD_MEMBER: u8 = 0x4d;      
    pub const GROUP_REMOVE_MEMBER: u8 = 0x4e;   
    pub const GROUP_DESTROY: u8 = 0x4f;         
    pub const GROUP_SET_PHOTO: u8 = 0x50;       
    pub const GROUP_REQUEST_SYNC: u8 = 0x51;    
    pub const GROUP_BALLOT_CREATE: u8 = 0x52;   
    pub const GROUP_BALLOT_VOTE: u8 = 0x53;     
    pub const GROUP_DELETE_PHOTO: u8 = 0x54;    
    pub const VOIP_CALL_OFFER: u8 = 0x60;       
    pub const VOIP_CALL_ANSWER: u8 = 0x61;      
    pub const VOIP_ICE_CANDIDATES: u8 = 0x62;   
    pub const VOIP_CALL_HANGUP: u8 = 0x63;      
    pub const VOIP_CALL_RINGING: u8 = 0x64;     
    pub const DELIVERY_RECEIPT: u8 = 0x80;      
    pub const TYPING_INDICATOR: u8 = 0x90;
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Packet to short for packet type: expected {expected}, got {got} bytes")]
    ToShort{expected:usize, got:usize},
    #[error("Could not decode UTF8 - invalid encoding")]
    InvalidUTF8,
    #[error("Decryption or verification failed")]
    DecryptionError,
}




#[derive(Default)]
pub struct AddressBook{
    key_cache: std::collections::HashMap<ThreemaID, naclbox::PublicKey>,
    api: directory_api::Connector,
}

impl AddressBook {
    pub async fn lookup(&mut self, identity: &ThreemaID) -> anyhow::Result<naclbox::PublicKey>{
        let e = self.key_cache.get(identity);
        match e {
            Some(pk) => Ok(*pk),
            None => {
                let pk = self.api.get_pubkey(identity).await?;
                self.key_cache.insert(*identity, pk);
                Ok(pk)
            }
        }
    }
}

pub struct Agent {
    creds: Credentials,
    con: transport::Connection,
    contacts: AddressBook,
}

impl Agent {
    pub async fn new(creds: Credentials) -> anyhow::Result<Self>{
        use transport::{SERVER, ThreemaServer};
        let server = ThreemaServer {addr: SERVER, pk: naclbox::PublicKey::from_slice(b"E\x0b\x97W5'\x9f\xde\xcb3\x13d\x8f_\xc6\xee\x9f\xf46\x0e\xa9*\x8c\x17Q\xc6a\xe4\xc0\xd8\xc9\t").unwrap()};
        let mut con = transport::Connection::connect(&server).await?;
        println!("connected!");
        con.login(&creds).await?;
        println!("logged in!");
        let contacts = AddressBook::default();

        Ok(Agent{creds, con, contacts})
    }
    pub async fn listen(&mut self) -> anyhow::Result<()>{
        loop {
            let p = self.con.receive_packet().await?;
            self.handle_packet(&p).await?;
        }
    }

    async fn handle_message(&mut self, envelope: &transport::Envelope, content: Vec<u8>) {
        let msg_type = content[0];
        let msg = &content[1..];
        use msg_types::*;
        match msg_type {
            TEXT => {
                println!("{:?} ({}) => {:?}: {}", envelope.sender, envelope.nickname, &envelope.recipient, String::from_utf8_lossy(msg));
                let _res = self.con.send_ack(envelope).await;
            }
            TYPING_INDICATOR => {
                if msg.len() < 1 {
                    eprintln!("empty typing indicator");
                }
                else{
                    let x = if msg[0] == 1 {"is"} else {"has stopped"};
                    println!("{} ({:?}) {} typing", envelope.nickname, envelope.sender, x);
                }
            }
            unknown => {
                eprintln!("Message with unknown type {}: {:?}", unknown, msg)
            }
        }
    }
    async fn handle_packet(&mut self, packet: &[u8]) -> Result<(), ParseError>{
        let x = packet[0..4].try_into().map_err(|_| ParseError::ToShort{got:packet.len(), expected:4})?;
        let ptype = u32::from_le_bytes(x);
        println!("type: {}", ptype);
        match ptype {
            pltypes::INCOMING_MESSAGE => {
                println!("New Message!");
                let h = transport::Envelope::from_buf(&packet)?;
                println!("{:?}", &h);
                let boxed_content = &packet[transport::Envelope::SIZE ..];
                match self.contacts.lookup(&h.sender).await {
                    Ok(their_pk) => {
                        match naclbox::open(boxed_content, &h.nonce, &their_pk, &self.creds.sk) {
                            Err(_) => println!("Decryption or verification failed"),
                            Ok(mut msg) =>{
                                if msg.len() < 1 {
                                    println!("Empty!");
                                }
                                else{
                                    let padsz = *msg.last().unwrap() as usize;
                                    if msg.len() <= padsz {
                                        println!("invalid padding");
                                    }
                                    else {
                                        msg.truncate(msg.len() - padsz);
                                        self.handle_message(&h, msg).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("No PublicKey found for sender {:?}: {}", h.sender, e);
                    }
                }
                println!("");
            }
            pltypes::QUEUE_SEND_COMPLETE => {
                println!("QUEUE_SEND_COMPLETE\n")
            }

            unknown => {
                println!("Unknown Payload Type: {}", unknown);
            }
        }

        Ok(())
    }
    
}

#[tokio::main]
async fn main() -> anyhow::Result<()>{
    sodiumoxide::init().expect("failed sodium initialisation");

    let args = std::env::args().collect::<Vec<_>>();
    let f = args.get(1).context("missing arg")?;
    let u = import::json_file::from_file(f)?;

    let mut agent = Agent::new(u).await?;
    agent.listen().await?;

    Ok(())
}
