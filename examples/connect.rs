use env_logger;
use tokio;
use anyhow::Context;

use threema_client::*;

#[derive(Default)]
pub struct AddressBook{
    key_cache: std::collections::HashMap<ThreemaID, naclbox::PublicKey>,
    api: directory_api::Client,
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
    r: transport::ReadHalf,
    w: transport::WriteHalf,
    contacts: AddressBook,
}

impl Agent {
    pub async fn new(creds: Credentials) -> anyhow::Result<Self>{
        use transport::{SERVER, ThreemaServer};
        let server = ThreemaServer {addr: SERVER.to_string(), pk: naclbox::PublicKey::from_slice(b"E\x0b\x97W5'\x9f\xde\xcb3\x13d\x8f_\xc6\xee\x9f\xf46\x0e\xa9*\x8c\x17Q\xc6a\xe4\xc0\xd8\xc9\t").unwrap()};
        let (r, w) = transport::connect(&server, &creds).await?;
        println!("logged in!");
        let contacts = AddressBook::default();

        Ok(Agent{creds, r, w, contacts})
    }
    pub async fn listen(&mut self) -> anyhow::Result<()>{
        loop {
            let p = self.r.receive_packet().await?;
            self.handle_packet(&p).await?;
        }
    }

    async fn handle_message(&mut self, envelope: &transport::Envelope, content: Vec<u8>) {
        let msg_type = content[0];
        let msg = &content[1..];
        use msg_types::*;
        match (msg_type, msg.len()) {
            (TEXT, _) => {
                println!("{:?} ({}) => {:?}: {}", envelope.sender, envelope.nickname, &envelope.recipient, String::from_utf8_lossy(msg));
                let _res = self.w.send_download_ack(envelope).await;
            }
            (TYPING_INDICATOR, 1) => {
                let x = if msg[0] == 1 {"is"} else {"has stopped"};
                println!("{} ({:?}) {} typing", envelope.nickname, envelope.sender, x);
            }
            (CONTACT_SET_PHOTO, 52) => {
                let blobref = blob_api::BlobRef::from_slice(msg);
                println!("CONTACT_SET_PHOTO, blob {:?}, {}", blobref, blobref.hex());
                //let res = blob_api::Client::new().download(&blobref).await;
                //println!(":) {:?}", res);
                
            }
            (unknown_type, unknown_length) => {
                eprintln!("Message with unknown type {} or length {}: {:?}", unknown_type, unknown_length, msg)
            }
        }
    }
    async fn handle_packet(&mut self, packet: &transport::Packet) -> Result<(), ParseError>{
        match packet {
            transport::Packet::BoxedMessageDownload(m) => {
                println!("New Message!");
                println!("{:?}", &m.envelope);
                match self.contacts.lookup(&m.envelope.sender).await {
                    Ok(their_pk) => {
                        match m.open(&their_pk, &self.creds.sk) {
                            Ok(msg) => self.handle_message(&m.envelope, msg).await,
                            Err(e) => eprintln!("Decryption or verification failed: {}", e),
                        }
                    }
                    Err(e) => {
                        eprintln!("No PublicKey found for sender {:?}: {}", m.envelope.sender, e);
                    }
                }
                println!("");
            }
            transport::Packet::QueueSendComplete => {
                println!("QUEUE_SEND_COMPLETE\n");
            }

            unknown => {
                println!("Unknown Payload Type: {:?}", unknown);
            }
        }

        Ok(())
    }
    
}

#[tokio::main]
async fn main() -> anyhow::Result<()>{
    sodiumoxide::init().expect("failed sodium initialisation");
    env_logger::init();

    let args = std::env::args().collect::<Vec<_>>();
    let f = args.get(1).context("missing arg")?;
    let u = import::json_file::from_file(f)?;

    let mut agent = Agent::new(u).await?;
    agent.listen().await?;

    Ok(())
}
