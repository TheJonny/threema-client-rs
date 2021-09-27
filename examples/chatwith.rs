use tokio;
use std::convert::TryFrom;

use threema_client::directory_api;
use threema_client::messaging_client;
use threema_client::transport::{ThreemaServer, SERVER, Envelope};
use threema_client::naclbox;
use threema_client::{ThreemaID, Credentials, Peer};

use tokio::io::AsyncBufReadExt;

use std::sync::Arc;

async fn handle_message(envelope: &Envelope, content: &[u8]) -> bool{
    let msg_type = content[0];
    let msg = &content[1..];
    use threema_client::msg_types::*;
    match (msg_type, msg.len()) {
        (TEXT, _) => {
            println!("{:?} ({}) => {:?}: {}", envelope.sender, envelope.nickname, &envelope.recipient, String::from_utf8_lossy(msg));
            true
        }
        (TYPING_INDICATOR, 1) => {
            let x = if msg[0] == 1 {"is"} else {"has stopped"};
            println!("{} ({:?}) {} typing", envelope.nickname, envelope.sender, x);
            false
        }
        (CONTACT_SET_PHOTO, 52) => {
            let blobref = threema_client::blob_api::BlobRef::from_slice(msg);
            println!("CONTACT_SET_PHOTO, blob {:?}, {}", blobref, blobref.hex());
            //let res = blob_api::Client::new().download(&blobref).await;
            //println!(":) {:?}", res);
            false
        }
        (unknown_type, unknown_length) => {
            eprintln!("Message with unknown type {} or length {}: {:?}", unknown_type, unknown_length, msg);
            false
        }
    }
}
async fn recv_print(c: Arc<messaging_client::Client>, peer: Peer, creds: Credentials){
    while let Some(e) =  c.event().await {
        match e {
            threema_client::messaging_client::Event::BoxedMessage(m) => {
                if m.envelope.sender != peer.id {
                    println!("new message from {} ({})", m.envelope.nickname, m.envelope.sender);
                }
                else {
                    match m.open(&peer.pk, &creds.sk) {
                        Ok(plain) => {
                            let ackit = handle_message(&m.envelope, &plain).await;
                            if ackit {
                                let _ = c.send_ack(&m.envelope.sender_ack()).await;
                            }
                        }
                        Err(e) => {
                            log::warn!("invalid message: {}", e);
                        }
                    }
                }
            }
            unhandled => {
                println!("Unhandled Event: {:?}", unhandled);
            }
        }
    }
}

#[tokio::main]
async fn main(){
    env_logger::init();
    let argv: Vec<_> = std::env::args().collect();
    if argv.len() != 3 {
        eprintln!("usage: {} CREDENTIALS-FILE CONTACT", argv[0]);
        std::process::exit(1);
    }
    let creds = threema_client::import::json_file::from_file(&argv[1]).expect("could not read credentials json");
    let contact = ThreemaID::try_from(argv[2].as_str()).expect("invalid ID");
    let contact_pubkey = directory_api::Client::default().get_pubkey(&contact).await.expect("could not get public key");
    let peer = threema_client::Peer{id: contact, pk: contact_pubkey};

    let server = ThreemaServer {addr: SERVER.to_string(), pk: naclbox::PublicKey::from_slice(b"E\x0b\x97W5'\x9f\xde\xcb3\x13d\x8f_\xc6\xee\x9f\xf46\x0e\xa9*\x8c\x17Q\xc6a\xe4\xc0\xd8\xc9\t").unwrap()};
    let messenger = Arc::new(messaging_client::Client::new(server, creds.clone()));

    let recver = tokio::spawn(recv_print(Arc::clone(&messenger), peer.clone(), creds.clone()));
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    loop {
        let mut line = String::new();
        match stdin.read_line(&mut line).await {
            Err(e) => {
                eprintln!("{}", e);
                break;
            }
            Ok(0) => { break; }
            Ok(_) => {
                let mut plain = threema_client::msg_types::TEXT.to_le_bytes().to_vec();
                plain.extend_from_slice(&line.trim_end().as_bytes());
                let m = threema_client::transport::BoxedMessage::encrypt(&creds, "hi", &peer, plain, 0);
                let sent = messenger.send_message(m).await;
                if let Err(c) = sent {
                    println!("{:?}", c);
                    break;
                }
            }
        }
    }
    messenger.shutdown();
    eprintln!("waiting for receiver to quit...");
    recver.await.unwrap();
}
