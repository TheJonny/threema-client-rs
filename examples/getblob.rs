use tokio;
use threema_rs::blob_api;
use std::io::prelude::*;
use env_logger;

#[tokio::main]
async fn main(){
    env_logger::init();
    let argv = std::env::args().collect::<Vec<_>>();
    let hexid;
    let mark_done;
    if argv.len() == 2 {
        hexid = &argv[1];
        mark_done = false;
    }
    else if argv.len() == 3 && argv[1] == "-d" {
        hexid = &argv[2];
        mark_done = true;
    }
    else {
        eprintln!("usage: {} HEXBLOBREF", std::env::args().next().unwrap());
        std::process::exit(1);
    }
    let blobref = blob_api::BlobRef::from_hex(hexid).expect("invalid id given.");
    let c = blob_api::Client::new();
    let blob = c.download(&blobref).await.expect("retrieving blob");
    std::io::stdout().lock().write_all(&blob).expect("write out failed");
    if mark_done {
        c.mark_done(&blobref.id).await.expect("mark_done failed");
    }
}
