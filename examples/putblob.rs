use tokio;
use threema_client::blob_api;
use std::io::prelude::*;
use std::io::BufReader;
use env_logger;

#[tokio::main]
async fn main(){
    env_logger::init();
    let argv = std::env::args().collect::<Vec<_>>();
    let mut blob = vec![];
    if argv.len() == 2 {
        let fname = &argv[1];
        let f = std::fs::File::open(fname).expect(fname);
        BufReader::new(f).read_to_end(&mut blob).expect(fname);
    }
    else {
        std::io::stdin().lock().read_to_end(&mut blob).expect("reading stdin");
    }
    let c = blob_api::Client::new();
    let blobid = c.upload(&blob).await.expect("upload blob");
    println!("{}", blobid.hex());
}
