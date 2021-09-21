use crypto::scrypt::{ScryptParams, scrypt};
use anyhow::{self, Context};
use std::io;
use std::io::prelude::*;
use hex;
use sodiumoxide::crypto::secretbox;
//use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as naclbox;
use serde_json;

use flate2::read::GzDecoder;


/*struct User {
    privatekey: box_::SecretKey,
    nickname: String,
    // deserialize as profilePic
    profile_pic: Vec<u8>,
}
struct Contact{
    firstname: Option<String>,
    lastname: Option<String>,
    nickname: Option<String>,
    identity: String,
}

struct AccountBackup {
    user: User,
    contacts: Vec<Contact>,
}*/

fn download_backup(id: &str, password: &str) -> anyhow::Result<serde_json::Value> {
    sodiumoxide::init().expect("failed sodium initialisation");
    let mut threema_safe_master_key = [0u8; 64];
    eprintln!("Hashing...");
    scrypt(password.as_bytes(), id.as_bytes(), &ScryptParams::new(16, 8, 1), &mut threema_safe_master_key);
    let backup_id = hex::encode(&threema_safe_master_key[0..32]);
    let encryption_key = &threema_safe_master_key[32..64];
    let encryption_key = secretbox::Key::from_slice(encryption_key).context("create encryption key")?;
    let url = format!("https://safe-{}.threema.ch/backups/{}", &backup_id[0..2], backup_id);
    eprintln!("Requesting url: {}", &url);
    let client = reqwest::blocking::Client::new();
    let req = client.get(url)
        .header("User-Agent", "Some Threema custom client test")
        .header("Accept", "application/octet-stream");
    let res = req.send()?;

    let data = res.error_for_status()?.bytes()?;
    if data.len() < 24 {
        panic!("received len to short");
    }
    let nonce = secretbox::Nonce::from_slice(&data[0..24]).context("create Nonce")?;
    let decrypted = secretbox::open(&data[24..], &nonce, &encryption_key).expect("Decryption failed");
    drop(data);

    //let mut decompressed = String::new();
    let gzdecoder = GzDecoder::new(&decrypted[..]);//.read_to_string(&mut decompressed)?;

    //println!("Response: {:?}", decompressed);
    let j : serde_json::Value = serde_json::from_reader(gzdecoder)?;
    return Ok(j);
}

fn main() -> anyhow::Result<()>{
    eprint!("ID: ");
    io::stdout().flush()?;
    let id = io::stdin().lock().lines().next().unwrap()?;
    let p = rpassword::read_password_from_tty(Some("password: "))?;

    let mut j = download_backup(&id, &p)?;
    j.get_mut("user").unwrap().as_object_mut().unwrap().insert("identity".to_string(), serde_json::to_value(id)?);

    println!("{}", serde_json::to_string_pretty(&j)?);

    Ok(())
}
