use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as naclbox;
use sodiumoxide::crypto::stream::xsalsa20;
use rpassword;
use std::io;
use std::io::BufRead;
use std::io::Write;
use crypto::digest::Digest;

pub struct User{
    pub id: [u8; 8],
    pub sk: naclbox::SecretKey,
}

pub fn decrypt_id_backup(backup: &str, password: &str) -> io::Result<User>{
    let b = backup.split('-').collect::<Vec<_>>().join("");
    let b = base32::decode(base32::Alphabet::RFC4648{padding:false}, &b).unwrap();


    let salt = &b[..8];
    let ct = &b[8..];
    let mut backup_key = [0u8; 32];

    crypto::pbkdf2::pbkdf2(&mut crypto::hmac::Hmac::new(crypto::sha2::Sha256::new(), password.as_bytes()),
        salt, 100000_u32, &mut backup_key);

    let backup_key = xsalsa20::Key::from_slice(&backup_key).unwrap();
    let pt = xsalsa20::stream_xor(ct, &xsalsa20::Nonce::from_slice(&[0u8; xsalsa20::NONCEBYTES as usize]).unwrap(), &backup_key);
    let id_ = &pt[..8];
    let mut id = [0u8; 8];
    id.clone_from_slice(&id_);
    let id = id;

    let sk = &pt[8..40];
    let decrypted_checksum = &pt[40..42];
    
    let calculated_checksum = {
        let mut d = crypto::sha2::Sha256::new();
        d.input(&pt[..40]);
        let mut h = [0u8; 32];
        d.result(&mut h[..]);
        h
    };

    if &calculated_checksum[..2] != decrypted_checksum {
        return Err(io::Error::new(io::ErrorKind::Other,"Password seams to be wrong"));
    }


    eprintln!("Password seams to be correct");
    //let id = String::from_utf8(id.to_vec()).expect("weird ID recovered");
    let sk = naclbox::SecretKey::from_slice(sk).unwrap();
    
    Ok(User{sk, id})
}

fn main() -> io::Result<()>{
    sodiumoxide::init().expect("failed sodium initialisation");
    let p = rpassword::read_password_from_tty(Some("Not your password: "))?;
    println!("Hello, world! You entered '{}'", p);
    eprint!("Backup String: ");
    io::stdout().flush()?;
    let b = io::stdin().lock().lines().next().unwrap()?;

    let u = decrypt_id_backup(&b, &p)?;

    let j = serde_json::json!({
        "user": {
            "privatekey" : base64::encode(&u.sk),
            "identity" : String::from_utf8(u.id.to_vec()).expect("ID must be ASCII"),
        }
    });
    serde_json::to_writer_pretty(io::stdout(), &j)?;
    io::stdout().flush()?;

    Ok(())
}

