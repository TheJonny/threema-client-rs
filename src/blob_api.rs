use sodiumoxide::crypto::secretbox::xsalsa20poly1305 as secretbox;
pub use secretbox::Key as BlobKey;

use std::convert::TryInto;
use reqwest;
use hex;

use thiserror;

pub type BlobId = [u8; 16];

// in the java code, file nonce, photo nonce, ... are all the same
const BLOB_NONCE: [u8;24] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01];
const THUMBNAIL_NONCE: [u8;24] = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02];
const UPLOAD_URL: &str = "https://upload.blob.threema.ch/upload";

#[derive(Debug, thiserror::Error)]
pub enum InvalidBlob {
    #[error("Blob server sent too many bytes")]
    TooLarge,
    #[error("Blob server sent too few bytes")]
    TooSmallDownload,
    #[error("Size in Blobref is too small for encrypted data")]
    TooSmallSize,
    #[error("Validation failed")]
    ValidationFailed,
    #[error("HTTP request unsuccessfull for {0}: {1}")]
    HttpError(String, reqwest::StatusCode),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Hex decoding Failed")]
    HexFailed,
    #[error("wrong size")]
    Size,
}

#[derive(Debug, Clone)]
pub struct BlobRef {
    pub id: BlobId,
    pub size: u32,
    pub key: BlobKey,
}


impl BlobRef {
    const SIZE: usize = 52;
    pub fn from_slice(data: &[u8]) -> Self{
        let id = data[0..16].try_into().unwrap();
        let size = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let key = BlobKey::from_slice(&data[20..52]).unwrap();
        return BlobRef{id, size, key};
    }
    pub fn from_hex(data: &str) -> Result<Self, ParseError>{
        let buf = hex::decode(data).map_err(|_| ParseError::HexFailed)?;
        if buf.len() != Self::SIZE {
            return Err(ParseError::Size);
        }
        return Ok(Self::from_slice(&buf))
    }
    pub fn to_slice(&self, out: &mut [u8]){
        out[0..16].clone_from_slice(&self.id);
        out[16..20].clone_from_slice(&self.size.to_le_bytes());
        out[20..52].clone_from_slice(self.key.as_ref());
    }
    pub fn hex(&self) -> String {
        let mut buf = [0; Self::SIZE];
        self.to_slice(&mut buf);
        return hex::encode(&buf);
    }
}

pub struct Client{
    http: reqwest::Client,
}
impl Client{

    pub fn new() -> Self{
        // certificate validation failed. For now disable checking. TODO Think about it
        // This is not a big problem, as the file is encrypted and authenticated anyway.
        //
        // TODO always limit response size!

        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .user_agent("Threema ist cool. (https://github.com/TheJonny/threema-rs)")
            .build().expect("HTTP Client creation failed");
        Client{http}
    }

    pub async fn download(&self, blobref: &BlobRef) -> Result<Vec<u8>, anyhow::Error>{
        let size = blobref.size as usize;
        let id_hex = hex::encode(&blobref.id);
        let url = format!("https://{}.blob.threema.ch/{}", &id_hex[0..2], id_hex);

        // Download 
        let mut res = self.http.get(&url).send().await?;
        if !res.status().is_success() {
            return Err(InvalidBlob::HttpError(url, res.status()).into());
        }
        let mut buf = Vec::<u8>::with_capacity(size);
        while let Some(b) = res.chunk().await? {
            if b.len() + buf.len() > size {
                return Err(InvalidBlob::TooLarge.into());
            }
            buf.extend_from_slice(&b);
        }
        if buf.len() != size {
            return Err(InvalidBlob::TooSmallDownload.into());
        }
        log::trace!("downloaded {} bytes for blobref {:?}", buf.len(), blobref);

        if size < secretbox::NONCEBYTES + secretbox::MACBYTES {
            return Err(InvalidBlob::TooSmallSize.into());
        }
        let nonce = secretbox::Nonce::from_slice(&BLOB_NONCE).unwrap();

        Ok(secretbox::open(&buf, &nonce, &blobref.key).map_err(|_| InvalidBlob::ValidationFailed)?)
    }
    pub async fn mark_done(&self, blobid: &BlobId) -> Result<(), anyhow::Error>{
        let id_hex = hex::encode(&blobid);
        let url = format!("https://{}.blob.threema.ch/{}/done", &id_hex[0..2], id_hex);
        let res = self.http.post(&url).send().await?;
        if !res.status().is_success() {
            return Err(InvalidBlob::HttpError(url, res.status()).into());
        }
        Ok(())
    }

    pub async fn upload(&self, plainblob: &[u8]) -> anyhow::Result<BlobRef> {
        if plainblob.len() + secretbox::MACBYTES > u32::MAX as usize {
            return Err(InvalidBlob::TooLarge.into());
        }
        let key = secretbox::gen_key();
        let nonce = secretbox::Nonce::from_slice(&BLOB_NONCE).unwrap();
        let enc = secretbox::seal(plainblob, &nonce, &key);
        let length = enc.len() as u64;
        let bodypart = reqwest::multipart::Part::stream_with_length(enc, length)
            .file_name("blob.bin");
        let body = reqwest::multipart::Form::new()
            .part("blob", bodypart);


        let res = self.http.post(UPLOAD_URL).multipart(body).send().await?;
        let id_hex = res.text().await?;
        let id_vec = hex::decode(&id_hex).map_err(|_| ParseError::HexFailed)?;
        let id: BlobId = id_vec.try_into().map_err(|_| ParseError::Size)?;

        return Ok(BlobRef{id, key, size: length as u32});
    }
}
