use crate::{ThreemaID, naclbox};
use reqwest;
use serde_json;
use anyhow::{self,Context};
use base64;

#[derive(Debug, Clone)]
pub struct Client{
    pub server: String,
    pub http: reqwest::Client,
}

impl Default for Client{
    fn default() -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Accept", reqwest::header::HeaderValue::from_static("application/json"));
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .user_agent("Threema ist cool")
            .build().expect("Failed to build Directory API HTTP Client");
        Client{server: "https://ds-apip.threema.ch/".to_string(), http}
    }
}

impl Client{
    pub async fn get_pubkey(&self, id: &ThreemaID) -> anyhow::Result<naclbox::PublicKey> {
        let response : serde_json::Value = self.http
            .get(format!("{}/identity/{}", self.server, id)).send().await?
            .json().await?;
        let kb64 = response.get("publicKey").context("response is missing publicKey")?.as_str().context("publicKey must be a string")?;
        let buf = base64::decode(kb64)?;
        
        naclbox::PublicKey::from_slice(&buf).context("pubkey has wrong length")
    }
}
