use crate::{naclbox, Credentials};
use anyhow::{self, Context};

pub fn from_file(f: &str) -> anyhow::Result<Credentials> {
    let txt = std::fs::read_to_string(f)?;
    let j : serde_json::Value = serde_json::from_str(&txt)?;

    let sk = base64::decode(
        j.get("user").context("key user missing in json")?
        .get("privatekey").context("key user.privkey missing")?
        .as_str().context("user.privkey must be a string")?)?;
    let sk = naclbox::SecretKey::from_slice(&sk).context("loading key failed")?;

    let id = j.get("user").unwrap()
        .get("identity").context("key user.identity missing")?
        .as_str().context("user.identity must be a string in json")?;
    return Ok(Credentials::new(id, sk)?);
}
