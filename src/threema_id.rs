use thiserror;
use std::convert::TryFrom;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreemaID {
    arr: [u8; ThreemaID::SIZE]
}
impl ThreemaID {
    const SIZE:usize = 8;

    pub fn as_bytes(&self) -> &[u8] {
        return &self.arr;
    }
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.arr).unwrap()
    }
}

impl TryFrom<&[u8]> for ThreemaID {
    type Error = InvalidID;
    fn try_from(bytes: &[u8]) -> Result<Self, InvalidID>{
        // must be 8 chars and valid utf8 and 8 bytes, so it must be ascii
        if bytes.len() != 8 || !bytes.is_ascii() {
            return Err(InvalidID);
        }
        let mut arr = [0; Self::SIZE];
        arr.copy_from_slice(&bytes);
        Ok(ThreemaID{arr})
    }
}

impl TryFrom<&str> for ThreemaID {
    type Error = InvalidID;
    fn try_from(s: &str) -> Result<Self, InvalidID>{
        Self::try_from(s.as_bytes())
    }
}
impl std::convert::AsRef<[u8]> for ThreemaID {
    fn as_ref(&self) -> &[u8] {
        return self.as_bytes();
    }
}

impl std::convert::AsRef<str> for ThreemaID {
    fn as_ref(&self) -> &str {
        return self.as_str();
    }
}

impl std::fmt::Debug for ThreemaID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "ThreemaID#\"{}\"", self.as_str())
    }
}
impl std::fmt::Display for ThreemaID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.as_str())
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Invalid ID Format (must be 8 ascii chars)")]
pub struct InvalidID;

