/// TODO: top comment

/// alias for sodiumoxide::crypto::box_::curve25519xsalsa20poly1305, the used public key crypto
/// suite. This `pub use` exists as long as `naclbox::PublicKey` and `naclbox::SecretKey` are part
/// of this crate's API.
pub use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as naclbox;

use std::convert::TryInto;

/// utilities to import threema accounts from the mobile app
pub mod import;

/// access account- and keyserver
pub mod directory_api;

/// upload, download and delete files
pub mod blob_api;

mod threema_id;
pub use threema_id::{ThreemaID, InvalidID};

// TODO: move somewhere better
pub mod pltypes{
    /// Payload Types used in the transport protocol
    pub const ECHO_REQUEST : u32 =  0x00;
    pub const ECHO_REPLY : u32 =  0x80;
    pub const OUTGOING_MESSAGE : u32 =  0x01;
    pub const OUTGOING_MESSAGE_ACK : u32 =  0x81;
    pub const INCOMING_MESSAGE : u32 =  0x02;
    pub const INCOMING_MESSAGE_ACK : u32 =  0x82;
    pub const PUSH_NOTIFICATION_TOKEN : u32 =  0x20;
    pub const PUSH_ALLOWED_IDENTITIES : u32 =  0x21;
    pub const VOIP_PUSH_NOTIFICATION_TOKEN : u32 =  0x24;
    pub const QUEUE_SEND_COMPLETE : u32 =  0xd0;
    pub const ERROR : u32 =  0xe0;
    pub const ALERT : u32 =  0xe1;
}

/// Threema Transport Layer
pub mod transport;

/// Managed connection using the `transport` layer
/// (keep alive, reconnect, ack management)
pub mod messaging_client;

/// Account credentials: Threema-ID and SecretKey
pub struct Credentials{
    pub id: ThreemaID,
    pub sk: naclbox::SecretKey,
}

impl Credentials{
    pub fn new(id: &str, sk: naclbox::SecretKey) -> Result<Self, InvalidID>{
        Ok(Credentials{id: id.try_into()?, sk})
    }
}

/// Message types used inside end-to-end messages
pub mod msg_types{
    pub const TEXT: u8 = 0x01;
    pub const IMAGE: u8 = 0x02;
    pub const LOCATION: u8 = 0x10;
    pub const VIDEO: u8 = 0x13;
    pub const AUDIO: u8 = 0x14;
    pub const BALLOT_CREATE: u8 = 0x15;
    pub const BALLOT_VOTE: u8 = 0x16;
    pub const FILE: u8 = 0x17;
    pub const CONTACT_SET_PHOTO: u8 = 0x18;     
    pub const CONTACT_DELETE_PHOTO: u8 = 0x19;  
    pub const CONTACT_REQUEST_PHOTO: u8 = 0x1a; 
    pub const GROUP_TEXT: u8 = 0x41;            
    pub const GROUP_LOCATION: u8 = 0x42;        
    pub const GROUP_IMAGE: u8 = 0x43;           
    pub const GROUP_VIDEO: u8 = 0x44;           
    pub const GROUP_AUDIO: u8 = 0x45;           
    pub const GROUP_FILE: u8 = 0x46;            
    pub const GROUP_CREATE: u8 = 0x4a;          
    pub const GROUP_RENAME: u8 = 0x4b;          
    pub const GROUP_LEAVE: u8 = 0x4c;           
    pub const GROUP_ADD_MEMBER: u8 = 0x4d;      
    pub const GROUP_REMOVE_MEMBER: u8 = 0x4e;   
    pub const GROUP_DESTROY: u8 = 0x4f;         
    pub const GROUP_SET_PHOTO: u8 = 0x50;       
    pub const GROUP_REQUEST_SYNC: u8 = 0x51;    
    pub const GROUP_BALLOT_CREATE: u8 = 0x52;   
    pub const GROUP_BALLOT_VOTE: u8 = 0x53;     
    pub const GROUP_DELETE_PHOTO: u8 = 0x54;    
    pub const VOIP_CALL_OFFER: u8 = 0x60;       
    pub const VOIP_CALL_ANSWER: u8 = 0x61;      
    pub const VOIP_ICE_CANDIDATES: u8 = 0x62;   
    pub const VOIP_CALL_HANGUP: u8 = 0x63;      
    pub const VOIP_CALL_RINGING: u8 = 0x64;     
    pub const DELIVERY_RECEIPT: u8 = 0x80;      
    pub const TYPING_INDICATOR: u8 = 0x90;
}

/// Collection of errors that could happen during protocol and message parsing
#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Packet to short for packet type: expected {expected}, got {got} bytes")]
    ToShort{expected:usize, got:usize},
    #[error("Could not decode UTF8 - invalid encoding")]
    InvalidUTF8,
    #[error("Decryption or verification failed")]
    DecryptionError,
    #[error("Invalid padding")]
    InvalidPadding,
}
