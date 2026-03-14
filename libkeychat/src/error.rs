use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeychatError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    #[error("NIP-44 encryption error: {0}")]
    Nip44Encrypt(String),

    #[error("NIP-44 decryption error: {0}")]
    Nip44Decrypt(String),

    #[error("gift wrap error: {0}")]
    GiftWrap(String),

    #[error("invalid event: {0}")]
    InvalidEvent(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("nostr error: {0}")]
    Nostr(String),

    #[error("hex encoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("signal key error: {0}")]
    SignalKey(String),

    #[error("signal encrypt error: {0}")]
    SignalEncrypt(String),

    #[error("signal decrypt error: {0}")]
    SignalDecrypt(String),

    #[error("signal session error: {0}")]
    SignalSession(String),

    #[error("signal protocol error: {0}")]
    Signal(String),

    #[error("friend request error: {0}")]
    FriendRequest(String),

    #[error("invalid ciphertext")]
    InvalidCiphertext,

    #[error("MLS error: {0}")]
    Mls(String),

    #[error("media crypto error: {0}")]
    MediaCrypto(String),

    #[error("storage error: {0}")]
    Storage(String),
}

impl From<libsignal_protocol::SignalProtocolError> for KeychatError {
    fn from(e: libsignal_protocol::SignalProtocolError) -> Self {
        KeychatError::Signal(e.to_string())
    }
}

impl From<secp256k1::Error> for KeychatError {
    fn from(e: secp256k1::Error) -> Self {
        KeychatError::Signal(format!("secp256k1 error: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, KeychatError>;
