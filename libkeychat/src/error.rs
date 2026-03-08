use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeychatError {
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("bip39 error: {0}")]
    Bip39(#[from] bip39::Error),
    #[error("bip32 error: {0}")]
    Bip32(#[from] bitcoin::bip32::Error),
    #[error("bech32 encode error: {0}")]
    Bech32Encode(#[from] bech32::EncodeError),
    #[error("bech32 decode error: {0}")]
    Bech32Decode(#[from] bech32::DecodeError),
    #[error("bech32 hrp error: {0}")]
    Bech32Hrp(#[from] bech32::primitives::hrp::Error),
    #[error("invalid bech32 hrp: expected {expected}, found {found}")]
    InvalidHrp {
        expected: &'static str,
        found: String,
    },
    #[error("invalid key length: expected {expected}, found {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
    #[error("signal protocol error: {0}")]
    Signal(#[from] libsignal_protocol::SignalProtocolError),
    #[error("serde json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("utf8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("invalid relay url: {0}")]
    InvalidRelayUrl(String),
    #[error("missing tag: {0}")]
    MissingTag(&'static str),
    #[error("missing peer: {0}")]
    MissingPeer(String),
    #[error("missing sending address for peer: {0}")]
    MissingSendingAddress(String),
    #[error("nostr signature mismatch")]
    InvalidSignature,
    #[error("invalid message kind: expected {expected}, found {actual}")]
    InvalidEventKind { expected: u16, actual: u16 },
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("nostr error: {0}")]
    Nostr(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("group error: {0}")]
    Group(String),
    #[error("mls error: {0}")]
    Mls(String),
    #[error("mls user not initialized: {0}")]
    MlsNotInitialized(String),
    #[error("ciphertext is neither a Signal message nor a PreKey Signal message")]
    InvalidCiphertext,
}

pub type Result<T> = std::result::Result<T, KeychatError>;

impl From<hex::FromHexError> for KeychatError {
    fn from(value: hex::FromHexError) -> Self {
        KeychatError::InvalidHex(value.to_string())
    }
}

impl From<bincode::Error> for KeychatError {
    fn from(value: bincode::Error) -> Self {
        KeychatError::Mls(value.to_string())
    }
}
