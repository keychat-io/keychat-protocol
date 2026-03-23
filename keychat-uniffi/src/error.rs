use libkeychat::KeychatError;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KeychatUniError {
    #[error("Identity error: {msg}")]
    Identity { msg: String },
    #[error("Transport error: {msg}")]
    Transport { msg: String },
    #[error("Signal error: {msg}")]
    Signal { msg: String },
    #[error("Storage error: {msg}")]
    Storage { msg: String },
    #[error("Peer not found: {peer_id}")]
    PeerNotFound { peer_id: String },
    #[error("Invalid argument: {msg}")]
    InvalidArgument { msg: String },
    #[error("Not initialized: {msg}")]
    NotInitialized { msg: String },
}

impl From<KeychatError> for KeychatUniError {
    fn from(err: KeychatError) -> Self {
        match err {
            // Identity
            KeychatError::InvalidMnemonic(msg) => KeychatUniError::Identity { msg },
            KeychatError::Identity(msg) => KeychatUniError::Identity { msg },
            KeychatError::KeyDerivation(msg) => KeychatUniError::Identity { msg },
            // Transport
            KeychatError::Transport(msg) => KeychatUniError::Transport { msg },
            // Storage
            KeychatError::Storage(msg) => KeychatUniError::Storage { msg },
            // Signal/crypto
            KeychatError::Signal(msg) => KeychatUniError::Signal { msg },
            KeychatError::SignalEncrypt(msg) => KeychatUniError::Signal { msg },
            KeychatError::SignalDecrypt(msg) => KeychatUniError::Signal { msg },
            KeychatError::SignalSession(msg) => KeychatUniError::Signal { msg },
            KeychatError::SignalKey(msg) => KeychatUniError::Signal { msg },
            KeychatError::FriendRequest(msg) => KeychatUniError::Signal { msg },
            KeychatError::Nip44Encrypt(msg) => KeychatUniError::Signal { msg },
            KeychatError::Nip44Decrypt(msg) => KeychatUniError::Signal { msg },
            KeychatError::GiftWrap(msg) => KeychatUniError::Signal { msg },
            KeychatError::InvalidEvent(msg) => KeychatUniError::Signal { msg },
            KeychatError::Nostr(msg) => KeychatUniError::Signal { msg },
            KeychatError::Mls(msg) => KeychatUniError::Signal { msg },
            KeychatError::MediaCrypto(msg) => KeychatUniError::Signal { msg },
            KeychatError::Stamp(msg) => KeychatUniError::Signal { msg },
            KeychatError::InvalidCiphertext => KeychatUniError::Signal {
                msg: "invalid ciphertext".into(),
            },
            KeychatError::Serialization(e) => KeychatUniError::Signal {
                msg: e.to_string(),
            },
            KeychatError::Hex(e) => KeychatUniError::Signal {
                msg: e.to_string(),
            },
        }
    }
}
