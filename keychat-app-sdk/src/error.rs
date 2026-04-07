use libkeychat::KeychatError;

#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi-export", derive(uniffi::Error))]
pub enum KeychatUniError {
    #[error("Identity error: {msg}")]
    Identity { msg: String },
    #[error("Transport error: {msg}")]
    Transport { msg: String },
    #[error("Signal error: {msg}")]
    Signal { msg: String },
    #[error("Storage error: {msg}")]
    Storage { msg: String },
    #[error("Crypto error: {msg}")]
    Crypto { msg: String },
    #[error("MLS error: {msg}")]
    Mls { msg: String },
    #[error("Serialization error: {msg}")]
    Serialization { msg: String },
    #[error("Media crypto error: {msg}")]
    MediaCrypto { msg: String },
    #[error("Media transfer error: {msg}")]
    MediaTransfer { msg: String },
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
            // Signal protocol
            KeychatError::Signal(msg) => KeychatUniError::Signal { msg },
            KeychatError::SignalEncrypt(msg) => KeychatUniError::Signal { msg },
            KeychatError::SignalDecrypt(msg) => KeychatUniError::Signal { msg },
            KeychatError::SignalSession(msg) => KeychatUniError::Signal { msg },
            KeychatError::SignalKey(msg) => KeychatUniError::Signal { msg },
            KeychatError::FriendRequest(msg) => KeychatUniError::Signal { msg },
            // Crypto (NIP-44, GiftWrap, ciphertext)
            KeychatError::Nip44Encrypt(msg) => KeychatUniError::Crypto { msg },
            KeychatError::Nip44Decrypt(msg) => KeychatUniError::Crypto { msg },
            KeychatError::GiftWrap(msg) => KeychatUniError::Crypto { msg },
            KeychatError::InvalidCiphertext => KeychatUniError::Crypto {
                msg: "invalid ciphertext".into(),
            },
            // MLS
            KeychatError::Mls(msg) => KeychatUniError::Mls { msg },
            // Media crypto
            KeychatError::MediaCrypto(msg) => KeychatUniError::MediaCrypto { msg },
            // Nostr / event
            KeychatError::InvalidEvent(msg) => KeychatUniError::Signal { msg },
            KeychatError::Nostr(msg) => KeychatUniError::Signal { msg },
            KeychatError::Stamp(msg) => KeychatUniError::Signal { msg },
            // Serialization
            KeychatError::Serialization(e) => KeychatUniError::Serialization { msg: e.to_string() },
            KeychatError::Hex(e) => KeychatUniError::Serialization { msg: e.to_string() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_variants_are_distinct() {
        let mls: KeychatUniError = KeychatError::Mls("test".into()).into();
        assert!(matches!(mls, KeychatUniError::Mls { .. }));

        let crypto: KeychatUniError = KeychatError::Nip44Encrypt("test".into()).into();
        assert!(matches!(crypto, KeychatUniError::Crypto { .. }));

        let media: KeychatUniError = KeychatError::MediaCrypto("test".into()).into();
        assert!(matches!(media, KeychatUniError::MediaCrypto { .. }));

        let ser: KeychatUniError =
            KeychatError::Serialization(serde_json::from_str::<()>("bad").unwrap_err()).into();
        assert!(matches!(ser, KeychatUniError::Serialization { .. }));

        let signal: KeychatUniError = KeychatError::Signal("test".into()).into();
        assert!(matches!(signal, KeychatUniError::Signal { .. }));

        let storage: KeychatUniError = KeychatError::Storage("test".into()).into();
        assert!(matches!(storage, KeychatUniError::Storage { .. }));
    }
}
