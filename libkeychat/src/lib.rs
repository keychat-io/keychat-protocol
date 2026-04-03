//! # libkeychat
//!
//! Keychat Protocol v2 implementation.
//!
//! ## Phase 1: Identity & Transport
//! - **Identity**: BIP-39 mnemonic → Nostr secp256k1 keypair (NIP-06)
//! - **NIP-44**: Authenticated encryption for Nostr (XChaCha20 + HMAC-SHA256)
//! - **Gift Wrap**: NIP-17 three-layer wrapping for metadata-protected messages
//! - **Transport**: Nostr relay connectivity, subscriptions, and event publishing
//!
//! ## Phase 2: KCMessage v2 + Signal Key Generation
//! - **Message**: KCMessage v2 envelope with typed payloads and forward compatibility
//! - **Signal Keys**: Curve25519 identity, signed/one-time prekeys, Kyber KEM prekeys
//! - **globalSign**: Schnorr signature binding Nostr identity to Signal identity
//!
//! ## Phase 3: Signal Sessions + Friend Request Flow
//! - **Signal Store**: In-memory protocol stores for Signal session management
//! - **Signal Session**: X3DH session establishment, encrypt/decrypt with Double Ratchet
//! - **Friend Request**: Send/receive/accept friend requests with NIP-17 wrapping
//! - **Encrypted Messaging**: Send/receive Signal-encrypted KCMessages via kind:1059
//!
//! ## Phase 4: Signal Chat Transport + SignalPrekeyAuth
//! - **Chat Transport**: Send/receive encrypted messages as kind:1059 events (Mode 1)
//! - **SignalPrekeyAuth**: Identity binding on first PrekeyMessage after session establishment
//! - **Message Routing**: KCMessage v2 kind-based dispatch with forward compatibility
//!
//! ## Phase 5: Address Rotation
//! - **AddressManager**: Per-peer ratchet-derived address tracking with sliding window
//! - **ChatSession**: High-level wrapper integrating Signal + address rotation
//! - **Address Resolution**: §9.4 priority-based sending address resolution
//! - **Lifecycle**: firstInbox → ratchet-derived addresses with automatic rotation
//!
//! ## Phase 6A: Signal Group (sendAll)
//! - **SignalGroup**: Group struct with members, admins, and group ID (Nostr pubkey)
//! - **GroupManager**: Manages multiple groups, lookup by groupId
//! - **send_group_message**: Fan-out encryption to all members via 1:1 Signal sessions
//! - **receive_group_message**: Decrypt + verify groupId membership
//! - **Group Management**: Invite, remove, leave, dissolve, rename operations
//! - **RoomProfile**: Serializable invite payload with member list
//!
//! ## Phase 6B: MLS Large Group (RFC 9420)
//! - **MlsProvider**: OpenMLS provider wrapper with in-memory SQLite storage
//! - **MlsParticipant**: Identity, credential, and group operations wrapper
//! - **mlsTempInbox**: Shared receiving address derived from MLS export secret (§11.2)
//! - **MLS Transport**: send/receive kind:1059 messages, broadcast Commits
//! - **Group Management**: Create, add/remove members, join, dissolve, rename via Commits
//! - **KeyPackage**: Publish (kind 10443) and parse for member addition
//!
//! ## Phase 7: Media & Payment
//! - **Media**: AES-256-CTR file encryption/decryption with PKCS7 padding (§12.1)
//! - **File Messages**: Build KCMessage for files, voice recordings, multi-file transfers
//! - **Cashu**: Ecash token message builders and validation (§13)
//! - **Lightning**: Lightning invoice message builders
//! - **Ecash Stamps**: Attach ecash stamps to relay events (§13.1)

pub mod address;
pub mod chat;
pub mod error;
pub mod ffi;
pub mod friend_request;
pub mod giftwrap;
pub mod group;
pub mod identity;
pub mod media;
pub mod message;
#[cfg(feature = "mls")]
pub mod mls;
#[cfg(feature = "mls")]
pub mod mls_extension;
#[cfg(feature = "mls")]
pub mod mls_provider;
pub mod nip44;
pub mod payment;
pub mod persistent_signal_store;
pub mod session;
pub mod signal_keys;
pub mod signal_session;
pub mod signal_store;
pub mod stamp;
#[cfg(feature = "storage")]
pub mod storage;
pub mod transport;

pub use address::{AddressManager, AddressUpdate, DerivedAddress, PeerAddressState};
pub use chat::{
    create_signal_prekey_auth, extract_p_tags, handle_received_message, parse_and_route,
    receive_encrypted_message, receive_encrypted_message_flexible, send_encrypted_message,
    verify_signal_prekey_auth, MessageAction, MessageMetadata,
};
pub use error::{KeychatError, Result};
pub use friend_request::{
    accept_friend_request, accept_friend_request_persistent, receive_friend_request,
    receive_signal_message, send_friend_request, send_friend_request_persistent,
    send_signal_message, FriendRequestAccepted, FriendRequestReceived, FriendRequestState,
};
pub use giftwrap::{create_gift_wrap, unwrap_gift_wrap, UnwrappedMessage};
pub use group::{
    build_group_admin_message, create_signal_group, encrypt_for_group_member, receive_group_invite,
    receive_group_message, send_group_dissolve, send_group_invite, send_group_member_removed,
    send_group_message, send_group_name_changed, send_group_self_leave, GroupManager, GroupMember,
    GroupMessageMetadata, RoomMember, RoomProfile, SignalGroup,
};
pub use identity::{normalize_pubkey, EphemeralKeypair, Identity, IdentityWithMnemonic};
pub use media::{
    build_file_message, build_multi_file_message, build_voice_message, decrypt_file, encrypt_file,
    encrypt_file_with_key, EncryptedFile,
};
pub use message::{
    FileCategory, ForwardFrom, KCCashuPayload, KCFilePayload, KCFilesPayload,
    KCFriendApprovePayload, KCFriendRejectPayload, KCFriendRequestPayload, KCLightningPayload,
    KCMessage, KCMessageKind, KCTextPayload, ReplyTo, SignalPrekeyAuth,
};
#[cfg(feature = "mls")]
pub use mls::{
    broadcast_commit, derive_mls_temp_inbox, parse_key_package, publish_key_package,
    receive_mls_message, send_mls_message, MlsGroupInvitePayload, MlsMessageMetadata,
    MlsParticipant, MlsProvider, KIND_MLS_KEY_PACKAGE, MLS_CIPHERSUITE,
};
pub use payment::{
    attach_ecash_stamp, build_cashu_message, build_lightning_message, validate_cashu_token,
};
pub use session::ChatSession;
pub use signal_keys::{
    build_friend_request_payload, compute_global_sign, generate_kyber_prekey,
    generate_one_time_prekey, generate_signal_identity, generate_signed_prekey, verify_global_sign,
    FriendRequestSecrets, KyberPrekey, OneTimePrekey, SignalIdentity, SignedPrekey,
};
pub use signal_session::{
    derive_nostr_address_from_ratchet, generate_prekey_material, reconstruct_prekey_material,
    serialize_prekey_material, SignalCiphertext, SignalDecryptResult, SignalParticipant,
    SignalPreKeyMaterial,
};
pub use signal_store::{CapturingSessionStore, SignalProtocolStoreBundle};
pub use stamp::{fetch_relay_info, RelayFeeRule, RelayFees, RelayInfo};
#[cfg(feature = "cashu")]
pub use stamp::{CashuWallet, StampManager};
// Re-export libsignal types that clients need
pub use libsignal_protocol::{
    DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KyberPreKeyId, KyberPreKeyRecord,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PrivateKey as SignalPrivateKey, ProtocolAddress,
    SignedPreKeyId, SignedPreKeyRecord,
};
pub use storage::{
    DerivedAddressSerialized, PeerAddressStateSerialized, PeerMapping, SecureStorage,
};
pub use transport::{PublishResult, RelayHealth, Transport, DEFAULT_RELAYS};

// Re-export key nostr types for convenience
pub use nostr::message::relay::RelayMessage;
pub use nostr::{Event, EventId, Keys, Kind, PublicKey, SecretKey, Timestamp};
pub use nostr_sdk::{RelayPoolNotification, RelayStatus, SubscriptionId};
