use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::group::types::GroupEvent;
use crate::protocol::address::AddressManager;
use crate::signal::SignalParticipantSnapshot;

/// Configuration for initializing a `KeychatClient`.
pub struct ClientConfig {
    /// Path to the SQLite database file.
    pub db_path: String,
    /// Display name used in hello messages.
    pub display_name: String,
    /// Relay URLs to connect to.
    pub relays: Vec<String>,
    /// BIP-39 mnemonic phrase. If `None`, a new one is generated.
    pub mnemonic: Option<String>,
    /// Media relay server base URL.
    /// If `None`, defaults to `https://relay.keychat.io`.
    pub media_server: Option<String>,
}

/// Serializable snapshot of all client state for persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientSnapshot {
    /// Signal participant snapshots keyed by peer nostr pubkey hex.
    pub signals: BTreeMap<String, SignalParticipantSnapshot>,
    /// Remote Signal protocol addresses (name, device_id) keyed by peer pubkey.
    pub remote_addrs: BTreeMap<String, (String, u32)>,
    /// Address manager state.
    pub address_manager: AddressManager,
}

/// An inbound event from the network.
#[derive(Debug, Clone)]
pub enum InboundEvent {
    /// A direct message from a peer.
    DirectMessage {
        /// Sender's Nostr pubkey hex.
        sender: String,
        /// Decrypted plaintext.
        plaintext: String,
        /// Whether this was a PreKey message (first message in session).
        is_prekey: bool,
    },
    /// A friend request (hello) received.
    FriendRequest {
        /// Sender's Nostr pubkey hex.
        sender: String,
        /// Sender's display name.
        sender_name: String,
        /// Hello message text.
        message: String,
    },
    /// A group event (message, invite, management action).
    GroupEvent {
        /// The peer who sent this event (via their Signal session).
        from_peer: String,
        /// The parsed group event.
        event: GroupEvent,
    },
}
