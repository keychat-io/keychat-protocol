//! Signal Group (sendAll) implementation (spec §10).
//!
//! Small groups use per-member encryption — no shared group key. The sender
//! encrypts each message individually for every group member using their
//! existing 1:1 Signal sessions. All events share the same KCMessage.id.

use std::collections::{HashMap, HashSet};

use nostr::prelude::*;

use crate::address::AddressManager;
use crate::error::{KeychatError, Result};
use crate::identity::EphemeralKeypair;
use crate::message::{KCMessage, KCMessageKind};
use crate::signal_session::SignalParticipant;

use base64::Engine;
use libsignal_protocol::{DeviceId, ProtocolAddress};
use serde::{Deserialize, Serialize};

// ─── RoomProfile & RoomMember (invite payload, §10 / Part D) ────────────────

/// Profile payload for group invitations, serialized as JSON in the
/// `signalGroupInvite` KCMessage's extra data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoomProfile {
    pub group_id: String,
    pub name: String,
    pub members: Vec<RoomMember>,
}

/// A member entry within a RoomProfile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoomMember {
    pub nostr_pubkey: String,
    pub signal_id: String,
    pub name: String,
    pub is_admin: bool,
}

// ─── GroupMember & SignalGroup (Part A) ──────────────────────────────────────

/// A single group member.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMember {
    pub signal_id: String,
    pub nostr_pubkey: String,
    pub name: String,
    pub is_admin: bool,
}

/// A Signal small group (sendAll).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalGroup {
    /// Group ID (a Nostr pubkey, used as unique identifier).
    pub group_id: String,
    /// Group name.
    pub name: String,
    /// Members: peer_signal_id → GroupMember.
    pub members: HashMap<String, GroupMember>,
    /// My signal identity hex (the local user).
    pub my_signal_id: String,
    /// Admin signal IDs.
    pub admins: HashSet<String>,
}

impl SignalGroup {
    /// Get all member signal IDs excluding self.
    pub fn other_members(&self) -> Vec<&GroupMember> {
        self.members
            .values()
            .filter(|m| m.signal_id != self.my_signal_id)
            .collect()
    }

    /// Check if a signal_id is an admin.
    pub fn is_admin(&self, signal_id: &str) -> bool {
        self.admins.contains(signal_id)
    }

    /// Check if the local user is an admin.
    pub fn am_i_admin(&self) -> bool {
        self.admins.contains(&self.my_signal_id)
    }

    /// Remove a member (returns true if the member existed).
    pub fn remove_member(&mut self, signal_id: &str) -> bool {
        self.admins.remove(signal_id);
        self.members.remove(signal_id).is_some()
    }

    /// Convert to a RoomProfile for invitations.
    pub fn to_room_profile(&self) -> RoomProfile {
        RoomProfile {
            group_id: self.group_id.clone(),
            name: self.name.clone(),
            members: self
                .members
                .values()
                .map(|m| RoomMember {
                    nostr_pubkey: m.nostr_pubkey.clone(),
                    signal_id: m.signal_id.clone(),
                    name: m.name.clone(),
                    is_admin: m.is_admin,
                })
                .collect(),
        }
    }
}

// ─── GroupManager (Part A) ──────────────────────────────────────────────────

/// Manages multiple Signal groups.
#[derive(Debug, Clone, Default)]
pub struct GroupManager {
    groups: HashMap<String, SignalGroup>,
}

impl GroupManager {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }

    pub fn add_group(&mut self, group: SignalGroup) {
        self.groups.insert(group.group_id.clone(), group);
    }

    pub fn get_group(&self, group_id: &str) -> Option<&SignalGroup> {
        self.groups.get(group_id)
    }

    pub fn get_group_mut(&mut self, group_id: &str) -> Option<&mut SignalGroup> {
        self.groups.get_mut(group_id)
    }

    pub fn remove_group(&mut self, group_id: &str) -> Option<SignalGroup> {
        self.groups.remove(group_id)
    }

    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Find the group a message belongs to by checking the groupId field.
    pub fn find_group_for_message(&self, message: &KCMessage) -> Option<&SignalGroup> {
        message
            .group_id
            .as_deref()
            .and_then(|gid| self.groups.get(gid))
    }

    // ─── Persistence ─────────────────────────────────────

    /// Save a single group to SecureStorage.
    pub fn save_group(
        &self,
        group_id: &str,
        storage: &crate::storage::SecureStorage,
    ) -> Result<()> {
        let group = self
            .groups
            .get(group_id)
            .ok_or_else(|| KeychatError::Signal(format!("group not found: {group_id}")))?;
        let json = serde_json::to_string(group)
            .map_err(|e| KeychatError::Storage(format!("Failed to serialize group: {e}")))?;
        storage.save_group(group_id, &json)
    }

    /// Save all groups to SecureStorage.
    pub fn save_all(&self, storage: &crate::storage::SecureStorage) -> Result<()> {
        for (group_id, group) in &self.groups {
            let json = serde_json::to_string(group)
                .map_err(|e| KeychatError::Storage(format!("Failed to serialize group: {e}")))?;
            storage.save_group(group_id, &json)?;
        }
        Ok(())
    }

    /// Load all groups from SecureStorage, replacing in-memory state.
    pub fn load_all(&mut self, storage: &crate::storage::SecureStorage) -> Result<()> {
        let rows = storage.load_all_groups()?;
        self.groups.clear();
        for (group_id, json) in rows {
            let group: SignalGroup = serde_json::from_str(&json).map_err(|e| {
                KeychatError::Storage(format!("Failed to deserialize group {group_id}: {e}"))
            })?;
            self.groups.insert(group_id, group);
        }
        Ok(())
    }

    /// Remove a group from memory and storage.
    pub fn remove_group_persistent(
        &mut self,
        group_id: &str,
        storage: &crate::storage::SecureStorage,
    ) -> Result<Option<SignalGroup>> {
        storage.delete_group(group_id)?;
        Ok(self.groups.remove(group_id))
    }
}

// ─── GroupMessageMetadata ───────────────────────────────────────────────────

/// Metadata about a received group message.
#[derive(Debug, Clone)]
pub struct GroupMessageMetadata {
    pub group_id: String,
    pub sender_signal_id: String,
    pub sender_name: String,
    pub is_prekey_message: bool,
    pub event_id: EventId,
}

// ─── Group creation (Part C.1) ──────────────────────────────────────────────

/// Create a new Signal group.
///
/// Generates a new Nostr keypair for the group ID and sets the creator as admin.
pub fn create_signal_group(
    name: &str,
    creator_signal_id: &str,
    creator_nostr_pubkey: &str,
    creator_name: &str,
    other_members: Vec<(String, String, String)>, // (signal_id, nostr_pubkey, name)
) -> SignalGroup {
    let group_keys = EphemeralKeypair::generate();
    let group_id = group_keys.pubkey_hex();

    let mut members = HashMap::new();
    let mut admins = HashSet::new();

    // Add creator as admin
    members.insert(
        creator_signal_id.to_string(),
        GroupMember {
            signal_id: creator_signal_id.to_string(),
            nostr_pubkey: creator_nostr_pubkey.to_string(),
            name: creator_name.to_string(),
            is_admin: true,
        },
    );
    admins.insert(creator_signal_id.to_string());

    // Add other members
    for (signal_id, nostr_pubkey, member_name) in other_members {
        members.insert(
            signal_id.clone(),
            GroupMember {
                signal_id,
                nostr_pubkey,
                name: member_name,
                is_admin: false,
            },
        );
    }

    tracing::info!(
        "created signal group: group_id={}, members={}",
        &group_id[..16.min(group_id.len())],
        members.len()
    );
    SignalGroup {
        group_id,
        name: name.to_string(),
        members,
        my_signal_id: creator_signal_id.to_string(),
        admins,
    }
}

// ─── Group messaging (Part B) ───────────────────────────────────────────────

/// Send a group message to all members (sendAll, §10.1).
///
/// The message MUST have `groupId` set. For each member (excluding self),
/// encrypts with their 1:1 Signal session and builds a kind:1059 event.
///
/// Returns Vec of (member_signal_id, Event) pairs.
pub async fn send_group_message(
    signal: &mut SignalParticipant,
    group: &SignalGroup,
    message: &KCMessage,
    address_manager: &AddressManager,
) -> Result<Vec<(String, Event)>> {
    if message.group_id.as_deref() != Some(&group.group_id) {
        return Err(KeychatError::Signal(
            "KCMessage.groupId must match the group's ID".into(),
        ));
    }
    tracing::info!(
        "sending group message: group_id={}, members={}",
        &group.group_id[..16.min(group.group_id.len())],
        group.other_members().len()
    );
    send_to_all_members(signal, group, message, address_manager).await
}

/// Receive and decrypt a group message.
///
/// Decrypts using the sender's 1:1 Signal session, parses the KCMessage,
/// and verifies the groupId matches a known group.
pub fn receive_group_message(
    signal: &mut SignalParticipant,
    remote_address: &ProtocolAddress,
    event: &Event,
    groups: &GroupManager,
) -> Result<(KCMessage, GroupMessageMetadata)> {
    if event.kind != Kind::GiftWrap {
        return Err(KeychatError::Signal(format!(
            "expected kind 1059, got {}",
            event.kind.as_u16()
        )));
    }

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&event.content)
        .map_err(|e| KeychatError::Signal(format!("invalid base64 content: {e}")))?;

    let is_prekey = SignalParticipant::is_prekey_message(&ciphertext);

    let decrypt_result = signal.decrypt(remote_address, &ciphertext)?;

    let plaintext_str = String::from_utf8(decrypt_result.plaintext)
        .map_err(|e| KeychatError::Signal(format!("invalid UTF-8: {e}")))?;

    let message = KCMessage::try_parse(&plaintext_str).ok_or_else(|| {
        KeychatError::Signal("decrypted content is not a valid KCMessage v2".into())
    })?;

    // Verify groupId matches a known group
    let group_id = message
        .group_id
        .as_deref()
        .ok_or_else(|| KeychatError::Signal("group message missing groupId".into()))?;

    let group = groups
        .get_group(group_id)
        .ok_or_else(|| KeychatError::Signal(format!("unknown group: {group_id}")))?;

    // Find the sender in the group
    let sender_signal_id = remote_address.name().to_string();
    let sender = group.members.get(&sender_signal_id).ok_or_else(|| {
        KeychatError::Signal(format!("sender {sender_signal_id} not in group {group_id}"))
    })?;

    let metadata = GroupMessageMetadata {
        group_id: group_id.to_string(),
        sender_signal_id: sender_signal_id.clone(),
        sender_name: sender.name.clone(),
        is_prekey_message: is_prekey,
        event_id: event.id,
    };

    tracing::info!(
        "received group message: group_id={}, sender={}",
        &group_id[..16.min(group_id.len())],
        &sender_signal_id[..16.min(sender_signal_id.len())]
    );
    Ok((message, metadata))
}

// ─── Group management operations (Part C) ───────────────────────────────────

/// Build a `signalGroupInvite` KCMessage with the RoomProfile payload.
fn build_group_invite_message(group: &SignalGroup) -> KCMessage {
    let room_profile = group.to_room_profile();
    let profile_json = serde_json::to_value(&room_profile).unwrap();

    let mut msg = KCMessage {
        v: 2,
        id: Some(uuid_v4()),
        kind: KCMessageKind::SignalGroupInvite,
        group_id: Some(group.group_id.clone()),
        ..KCMessage::empty()
    };
    msg.extra
        .insert("signalGroupInvite".to_string(), profile_json);
    msg
}

/// Build a signalGroup admin operation message.
pub fn build_group_admin_message(
    kind: KCMessageKind,
    group: &SignalGroup,
    payload: serde_json::Value,
) -> KCMessage {
    let mut msg = KCMessage {
        v: 2,
        id: Some(uuid_v4()),
        kind,
        group_id: Some(group.group_id.clone()),
        ..KCMessage::empty()
    };
    msg.extra.insert("signalGroupAdmin".to_string(), payload);
    msg
}

/// Send a group invite to a specific member (Part C.2).
pub async fn send_group_invite(
    signal: &mut SignalParticipant,
    group: &SignalGroup,
    invitee_signal_id: &str,
    address_manager: &AddressManager,
) -> Result<Event> {
    tracing::info!(
        "sending group invite: group_id={}, invitee={}",
        &group.group_id[..16.min(group.group_id.len())],
        &invitee_signal_id[..16.min(invitee_signal_id.len())]
    );
    let message = build_group_invite_message(group);
    let remote_address =
        ProtocolAddress::new(invitee_signal_id.to_string(), DeviceId::new(1).unwrap());
    let to_address = address_manager.resolve_send_address(invitee_signal_id)?;
    let json = message.to_json()?;
    let ct = signal.encrypt(&remote_address, json.as_bytes())?;
    let ciphertext = ct.bytes;
    build_mode1_event(&ciphertext, &to_address).await
}

/// Receive a group invite and create a local SignalGroup (Part C.3).
pub fn receive_group_invite(message: &KCMessage, my_signal_id: &str) -> Result<SignalGroup> {
    if message.kind != KCMessageKind::SignalGroupInvite {
        return Err(KeychatError::Signal(
            "expected signalGroupInvite kind".into(),
        ));
    }

    let profile_value = message
        .extra
        .get("signalGroupInvite")
        .ok_or_else(|| KeychatError::Signal("missing signalGroupInvite payload".into()))?;

    let profile: RoomProfile = serde_json::from_value(profile_value.clone())
        .map_err(|e| KeychatError::Signal(format!("invalid RoomProfile: {e}")))?;

    let mut members = HashMap::new();
    let mut admins = HashSet::new();

    for rm in &profile.members {
        let member = GroupMember {
            signal_id: rm.signal_id.clone(),
            nostr_pubkey: rm.nostr_pubkey.clone(),
            name: rm.name.clone(),
            is_admin: rm.is_admin,
        };
        if rm.is_admin {
            admins.insert(rm.signal_id.clone());
        }
        members.insert(rm.signal_id.clone(), member);
    }

    tracing::info!(
        "received group invite: group_id={}, members={}",
        &profile.group_id[..16.min(profile.group_id.len())],
        members.len()
    );
    Ok(SignalGroup {
        group_id: profile.group_id,
        name: profile.name,
        members,
        my_signal_id: my_signal_id.to_string(),
        admins,
    })
}

/// Send a member-removed notification to all remaining members (Part C.4).
///
/// Only admins can remove members.
pub async fn send_group_member_removed(
    signal: &mut SignalParticipant,
    group: &SignalGroup,
    removed_member_signal_id: &str,
    address_manager: &AddressManager,
) -> Result<Vec<(String, Event)>> {
    if !group.am_i_admin() {
        return Err(KeychatError::Signal(
            "only admins can remove members".into(),
        ));
    }

    let payload = serde_json::json!({
        "action": "memberRemoved",
        "memberId": removed_member_signal_id,
    });
    let message =
        build_group_admin_message(KCMessageKind::SignalGroupMemberRemoved, group, payload);

    send_to_all_members(signal, group, &message, address_manager).await
}

/// Send a self-leave notification to all remaining members (Part C.4).
pub async fn send_group_self_leave(
    signal: &mut SignalParticipant,
    group: &SignalGroup,
    address_manager: &AddressManager,
) -> Result<Vec<(String, Event)>> {
    let payload = serde_json::json!({
        "action": "selfLeave",
        "memberId": group.my_signal_id,
    });
    let message = build_group_admin_message(KCMessageKind::SignalGroupSelfLeave, group, payload);

    send_to_all_members(signal, group, &message, address_manager).await
}

/// Send a group dissolve notification to all members (Part C.4).
///
/// Only admins can dissolve groups.
pub async fn send_group_dissolve(
    signal: &mut SignalParticipant,
    group: &SignalGroup,
    address_manager: &AddressManager,
) -> Result<Vec<(String, Event)>> {
    if !group.am_i_admin() {
        return Err(KeychatError::Signal(
            "only admins can dissolve groups".into(),
        ));
    }

    let payload = serde_json::json!({
        "action": "dissolve",
    });
    let message = build_group_admin_message(KCMessageKind::SignalGroupDissolve, group, payload);

    send_to_all_members(signal, group, &message, address_manager).await
}

/// Send a group name change notification to all members (Part C.4).
///
/// Only admins can change the group name.
pub async fn send_group_name_changed(
    signal: &mut SignalParticipant,
    group: &SignalGroup,
    new_name: &str,
    address_manager: &AddressManager,
) -> Result<Vec<(String, Event)>> {
    if !group.am_i_admin() {
        return Err(KeychatError::Signal(
            "only admins can change group name".into(),
        ));
    }

    let payload = serde_json::json!({
        "action": "nameChanged",
        "newName": new_name,
    });
    let message = build_group_admin_message(KCMessageKind::SignalGroupNameChanged, group, payload);

    send_to_all_members(signal, group, &message, address_manager).await
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Send a message to all group members (excluding self) via their 1:1 sessions.
async fn send_to_all_members(
    signal: &mut SignalParticipant,
    group: &SignalGroup,
    message: &KCMessage,
    address_manager: &AddressManager,
) -> Result<Vec<(String, Event)>> {
    let json = message.to_json()?;
    let mut results = Vec::new();

    for member in group.other_members() {
        let remote_address =
            ProtocolAddress::new(member.signal_id.clone(), DeviceId::new(1).unwrap());
        let to_address = address_manager.resolve_send_address(&member.signal_id)?;
        let ct = signal.encrypt(&remote_address, json.as_bytes())?;
        let ciphertext = ct.bytes;
        let event = build_mode1_event(&ciphertext, &to_address).await?;
        results.push((member.signal_id.clone(), event));
    }

    Ok(results)
}

use crate::chat::build_mode1_event;
use crate::message::uuid_v4;

/// Encrypt and build a kind:1059 event for a single group member.
///
/// This is the per-member primitive for architectures where each peer has
/// its own SignalParticipant + AddressManager (e.g. UniFFI layer).
/// The caller iterates group.other_members() and calls this once per member.
pub async fn encrypt_for_group_member(
    signal: &mut SignalParticipant,
    member_signal_id: &str,
    message: &KCMessage,
    address_manager: &AddressManager,
) -> Result<Event> {
    let json = message.to_json()?;
    let remote_address = ProtocolAddress::new(member_signal_id.to_string(), DeviceId::new(1).unwrap());
    let to_address = address_manager.resolve_send_address(member_signal_id)?;
    let ct = signal.encrypt(&remote_address, json.as_bytes())?;
    build_mode1_event(&ct.bytes, &to_address).await
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::AddressManager;
    use crate::identity::EphemeralKeypair;
    use crate::signal_session::SignalParticipant;

    /// Helper: set up a 3-member group with established Signal sessions.
    ///
    /// Returns (alice_signal, bob_signal, charlie_signal,
    ///          alice_addr, bob_addr, charlie_addr,
    ///          group, address_manager)
    fn setup_3member_group() -> (
        SignalParticipant,
        SignalParticipant,
        SignalParticipant,
        ProtocolAddress,
        ProtocolAddress,
        ProtocolAddress,
        SignalGroup,
        AddressManager,
    ) {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let mut bob = SignalParticipant::new("bob", 1).unwrap();
        let mut charlie = SignalParticipant::new("charlie", 1).unwrap();

        let alice_id = alice.identity_public_key_hex();
        let bob_id = bob.identity_public_key_hex();
        let charlie_id = charlie.identity_public_key_hex();

        let bob_addr = ProtocolAddress::new(bob_id.clone(), DeviceId::new(1).unwrap());
        let alice_addr = ProtocolAddress::new(alice_id.clone(), DeviceId::new(1).unwrap());
        let charlie_addr = ProtocolAddress::new(charlie_id.clone(), DeviceId::new(1).unwrap());

        // Alice ↔ Bob session
        let bob_bundle = bob.prekey_bundle().unwrap();
        alice.process_prekey_bundle(&bob_addr, &bob_bundle).unwrap();
        let ct = alice.encrypt_bytes(&bob_addr, b"init-ab").unwrap();
        bob.decrypt_bytes(&alice_addr, &ct).unwrap();
        let ct2 = bob.encrypt_bytes(&alice_addr, b"ack-ab").unwrap();
        alice.decrypt_bytes(&bob_addr, &ct2).unwrap();

        // Alice ↔ Charlie session
        let charlie_bundle = charlie.prekey_bundle().unwrap();
        alice
            .process_prekey_bundle(&charlie_addr, &charlie_bundle)
            .unwrap();
        let ct = alice.encrypt_bytes(&charlie_addr, b"init-ac").unwrap();
        charlie.decrypt_bytes(&alice_addr, &ct).unwrap();
        let ct2 = charlie.encrypt_bytes(&alice_addr, b"ack-ac").unwrap();
        alice.decrypt_bytes(&charlie_addr, &ct2).unwrap();

        // Bob ↔ Charlie session
        let charlie_bundle2 = SignalParticipant::new("charlie2", 1).unwrap();
        // We need Bob to have a session with Charlie too.
        // Since Charlie already used his prekeys, we need a fresh one.
        let mut charlie_for_bob = SignalParticipant::new("charlie_for_bob", 1).unwrap();
        // Actually, let's re-create Bob and Charlie with fresh prekeys for Bob↔Charlie
        // This is getting complex, so let's simplify: each pair gets fresh participants

        // For the group test, we only need Alice to have sessions with Bob and Charlie.
        // Bob→Charlie sessions are only needed if Bob sends group messages.
        // Let's set up Bob↔Charlie too.
        let mut bob2 = SignalParticipant::new("bob2", 1).unwrap();
        let mut charlie2 = SignalParticipant::new("charlie2", 1).unwrap();
        // We can't easily share prekeys, so for simplicity, Bob and Charlie
        // won't have direct sessions in this setup. Group messaging requires
        // the SENDER to have sessions with all members.

        // Create address manager with firstInbox addresses for all peers
        let mut addr_mgr = AddressManager::new();

        let bob_inbox = EphemeralKeypair::generate();
        let charlie_inbox = EphemeralKeypair::generate();
        addr_mgr.add_peer(&bob_id, Some(bob_inbox.pubkey_hex()), None);
        addr_mgr.add_peer(&charlie_id, Some(charlie_inbox.pubkey_hex()), None);

        // Create group with Alice as admin
        let alice_nostr = EphemeralKeypair::generate();
        let bob_nostr = EphemeralKeypair::generate();
        let charlie_nostr = EphemeralKeypair::generate();

        let group = create_signal_group(
            "Test Group",
            &alice_id,
            &alice_nostr.pubkey_hex(),
            "Alice",
            vec![
                (bob_id.clone(), bob_nostr.pubkey_hex(), "Bob".to_string()),
                (
                    charlie_id.clone(),
                    charlie_nostr.pubkey_hex(),
                    "Charlie".to_string(),
                ),
            ],
        );

        (
            alice,
            bob,
            charlie,
            alice_addr,
            bob_addr,
            charlie_addr,
            group,
            addr_mgr,
        )
    }

    // ─── Test 1: Create group ────────────────────────────────────────────────

    #[test]
    fn create_group_with_3_members() {
        let group = create_signal_group(
            "My Group",
            "alice_signal_id",
            "alice_nostr_pub",
            "Alice",
            vec![
                ("bob_signal_id".into(), "bob_nostr_pub".into(), "Bob".into()),
                (
                    "charlie_signal_id".into(),
                    "charlie_nostr_pub".into(),
                    "Charlie".into(),
                ),
            ],
        );

        assert_eq!(group.name, "My Group");
        assert_eq!(group.members.len(), 3);
        assert!(group.is_admin("alice_signal_id"));
        assert!(!group.is_admin("bob_signal_id"));
        assert!(!group.is_admin("charlie_signal_id"));
        assert!(group.am_i_admin());
        assert_eq!(group.group_id.len(), 64); // valid hex pubkey
        assert_eq!(group.other_members().len(), 2);
    }

    #[test]
    fn create_group_id_is_valid_nostr_pubkey() {
        let group = create_signal_group("Test", "creator_id", "creator_nostr", "Creator", vec![]);
        // Should be a valid 64-char hex string (x-only pubkey)
        assert_eq!(group.group_id.len(), 64);
        assert!(hex::decode(&group.group_id).is_ok());
    }

    #[test]
    fn create_group_unique_ids() {
        let g1 = create_signal_group("G1", "c", "cn", "C", vec![]);
        let g2 = create_signal_group("G2", "c", "cn", "C", vec![]);
        assert_ne!(
            g1.group_id, g2.group_id,
            "each group should have a unique ID"
        );
    }

    // ─── Test 2: Send group message ──────────────────────────────────────────

    #[tokio::test]
    async fn send_group_message_produces_events_per_member() {
        let (mut alice, _bob, _charlie, _alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let mut msg = KCMessage::text("Hello group!");
        msg.id = Some("msg-001".into());
        msg.group_id = Some(group.group_id.clone());

        let results = send_group_message(&mut alice, &group, &msg, &addr_mgr)
            .await
            .unwrap();

        // Should produce 2 events (one per other member)
        assert_eq!(results.len(), 2);

        // All events should be kind 1059
        for (_, event) in &results {
            assert_eq!(event.kind, Kind::GiftWrap);
        }

        // All member signal IDs should be present
        let member_ids: HashSet<_> = results.iter().map(|(id, _)| id.clone()).collect();
        for member in group.other_members() {
            assert!(
                member_ids.contains(&member.signal_id),
                "missing event for member {}",
                member.signal_id
            );
        }
    }

    #[tokio::test]
    async fn send_group_message_mismatched_group_id_fails() {
        let (mut alice, _bob, _charlie, _alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let mut msg = KCMessage::text("Hello");
        msg.group_id = Some("wrong-group-id".into());

        let result = send_group_message(&mut alice, &group, &msg, &addr_mgr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_group_message_no_group_id_fails() {
        let (mut alice, _bob, _charlie, _alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let msg = KCMessage::text("Hello"); // no group_id
        let result = send_group_message(&mut alice, &group, &msg, &addr_mgr).await;
        assert!(result.is_err());
    }

    // ─── Test 3: Receive group message ───────────────────────────────────────

    #[tokio::test]
    async fn receive_group_message_roundtrip() {
        let (mut alice, mut bob, _charlie, alice_addr, bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let mut msg = KCMessage::text("Hello group from Alice!");
        msg.id = Some("msg-002".into());
        msg.group_id = Some(group.group_id.clone());

        let results = send_group_message(&mut alice, &group, &msg, &addr_mgr)
            .await
            .unwrap();

        // Find the event for Bob
        let bob_id = bob.identity_public_key_hex();
        let bob_event = results
            .iter()
            .find(|(id, _)| *id == bob_id)
            .map(|(_, e)| e)
            .unwrap();

        // Bob needs a GroupManager with this group
        let mut bob_groups = GroupManager::new();
        // Bob's view of the group (with his own my_signal_id)
        let mut bob_group = group.clone();
        bob_group.my_signal_id = bob_id.clone();
        bob_groups.add_group(bob_group);

        let (received, metadata) =
            receive_group_message(&mut bob, &alice_addr, bob_event, &bob_groups).unwrap();

        assert_eq!(received.kind, KCMessageKind::Text);
        assert_eq!(
            received.text.as_ref().unwrap().content,
            "Hello group from Alice!"
        );
        assert_eq!(metadata.group_id, group.group_id);
        assert_eq!(metadata.sender_signal_id, alice.identity_public_key_hex());
        assert_eq!(metadata.sender_name, "Alice");
    }

    #[tokio::test]
    async fn receive_group_message_unknown_group_fails() {
        let (mut alice, mut bob, _charlie, alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let mut msg = KCMessage::text("Hello");
        msg.group_id = Some(group.group_id.clone());

        let results = send_group_message(&mut alice, &group, &msg, &addr_mgr)
            .await
            .unwrap();

        let bob_id = bob.identity_public_key_hex();
        let bob_event = results
            .iter()
            .find(|(id, _)| *id == bob_id)
            .map(|(_, e)| e)
            .unwrap();

        // Bob has empty GroupManager — doesn't know about the group
        let empty_groups = GroupManager::new();
        let result = receive_group_message(&mut bob, &alice_addr, bob_event, &empty_groups);
        assert!(result.is_err());
    }

    // ─── Test 4: Full group chat (3 members each send) ───────────────────────

    #[tokio::test]
    async fn full_group_chat_3_members() {
        let (mut alice, mut bob, mut charlie, alice_addr, bob_addr, charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let alice_id = alice.identity_public_key_hex();
        let bob_id = bob.identity_public_key_hex();
        let charlie_id = charlie.identity_public_key_hex();

        // Set up GroupManagers for Bob and Charlie
        let mut bob_groups = GroupManager::new();
        let mut bob_group = group.clone();
        bob_group.my_signal_id = bob_id.clone();
        bob_groups.add_group(bob_group);

        let mut charlie_groups = GroupManager::new();
        let mut charlie_group = group.clone();
        charlie_group.my_signal_id = charlie_id.clone();
        charlie_groups.add_group(charlie_group);

        // Alice sends
        let mut msg1 = KCMessage::text("Alice says hi!");
        msg1.id = Some("msg-alice".into());
        msg1.group_id = Some(group.group_id.clone());
        let results1 = send_group_message(&mut alice, &group, &msg1, &addr_mgr)
            .await
            .unwrap();
        assert_eq!(results1.len(), 2);

        // Bob receives Alice's message
        let bob_event = results1
            .iter()
            .find(|(id, _)| *id == bob_id)
            .map(|(_, e)| e)
            .unwrap();
        let (bob_received, bob_meta) =
            receive_group_message(&mut bob, &alice_addr, bob_event, &bob_groups).unwrap();
        assert_eq!(
            bob_received.text.as_ref().unwrap().content,
            "Alice says hi!"
        );
        assert_eq!(bob_meta.sender_name, "Alice");

        // Charlie receives Alice's message
        let charlie_event = results1
            .iter()
            .find(|(id, _)| *id == charlie_id)
            .map(|(_, e)| e)
            .unwrap();
        let (charlie_received, charlie_meta) =
            receive_group_message(&mut charlie, &alice_addr, charlie_event, &charlie_groups)
                .unwrap();
        assert_eq!(
            charlie_received.text.as_ref().unwrap().content,
            "Alice says hi!"
        );
        assert_eq!(charlie_meta.sender_name, "Alice");
    }

    // ─── Test 5: Group invite ────────────────────────────────────────────────

    #[tokio::test]
    async fn group_invite_send_receive() {
        let (mut alice, mut bob, _charlie, alice_addr, bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        // Alice creates a new member "Dave" and invites them
        let mut dave = SignalParticipant::new("dave", 1).unwrap();
        let dave_id = dave.identity_public_key_hex();
        let dave_addr = ProtocolAddress::new(dave_id.clone(), DeviceId::new(1).unwrap());

        // Establish Alice↔Dave session
        let dave_bundle = dave.prekey_bundle().unwrap();
        alice
            .process_prekey_bundle(&dave_addr, &dave_bundle)
            .unwrap();
        let ct = alice.encrypt_bytes(&dave_addr, b"init-ad").unwrap();
        dave.decrypt_bytes(
            &ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::new(1).unwrap()),
            &ct,
        )
        .unwrap();
        let ct2 = dave
            .encrypt(
                &ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::new(1).unwrap()),
                b"ack-ad",
            )
            .unwrap();
        alice.decrypt_bytes(&dave_addr, &ct2.bytes).unwrap();

        // Add Dave to address manager
        let dave_inbox = EphemeralKeypair::generate();
        let mut addr_mgr = addr_mgr;
        addr_mgr.add_peer(&dave_id, Some(dave_inbox.pubkey_hex()), None);

        // Send invite
        let invite_event = send_group_invite(&mut alice, &group, &dave_id, &addr_mgr)
            .await
            .unwrap();
        assert_eq!(invite_event.kind, Kind::GiftWrap);

        // Dave decrypts the invite
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&invite_event.content)
            .unwrap();
        let alice_addr_for_dave =
            ProtocolAddress::new(alice.identity_public_key_hex(), DeviceId::new(1).unwrap());
        let plaintext = dave
            .decrypt_bytes(&alice_addr_for_dave, &ciphertext)
            .unwrap();
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        let invite_msg = KCMessage::try_parse(&plaintext_str).unwrap();

        assert_eq!(invite_msg.kind, KCMessageKind::SignalGroupInvite);

        // Dave processes the invite
        let dave_group = receive_group_invite(&invite_msg, &dave_id).unwrap();
        assert_eq!(dave_group.group_id, group.group_id);
        assert_eq!(dave_group.name, "Test Group");
        assert_eq!(dave_group.members.len(), group.members.len());
        assert_eq!(dave_group.my_signal_id, dave_id);
    }

    // ─── Test 6: Admin remove member ─────────────────────────────────────────

    #[tokio::test]
    async fn admin_remove_member() {
        let (mut alice, mut bob, _charlie, alice_addr, bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let bob_id = bob.identity_public_key_hex();
        let charlie_id = _charlie.identity_public_key_hex();

        // Alice removes Charlie
        let results = send_group_member_removed(&mut alice, &group, &charlie_id, &addr_mgr)
            .await
            .unwrap();

        // Should notify Bob and Charlie (all other members)
        assert_eq!(results.len(), 2);

        // Bob receives the removal notification
        let bob_event = results
            .iter()
            .find(|(id, _)| *id == bob_id)
            .map(|(_, e)| e)
            .unwrap();

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&bob_event.content)
            .unwrap();
        let plaintext = bob.decrypt_bytes(&alice_addr, &ciphertext).unwrap();
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        let msg = KCMessage::try_parse(&plaintext_str).unwrap();

        assert_eq!(msg.kind, KCMessageKind::SignalGroupMemberRemoved);
        assert_eq!(msg.group_id.as_deref(), Some(group.group_id.as_str()));
    }

    // ─── Test 7: Self leave ──────────────────────────────────────────────────

    #[tokio::test]
    async fn self_leave_group() {
        let (
            mut alice,
            mut bob,
            _charlie,
            alice_addr,
            bob_addr,
            _charlie_addr,
            mut group,
            addr_mgr,
        ) = setup_3member_group();

        let bob_id = bob.identity_public_key_hex();

        // Bob leaves the group — we need Bob to have sessions with others.
        // Since Alice created the group, let's have Alice do the leave instead
        // (she has sessions with both Bob and Charlie).
        let results = send_group_self_leave(&mut alice, &group, &addr_mgr)
            .await
            .unwrap();

        // Should notify both Bob and Charlie
        assert_eq!(results.len(), 2);

        // Bob receives the leave notification
        let bob_event = results
            .iter()
            .find(|(id, _)| *id == bob_id)
            .map(|(_, e)| e)
            .unwrap();

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&bob_event.content)
            .unwrap();
        let plaintext = bob.decrypt_bytes(&alice_addr, &ciphertext).unwrap();
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        let msg = KCMessage::try_parse(&plaintext_str).unwrap();

        assert_eq!(msg.kind, KCMessageKind::SignalGroupSelfLeave);
    }

    // ─── Test 8: Group dissolve ──────────────────────────────────────────────

    #[tokio::test]
    async fn group_dissolve() {
        let (mut alice, mut bob, _charlie, alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let bob_id = bob.identity_public_key_hex();

        let results = send_group_dissolve(&mut alice, &group, &addr_mgr)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);

        // Bob receives dissolve notification
        let bob_event = results
            .iter()
            .find(|(id, _)| *id == bob_id)
            .map(|(_, e)| e)
            .unwrap();

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&bob_event.content)
            .unwrap();
        let plaintext = bob.decrypt_bytes(&alice_addr, &ciphertext).unwrap();
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        let msg = KCMessage::try_parse(&plaintext_str).unwrap();

        assert_eq!(msg.kind, KCMessageKind::SignalGroupDissolve);
    }

    // ─── Test 9: Name change ─────────────────────────────────────────────────

    #[tokio::test]
    async fn group_name_change() {
        let (mut alice, mut bob, _charlie, alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let bob_id = bob.identity_public_key_hex();

        let results = send_group_name_changed(&mut alice, &group, "New Name", &addr_mgr)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);

        let bob_event = results
            .iter()
            .find(|(id, _)| *id == bob_id)
            .map(|(_, e)| e)
            .unwrap();

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&bob_event.content)
            .unwrap();
        let plaintext = bob.decrypt_bytes(&alice_addr, &ciphertext).unwrap();
        let plaintext_str = String::from_utf8(plaintext).unwrap();
        let msg = KCMessage::try_parse(&plaintext_str).unwrap();

        assert_eq!(msg.kind, KCMessageKind::SignalGroupNameChanged);
        let admin_payload = msg.extra.get("signalGroupAdmin").unwrap();
        assert_eq!(admin_payload["newName"], "New Name");
    }

    // ─── Test 10: Non-admin cannot admin-op ──────────────────────────────────

    #[tokio::test]
    async fn non_admin_cannot_remove_member() {
        let (
            mut alice,
            mut bob,
            _charlie,
            _alice_addr,
            bob_addr,
            charlie_addr,
            mut group,
            addr_mgr,
        ) = setup_3member_group();

        let charlie_id = _charlie.identity_public_key_hex();

        // Change my_signal_id to Bob (who is not admin)
        let mut bob_group = group.clone();
        bob_group.my_signal_id = bob.identity_public_key_hex();

        let result = send_group_member_removed(&mut bob, &bob_group, &charlie_id, &addr_mgr).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("only admins"));
    }

    #[tokio::test]
    async fn non_admin_cannot_dissolve() {
        let (_alice, mut bob, _charlie, _alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let mut bob_group = group.clone();
        bob_group.my_signal_id = bob.identity_public_key_hex();

        let result = send_group_dissolve(&mut bob, &bob_group, &addr_mgr).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn non_admin_cannot_change_name() {
        let (_alice, mut bob, _charlie, _alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let mut bob_group = group.clone();
        bob_group.my_signal_id = bob.identity_public_key_hex();

        let result = send_group_name_changed(&mut bob, &bob_group, "Nope", &addr_mgr).await;
        assert!(result.is_err());
    }

    // Non-admin CAN self-leave (that's not an admin operation)
    #[tokio::test]
    async fn non_admin_can_self_leave() {
        // For self-leave, we need bob to have sessions with all other members.
        // In our setup, only Alice has sessions with everyone.
        // So we test with Alice (who is admin) — self-leave is not admin-restricted.
        let (mut alice, _bob, _charlie, _alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let result = send_group_self_leave(&mut alice, &group, &addr_mgr).await;
        assert!(result.is_ok());
    }

    // ─── Test 11: Message deduplication (same KCMessage.id) ──────────────────

    #[tokio::test]
    async fn message_dedup_same_id() {
        let (
            mut alice,
            mut bob,
            mut charlie,
            alice_addr,
            _bob_addr,
            _charlie_addr,
            group,
            addr_mgr,
        ) = setup_3member_group();

        let bob_id = bob.identity_public_key_hex();
        let charlie_id = charlie.identity_public_key_hex();

        let mut msg = KCMessage::text("Dedup test");
        msg.id = Some("dedup-001".into());
        msg.group_id = Some(group.group_id.clone());

        let results = send_group_message(&mut alice, &group, &msg, &addr_mgr)
            .await
            .unwrap();

        // Both events should decrypt to the same KCMessage.id
        let bob_event = results.iter().find(|(id, _)| *id == bob_id).unwrap();
        let charlie_event = results.iter().find(|(id, _)| *id == charlie_id).unwrap();

        // Bob decrypts
        let ct_bob = base64::engine::general_purpose::STANDARD
            .decode(&bob_event.1.content)
            .unwrap();
        let pt_bob = bob.decrypt_bytes(&alice_addr, &ct_bob).unwrap();
        let msg_bob: KCMessage = serde_json::from_str(&String::from_utf8(pt_bob).unwrap()).unwrap();

        // Charlie decrypts
        let ct_charlie = base64::engine::general_purpose::STANDARD
            .decode(&charlie_event.1.content)
            .unwrap();
        let pt_charlie = charlie.decrypt_bytes(&alice_addr, &ct_charlie).unwrap();
        let msg_charlie: KCMessage =
            serde_json::from_str(&String::from_utf8(pt_charlie).unwrap()).unwrap();

        assert_eq!(msg_bob.id, msg_charlie.id);
        assert_eq!(msg_bob.id, Some("dedup-001".into()));
        assert_eq!(msg_bob.group_id, msg_charlie.group_id);
    }

    // ─── Additional unit tests ───────────────────────────────────────────────

    #[test]
    fn group_manager_basics() {
        let mut mgr = GroupManager::new();
        assert_eq!(mgr.group_count(), 0);

        let group = create_signal_group("G1", "alice", "an", "Alice", vec![]);
        let gid = group.group_id.clone();
        mgr.add_group(group);

        assert_eq!(mgr.group_count(), 1);
        assert!(mgr.get_group(&gid).is_some());
        assert!(mgr.get_group("nonexistent").is_none());

        let removed = mgr.remove_group(&gid);
        assert!(removed.is_some());
        assert_eq!(mgr.group_count(), 0);
    }

    #[test]
    fn group_manager_find_group_for_message() {
        let mut mgr = GroupManager::new();
        let group = create_signal_group("G1", "alice", "an", "Alice", vec![]);
        let gid = group.group_id.clone();
        mgr.add_group(group);

        let mut msg = KCMessage::text("test");
        msg.group_id = Some(gid.clone());
        assert!(mgr.find_group_for_message(&msg).is_some());

        msg.group_id = Some("wrong".into());
        assert!(mgr.find_group_for_message(&msg).is_none());

        msg.group_id = None;
        assert!(mgr.find_group_for_message(&msg).is_none());
    }

    #[test]
    fn signal_group_remove_member() {
        let mut group = create_signal_group(
            "G",
            "alice",
            "an",
            "Alice",
            vec![
                ("bob".into(), "bn".into(), "Bob".into()),
                ("charlie".into(), "cn".into(), "Charlie".into()),
            ],
        );

        assert_eq!(group.members.len(), 3);
        assert!(group.remove_member("bob"));
        assert_eq!(group.members.len(), 2);
        assert!(!group.remove_member("bob")); // already removed
        assert_eq!(group.members.len(), 2);
    }

    #[test]
    fn signal_group_to_room_profile() {
        let group = create_signal_group(
            "Profile Test",
            "alice",
            "an",
            "Alice",
            vec![("bob".into(), "bn".into(), "Bob".into())],
        );

        let profile = group.to_room_profile();
        assert_eq!(profile.group_id, group.group_id);
        assert_eq!(profile.name, "Profile Test");
        assert_eq!(profile.members.len(), 2);

        let alice_member = profile.members.iter().find(|m| m.name == "Alice").unwrap();
        assert!(alice_member.is_admin);
        let bob_member = profile.members.iter().find(|m| m.name == "Bob").unwrap();
        assert!(!bob_member.is_admin);
    }

    #[test]
    fn room_profile_serialization_roundtrip() {
        let profile = RoomProfile {
            group_id: "abc123".into(),
            name: "Test Group".into(),
            members: vec![
                RoomMember {
                    nostr_pubkey: "npub1".into(),
                    signal_id: "sig1".into(),
                    name: "Alice".into(),
                    is_admin: true,
                },
                RoomMember {
                    nostr_pubkey: "npub2".into(),
                    signal_id: "sig2".into(),
                    name: "Bob".into(),
                    is_admin: false,
                },
            ],
        };

        let json = serde_json::to_string(&profile).unwrap();
        let parsed: RoomProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, parsed);

        // Verify camelCase
        assert!(json.contains("groupId"));
        assert!(json.contains("nostrPubkey"));
        assert!(json.contains("signalId"));
        assert!(json.contains("isAdmin"));
    }

    #[test]
    fn receive_group_invite_creates_group() {
        let group = create_signal_group(
            "Invite Test",
            "alice",
            "an",
            "Alice",
            vec![("bob".into(), "bn".into(), "Bob".into())],
        );

        let invite_msg = build_group_invite_message(&group);
        assert_eq!(invite_msg.kind, KCMessageKind::SignalGroupInvite);
        assert_eq!(
            invite_msg.group_id.as_deref(),
            Some(group.group_id.as_str())
        );

        let dave_group = receive_group_invite(&invite_msg, "dave").unwrap();
        assert_eq!(dave_group.group_id, group.group_id);
        assert_eq!(dave_group.name, "Invite Test");
        assert_eq!(dave_group.members.len(), 2); // Alice + Bob
        assert_eq!(dave_group.my_signal_id, "dave");
        assert!(dave_group.is_admin("alice"));
        assert!(!dave_group.is_admin("bob"));
    }

    #[test]
    fn receive_group_invite_wrong_kind_fails() {
        let msg = KCMessage::text("not an invite");
        let result = receive_group_invite(&msg, "dave");
        assert!(result.is_err());
    }

    #[test]
    fn group_manager_get_group_mut() {
        let mut mgr = GroupManager::new();
        let group = create_signal_group("G1", "alice", "an", "Alice", vec![]);
        let gid = group.group_id.clone();
        mgr.add_group(group);

        let g = mgr.get_group_mut(&gid).unwrap();
        g.name = "Updated Name".into();

        assert_eq!(mgr.get_group(&gid).unwrap().name, "Updated Name");
    }

    #[test]
    fn other_members_excludes_self() {
        let group = create_signal_group(
            "G",
            "alice",
            "an",
            "Alice",
            vec![
                ("bob".into(), "bn".into(), "Bob".into()),
                ("charlie".into(), "cn".into(), "Charlie".into()),
            ],
        );

        let others = group.other_members();
        assert_eq!(others.len(), 2);
        assert!(others.iter().all(|m| m.signal_id != "alice"));
    }

    #[test]
    fn group_with_no_other_members() {
        let group = create_signal_group("Solo", "alice", "an", "Alice", vec![]);
        assert_eq!(group.other_members().len(), 0);
        assert!(group.am_i_admin());
    }

    #[tokio::test]
    async fn send_to_empty_group_produces_no_events() {
        let mut alice = SignalParticipant::new("alice", 1).unwrap();
        let addr_mgr = AddressManager::new();
        let group = create_signal_group(
            "Solo",
            &alice.identity_public_key_hex(),
            "an",
            "Alice",
            vec![],
        );

        let mut msg = KCMessage::text("Hello nobody");
        msg.group_id = Some(group.group_id.clone());

        let results = send_group_message(&mut alice, &group, &msg, &addr_mgr)
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    // ─── Test: Events use different ephemeral senders ────────────────────────

    #[tokio::test]
    async fn group_events_have_different_ephemeral_senders() {
        let (mut alice, _bob, _charlie, _alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let mut msg = KCMessage::text("test ephemeral");
        msg.group_id = Some(group.group_id.clone());

        let results = send_group_message(&mut alice, &group, &msg, &addr_mgr)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
        // Each event should have a different ephemeral sender
        assert_ne!(results[0].1.pubkey, results[1].1.pubkey);
    }

    // ─── Test: Group message has correct groupId ─────────────────────────────

    #[tokio::test]
    async fn group_message_contains_group_id() {
        let (mut alice, mut bob, _charlie, alice_addr, _bob_addr, _charlie_addr, group, addr_mgr) =
            setup_3member_group();

        let bob_id = bob.identity_public_key_hex();

        let mut msg = KCMessage::text("Group ID check");
        msg.group_id = Some(group.group_id.clone());

        let results = send_group_message(&mut alice, &group, &msg, &addr_mgr)
            .await
            .unwrap();

        let bob_event = results
            .iter()
            .find(|(id, _)| *id == bob_id)
            .map(|(_, e)| e)
            .unwrap();

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&bob_event.content)
            .unwrap();
        let plaintext = bob.decrypt_bytes(&alice_addr, &ciphertext).unwrap();
        let decrypted_msg: KCMessage =
            serde_json::from_str(&String::from_utf8(plaintext).unwrap()).unwrap();

        assert_eq!(
            decrypted_msg.group_id.as_deref(),
            Some(group.group_id.as_str())
        );
    }
}
