//! Signal-based small group support (M5).
//!
//! Small groups use fan-out encryption: each message is individually
//! encrypted for each member using their respective Signal sessions.
//! This is suitable for groups up to ~20 members.
//!
//! For larger groups, use MLS (see `crate::mls`).

pub mod types;

use crate::error::{KeychatError, Result};
use types::*;

/// Create a new Signal-based small group.
///
/// Generates a random Nostr keypair as the group identity.
/// The caller (admin) should store the secret key and send
/// the profile to members via their Signal sessions.
pub fn create_group(
    admin_pubkey: &str,
    admin_name: &str,
    group_name: &str,
) -> Result<CreateGroupResult> {
    let group_keypair = crate::identity::generate_random_nostr_keypair();
    let group_pubkey = group_keypair.public_key_hex();
    let group_secret = hex::encode(group_keypair.secret_key_bytes());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let profile = GroupProfile {
        pubkey: group_pubkey.clone(),
        name: group_name.to_owned(),
        users: vec![serde_json::json!({
            "idPubkey": admin_pubkey,
            "name": admin_name,
            "isAdmin": true,
        })],
        group_type: GroupTypeWire::SendAll,
        updated_at: now,
        group_relay: None,
        small_group_id: Some(group_pubkey),
    };

    Ok(CreateGroupResult {
        profile,
        group_secret_key: group_secret,
    })
}

/// Build an invite message payload (KeychatMessage JSON string).
///
/// The returned string should be sent to each invitee via their
/// Signal session (normal `send_message`).
pub fn build_invite_message(
    profile: &GroupProfile,
    inviter_message: &str,
    inviter_pubkey: &str,
) -> String {
    serde_json::json!({
        "c": "group",
        "type": event_kinds::GROUP_INVITE,
        "msg": serde_json::to_string(profile).unwrap_or_default(),
        "name": serde_json::json!([inviter_message, inviter_pubkey]).to_string(),
    })
    .to_string()
}

/// Build a group chat message payload (KeychatMessage JSON string).
///
/// The returned string should be encrypted and sent to each member
/// via their Signal session.
pub fn build_group_message(group_pubkey: &str, _sender_pubkey: &str, content: &str) -> String {
    // GroupMessage format matches Keychat app: {message, pubkey, sig?, subtype?, ext?}
    let gm = serde_json::json!({
        "message": content,
        "pubkey": group_pubkey,
    });

    serde_json::json!({
        "c": "group",
        "type": event_kinds::GROUP_SEND_TO_ALL,
        "msg": gm.to_string(),
    })
    .to_string()
}

/// Build a remove-member message payload.
pub fn build_remove_member_message(group_pubkey: &str, member_pubkey: &str) -> String {
    // Sent as GROUP_SEND_TO_ALL with subtype=GROUP_REMOVE_MEMBER.
    // The removed member's pubkey goes in `ext`.
    let gm = serde_json::json!({
        "message": format!("[System] Member {} removed", &member_pubkey[..12.min(member_pubkey.len())]),
        "pubkey": group_pubkey,
        "subtype": event_kinds::GROUP_REMOVE_MEMBER,
        "ext": member_pubkey,
    });
    serde_json::json!({
        "c": "group",
        "type": event_kinds::GROUP_SEND_TO_ALL,
        "msg": gm.to_string(),
    })
    .to_string()
}

/// Build a dissolve-group message payload.
///
/// Sent as GROUP_SEND_TO_ALL with subtype=GROUP_DISSOLVE inside GroupMessage.
pub fn build_dissolve_message(group_pubkey: &str) -> String {
    let gm = serde_json::json!({
        "message": "[System] The admin closed the group chat",
        "pubkey": group_pubkey,
        "subtype": event_kinds::GROUP_DISSOLVE,
    });
    serde_json::json!({
        "c": "group",
        "type": event_kinds::GROUP_SEND_TO_ALL,
        "msg": gm.to_string(),
    })
    .to_string()
}

/// Build a rename-group message payload.
///
/// Sent as GROUP_SEND_TO_ALL with subtype=GROUP_CHANGE_ROOM_NAME.
/// New name goes in `ext` field of GroupMessage.
pub fn build_rename_message(group_pubkey: &str, new_name: &str) -> String {
    let gm = serde_json::json!({
        "message": format!("[System] New room name: {new_name}"),
        "pubkey": group_pubkey,
        "subtype": event_kinds::GROUP_CHANGE_ROOM_NAME,
        "ext": new_name,
    });
    serde_json::json!({
        "c": "group",
        "type": event_kinds::GROUP_SEND_TO_ALL,
        "msg": gm.to_string(),
    })
    .to_string()
}

/// Build a change-nickname message payload.
pub fn build_nickname_message(group_pubkey: &str, new_name: &str) -> String {
    let gm = serde_json::json!({
        "message": format!("[System] Nickname changed to: {new_name}"),
        "pubkey": group_pubkey,
        "subtype": event_kinds::GROUP_CHANGE_NICKNAME,
        "ext": new_name,
    });
    serde_json::json!({
        "c": "group",
        "type": event_kinds::GROUP_SEND_TO_ALL,
        "msg": gm.to_string(),
    })
    .to_string()
}

/// Parse an inbound KeychatMessage JSON into a `GroupEvent`.
///
/// This handles all group-related subtypes (invite, message,
/// remove, dissolve, rename, nickname change).
pub fn parse_group_message(
    json_str: &str,
    sender_pubkey: &str,
    group_pubkey: &str,
) -> Result<GroupEvent> {
    let km: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| KeychatError::Group(format!("invalid group message JSON: {e}")))?;

    let c = km.get("c").and_then(|v| v.as_str()).unwrap_or("");
    if c != "group" {
        return Err(KeychatError::Group(format!(
            "expected group message (c='group'), got c='{c}'"
        )));
    }

    let msg_type = km.get("type").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let msg = km.get("msg").and_then(|v| v.as_str()).unwrap_or("");
    let name = km.get("name").and_then(|v| v.as_str()).unwrap_or("");

    match msg_type {
        event_kinds::GROUP_INVITE => {
            let profile: GroupProfile = serde_json::from_str(msg)
                .map_err(|e| KeychatError::Group(format!("invalid group profile: {e}")))?;
            Ok(GroupEvent::Invite {
                profile,
                inviter: sender_pubkey.to_owned(),
            })
        }
        event_kinds::GROUP_SEND_TO_ALL => {
            // msg is JSON GroupMessage: {message, pubkey, sig?, subtype?, ext?}
            let gm: serde_json::Value = serde_json::from_str(msg)
                .map_err(|e| KeychatError::Group(format!("invalid group message: {e}")))?;
            let gm_pubkey = gm.get("pubkey").and_then(|v| v.as_str()).unwrap_or(group_pubkey);

            // Check for management subtypes
            if let Some(subtype) = gm.get("subtype").and_then(|v| v.as_i64()) {
                let ext = gm.get("ext").and_then(|v| v.as_str()).unwrap_or("");
                match subtype as i32 {
                    x if x == event_kinds::GROUP_DISSOLVE => {
                        return Ok(GroupEvent::Dissolved {
                            by: sender_pubkey.to_owned(),
                            group_pubkey: gm_pubkey.to_owned(),
                        });
                    }
                    x if x == event_kinds::GROUP_CHANGE_ROOM_NAME => {
                        return Ok(GroupEvent::RoomNameChanged {
                            new_name: ext.to_owned(),
                            by: sender_pubkey.to_owned(),
                            group_pubkey: gm_pubkey.to_owned(),
                        });
                    }
                    x if x == event_kinds::GROUP_CHANGE_NICKNAME => {
                        return Ok(GroupEvent::NicknameChanged {
                            new_name: ext.to_owned(),
                            by: sender_pubkey.to_owned(),
                            group_pubkey: gm_pubkey.to_owned(),
                        });
                    }
                    x if x == event_kinds::GROUP_REMOVE_MEMBER => {
                        return Ok(GroupEvent::MemberRemoved {
                            member_pubkey: ext.to_owned(),
                            by: sender_pubkey.to_owned(),
                            group_pubkey: gm_pubkey.to_owned(),
                        });
                    }
                    _ => {} // Unknown subtype, fall through to regular message
                }
            }

            let content = gm
                .get("message")
                .and_then(|v| v.as_str())
                .or_else(|| gm.get("content").and_then(|v| v.as_str()))
                .unwrap_or(msg);
            Ok(GroupEvent::Message {
                sender: sender_pubkey.to_owned(),
                content: content.to_owned(),
                group_pubkey: gm_pubkey.to_owned(),
            })
        }
        event_kinds::GROUP_REMOVE_MEMBER => Ok(GroupEvent::MemberRemoved {
            member_pubkey: name.to_owned(),
            by: sender_pubkey.to_owned(),
            group_pubkey: group_pubkey.to_owned(),
        }),
        event_kinds::GROUP_DISSOLVE => Ok(GroupEvent::Dissolved {
            by: sender_pubkey.to_owned(),
            group_pubkey: group_pubkey.to_owned(),
        }),
        event_kinds::GROUP_CHANGE_ROOM_NAME => Ok(GroupEvent::RoomNameChanged {
            new_name: name.to_owned(),
            by: sender_pubkey.to_owned(),
            group_pubkey: group_pubkey.to_owned(),
        }),
        event_kinds::GROUP_CHANGE_NICKNAME => Ok(GroupEvent::NicknameChanged {
            new_name: name.to_owned(),
            by: sender_pubkey.to_owned(),
            group_pubkey: group_pubkey.to_owned(),
        }),
        _ => Err(KeychatError::Group(format!(
            "unknown group message type: {msg_type}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_group_returns_valid_profile() {
        let result = create_group("abc123", "Alice", "Test Group").unwrap();
        assert_eq!(result.profile.name, "Test Group");
        assert_eq!(result.profile.pubkey.len(), 64);
        assert_eq!(result.group_secret_key.len(), 64);
        assert!(result.profile.updated_at > 0);
        assert_eq!(result.profile.users.len(), 1);
    }

    #[test]
    fn build_and_parse_invite_roundtrip() {
        let result = create_group("abc123", "Alice", "My Group").unwrap();
        let invite_msg = build_invite_message(&result.profile, "Join my group!", "abc123");
        let event = parse_group_message(&invite_msg, "abc123", &result.profile.pubkey).unwrap();
        match event {
            GroupEvent::Invite { profile, inviter } => {
                assert_eq!(profile.name, "My Group");
                assert_eq!(inviter, "abc123");
            }
            _ => panic!("expected Invite"),
        }
    }

    #[test]
    fn build_and_parse_group_message_roundtrip() {
        let msg = build_group_message("group123", "sender456", "Hello group!");
        let event = parse_group_message(&msg, "sender456", "group123").unwrap();
        match event {
            GroupEvent::Message {
                sender,
                content,
                group_pubkey,
            } => {
                assert_eq!(sender, "sender456");
                assert_eq!(content, "Hello group!");
                assert_eq!(group_pubkey, "group123");
            }
            _ => panic!("expected Message"),
        }
    }

    #[test]
    fn build_and_parse_remove_member() {
        let msg = build_remove_member_message("group123", "badmember789");
        let event = parse_group_message(&msg, "admin123", "group123").unwrap();
        match event {
            GroupEvent::MemberRemoved {
                member_pubkey, by, ..
            } => {
                assert_eq!(member_pubkey, "badmember789");
                assert_eq!(by, "admin123");
            }
            _ => panic!("expected MemberRemoved"),
        }
    }

    #[test]
    fn build_and_parse_dissolve() {
        let msg = build_dissolve_message("group123");
        let event = parse_group_message(&msg, "admin123", "group123").unwrap();
        match event {
            GroupEvent::Dissolved { by, group_pubkey } => {
                assert_eq!(by, "admin123");
                assert_eq!(group_pubkey, "group123");
            }
            _ => panic!("expected Dissolved"),
        }
    }

    #[test]
    fn build_and_parse_rename() {
        let msg = build_rename_message("test_group_pubkey", "New Name");
        let event = parse_group_message(&msg, "admin123", "group123").unwrap();
        match event {
            GroupEvent::RoomNameChanged { new_name, .. } => {
                assert_eq!(new_name, "New Name");
            }
            _ => panic!("expected RoomNameChanged"),
        }
    }

    #[test]
    fn build_and_parse_nickname() {
        let msg = build_nickname_message("test_group_pubkey", "Cool Alice");
        let event = parse_group_message(&msg, "alice123", "group123").unwrap();
        match event {
            GroupEvent::NicknameChanged { new_name, .. } => {
                assert_eq!(new_name, "Cool Alice");
            }
            _ => panic!("expected NicknameChanged"),
        }
    }
}
