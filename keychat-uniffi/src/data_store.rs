//! FFI query layer for app data (identities, rooms, messages, contacts).
//! Bridges libkeychat::SecureStorage CRUD to UniFFI-exported methods.

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    // ─── Identity Queries ────────────────────────────────────

    pub async fn get_identities(&self) -> Result<Vec<IdentityInfo>, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        let rows = store.get_app_identities().map_err(|e| KeychatUniError::Storage {
            msg: format!("get_app_identities: {e}"),
        })?;
        Ok(rows
            .into_iter()
            .map(|r| IdentityInfo {
                npub: r.npub,
                nostr_pubkey_hex: r.nostr_pubkey_hex,
                name: r.name,
                avatar: r.avatar,
                index: r.idx,
                is_default: r.is_default,
                created_at: r.created_at as u64,
            })
            .collect())
    }

    pub async fn save_app_identity_ffi(
        &self,
        npub: String,
        nostr_pubkey_hex: String,
        name: String,
        index: i32,
        is_default: bool,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .save_app_identity(&npub, &nostr_pubkey_hex, &name, index, is_default)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("save_app_identity: {e}"),
            })
    }

    pub async fn update_app_identity_ffi(
        &self,
        npub: String,
        name: Option<String>,
        avatar: Option<String>,
        is_default: Option<bool>,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .update_app_identity(
                &npub,
                name.as_deref(),
                avatar.as_deref(),
                is_default,
            )
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("update_app_identity: {e}"),
            })
    }

    pub async fn delete_app_identity_ffi(&self, npub: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store.delete_app_identity(&npub).map_err(|e| KeychatUniError::Storage {
            msg: format!("delete_app_identity: {e}"),
        })
    }

    // ─── Room Queries ────────────────────────────────────────

    pub async fn get_rooms(&self, identity_npub: String) -> Result<Vec<RoomInfo>, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        let rows = store
            .get_app_rooms(&identity_npub)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("get_app_rooms: {e}"),
            })?;
        Ok(rows.into_iter().map(room_row_to_info).collect())
    }

    pub async fn get_room(&self, room_id: String) -> Result<Option<RoomInfo>, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        let row = store
            .get_app_room(&room_id)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("get_app_room: {e}"),
            })?;
        Ok(row.map(room_row_to_info))
    }

    pub async fn mark_room_read(&self, room_id: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .mark_app_messages_read(&room_id)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("mark_app_messages_read: {e}"),
            })?;
        store
            .clear_app_room_unread(&room_id)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("clear_app_room_unread: {e}"),
            })
    }

    // ─── Message Queries ─────────────────────────────────────

    pub async fn get_messages(
        &self,
        room_id: String,
        limit: i32,
        offset: i32,
    ) -> Result<Vec<MessageInfo>, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        let rows = store
            .get_app_messages(&room_id, limit, offset)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("get_app_messages: {e}"),
            })?;
        Ok(rows.into_iter().map(message_row_to_info).collect())
    }

    pub async fn get_message_count(&self, room_id: String) -> Result<i32, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .get_app_message_count(&room_id)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("get_app_message_count: {e}"),
            })
    }

    // ─── Contact Queries ─────────────────────────────────────

    pub async fn get_contacts(
        &self,
        identity_npub: String,
    ) -> Result<Vec<ContactInfoFull>, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        let rows = store
            .get_app_contacts(&identity_npub)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("get_app_contacts: {e}"),
            })?;
        Ok(rows
            .into_iter()
            .map(|r| ContactInfoFull {
                pubkey: r.pubkey,
                npubkey: r.npubkey,
                identity_npub: r.identity_npub,
                petname: r.petname,
                name: r.name,
                avatar: r.avatar,
            })
            .collect())
    }

    pub async fn update_contact_petname(
        &self,
        pubkey: String,
        identity_npub: String,
        petname: String,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .update_app_contact(&pubkey, &identity_npub, Some(&petname), None, None)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("update_app_contact: {e}"),
            })
    }

    // ─── Write methods (used by tests + future Swift UI) ──────

    pub async fn save_app_room_ffi(
        &self,
        to_main_pubkey: String,
        identity_npub: String,
        status: i32,
        room_type: i32,
        name: Option<String>,
    ) -> Result<String, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .save_app_room(&to_main_pubkey, &identity_npub, status, room_type, name.as_deref(), None)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("save_app_room: {e}"),
            })
    }

    pub async fn save_app_message_ffi(
        &self,
        msgid: String,
        event_id: Option<String>,
        room_id: String,
        identity_npub: String,
        sender_pubkey: String,
        content: String,
        is_me_send: bool,
        status: i32,
        created_at: u64,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .save_app_message(
                &msgid, event_id.as_deref(), &room_id, &identity_npub,
                &sender_pubkey, &content, is_me_send, status, created_at as i64,
            )
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("save_app_message: {e}"),
            })
    }

    pub async fn save_app_contact_ffi(
        &self,
        pubkey: String,
        npubkey: String,
        identity_npub: String,
        name: Option<String>,
    ) -> Result<String, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .save_app_contact(&pubkey, &npubkey, &identity_npub, name.as_deref())
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("save_app_contact: {e}"),
            })
    }

    pub async fn update_app_room_ffi(
        &self,
        room_id: String,
        status: Option<i32>,
        name: Option<String>,
        last_message_content: Option<String>,
        last_message_at: Option<u64>,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .update_app_room(
                &room_id, status, name.as_deref(),
                last_message_content.as_deref(),
                last_message_at.map(|t| t as i64),
            )
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("update_app_room: {e}"),
            })
    }

    pub async fn update_app_message_ffi(
        &self,
        msgid: String,
        event_id: Option<String>,
        status: Option<i32>,
        relay_status_json: Option<String>,
        payload_json: Option<String>,
        nostr_event_json: Option<String>,
        reply_to_event_id: Option<String>,
        reply_to_content: Option<String>,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .update_app_message(
                &msgid, event_id.as_deref(), status, relay_status_json.as_deref(),
                payload_json.as_deref(), nostr_event_json.as_deref(),
                reply_to_event_id.as_deref(), reply_to_content.as_deref(),
            )
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("update_app_message: {e}"),
            })
    }

    pub async fn increment_app_room_unread_ffi(
        &self,
        room_id: String,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .increment_app_room_unread(&room_id)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("increment_app_room_unread: {e}"),
            })
    }

    pub async fn is_app_message_duplicate_ffi(
        &self,
        event_id: String,
    ) -> Result<bool, KeychatUniError> {
        let inner = self.inner.read().await;
        let store = inner.storage.lock().map_err(|e| KeychatUniError::Storage {
            msg: format!("storage lock: {e}"),
        })?;
        store
            .is_app_message_duplicate(&event_id)
            .map_err(|e| KeychatUniError::Storage {
                msg: format!("is_app_message_duplicate: {e}"),
            })
    }
}

// ─── Conversion Helpers ──────────────────────────────────────────

fn room_row_to_info(r: libkeychat::storage::RoomRow) -> RoomInfo {
    RoomInfo {
        id: r.id,
        to_main_pubkey: r.to_main_pubkey,
        identity_npub: r.identity_npub,
        status: r.status,
        room_type: r.room_type,
        name: r.name,
        avatar: r.avatar,
        last_message_content: r.last_message_content,
        last_message_at: r.last_message_at.map(|t| t as u64),
        unread_count: r.unread_count,
        created_at: r.created_at as u64,
    }
}

fn message_row_to_info(r: libkeychat::storage::MessageRow) -> MessageInfo {
    MessageInfo {
        msgid: r.msgid,
        event_id: r.event_id,
        room_id: r.room_id,
        sender_pubkey: r.sender_pubkey,
        content: r.content,
        is_me_send: r.is_me_send,
        is_read: r.is_read,
        status: r.status,
        reply_to_event_id: r.reply_to_event_id,
        reply_to_content: r.reply_to_content,
        payload_json: r.payload_json,
        nostr_event_json: r.nostr_event_json,
        relay_status_json: r.relay_status_json,
        local_file_path: r.local_file_path,
        created_at: r.created_at as u64,
    }
}
