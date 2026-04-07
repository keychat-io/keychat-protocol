//! Data store queries — CRUD wrappers around AppStorage.

use crate::app_client::{lock_app_storage_result, AppClient, AppError, AppResult};
use crate::app_storage::{RoomRow, MessageRow};
use crate::types::*;

macro_rules! se {
    ($op:expr, $e:expr) => { AppError::Storage(format!("{}: {}", $op, $e)) };
}

impl AppClient {
    pub async fn update_app_identity(
        &self, pubkey_hex: String, name: Option<String>, avatar: Option<String>, is_default: Option<bool>,
    ) -> AppResult<()> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.update_app_identity(&pubkey_hex, name.as_deref(), avatar.as_deref(), is_default).map_err(|e| se!("update_identity", e))
    }

    pub async fn delete_app_identity(&self, pubkey_hex: String) -> AppResult<()> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.delete_app_identity(&pubkey_hex).map_err(|e| se!("delete_identity", e))
    }

    pub async fn save_app_room(
        &self, to_main_pubkey: String, identity_pubkey: String,
        status: RoomStatus, room_type: RoomType, name: Option<String>, parent_room_id: Option<String>,
    ) -> AppResult<String> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.save_app_room(&to_main_pubkey, &identity_pubkey, status.to_i32(), room_type.to_i32(), name.as_deref(), None, parent_room_id.as_deref())
            .map_err(|e| se!("save_room", e))
    }

    pub async fn update_app_room_record(
        &self, room_id: String, status: Option<RoomStatus>, name: Option<String>,
        last_message_content: Option<String>, last_message_at: Option<u64>,
    ) -> AppResult<()> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.update_app_room(&room_id, status.map(|v| v.to_i32()), name.as_deref(), last_message_content.as_deref(), last_message_at.map(|t| t as i64))
            .map_err(|e| se!("update_room", e))
    }

    pub async fn delete_app_room_record(&self, room_id: String) -> AppResult<()> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.delete_app_room(&room_id).map_err(|e| se!("delete_room", e))
    }

    pub async fn increment_app_room_unread_record(&self, room_id: String) -> AppResult<()> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.increment_app_room_unread(&room_id).map_err(|e| se!("increment_unread", e))
    }

    pub async fn save_app_message_record(
        &self, msgid: String, event_id: Option<String>, room_id: String,
        identity_pubkey: String, sender_pubkey: String, content: String,
        is_me_send: bool, status: MessageStatus, created_at: u64,
    ) -> AppResult<()> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.save_app_message(&msgid, event_id.as_deref(), &room_id, &identity_pubkey, &sender_pubkey, &content, is_me_send, status.to_i32(), created_at as i64)
            .map_err(|e| se!("save_message", e))
    }

    pub async fn update_app_message_record(
        &self, msgid: String, event_id: Option<String>, status: Option<MessageStatus>,
        relay_status_json: Option<String>, payload_json: Option<String>,
        nostr_event_json: Option<String>, reply_to_event_id: Option<String>, reply_to_content: Option<String>,
    ) -> AppResult<()> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.update_app_message(&msgid, event_id.as_deref(), status.map(|v| v.to_i32()), relay_status_json.as_deref(), payload_json.as_deref(), nostr_event_json.as_deref(), reply_to_event_id.as_deref(), reply_to_content.as_deref())
            .map_err(|e| se!("update_message", e))
    }

    pub async fn update_local_meta(&self, msgid: String, local_meta: String) -> AppResult<()> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.update_local_meta(&msgid, &local_meta).map_err(|e| se!("update_local_meta", e))
    }

    pub async fn is_app_message_duplicate(&self, event_id: String) -> AppResult<bool> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.is_app_message_duplicate(&event_id).map_err(|e| se!("is_duplicate", e))
    }

    pub async fn save_app_contact_record(
        &self, pubkey: String, npubkey: String, identity_pubkey: String, name: Option<String>,
    ) -> AppResult<String> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        s.save_app_contact(&pubkey, &npubkey, &identity_pubkey, name.as_deref()).map_err(|e| se!("save_contact", e))
    }

    pub async fn get_messages_initial(&self, room_id: String, context_count: i32) -> AppResult<Vec<MessageInfo>> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        let rows = s.get_app_messages_unread_with_context(&room_id, context_count).map_err(|e| se!("get_messages_initial", e))?;
        Ok(rows.into_iter().map(msg_row_to_info).collect())
    }

    pub async fn get_messages_before(&self, room_id: String, before_ts: i64, limit: i32) -> AppResult<Vec<MessageInfo>> {
        let _inner = self.inner.read().await; let s = lock_app_storage_result(&_inner.app_storage)?;
        let rows = s.get_app_messages_before(&room_id, before_ts, limit).map_err(|e| se!("get_messages_before", e))?;
        Ok(rows.into_iter().map(msg_row_to_info).collect())
    }
}

pub(crate) fn room_row_to_info(r: RoomRow) -> RoomInfo {
    RoomInfo {
        id: r.id, to_main_pubkey: r.to_main_pubkey, identity_pubkey: r.identity_pubkey,
        status: RoomStatus::from_i32(r.status), room_type: RoomType::from_i32(r.room_type),
        name: r.name, avatar: r.avatar, peer_signal_identity_key: r.peer_signal_identity_key,
        parent_room_id: r.parent_room_id, last_message_content: r.last_message_content,
        last_message_at: r.last_message_at, unread_count: r.unread_count, created_at: r.created_at,
    }
}

pub(crate) fn msg_row_to_info(r: MessageRow) -> MessageInfo {
    MessageInfo {
        msgid: r.msgid, event_id: r.event_id, room_id: r.room_id,
        identity_pubkey: r.identity_pubkey, sender_pubkey: r.sender_pubkey,
        content: r.content, is_me_send: r.is_me_send, is_read: r.is_read,
        status: MessageStatus::from_i32(r.status), reply_to_event_id: r.reply_to_event_id,
        reply_to_content: r.reply_to_content, payload_json: r.payload_json,
        nostr_event_json: r.nostr_event_json, relay_status_json: r.relay_status_json,
        local_file_path: r.local_file_path, local_meta: r.local_meta, created_at: r.created_at,
    }
}
