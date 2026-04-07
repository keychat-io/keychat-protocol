//! Data store — thin UniFFI delegation to keychat-app-core.

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    pub async fn get_identities(&self) -> Result<Vec<IdentityInfo>, KeychatUniError> {
        self.app.get_identities().await.map(|v| v.into_iter().map(convert_identity_info).collect()).map_err(Into::into)
    }
    pub async fn save_app_identity_ffi(&self, pubkey_hex: String, npub: String, name: String, index: i32, is_default: bool) -> Result<(), KeychatUniError> {
        self.app.save_app_identity(pubkey_hex, npub, name, index, is_default).await.map_err(Into::into)
    }
    pub async fn update_app_identity_ffi(&self, pubkey_hex: String, name: Option<String>, avatar: Option<String>, is_default: Option<bool>) -> Result<(), KeychatUniError> {
        self.app.update_app_identity(pubkey_hex, name, avatar, is_default).await.map_err(Into::into)
    }
    pub async fn delete_app_identity_ffi(&self, pubkey_hex: String) -> Result<(), KeychatUniError> {
        self.app.delete_app_identity(pubkey_hex).await.map_err(Into::into)
    }
    pub async fn get_setting(&self, key: String) -> Result<Option<String>, KeychatUniError> {
        self.app.get_setting(key).await.map_err(Into::into)
    }
    pub async fn set_setting(&self, key: String, value: String) -> Result<(), KeychatUniError> {
        self.app.set_setting(key, value).await.map_err(Into::into)
    }
    pub async fn delete_setting(&self, key: String) -> Result<(), KeychatUniError> {
        self.app.delete_setting(key).await.map_err(Into::into)
    }
    pub async fn get_rooms(&self, identity_pubkey: String) -> Result<Vec<RoomInfo>, KeychatUniError> {
        self.app.get_rooms(identity_pubkey).await.map(|v| v.into_iter().map(convert_room_info).collect()).map_err(Into::into)
    }
    pub async fn get_room(&self, room_id: String) -> Result<Option<RoomInfo>, KeychatUniError> {
        self.app.get_room(room_id).await.map(|v| v.map(convert_room_info)).map_err(Into::into)
    }
    pub async fn mark_room_read(&self, room_id: String) -> Result<(), KeychatUniError> {
        self.app.mark_room_read(room_id).await.map_err(Into::into)
    }
    pub async fn should_auto_download(&self, file_size: u64) -> Result<bool, KeychatUniError> {
        self.app.should_auto_download(file_size).await.map_err(Into::into)
    }
    pub async fn get_active_media_server(&self) -> Result<String, KeychatUniError> {
        self.app.get_active_media_server().await.map_err(Into::into)
    }
    pub async fn get_messages(&self, room_id: String, limit: i32, offset: i32) -> Result<Vec<MessageInfo>, KeychatUniError> {
        self.app.get_messages(room_id, limit, offset).await.map(|v| v.into_iter().map(convert_message_info).collect()).map_err(Into::into)
    }
    pub async fn get_message_by_msgid(&self, msgid: String) -> Result<Option<MessageInfo>, KeychatUniError> {
        self.app.get_message_by_msgid(msgid).await.map(|v| v.map(convert_message_info)).map_err(Into::into)
    }
    pub async fn get_messages_initial(&self, room_id: String, context_count: i32) -> Result<Vec<MessageInfo>, KeychatUniError> {
        self.app.get_messages_initial(room_id, context_count).await.map(|v| v.into_iter().map(convert_message_info).collect()).map_err(Into::into)
    }
    pub async fn get_messages_before(&self, room_id: String, before_ts: i64, limit: i32) -> Result<Vec<MessageInfo>, KeychatUniError> {
        self.app.get_messages_before(room_id, before_ts, limit).await.map(|v| v.into_iter().map(convert_message_info).collect()).map_err(Into::into)
    }
    pub async fn get_message_count(&self, room_id: String) -> Result<i32, KeychatUniError> {
        self.app.get_message_count(room_id).await.map_err(Into::into)
    }
    pub async fn get_contacts(&self, identity_pubkey: String) -> Result<Vec<ContactInfoFull>, KeychatUniError> {
        self.app.get_contacts(identity_pubkey).await.map(|v| v.into_iter().map(convert_contact_info).collect()).map_err(Into::into)
    }
    pub async fn update_contact_petname(&self, pubkey: String, identity_pubkey: String, petname: String) -> Result<(), KeychatUniError> {
        self.app.update_contact_petname(pubkey, identity_pubkey, petname).await.map_err(Into::into)
    }
    pub async fn save_app_room_ffi(&self, to_main_pubkey: String, identity_pubkey: String, status: RoomStatus, room_type: RoomType, name: Option<String>, parent_room_id: Option<String>) -> Result<String, KeychatUniError> {
        let core_status = convert_room_status_to_core(status);
        let core_type = convert_room_type_to_core(room_type);
        self.app.save_app_room(to_main_pubkey, identity_pubkey, core_status, core_type, name, parent_room_id).await.map_err(Into::into)
    }
    pub async fn save_app_message_ffi(&self, msgid: String, event_id: Option<String>, room_id: String, identity_pubkey: String, sender_pubkey: String, content: String, is_me_send: bool, status: MessageStatus, created_at: u64) -> Result<(), KeychatUniError> {
        let core_status = convert_message_status_to_core(status);
        self.app.save_app_message_record(msgid, event_id, room_id, identity_pubkey, sender_pubkey, content, is_me_send, core_status, created_at).await.map_err(Into::into)
    }
    pub async fn save_app_contact_ffi(&self, pubkey: String, npubkey: String, identity_pubkey: String, name: Option<String>) -> Result<String, KeychatUniError> {
        self.app.save_app_contact_record(pubkey, npubkey, identity_pubkey, name).await.map_err(Into::into)
    }
    pub async fn update_app_room_ffi(&self, room_id: String, status: Option<RoomStatus>, name: Option<String>, last_message_content: Option<String>, last_message_at: Option<u64>) -> Result<(), KeychatUniError> {
        let core_status = status.map(convert_room_status_to_core);
        self.app.update_app_room_record(room_id, core_status, name, last_message_content, last_message_at).await.map_err(Into::into)
    }
    pub async fn update_app_message_ffi(&self, msgid: String, event_id: Option<String>, status: Option<MessageStatus>, relay_status_json: Option<String>, payload_json: Option<String>, nostr_event_json: Option<String>, reply_to_event_id: Option<String>, reply_to_content: Option<String>) -> Result<(), KeychatUniError> {
        let core_status = status.map(convert_message_status_to_core);
        self.app.update_app_message_record(msgid, event_id, core_status, relay_status_json, payload_json, nostr_event_json, reply_to_event_id, reply_to_content).await.map_err(Into::into)
    }
    pub async fn update_local_meta_ffi(&self, msgid: String, local_meta: String) -> Result<(), KeychatUniError> {
        self.app.update_local_meta(msgid, local_meta).await.map_err(Into::into)
    }
    pub async fn increment_app_room_unread_ffi(&self, room_id: String) -> Result<(), KeychatUniError> {
        self.app.increment_app_room_unread_record(room_id).await.map_err(Into::into)
    }
    pub async fn is_app_message_duplicate_ffi(&self, event_id: String) -> Result<bool, KeychatUniError> {
        self.app.is_app_message_duplicate(event_id).await.map_err(Into::into)
    }
    pub async fn get_inbound_request_id(&self, sender_pubkey: String) -> Result<Option<String>, KeychatUniError> {
        self.app.get_inbound_request_id(sender_pubkey).await.map_err(Into::into)
    }
    pub async fn delete_app_room_ffi(&self, room_id: String) -> Result<(), KeychatUniError> {
        self.app.delete_app_room_record(room_id).await.map_err(Into::into)
    }
}

// Type conversions between UniFFI and app-core types
fn convert_identity_info(i: keychat_app_core::IdentityInfo) -> IdentityInfo {
    IdentityInfo { npub: i.npub, nostr_pubkey_hex: i.nostr_pubkey_hex, name: i.name, avatar: i.avatar, index: i.idx, is_default: i.is_default, created_at: i.created_at as u64 }
}
fn convert_room_info(r: keychat_app_core::RoomInfo) -> RoomInfo {
    RoomInfo { id: r.id, to_main_pubkey: r.to_main_pubkey, identity_pubkey: r.identity_pubkey, status: RoomStatus::from_i32(r.status.to_i32()), room_type: RoomType::from_i32(r.room_type.to_i32()), name: r.name, avatar: r.avatar, parent_room_id: r.parent_room_id, last_message_content: r.last_message_content, last_message_at: r.last_message_at.map(|t| t as u64), unread_count: r.unread_count, created_at: r.created_at as u64 }
}
fn convert_message_info(m: keychat_app_core::MessageInfo) -> MessageInfo {
    MessageInfo { msgid: m.msgid, event_id: m.event_id, room_id: m.room_id, sender_pubkey: m.sender_pubkey, content: m.content, is_me_send: m.is_me_send, is_read: m.is_read, status: MessageStatus::from_i32(m.status.to_i32()), reply_to_event_id: m.reply_to_event_id, reply_to_content: m.reply_to_content, payload_json: m.payload_json, nostr_event_json: m.nostr_event_json, relay_status_json: m.relay_status_json, local_file_path: m.local_file_path, local_meta: m.local_meta, created_at: m.created_at as u64 }
}
fn convert_contact_info(c: keychat_app_core::ContactInfoFull) -> ContactInfoFull {
    ContactInfoFull { pubkey: c.pubkey, npubkey: c.npubkey, identity_pubkey: c.identity_pubkey, petname: c.petname, name: c.name, avatar: c.avatar }
}
fn convert_room_status_to_core(s: RoomStatus) -> keychat_app_core::RoomStatus {
    keychat_app_core::RoomStatus::from_i32(s.to_i32())
}
fn convert_room_type_to_core(t: RoomType) -> keychat_app_core::RoomType {
    keychat_app_core::RoomType::from_i32(t.to_i32())
}
fn convert_message_status_to_core(s: MessageStatus) -> keychat_app_core::MessageStatus {
    keychat_app_core::MessageStatus::from_i32(s.to_i32())
}
