//! Messaging — thin UniFFI delegation to keychat-app-core::AppClient.

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    pub async fn send_text(
        &self,
        room_id: String,
        text: String,
        _format: Option<String>,
        reply_to: Option<ReplyToPayload>,
        _thread_id: Option<String>,
    ) -> Result<SentMessage, KeychatUniError> {
        let core_reply = reply_to.map(|r| keychat_app_core::ReplyToPayload {
            target_event_id: r.target_event_id,
            content: r.content,
        });
        let result = self.app.send_text(room_id, text, _format, core_reply, _thread_id).await?;
        Ok(convert_sent_message(result))
    }

    pub async fn send_file(
        &self,
        room_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<SentMessage, KeychatUniError> {
        let core_files = files.into_iter().map(convert_file_payload).collect();
        let core_reply = reply_to.map(|r| keychat_app_core::ReplyToPayload {
            target_event_id: r.target_event_id,
            content: r.content,
        });
        let result = self.app.send_file(room_id, core_files, message, core_reply).await?;
        Ok(convert_sent_message(result))
    }

    pub async fn send_nip17_dm(
        &self,
        peer_pubkey: String,
        text: String,
    ) -> Result<SentMessage, KeychatUniError> {
        let result = self.app.send_nip17_dm(peer_pubkey, text).await?;
        Ok(convert_sent_message(result))
    }

    pub async fn retry_failed_messages(&self) -> Result<u32, KeychatUniError> {
        self.app.retry_failed_messages().await.map_err(Into::into)
    }
}

fn convert_sent_message(m: keychat_app_core::SentMessage) -> SentMessage {
    SentMessage {
        event_id: m.event_id,
        payload_json: m.payload_json,
        nostr_event_json: m.nostr_event_json,
        connected_relays: m.connected_relays,
        new_receiving_addresses: m.new_receiving_addresses,
        dropped_receiving_addresses: m.dropped_receiving_addresses,
        new_sending_address: m.new_sending_address,
    }
}

fn convert_file_payload(f: FilePayload) -> keychat_app_core::FilePayload {
    keychat_app_core::FilePayload {
        category: convert_file_category(f.category),
        url: f.url,
        mime_type: f.mime_type,
        suffix: f.suffix,
        size: f.size,
        key: f.key,
        iv: f.iv,
        hash: f.hash,
        source_name: f.source_name,
        audio_duration: f.audio_duration,
        amplitude_samples: f.amplitude_samples,
    }
}

fn convert_file_category(c: FileCategory) -> keychat_app_core::FileCategory {
    match c {
        FileCategory::Image => keychat_app_core::FileCategory::Image,
        FileCategory::Video => keychat_app_core::FileCategory::Video,
        FileCategory::Voice => keychat_app_core::FileCategory::Voice,
        FileCategory::Audio => keychat_app_core::FileCategory::Audio,
        FileCategory::Document => keychat_app_core::FileCategory::Document,
        FileCategory::Text => keychat_app_core::FileCategory::Text,
        FileCategory::Archive => keychat_app_core::FileCategory::Archive,
        FileCategory::Other => keychat_app_core::FileCategory::Other,
    }
}
