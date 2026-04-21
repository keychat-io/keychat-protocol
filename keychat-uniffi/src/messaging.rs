//! Messaging — thin UniFFI delegation to keychat-app-core::AppClient.

use crate::client::{convert_file_payload, convert_reply_to, KeychatClient};
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
        let core_reply = reply_to.map(convert_reply_to);
        let r = self
            .app
            .send_text(room_id, text, _format, core_reply, _thread_id)
            .await?;
        Ok(convert_sent_message(r))
    }

    pub async fn send_file(
        &self,
        room_id: String,
        files: Vec<FilePayload>,
        message: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<SentMessage, KeychatUniError> {
        let core_files = files.into_iter().map(convert_file_payload).collect();
        let core_reply = reply_to.map(convert_reply_to);
        let r = self
            .app
            .send_file(room_id, core_files, message, core_reply)
            .await?;
        Ok(convert_sent_message(r))
    }

    pub async fn send_nip17_dm(
        &self,
        peer_pubkey: String,
        text: String,
    ) -> Result<SentMessage, KeychatUniError> {
        let r = self.app.send_nip17_dm(peer_pubkey, text).await?;
        Ok(convert_sent_message(r))
    }

    pub async fn send_cashu(
        &self,
        room_id: String,
        mint: String,
        token: String,
        amount: u64,
        memo: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<SentMessage, KeychatUniError> {
        let core_reply = reply_to.map(convert_reply_to);
        let r = self.app.send_cashu(room_id, mint, token, amount, memo, core_reply).await?;
        Ok(convert_sent_message(r))
    }

    pub async fn send_lightning_invoice(
        &self,
        room_id: String,
        invoice: String,
        amount: u64,
        memo: Option<String>,
        reply_to: Option<ReplyToPayload>,
    ) -> Result<SentMessage, KeychatUniError> {
        let core_reply = reply_to.map(convert_reply_to);
        let r = self.app.send_lightning_invoice(room_id, invoice, amount, memo, core_reply).await?;
        Ok(convert_sent_message(r))
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
