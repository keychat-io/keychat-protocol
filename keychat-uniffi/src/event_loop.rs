//! Event loop — thin UniFFI delegation to keychat-app-core.
//!
//! Now that KeychatClient holds Arc<AppClient>, we can directly call
//! AppClient::start_event_loop(self: Arc<Self>) without reimplementing
//! the subscribe+spawn logic.

use std::sync::Arc;

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    pub async fn start_event_loop(self: Arc<Self>) -> Result<(), KeychatUniError> {
        self.app.clone().start_event_loop().await.map_err(Into::into)
    }

    pub async fn stop_event_loop(&self) {
        self.app.stop_event_loop().await;
    }

    pub async fn enable_auto_reconnect(
        self: Arc<Self>,
        max_delay_secs: u32,
    ) -> Result<(), KeychatUniError> {
        self.app.enable_auto_reconnect(max_delay_secs).await.map_err(Into::into)
    }

    pub async fn disable_auto_reconnect(&self) {
        self.app.disable_auto_reconnect().await;
    }

    pub async fn check_connection(self: Arc<Self>) -> ConnectionStatus {
        let core_status = self.app.check_connection().await;
        match core_status {
            keychat_app_core::ConnectionStatus::Disconnected => ConnectionStatus::Disconnected,
            keychat_app_core::ConnectionStatus::Connecting => ConnectionStatus::Connecting,
            keychat_app_core::ConnectionStatus::Connected => ConnectionStatus::Connected,
            keychat_app_core::ConnectionStatus::Reconnecting => ConnectionStatus::Reconnecting,
            keychat_app_core::ConnectionStatus::Failed => ConnectionStatus::Failed,
        }
    }
}
