use crate::client::KeychatClient;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Get all current receiving addresses (for debugging/monitoring).
    pub async fn get_all_receiving_addresses(&self) -> Vec<String> {
        let session_arcs: Vec<_> = {
            let inner = self.app.inner.read().await;
            inner.protocol.all_session_arcs()
        };
        let mut addrs = Vec::new();
        for session_mutex in &session_arcs {
            let session = session_mutex.lock().await;
            addrs.extend(session.addresses.get_all_receiving_address_strings());
        }
        addrs
    }
}
