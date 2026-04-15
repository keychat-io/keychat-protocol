//! Friend request — thin UniFFI delegation to keychat-app-core::AppClient.

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    pub async fn send_friend_request(
        &self,
        peer_nostr_pubkey: String,
        my_name: String,
        device_id: String,
    ) -> Result<PendingFriendRequest, KeychatUniError> {
        let result: keychat_app_core::PendingFriendRequest = self
            .app
            .send_friend_request(peer_nostr_pubkey, my_name, device_id)
            .await
            .map_err(KeychatUniError::from)?;

        Ok(PendingFriendRequest {
            request_id: result.request_id,
            peer_nostr_pubkey: result.peer_nostr_pubkey,
        })
    }

    pub async fn accept_friend_request(
        &self,
        request_id: String,
        my_name: String,
    ) -> Result<ContactInfo, KeychatUniError> {
        let result: keychat_app_core::ContactInfo = self
            .app
            .accept_friend_request(request_id, my_name)
            .await
            .map_err(KeychatUniError::from)?;

        Ok(ContactInfo {
            nostr_pubkey_hex: result.nostr_pubkey_hex,
            signal_id_hex: result.signal_id_hex,
            display_name: result.display_name,
        })
    }

    pub async fn reject_friend_request(
        &self,
        request_id: String,
        _message: Option<String>,
    ) -> Result<(), KeychatUniError> {
        self.app
            .reject_friend_request(request_id, _message)
            .await
            .map_err(KeychatUniError::from)
    }

    /// Export my contact bundle as a JSON string (spec §6.5).
    pub async fn export_contact_bundle(
        &self,
        my_name: String,
        device_id: String,
    ) -> Result<String, KeychatUniError> {
        self.app
            .export_contact_bundle(my_name, device_id)
            .await
            .map_err(KeychatUniError::from)
    }

    /// Add a contact by consuming a peer-supplied bundle (spec §6.5).
    pub async fn add_contact_via_bundle(
        &self,
        bundle_json: String,
        my_name: String,
    ) -> Result<ContactInfo, KeychatUniError> {
        let result: keychat_app_core::ContactInfo = self
            .app
            .add_contact_via_bundle(bundle_json, my_name)
            .await
            .map_err(KeychatUniError::from)?;

        Ok(ContactInfo {
            nostr_pubkey_hex: result.nostr_pubkey_hex,
            signal_id_hex: result.signal_id_hex,
            display_name: result.display_name,
        })
    }
}
