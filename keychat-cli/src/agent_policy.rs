//! Auto-accept and owner-based friend request policy for agent mode.

use std::sync::Arc;

use keychat_app_core::{AppClient, ClientEvent};
use tokio::sync::{broadcast, RwLock};

const SETTING_OWNER: &str = "agent_owner";

// ─── Types ─────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PendingFriendRequest {
    pub request_id: String,
    pub sender_pubkey: String,
    pub sender_name: String,
    pub created_at: u64,
}

// ─── AgentPolicy ───────────────────────────────────────────────

pub struct AgentPolicy {
    client: Arc<AppClient>,
    auto_accept: bool,
    agent_name: String,
    pending: Arc<RwLock<Vec<PendingFriendRequest>>>,
    pending_tx: broadcast::Sender<PendingFriendRequest>,
}

impl AgentPolicy {
    pub fn new(client: Arc<AppClient>, auto_accept: bool, agent_name: String) -> Self {
        let (pending_tx, _) = broadcast::channel(64);
        Self {
            client,
            auto_accept,
            agent_name,
            pending: Arc::new(RwLock::new(Vec::new())),
            pending_tx,
        }
    }

    /// Subscribe to pending friend request notifications (for SSE).
    pub fn subscribe_pending(&self) -> broadcast::Receiver<PendingFriendRequest> {
        self.pending_tx.subscribe()
    }

    /// Start the background policy task that listens for friend request events.
    pub fn start(&self, mut event_rx: broadcast::Receiver<ClientEvent>) {
        let client = Arc::clone(&self.client);
        let auto_accept = self.auto_accept;
        let agent_name = self.agent_name.clone();
        let pending = Arc::clone(&self.pending);
        let pending_tx = self.pending_tx.clone();

        tokio::spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                if let ClientEvent::FriendRequestReceived {
                    request_id,
                    sender_pubkey,
                    sender_name,
                    created_at,
                    ..
                } = event
                {
                    handle_friend_request(
                        &client,
                        auto_accept,
                        &agent_name,
                        &pending,
                        &pending_tx,
                        request_id,
                        sender_pubkey,
                        sender_name,
                        created_at,
                    )
                    .await;
                }
            }
            tracing::warn!("AgentPolicy event listener stopped");
        });
    }

    // ─── Owner Management ──────────────────────────────────────

    pub async fn get_owner(&self) -> Option<String> {
        self.client
            .get_setting(SETTING_OWNER.to_string())
            .await
            .ok()
            .flatten()
    }

    pub async fn set_owner(&self, requester: &str, new_owner: &str) -> Result<(), String> {
        let current_owner = self.get_owner().await;

        // Only current owner (or unset) can change owner
        if let Some(ref owner) = current_owner {
            if owner != requester {
                return Err("only the current owner can transfer ownership".into());
            }
        }

        self.client
            .set_setting(SETTING_OWNER.to_string(), new_owner.to_string())
            .await
            .map_err(|e| format!("failed to set owner: {e}"))?;

        tracing::info!("Owner set to {}", &new_owner[..16.min(new_owner.len())]);
        Ok(())
    }

    // ─── Pending Friend Requests ───────────────────────────────

    pub async fn get_pending(&self) -> Vec<PendingFriendRequest> {
        self.pending.read().await.clone()
    }

    pub async fn approve_friend(&self, request_id: &str) -> Result<String, String> {
        let entry = self.remove_pending(request_id).await?;

        self.client
            .accept_friend_request(entry.request_id, self.agent_name.clone())
            .await
            .map_err(|e| format!("accept failed: {e}"))?;

        tracing::info!("Approved friend request from {}", entry.sender_name);
        Ok(entry.sender_pubkey)
    }

    pub async fn reject_friend(&self, request_id: &str) -> Result<(), String> {
        let entry = self.remove_pending(request_id).await?;

        self.client
            .reject_friend_request(entry.request_id, None)
            .await
            .map_err(|e| format!("reject failed: {e}"))?;

        tracing::info!("Rejected friend request from {}", entry.sender_name);
        Ok(())
    }

    // ─── Mnemonic Backup ───────────────────────────────────────

    pub async fn backup_mnemonic(&self, requester: &str) -> Result<String, String> {
        let owner = self.get_owner().await;
        match owner {
            Some(ref o) if o == requester => {}
            Some(_) => return Err("only the owner can backup the mnemonic".into()),
            None => return Err("no owner set".into()),
        }

        self.client
            .get_setting(crate::commands::SETTING_MNEMONIC.to_string())
            .await
            .map_err(|e| format!("failed to read mnemonic: {e}"))?
            .ok_or_else(|| "no mnemonic found".into())
    }

    // ─── Internal ──────────────────────────────────────────────

    async fn remove_pending(&self, request_id: &str) -> Result<PendingFriendRequest, String> {
        let mut pending = self.pending.write().await;
        let idx = pending
            .iter()
            .position(|p| p.request_id == request_id)
            .ok_or_else(|| format!("pending request {request_id} not found"))?;
        Ok(pending.remove(idx))
    }
}

// ─── Policy Logic ──────────────────────────────────────────────

async fn handle_friend_request(
    client: &AppClient,
    auto_accept: bool,
    agent_name: &str,
    pending: &RwLock<Vec<PendingFriendRequest>>,
    pending_tx: &broadcast::Sender<PendingFriendRequest>,
    request_id: String,
    sender_pubkey: String,
    sender_name: String,
    created_at: u64,
) {
    let owner = client
        .get_setting(SETTING_OWNER.to_string())
        .await
        .ok()
        .flatten();

    // First person with no owner → auto-accept and set as owner.
    // All subsequent requests → queue as pending for owner approval.
    if owner.is_none() {
        tracing::info!(
            "First friend request from {} — auto-accepting and setting as owner",
            sender_name
        );
        match client
            .accept_friend_request(request_id.clone(), agent_name.to_string())
            .await
        {
            Ok(_) => {
                if let Err(e) = client
                    .set_setting(SETTING_OWNER.to_string(), sender_pubkey.clone())
                    .await
                {
                    tracing::warn!("Failed to set owner: {e}");
                }
                tracing::info!("Owner set to {sender_name} ({sender_pubkey})");
            }
            Err(e) => {
                tracing::warn!("Auto-accept failed for {sender_name}: {e}");
            }
        }
        // Notify SSE (plugin uses this to add owner to allowFrom)
        let entry = PendingFriendRequest {
            request_id,
            sender_pubkey,
            sender_name,
            created_at,
        };
        let _ = pending_tx.send(entry);
        return;
    }

    // Has owner — queue as pending for owner approval via plugin
    tracing::info!("Friend request from {sender_name} queued for owner approval");
    let entry = PendingFriendRequest {
        request_id,
        sender_pubkey,
        sender_name,
        created_at,
    };
    let _ = pending_tx.send(entry.clone());
    pending.write().await.push(entry);
}
