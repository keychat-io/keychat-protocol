//! Agent daemon mode — headless HTTP server for AI frameworks.
//!
//! Supports multiple agent identities, each with its own AppClient,
//! database, relay connections, and friend-request policy.
//!
//! Routes:
//!   Legacy (single-identity, backward compatible):
//!     All routes from daemon::build_router + agent-specific routes
//!   Multi-identity:
//!     POST /agents/{id}/identity/create  — create new identity for agent
//!     POST /agents/{id}/identity/import  — import mnemonic for agent
//!     GET  /agents/{id}/identity         — get agent's identity
//!     POST /agents/{id}/send             — send message as agent
//!     GET  /agents/{id}/rooms            — agent's chat rooms
//!     GET  /agents/{id}/contacts         — agent's contacts
//!     GET  /agents/{id}/events           — SSE stream for one agent
//!     GET  /agents/{id}/pending-friends  — pending friend requests
//!     POST /agents/{id}/approve-friend   — approve a friend request
//!     POST /agents/{id}/reject-friend    — reject a friend request
//!     GET  /agents/{id}/owner            — get agent's owner
//!     POST /agents/{id}/owner            — set agent's owner
//!     POST /agents/{id}/backup-mnemonic  — backup agent's mnemonic
//!     GET  /agents                       — list all agents
//!     GET  /events                       — SSE stream for all agents

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        Json,
    },
    routing::{get, post},
    Router,
};
use keychat_app_core::{ClientEvent, DataChange, AppClient};
use serde::Deserialize;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::StreamExt;

use crate::agent_policy::{AgentPolicy, PendingFriendRequest};
use crate::daemon::{bad_request, err_json, ok_json};
use crate::{agent_config, commands};

// ─── Per-Agent Instance ───────────────────────────────────────

/// Everything needed to run a single agent identity.
struct AgentInstance {
    id: String,
    client: Arc<AppClient>,
    policy: Arc<AgentPolicy>,
    event_tx: broadcast::Sender<ClientEvent>,
    #[allow(dead_code)] // held to keep broadcast channel alive
    data_tx: broadcast::Sender<DataChange>,
    pending_tx: broadcast::Sender<PendingFriendRequest>,
    npub: String,
    pubkey_hex: String,
}

// ─── Agent Registry ───────────────────────────────────────────

/// Manages all running agent instances.
#[derive(Clone)]
struct AgentRegistry {
    agents: Arc<RwLock<HashMap<String, Arc<AgentInstance>>>>,
    data_dir: String,
    auto_accept: bool,
    relay_urls: Vec<String>,
    /// Global event channel: all agents' events merged here.
    global_event_tx: broadcast::Sender<AgentEvent>,
}

/// An event tagged with the originating agent_id.
#[derive(Clone, Debug)]
struct AgentEvent {
    agent_id: String,
    json: String,
    event_type: String,
}

impl AgentRegistry {
    fn new(
        data_dir: String,
        auto_accept: bool,
        relay_urls: Vec<String>,
    ) -> Self {
        let (global_event_tx, _) = broadcast::channel(512);
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            data_dir,
            auto_accept,
            relay_urls,
            global_event_tx,
        }
    }

    /// Boot an agent: create client, resolve identity, connect relays, start policy.
    async fn boot_agent(
        &self,
        agent_id: &str,
        agent_name: &str,
        import_mnemonic: Option<&str>,
    ) -> anyhow::Result<Arc<AgentInstance>> {
        // Check if already running
        {
            let agents = self.agents.read().await;
            if agents.contains_key(agent_id) {
                anyhow::bail!("agent {agent_id} is already running");
            }
        }

        // 1. Resolve data dir and secrets
        let agent_data = agent_config::agent_data_dir(&self.data_dir, agent_id);
        let agent_db_dir = format!("{}/db", agent_data);
        std::fs::create_dir_all(&agent_db_dir)?;

        let db_key = agent_config::resolve_db_key_for_agent(agent_id)?;
        let db_path = format!("{}/protocol.db", agent_db_dir);

        // 2. Initialize client
        let client = Arc::new(AppClient::new(db_path, db_key)?);

        let (event_tx, _) = broadcast::channel(256);
        let (data_tx, _) = broadcast::channel(256);

        let event_listener = commands::CliEventListener::new(event_tx.clone());
        let data_listener = commands::CliDataListener::new(data_tx.clone());
        client.set_event_listener(Box::new(event_listener)).await;
        client.set_data_listener(Box::new(data_listener)).await;

        // 3. Resolve identity
        let mnemonic = match import_mnemonic {
            Some(m) => Some(m.to_string()),
            None => agent_config::resolve_mnemonic_for_agent(agent_id)?,
        };

        let pubkey = match mnemonic {
            Some(m) => {
                let pk = commands::import_identity(&client, &m).await
                    .map_err(|e| anyhow::anyhow!("failed to import identity for agent {agent_id}: {e}"))?;
                agent_config::save_mnemonic_for_agent(agent_id, &m)?;
                pk
            }
            None => {
                match commands::restore_identity(&client).await {
                    Some(pk) => pk,
                    None => {
                        let (pk, _npub, mnemonic) =
                            commands::create_identity(&client, agent_name).await
                                .map_err(|e| anyhow::anyhow!("failed to create identity for agent {agent_id}: {e}"))?;
                        agent_config::save_mnemonic_for_agent(agent_id, &mnemonic)?;
                        tracing::info!("Created new identity for agent {agent_id}");
                        pk
                    }
                }
            }
        };

        let npub = keychat_app_core::npub_from_hex(pubkey.clone()).unwrap_or_default();

        // 4. Connect to relays
        match client.restore_sessions().await {
            Ok(n) if n > 0 => tracing::info!("Agent {agent_id}: restored {n} session(s)"),
            Err(e) => tracing::warn!("Agent {agent_id} restore_sessions: {e}"),
            _ => {}
        }
        commands::connect_and_start(&client, self.relay_urls.clone());

        // 5. Start agent policy
        let policy = Arc::new(AgentPolicy::new(
            Arc::clone(&client),
            self.auto_accept,
            agent_name.to_string(),
        ));
        let (pending_tx, _) = broadcast::channel::<PendingFriendRequest>(64);

        // Forward policy pending events to pending_tx
        let pending_tx_for_sse = pending_tx.clone();
        let mut pending_rx = policy.subscribe_pending();
        tokio::spawn(async move {
            while let Ok(pfr) = pending_rx.recv().await {
                let _ = pending_tx_for_sse.send(pfr);
            }
        });

        policy.start(event_tx.subscribe());

        // 6. Forward events to global channel
        let global_tx = self.global_event_tx.clone();
        let aid = agent_id.to_string();
        let mut erx = event_tx.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = erx.recv().await {
                let event_type = crate::daemon::client_event_type_str(&event);
                let json = crate::daemon::serialize_client_event_str(&event);
                let _ = global_tx.send(AgentEvent {
                    agent_id: aid.clone(),
                    json,
                    event_type: event_type.to_string(),
                });
            }
        });

        let instance = Arc::new(AgentInstance {
            id: agent_id.to_string(),
            client,
            policy,
            event_tx,
            data_tx,
            pending_tx,
            npub,
            pubkey_hex: pubkey,
        });

        self.agents.write().await.insert(agent_id.to_string(), Arc::clone(&instance));

        tracing::info!("Agent {agent_id} booted: {}", &instance.npub);
        Ok(instance)
    }

    async fn get_agent(&self, agent_id: &str) -> Option<Arc<AgentInstance>> {
        self.agents.read().await.get(agent_id).cloned()
    }

    async fn list_agents(&self) -> Vec<serde_json::Value> {
        let agents = self.agents.read().await;
        agents.values().map(|a| {
            serde_json::json!({
                "id": a.id,
                "npub": a.npub,
                "pubkey_hex": a.pubkey_hex,
            })
        }).collect()
    }
}

// ─── Legacy Single-Agent State (backward compat) ──────────────

#[derive(Clone)]
struct LegacyAgentState {
    policy: Arc<AgentPolicy>,
    pending_tx: broadcast::Sender<PendingFriendRequest>,
}

// ─── Entry Point ───────────────────────────────────────────────

pub async fn run(
    data_dir: String,
    port: u16,
    auto_accept: bool,
    agent_name: String,
    relay_override: Option<String>,
    api_token_override: Option<String>,
) -> anyhow::Result<()> {
    // Create subdirectories: db/, files/, logs/
    let db_dir = format!("{}/db", data_dir);
    std::fs::create_dir_all(&db_dir)?;

    let relay_urls = match relay_override {
        Some(r) => r.split(',').map(|s| s.trim().to_string()).collect(),
        None => keychat_app_core::default_relays(),
    };

    // Check if multi-agent mode: {data_dir}/agents/ exists with subdirs
    let existing_agents = agent_config::list_agent_ids(&data_dir);
    let is_multi = !existing_agents.is_empty();

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    if is_multi {
        // ─── Multi-Agent Mode ──────────────────────────────
        let registry = AgentRegistry::new(data_dir.clone(), auto_accept, relay_urls);

        // Boot all existing agents
        for aid in &existing_agents {
            match registry.boot_agent(aid, &agent_name, None).await {
                Ok(inst) => println!("Agent {aid} ready: {}", inst.npub),
                Err(e) => tracing::error!("Failed to boot agent {aid}: {e}"),
            }
        }

        let _api_token = agent_config::resolve_api_token(
            &data_dir,
            api_token_override.as_deref(),
        )?;

        let router = build_multi_router(registry);

        println!("Multi-agent mode: {} agent(s) loaded", existing_agents.len());
        println!("Listening on http://{addr}");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await?;
    } else {
        // ─── Legacy Single-Agent Mode ──────────────────────
        let db_key = agent_config::resolve_db_key(&data_dir)?;
        let db_path = format!("{}/protocol.db", db_dir);

        let client = Arc::new(AppClient::new(db_path, db_key)?);

        let (event_tx, _) = broadcast::channel(256);
        let (data_tx, _) = broadcast::channel(256);

        let event_listener = commands::CliEventListener::new(event_tx.clone());
        let data_listener = commands::CliDataListener::new(data_tx.clone());
        client.set_event_listener(Box::new(event_listener)).await;
        client.set_data_listener(Box::new(data_listener)).await;

        let mnemonic = agent_config::resolve_mnemonic(&data_dir)?;
        let pubkey = match mnemonic {
            Some(m) => {
                let pk = commands::import_identity(&client, &m).await
                    .map_err(|e| anyhow::anyhow!("failed to import identity: {e}"))?;
                agent_config::save_mnemonic(&data_dir, &m)?;
                pk
            }
            None => {
                match commands::restore_identity(&client).await {
                    Some(pk) => pk,
                    None => {
                        let (pk, _npub, mnemonic) =
                            commands::create_identity(&client, &agent_name).await
                                .map_err(|e| anyhow::anyhow!("failed to create identity: {e}"))?;
                        agent_config::save_mnemonic(&data_dir, &mnemonic)?;
                        tracing::info!("Created new agent identity");
                        pk
                    }
                }
            }
        };

        let npub = keychat_app_core::npub_from_hex(pubkey.clone()).unwrap_or_default();

        match client.restore_sessions().await {
            Ok(n) if n > 0 => tracing::info!("Restored {n} session(s)"),
            Err(e) => tracing::warn!("restore_sessions: {e}"),
            _ => {}
        }
        commands::connect_and_start(&client, relay_urls);

        let policy = Arc::new(AgentPolicy::new(
            Arc::clone(&client),
            auto_accept,
            agent_name.clone(),
        ));
        let (pending_tx, _) = broadcast::channel::<PendingFriendRequest>(64);

        let pending_tx_for_sse = pending_tx.clone();
        let mut pending_rx = policy.subscribe_pending();
        tokio::spawn(async move {
            while let Ok(pfr) = pending_rx.recv().await {
                let _ = pending_tx_for_sse.send(pfr);
            }
        });

        policy.start(event_tx.subscribe());

        let _api_token = agent_config::resolve_api_token(
            &data_dir,
            api_token_override.as_deref(),
        )?;

        let base_router = crate::daemon::build_router(
            Arc::clone(&client),
            event_tx.clone(),
            data_tx.clone(),
        );

        let legacy_state = LegacyAgentState {
            policy: Arc::clone(&policy),
            pending_tx: pending_tx.clone(),
        };

        let agent_routes = Router::new()
            .route("/pending-friends", get(legacy_get_pending_friends))
            .route("/approve-friend", post(legacy_approve_friend))
            .route("/reject-friend", post(legacy_reject_friend))
            .route("/owner", get(legacy_get_owner))
            .route("/owner", post(legacy_set_owner))
            .route("/backup-mnemonic", post(legacy_backup_mnemonic))
            .route("/agent/events", get(legacy_agent_sse_events))
            .with_state(legacy_state);

        let router = base_router.merge(agent_routes);

        println!("Agent ready: {npub}");
        println!("Listening on http://{addr}");

        tracing::info!("Agent {agent_name} ({}) listening on {addr}", &pubkey[..16.min(pubkey.len())]);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await?;
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Multi-Agent Router
// ═══════════════════════════════════════════════════════════════

fn build_multi_router(registry: AgentRegistry) -> Router {
    Router::new()
        // Agent management
        .route("/agents", get(list_agents))
        .route("/agents/{id}/identity/create", post(create_agent_identity))
        .route("/agents/{id}/identity/import", post(import_agent_identity))
        .route("/agents/{id}/identity", get(get_agent_identity))
        // Messaging
        .route("/agents/{id}/send", post(agent_send_message))
        .route("/agents/{id}/rooms", get(agent_list_rooms))
        .route("/agents/{id}/rooms/{room_id}/messages", get(agent_get_messages))
        .route("/agents/{id}/contacts", get(agent_list_contacts))
        // Friends
        .route("/agents/{id}/pending-friends", get(agent_get_pending_friends))
        .route("/agents/{id}/approve-friend", post(agent_approve_friend))
        .route("/agents/{id}/reject-friend", post(agent_reject_friend))
        // Owner
        .route("/agents/{id}/owner", get(agent_get_owner))
        .route("/agents/{id}/owner", post(agent_set_owner))
        .route("/agents/{id}/backup-mnemonic", post(agent_backup_mnemonic))
        // Events
        .route("/agents/{id}/events", get(agent_sse_events))
        .route("/events", get(global_sse_events))
        // Status
        .route("/agents/{id}/status", get(agent_get_status))
        .with_state(registry)
}

// ─── Multi-Agent: List ────────────────────────────────────────

async fn list_agents(
    State(reg): State<AgentRegistry>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agents = reg.list_agents().await;
    ok_json(agents)
}

// ─── Multi-Agent: Identity ────────────────────────────────────

fn default_agent_name() -> String {
    "Keychat Agent".to_string()
}

async fn create_agent_identity(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // If agent already exists, return its identity
    if let Some(existing) = reg.get_agent(&id).await {
        return ok_json(serde_json::json!({
            "agent_id": existing.id,
            "npub": existing.npub,
            "pubkey_hex": existing.pubkey_hex,
        }));
    }
    match reg.boot_agent(&id, &default_agent_name(), None).await {
        Ok(inst) => ok_json(serde_json::json!({
            "agent_id": inst.id,
            "npub": inst.npub,
            "pubkey_hex": inst.pubkey_hex,
        })),
        Err(e) => bad_request(format!("{e}")),
    }
}

#[derive(Deserialize)]
struct ImportAgentIdentityReq {
    mnemonic: String,
    #[serde(default = "default_agent_name")]
    name: String,
}

async fn import_agent_identity(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
    Json(req): Json<ImportAgentIdentityReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match reg.boot_agent(&id, &req.name, Some(&req.mnemonic)).await {
        Ok(inst) => ok_json(serde_json::json!({
            "agent_id": inst.id,
            "npub": inst.npub,
            "pubkey_hex": inst.pubkey_hex,
        })),
        Err(e) => bad_request(format!("{e}")),
    }
}

async fn get_agent_identity(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    // Use cached npub/pubkey from AgentInstance (consistent with list_agents)
    if !agent.npub.is_empty() {
        return ok_json(serde_json::json!({
            "agent_id": id,
            "pubkey_hex": agent.pubkey_hex,
            "name": agent.id.clone(),
            "npub": agent.npub,
        }));
    }
    match agent.client.get_pubkey_hex().await {
        Ok(pubkey) => {
            let npub = keychat_app_core::npub_from_hex(pubkey.clone()).unwrap_or_default();
            ok_json(serde_json::json!({
                "agent_id": id,
                "pubkey_hex": pubkey,
                "name": agent.id.clone(),
                "npub": npub,
            }))
        }
        Err(_) => err_json(StatusCode::NOT_FOUND, "no identity set"),
    }
}

// ─── Multi-Agent: Status ──────────────────────────────────────

async fn agent_get_status(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    let identity = agent.client.get_pubkey_hex().await.ok();
    let relay_statuses = agent.client.get_relay_statuses().await.unwrap_or_default();
    let connected_count = relay_statuses.iter().filter(|s| s.status == "connected").count();

    ok_json(serde_json::json!({
        "agent_id": id,
        "identity": identity,
        "npub": agent.npub,
        "relays_connected": connected_count,
        "relays_total": relay_statuses.len(),
    }))
}

// ─── Multi-Agent: Messaging ───────────────────────────────────

#[derive(Deserialize)]
struct AgentSendMessageReq {
    room_id: String,
    text: String,
}

async fn agent_send_message(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
    Json(req): Json<AgentSendMessageReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    match commands::send_message(&agent.client, &req.room_id, &req.text).await {
        Ok(commands::SendResult::Dm { event_id, relay_count }) => {
            ok_json(serde_json::json!({
                "agent_id": id,
                "event_id": event_id,
                "relay_count": relay_count,
            }))
        }
        Ok(commands::SendResult::Group { event_count }) => {
            ok_json(serde_json::json!({
                "agent_id": id,
                "type": "group",
                "event_count": event_count,
            }))
        }
        Ok(commands::SendResult::MlsNotSupported) => {
            bad_request("MLS groups not yet supported")
        }
        Err(e) => bad_request(format!("{e}")),
    }
}

async fn agent_list_rooms(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    let pubkey = match agent.client.get_pubkey_hex().await {
        Ok(pk) => pk,
        Err(e) => return bad_request(format!("{e}")),
    };

    match agent.client.get_rooms(pubkey).await {
        Ok(rooms) => {
            let list: Vec<_> = rooms
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "to_main_pubkey": r.to_main_pubkey,
                        "status": format!("{:?}", r.status).to_lowercase(),
                        "room_type": format!("{:?}", r.room_type).to_lowercase(),
                        "last_message_content": r.last_message_content,
                        "last_message_at": r.last_message_at,
                        "unread_count": r.unread_count,
                        "created_at": r.created_at,
                    })
                })
                .collect();
            ok_json(serde_json::json!({ "agent_id": id, "rooms": list }))
        }
        Err(e) => bad_request(format!("{e}")),
    }
}

#[derive(Deserialize, Default)]
struct MessageQuery {
    #[serde(default = "default_limit")]
    limit: i32,
    #[serde(default)]
    offset: i32,
}

fn default_limit() -> i32 {
    50
}

async fn agent_get_messages(
    State(reg): State<AgentRegistry>,
    Path((id, room_id)): Path<(String, String)>,
    Query(query): Query<MessageQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    match agent.client.get_messages(room_id, query.limit, query.offset).await {
        Ok(messages) => {
            let list: Vec<_> = messages
                .into_iter()
                .map(|m| {
                    serde_json::json!({
                        "msgid": m.msgid,
                        "event_id": m.event_id,
                        "room_id": m.room_id,
                        "sender_pubkey": m.sender_pubkey,
                        "content": m.content,
                        "is_me_send": m.is_me_send,
                        "is_read": m.is_read,
                        "created_at": m.created_at,
                    })
                })
                .collect();
            ok_json(serde_json::json!({ "agent_id": id, "messages": list }))
        }
        Err(e) => bad_request(format!("{e}")),
    }
}

async fn agent_list_contacts(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    let pubkey = match agent.client.get_pubkey_hex().await {
        Ok(pk) => pk,
        Err(e) => return bad_request(format!("{e}")),
    };

    match agent.client.get_contacts(pubkey).await {
        Ok(contacts) => {
            let list: Vec<_> = contacts
                .into_iter()
                .map(|c| {
                    serde_json::json!({
                        "pubkey": c.pubkey,
                        "npubkey": c.npubkey,
                        "identity_pubkey": c.identity_pubkey,
                        "petname": c.petname,
                        "name": c.name,
                        "avatar": c.avatar,
                    })
                })
                .collect();
            ok_json(serde_json::json!({ "agent_id": id, "contacts": list }))
        }
        Err(e) => bad_request(format!("{e}")),
    }
}

// ─── Multi-Agent: Friends ─────────────────────────────────────

async fn agent_get_pending_friends(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    let pending = agent.policy.get_pending().await;
    let list: Vec<_> = pending
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "request_id": p.request_id,
                "sender_pubkey": p.sender_pubkey,
                "sender_name": p.sender_name,
                "created_at": p.created_at,
            })
        })
        .collect();
    ok_json(serde_json::json!({ "agent_id": id, "pending": list }))
}

#[derive(Deserialize)]
struct ApproveFriendReq {
    request_id: String,
}

async fn agent_approve_friend(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
    Json(req): Json<ApproveFriendReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    match agent.policy.approve_friend(&req.request_id).await {
        Ok(pubkey) => ok_json(serde_json::json!({
            "agent_id": id,
            "approved": true,
            "sender_pubkey": pubkey,
        })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct RejectFriendReq {
    request_id: String,
}

async fn agent_reject_friend(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
    Json(req): Json<RejectFriendReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    match agent.policy.reject_friend(&req.request_id).await {
        Ok(()) => ok_json(serde_json::json!({ "agent_id": id, "rejected": true })),
        Err(e) => bad_request(e),
    }
}

// ─── Multi-Agent: Owner ───────────────────────────────────────

async fn agent_get_owner(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    let owner = agent.policy.get_owner().await;
    ok_json(serde_json::json!({ "agent_id": id, "owner": owner }))
}

#[derive(Deserialize)]
struct SetOwnerReq {
    requester: String,
    new_owner: String,
}

async fn agent_set_owner(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
    Json(req): Json<SetOwnerReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    match agent.policy.set_owner(&req.requester, &req.new_owner).await {
        Ok(()) => ok_json(serde_json::json!({ "agent_id": id, "owner": req.new_owner })),
        Err(e) => err_json(StatusCode::FORBIDDEN, e),
    }
}

#[derive(Deserialize)]
struct BackupMnemonicReq {
    requester: String,
}

async fn agent_backup_mnemonic(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
    Json(req): Json<BackupMnemonicReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return err_json(StatusCode::NOT_FOUND, format!("agent {id} not found")),
    };

    match agent.policy.backup_mnemonic(&req.requester).await {
        Ok(mnemonic) => ok_json(serde_json::json!({ "agent_id": id, "mnemonic": mnemonic })),
        Err(e) => err_json(StatusCode::FORBIDDEN, e),
    }
}

// ─── Multi-Agent: SSE Events ──────────────────────────────────

#[derive(Deserialize, Default)]
#[allow(dead_code)]
struct SseQuery {
    #[serde(default)]
    token: Option<String>,
}

/// SSE stream for a single agent.
async fn agent_sse_events(
    State(reg): State<AgentRegistry>,
    Path(id): Path<String>,
    Query(_query): Query<SseQuery>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>>, (StatusCode, Json<serde_json::Value>)> {
    let agent = match reg.get_agent(&id).await {
        Some(a) => a,
        None => return Err(err_json(StatusCode::NOT_FOUND, format!("agent {id} not found"))),
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<SseEvent>(256);

    // Forward ClientEvent
    let mut event_rx = agent.event_tx.subscribe();
    let tx1 = tx.clone();
    let aid = id.clone();
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let event_type = crate::daemon::client_event_type_str(&event);
            let mut json: serde_json::Value = serde_json::from_str(
                &crate::daemon::serialize_client_event_str(&event)
            ).unwrap_or_default();
            if let Some(obj) = json.as_object_mut() {
                obj.insert("agent_id".to_string(), serde_json::Value::String(aid.clone()));
            }
            let sse = SseEvent::default()
                .event(event_type)
                .data(json.to_string());
            if tx1.send(sse).await.is_err() {
                break;
            }
        }
    });

    // Forward pending friend requests
    let mut pending_rx = agent.pending_tx.subscribe();
    let aid2 = id.clone();
    tokio::spawn(async move {
        while let Ok(pfr) = pending_rx.recv().await {
            let json = serde_json::json!({
                "type": "pending_friend_request",
                "agent_id": aid2,
                "request_id": pfr.request_id,
                "sender_pubkey": pfr.sender_pubkey,
                "sender_npub": keychat_app_core::npub_from_hex(pfr.sender_pubkey.clone()).unwrap_or_default(),
                "sender_name": pfr.sender_name,
                "created_at": pfr.created_at,
            })
            .to_string();
            let sse = SseEvent::default()
                .event("pending_friend_request")
                .data(json);
            if tx.send(sse).await.is_err() {
                break;
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(|e| Ok::<_, Infallible>(e));
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Global SSE stream: events from all agents, each tagged with agent_id.
async fn global_sse_events(
    State(reg): State<AgentRegistry>,
    Query(_query): Query<SseQuery>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<SseEvent>(512);

    let mut global_rx = reg.global_event_tx.subscribe();
    tokio::spawn(async move {
        while let Ok(ae) = global_rx.recv().await {
            // Inject agent_id into the JSON
            let mut json: serde_json::Value = serde_json::from_str(&ae.json).unwrap_or_default();
            if let Some(obj) = json.as_object_mut() {
                obj.insert("agent_id".to_string(), serde_json::Value::String(ae.agent_id));
            }
            let sse = SseEvent::default()
                .event(ae.event_type)
                .data(json.to_string());
            if tx.send(sse).await.is_err() {
                break;
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(|e| Ok::<_, Infallible>(e));
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ═══════════════════════════════════════════════════════════════
// Legacy Single-Agent Routes (backward compatible)
// ═══════════════════════════════════════════════════════════════

async fn legacy_get_pending_friends(
    State(state): State<LegacyAgentState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pending = state.policy.get_pending().await;
    let list: Vec<_> = pending
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "request_id": p.request_id,
                "sender_pubkey": p.sender_pubkey,
                "sender_name": p.sender_name,
                "created_at": p.created_at,
            })
        })
        .collect();
    ok_json(list)
}

async fn legacy_approve_friend(
    State(state): State<LegacyAgentState>,
    Json(req): Json<ApproveFriendReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.policy.approve_friend(&req.request_id).await {
        Ok(pubkey) => ok_json(serde_json::json!({
            "approved": true,
            "sender_pubkey": pubkey,
        })),
        Err(e) => bad_request(e),
    }
}

async fn legacy_reject_friend(
    State(state): State<LegacyAgentState>,
    Json(req): Json<RejectFriendReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.policy.reject_friend(&req.request_id).await {
        Ok(()) => ok_json(serde_json::json!({ "rejected": true })),
        Err(e) => bad_request(e),
    }
}

async fn legacy_get_owner(
    State(state): State<LegacyAgentState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let owner = state.policy.get_owner().await;
    ok_json(serde_json::json!({ "owner": owner }))
}

async fn legacy_set_owner(
    State(state): State<LegacyAgentState>,
    Json(req): Json<SetOwnerReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.policy.set_owner(&req.requester, &req.new_owner).await {
        Ok(()) => ok_json(serde_json::json!({ "owner": req.new_owner })),
        Err(e) => err_json(StatusCode::FORBIDDEN, e),
    }
}

async fn legacy_backup_mnemonic(
    State(state): State<LegacyAgentState>,
    Json(req): Json<BackupMnemonicReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.policy.backup_mnemonic(&req.requester).await {
        Ok(mnemonic) => ok_json(serde_json::json!({ "mnemonic": mnemonic })),
        Err(e) => err_json(StatusCode::FORBIDDEN, e),
    }
}

async fn legacy_agent_sse_events(
    State(state): State<LegacyAgentState>,
    Query(_query): Query<SseQuery>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<SseEvent>(256);

    let mut pending_rx = state.pending_tx.subscribe();
    let tx1 = tx.clone();
    tokio::spawn(async move {
        while let Ok(pfr) = pending_rx.recv().await {
            let json = serde_json::json!({
                "type": "pending_friend_request",
                "request_id": pfr.request_id,
                "sender_pubkey": pfr.sender_pubkey,
                "sender_npub": keychat_app_core::npub_from_hex(pfr.sender_pubkey.clone()).unwrap_or_default(),
                "sender_name": pfr.sender_name,
                "created_at": pfr.created_at,
            })
            .to_string();
            let sse = SseEvent::default()
                .event("pending_friend_request")
                .data(json);
            if tx1.send(sse).await.is_err() {
                break;
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(|e| Ok::<_, Infallible>(e));
    Sse::new(stream).keep_alive(KeepAlive::default())
}
