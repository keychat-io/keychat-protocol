//! Multi-agent daemon — HTTP API for managing multiple agents.
//!
//! Endpoints:
//!   GET  /agents                      — List all agents
//!   POST /agents                      — Create new agent {"id":"...","name":"..."}
//!   GET  /agents/:id/identity         — Agent identity
//!   GET  /agents/:id/peers            — Agent's contacts
//!   POST /agents/:id/send             — Send message {"to":"...","message":"..."}
//!   POST /agents/:id/add-friend       — Send friend request {"npub":"..."}
//!   POST /agents/:id/approve-friend   — Approve pending request {"npub":"..."}
//!   POST /agents/:id/reject-friend    — Reject pending request {"npub":"..."}
//!   GET  /agents/:id/pending-friends  — List pending requests
//!   GET  /agents/:id/owner            — Get owner
//!   POST /agents/:id/backup-mnemonic  — Backup mnemonic (owner only)
//!   GET  /events                      — SSE stream (all agents, tagged with agent_id)
//!   GET  /health                      — Liveness check

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::chat;
use crate::multi_agent::{AgentEvent, AgentInfo, MultiAgentManager};

pub async fn run(
    root_dir: String,
    relay_urls: Vec<String>,
    listen: String,
) -> anyhow::Result<()> {
    let root_path = std::path::Path::new(&root_dir);
    std::fs::create_dir_all(root_path)?;

    let manager = Arc::new(MultiAgentManager::new(root_path, relay_urls.clone()));

    eprintln!("Keychat multi-agent daemon starting");
    for r in &relay_urls {
        eprintln!("  relay: {}", r);
    }

    // Load existing agents
    manager.load_all().await?;

    // Watch for new agent directories
    let watcher = manager.clone();
    tokio::spawn(async move { watcher.watch_new_agents().await });

    // HTTP server
    let router = Router::new()
        .route("/agents", get(list_agents).post(create_agent))
        .route("/agents/{id}/identity", get(agent_identity))
        .route("/agents/{id}/peers", get(agent_peers))
        .route("/agents/{id}/send", post(agent_send))
        .route("/agents/{id}/add-friend", post(agent_add_friend))
        .route("/agents/{id}/approve-friend", post(agent_approve_friend))
        .route("/agents/{id}/reject-friend", post(agent_reject_friend))
        .route("/agents/{id}/pending-friends", get(agent_pending_friends))
        .route("/agents/{id}/owner", get(agent_owner))
        .route("/agents/{id}/backup-mnemonic", post(agent_backup_mnemonic))
        .route("/events", get(sse_handler))
        .route("/health", get(health_handler))
        .with_state(manager.clone());

    let addr: SocketAddr = listen.parse()?;
    eprintln!("  http: http://{}", addr);
    eprintln!("Ready. Watching for new agents...");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

// ─── SSE (all agents) ───────────────────────────────────────────────────────

async fn sse_handler(
    State(mgr): State<Arc<MultiAgentManager>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = mgr.event_tx().subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        match result {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_default();
                let sse_event = match &event.event {
                    crate::chat::IncomingEvent::Message(_) =>
                        SseEvent::default().event("message").data(json),
                    crate::chat::IncomingEvent::FriendRequest { .. } =>
                        SseEvent::default().event("friend_request").data(json),
                };
                Some(Ok(sse_event))
            }
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ─── Agent management ───────────────────────────────────────────────────────

async fn list_agents(
    State(mgr): State<Arc<MultiAgentManager>>,
) -> Json<Vec<AgentInfo>> {
    Json(mgr.list_agents().await)
}

#[derive(Deserialize)]
struct CreateAgentRequest {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct CreateAgentResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    npub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn create_agent(
    State(mgr): State<Arc<MultiAgentManager>>,
    Json(req): Json<CreateAgentRequest>,
) -> impl IntoResponse {
    match mgr.create_agent(&req.id, &req.name).await {
        Ok(npub) => (StatusCode::CREATED, Json(CreateAgentResponse {
            ok: true, npub: Some(npub), error: None,
        })),
        Err(e) => (StatusCode::BAD_REQUEST, Json(CreateAgentResponse {
            ok: false, npub: None, error: Some(e.to_string()),
        })),
    }
}

// ─── Per-agent endpoints ────────────────────────────────────────────────────

#[derive(Serialize)]
struct ApiResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

macro_rules! get_agent {
    ($mgr:expr, $id:expr) => {
        match $mgr.get_agent(&$id).await {
            Some(state) => state,
            None => return (StatusCode::NOT_FOUND, Json(ApiResponse {
                ok: false, error: Some(format!("Agent '{}' not found", $id)),
            })).into_response(),
        }
    };
}

#[derive(Serialize)]
struct IdentityResponse {
    npub: String,
    name: String,
    relays: Vec<String>,
}

async fn agent_identity(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    Json(IdentityResponse {
        npub: state.npub(),
        name: state.name.clone(),
        relays: state.relay_urls.clone(),
    }).into_response()
}

#[derive(Serialize)]
struct PeerInfo {
    npub: String,
    name: String,
    signal_id: String,
}

async fn agent_peers(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    let peers = state.peers.read().await;
    let list: Vec<PeerInfo> = peers.values().map(|p| PeerInfo {
        npub: p.nostr_pubkey.clone(),
        name: p.name.clone(),
        signal_id: p.signal_id.clone(),
    }).collect();
    Json(list).into_response()
}

#[derive(Deserialize)]
struct SendRequest {
    to: String,
    message: String,
}

async fn agent_send(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
    Json(req): Json<SendRequest>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    match chat::send_text_to(&state, &req.to, &req.message).await {
        Ok(()) => (StatusCode::OK, Json(ApiResponse { ok: true, error: None })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiResponse {
            ok: false, error: Some(e.to_string()),
        })).into_response(),
    }
}

#[derive(Deserialize)]
struct FriendRequest {
    npub: String,
}

async fn agent_add_friend(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
    Json(req): Json<FriendRequest>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    match chat::add_friend(&state, &req.npub).await {
        Ok(()) => (StatusCode::OK, Json(ApiResponse { ok: true, error: None })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiResponse {
            ok: false, error: Some(e.to_string()),
        })).into_response(),
    }
}

async fn agent_approve_friend(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
    Json(req): Json<FriendRequest>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    let (tx, _) = tokio::sync::broadcast::channel(1);
    match chat::approve_friend(&state, &req.npub, &tx).await {
        Ok(()) => (StatusCode::OK, Json(ApiResponse { ok: true, error: None })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiResponse {
            ok: false, error: Some(e.to_string()),
        })).into_response(),
    }
}

async fn agent_reject_friend(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
    Json(req): Json<FriendRequest>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    match chat::reject_friend(&state, &req.npub).await {
        Ok(()) => (StatusCode::OK, Json(ApiResponse { ok: true, error: None })).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(ApiResponse {
            ok: false, error: Some(e.to_string()),
        })).into_response(),
    }
}

#[derive(Serialize)]
struct PendingFriendInfo {
    npub: String,
    name: String,
}

async fn agent_pending_friends(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    let pending = chat::list_pending_friends(&state).await;
    Json(pending.into_iter().map(|p| PendingFriendInfo {
        npub: p.sender_npub,
        name: p.sender_name,
    }).collect::<Vec<_>>()).into_response()
}

#[derive(Serialize)]
struct OwnerResponse {
    owner: Option<String>,
}

async fn agent_owner(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    let owner = state.owner.read().await.clone();
    Json(OwnerResponse { owner }).into_response()
}

#[derive(Deserialize)]
struct BackupRequest {
    owner_npub: String,
}

#[derive(Serialize)]
struct BackupResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn agent_backup_mnemonic(
    State(mgr): State<Arc<MultiAgentManager>>,
    Path(id): Path<String>,
    Json(req): Json<BackupRequest>,
) -> impl IntoResponse {
    let state = get_agent!(mgr, id);
    let owner = state.owner.read().await;
    match owner.as_deref() {
        Some(o) if o == req.owner_npub => {
            let npub = state.npub();
            match crate::config::load_mnemonic(&npub) {
                Ok(m) => (StatusCode::OK, Json(BackupResponse {
                    mnemonic: Some(m), error: None,
                })).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(BackupResponse {
                    mnemonic: None, error: Some(e.to_string()),
                })).into_response(),
            }
        }
        _ => (StatusCode::FORBIDDEN, Json(BackupResponse {
            mnemonic: None, error: Some("Only the owner can backup the mnemonic".to_string()),
        })).into_response(),
    }
}

// ─── Health ─────────────────────────────────────────────────────────────────

async fn health_handler() -> &'static str {
    "ok"
}
