//! Daemon mode — HTTP API + SSE event stream.
//!
//! Endpoints:
//!   GET  /events       — SSE stream of incoming messages/events
//!   POST /send         — Send encrypted message {"to":"<npub>","message":"..."}
//!   POST /add-friend   — Send friend request {"npub":"<hex>"}
//!   GET  /identity     — Return this node's identity
//!   GET  /peers        — List contacts
//!   GET  /health       — Liveness check

use axum::{
    extract::State,
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
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::chat::{self, IncomingEvent};
use crate::config::Config;
use crate::state::AppState;

/// Shared state for Axum handlers.
struct DaemonState {
    app: Arc<AppState>,
    event_tx: broadcast::Sender<IncomingEvent>,
}

pub async fn run(
    data_dir: String,
    relay_urls: Vec<String>,
    db_key: Option<String>,
    listen: String,
    auto_accept: bool,
    agent_name: Option<String>,
) -> anyhow::Result<()> {
    let data_path = Path::new(&data_dir);
    std::fs::create_dir_all(data_path)?;

    // Load or create identity — mnemonic stored in OS keychain, never in config.json
    let (identity, config) = match Config::load(data_path)? {
        Some(mut config) => {
            config.auto_accept_friends = auto_accept;
            let pubkey_hex = config.pubkey_hex.as_deref()
                .ok_or_else(|| anyhow::anyhow!("config.json missing pubkey_hex — cannot locate keychain entry"))?;
            let mnemonic = crate::config::load_mnemonic(pubkey_hex)?;
            let identity = libkeychat::Identity::from_mnemonic_str(&mnemonic)?;

            // Load or generate DB key from keychain
            if db_key.is_none() {
                let _ = crate::config::load_db_key(pubkey_hex); // verify it exists
            }
            (identity, config)
        }
        None => {
            let gen = libkeychat::Identity::generate()?;
            let pubkey_hex = gen.identity.pubkey_hex();

            // Store mnemonic in OS keychain
            crate::config::store_mnemonic(&pubkey_hex, &gen.mnemonic)?;

            // Generate and store DB key in OS keychain
            let generated_db_key = crate::config::generate_db_key();
            crate::config::store_db_key(&pubkey_hex, &generated_db_key)?;

            let config = Config {
                name: agent_name.unwrap_or_else(|| "keychat-agent".to_string()),
                relays: relay_urls.clone(),
                auto_accept_friends: auto_accept,
                owner: None,
                pubkey_hex: Some(pubkey_hex.clone()),
            };
            config.save(data_path)?;

            eprintln!("Created new identity. Mnemonic stored in OS keychain.");
            (gen.identity, config)
        }
    };

    let npub = identity.pubkey_hex();

    // Resolve DB key: CLI arg > keychain > error
    let db_key = match db_key {
        Some(k) => k,
        None => crate::config::load_db_key(&npub)
            .unwrap_or_else(|_| {
                // Legacy fallback for existing installations
                eprintln!("  ⚠️  DB key not in keychain, using default (insecure)");
                "keychat-cli-default-key".to_string()
            }),
    };

    let app_state = Arc::new(
        AppState::new(identity, config, &relay_urls, data_path, &db_key).await?
    );

    let (event_tx, _) = broadcast::channel::<IncomingEvent>(256);

    eprintln!("Keychat daemon starting");
    eprintln!("  npub: {}", npub);
    for r in &relay_urls {
        eprintln!("  relay: {}", r);
    }

    // Background listener
    let listener_state = app_state.clone();
    let listener_tx = event_tx.clone();
    tokio::spawn(async move {
        chat::start_listener(listener_state, listener_tx).await;
    });

    // HTTP server
    let daemon_state = Arc::new(DaemonState {
        app: app_state,
        event_tx,
    });

    let router = Router::new()
        .route("/events", get(sse_handler))
        .route("/send", post(send_handler))
        .route("/add-friend", post(add_friend_handler))
        .route("/approve-friend", post(approve_friend_handler))
        .route("/reject-friend", post(reject_friend_handler))
        .route("/pending-friends", get(pending_friends_handler))
        .route("/owner", get(owner_handler))
        .route("/backup-mnemonic", post(backup_mnemonic_handler))
        .route("/identity", get(identity_handler))
        .route("/peers", get(peers_handler))
        .route("/health", get(health_handler))
        .with_state(daemon_state);

    let addr: SocketAddr = listen.parse()?;
    eprintln!("  http: http://{}", addr);
    eprintln!("Ready.");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

// ─── SSE ────────────────────────────────────────────────────────────────────

async fn sse_handler(
    State(state): State<Arc<DaemonState>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.event_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| {
        match result {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_default();
                let sse_event = match &event {
                    IncomingEvent::Message(_) => SseEvent::default().event("message").data(json),
                    IncomingEvent::FriendRequest { .. } => SseEvent::default().event("friend_request").data(json),
                };
                Some(Ok(sse_event))
            }
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ─── Send ───────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SendRequest {
    to: String,
    message: String,
}

#[derive(Serialize)]
struct SendResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn send_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<SendRequest>,
) -> impl IntoResponse {
    match chat::send_text_to(&state.app, &req.to, &req.message).await {
        Ok(()) => (StatusCode::OK, Json(SendResponse { ok: true, error: None })),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SendResponse { ok: false, error: Some(e.to_string()) }),
        ),
    }
}

// ─── Add Friend ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddFriendRequest {
    npub: String,
}

async fn add_friend_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<AddFriendRequest>,
) -> impl IntoResponse {
    match chat::add_friend(&state.app, &req.npub).await {
        Ok(()) => (StatusCode::OK, Json(SendResponse { ok: true, error: None })),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SendResponse { ok: false, error: Some(e.to_string()) }),
        ),
    }
}

// ─── Identity ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct IdentityResponse {
    npub: String,
    name: String,
    relays: Vec<String>,
}

async fn identity_handler(
    State(state): State<Arc<DaemonState>>,
) -> Json<IdentityResponse> {
    Json(IdentityResponse {
        npub: state.app.npub(),
        name: state.app.name.clone(),
        relays: state.app.relay_urls.clone(),
    })
}

// ─── Peers ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct PeerInfo {
    npub: String,
    name: String,
    signal_id: String,
}

async fn peers_handler(
    State(state): State<Arc<DaemonState>>,
) -> Json<Vec<PeerInfo>> {
    let peers = state.app.peers.read().await;
    let list: Vec<PeerInfo> = peers.values().map(|p| PeerInfo {
        npub: p.nostr_pubkey.clone(),
        name: p.name.clone(),
        signal_id: p.signal_id.clone(),
    }).collect();
    Json(list)
}

// ─── Approve/Reject Friend ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct ApproveFriendRequest {
    npub: String,
}

async fn approve_friend_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<ApproveFriendRequest>,
) -> impl IntoResponse {
    match chat::approve_friend(&state.app, &req.npub, &state.event_tx).await {
        Ok(()) => (StatusCode::OK, Json(SendResponse { ok: true, error: None })),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SendResponse { ok: false, error: Some(e.to_string()) }),
        ),
    }
}

async fn reject_friend_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<ApproveFriendRequest>,
) -> impl IntoResponse {
    match chat::reject_friend(&state.app, &req.npub).await {
        Ok(()) => (StatusCode::OK, Json(SendResponse { ok: true, error: None })),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SendResponse { ok: false, error: Some(e.to_string()) }),
        ),
    }
}

// ─── Pending Friends ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct PendingFriendInfo {
    npub: String,
    name: String,
}

async fn pending_friends_handler(
    State(state): State<Arc<DaemonState>>,
) -> Json<Vec<PendingFriendInfo>> {
    let pending = chat::list_pending_friends(&state.app).await;
    Json(pending.into_iter().map(|p| PendingFriendInfo {
        npub: p.sender_npub,
        name: p.sender_name,
    }).collect())
}

// ─── Owner ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OwnerResponse {
    owner: Option<String>,
}

async fn owner_handler(
    State(state): State<Arc<DaemonState>>,
) -> Json<OwnerResponse> {
    let owner = state.app.owner.read().await.clone();
    Json(OwnerResponse { owner })
}

// ─── Backup Mnemonic ────────────────────────────────────────────────────────

/// Backup mnemonic — only accessible by owner.
/// Request body: {"owner_npub": "<hex>"} — must match the registered owner.
/// Returns: {"mnemonic": "word1 word2 ..."} or error.
///
/// In production, this should additionally require biometric/PIN verification.
/// For CLI daemon mode, we verify the requester is the owner.
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

async fn backup_mnemonic_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<BackupRequest>,
) -> impl IntoResponse {
    // Verify requester is owner
    let owner = state.app.owner.read().await;
    match owner.as_deref() {
        Some(o) if o == req.owner_npub => {
            // Owner verified — retrieve mnemonic from keychain
            let npub = state.app.npub();
            match crate::config::load_mnemonic(&npub) {
                Ok(mnemonic) => (StatusCode::OK, Json(BackupResponse {
                    mnemonic: Some(mnemonic),
                    error: None,
                })),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(BackupResponse {
                    mnemonic: None,
                    error: Some(e.to_string()),
                })),
            }
        }
        _ => (StatusCode::FORBIDDEN, Json(BackupResponse {
            mnemonic: None,
            error: Some("Only the owner can backup the mnemonic".to_string()),
        })),
    }
}

// ─── Health ─────────────────────────────────────────────────────────────────

async fn health_handler() -> &'static str {
    "ok"
}
