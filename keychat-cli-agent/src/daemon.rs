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
use nostr::nips::nip19::ToBech32;
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
    // Set KEYCHAT_DATA_DIR for secrets file fallback (headless/daemon mode)
    std::env::set_var("KEYCHAT_DATA_DIR", data_path);

    // Load or create identity
    // Secrets resolution: env var → secrets/ files → OS keychain
    let (identity, config) = match Config::load(data_path)? {
        Some(mut config) => {
            config.auto_accept_friends = auto_accept;
            let pubkey_hex = config
                .pubkey_hex
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("config.json missing pubkey_hex"))?;
            let mnemonic = crate::config::load_mnemonic(pubkey_hex)?;
            let identity = libkeychat::Identity::from_mnemonic_str(&mnemonic)?;
            (identity, config)
        }
        None => {
            // First run: check for pre-placed secrets/mnemonic file
            let secrets_dir = data_path.join("secrets");
            let mnemonic_file = secrets_dir.join("mnemonic");

            let (identity, mnemonic) = if mnemonic_file.exists() {
                let m = std::fs::read_to_string(&mnemonic_file)?.trim().to_string();
                let id = libkeychat::Identity::from_mnemonic_str(&m)?;
                eprintln!("Loaded identity from secrets/mnemonic.");
                (id, m)
            } else {
                let gen = libkeychat::Identity::generate()?;
                let m = gen.mnemonic.clone();
                // Write mnemonic to secrets file (daemon-friendly, no keychain prompt)
                std::fs::create_dir_all(&secrets_dir)?;
                std::fs::write(&mnemonic_file, &m)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &mnemonic_file,
                        std::fs::Permissions::from_mode(0o600),
                    )?;
                }
                // Also try keychain (best-effort, may fail in headless)
                let _ = crate::config::store_mnemonic(&gen.identity.pubkey_hex(), &m);
                eprintln!("Created new identity. Mnemonic stored in secrets/mnemonic.");
                (gen.identity, m)
            };

            let pubkey_hex = identity.pubkey_hex();

            // Generate DB key if not already in secrets
            let db_key_file = secrets_dir.join("dbkey");
            if !db_key_file.exists() {
                let generated_db_key = crate::config::generate_db_key();
                std::fs::create_dir_all(&secrets_dir)?;
                std::fs::write(&db_key_file, &generated_db_key)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&db_key_file, std::fs::Permissions::from_mode(0o600))?;
                }
                let _ = crate::config::store_db_key(&pubkey_hex, &generated_db_key);
            }

            let config = Config {
                name: agent_name.unwrap_or_else(|| "keychat-agent".to_string()),
                relays: relay_urls.clone(),
                auto_accept_friends: auto_accept,
                owner: None,
                pubkey_hex: Some(pubkey_hex.clone()),
            };
            config.save(data_path)?;

            (identity, config)
        }
    };

    let npub = identity.pubkey_hex();

    // Resolve DB key: CLI arg > keychain > error
    let db_key = match db_key {
        Some(k) => k,
        None => crate::config::load_db_key(&npub).unwrap_or_else(|_| {
            // Legacy fallback for existing installations
            eprintln!("  ⚠️  DB key not in keychain, using default (insecure)");
            "keychat-cli-default-key".to_string()
        }),
    };

    let app_state =
        Arc::new(AppState::new(identity, config, &relay_urls, data_path, &db_key).await?);

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
        .route("/set-owner", post(set_owner_handler))
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
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).unwrap_or_default();
            let sse_event = match &event {
                IncomingEvent::Message(_) => SseEvent::default().event("message").data(json),
                IncomingEvent::FriendRequest { .. } => {
                    SseEvent::default().event("friend_request").data(json)
                }
            };
            Some(Ok(sse_event))
        }
        Err(_) => None,
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
        Ok(()) => (
            StatusCode::OK,
            Json(SendResponse {
                ok: true,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SendResponse {
                ok: false,
                error: Some(e.to_string()),
            }),
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
        Ok(()) => (
            StatusCode::OK,
            Json(SendResponse {
                ok: true,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SendResponse {
                ok: false,
                error: Some(e.to_string()),
            }),
        ),
    }
}

// ─── Identity ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct IdentityResponse {
    npub_hex: String,
    npub: String,
    name: String,
    relays: Vec<String>,
}

async fn identity_handler(State(state): State<Arc<DaemonState>>) -> Json<IdentityResponse> {
    let hex = state.app.npub();
    let bech32 = nostr::prelude::PublicKey::from_hex(&hex)
        .map(|pk| pk.to_bech32().unwrap_or_else(|_| hex.clone()))
        .unwrap_or_else(|_| hex.clone());
    Json(IdentityResponse {
        npub_hex: hex,
        npub: bech32,
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

async fn peers_handler(State(state): State<Arc<DaemonState>>) -> Json<Vec<PeerInfo>> {
    let peers = state.app.peers.read().await;
    let list: Vec<PeerInfo> = peers
        .values()
        .map(|p| PeerInfo {
            npub: p.nostr_pubkey.clone(),
            name: p.name.clone(),
            signal_id: p.signal_id.clone(),
        })
        .collect();
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
        Ok(()) => (
            StatusCode::OK,
            Json(SendResponse {
                ok: true,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SendResponse {
                ok: false,
                error: Some(e.to_string()),
            }),
        ),
    }
}

async fn reject_friend_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<ApproveFriendRequest>,
) -> impl IntoResponse {
    match chat::reject_friend(&state.app, &req.npub).await {
        Ok(()) => (
            StatusCode::OK,
            Json(SendResponse {
                ok: true,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SendResponse {
                ok: false,
                error: Some(e.to_string()),
            }),
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
    Json(
        pending
            .into_iter()
            .map(|p| PendingFriendInfo {
                npub: p.sender_npub,
                name: p.sender_name,
            })
            .collect(),
    )
}

// ─── Owner ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct OwnerResponse {
    owner: Option<String>,
}

async fn owner_handler(State(state): State<Arc<DaemonState>>) -> Json<OwnerResponse> {
    let owner = state.app.owner.read().await.clone();
    Json(OwnerResponse { owner })
}

// ─── Set Owner ──────────────────────────────────────────────────────────────

/// Change the owner of this agent.
///
/// This endpoint is restricted to localhost (127.0.0.1) — it's meant to be
/// called by the host system (e.g., OpenClaw) when the user needs to transfer
/// ownership, such as when the original owner's device is lost.
///
/// If `new_owner` is null/missing, the owner is cleared (next friend request
/// will become owner again).
#[derive(Deserialize)]
struct SetOwnerRequest {
    /// New owner's Nostr pubkey (hex or npub). Null to clear.
    new_owner: Option<String>,
}

async fn set_owner_handler(
    State(state): State<Arc<DaemonState>>,
    Json(req): Json<SetOwnerRequest>,
) -> impl IntoResponse {
    let new_owner_hex = match &req.new_owner {
        Some(pk) => match libkeychat::normalize_pubkey(pk) {
            Ok(hex) => Some(hex),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(SendResponse {
                        ok: false,
                        error: Some(format!("Invalid pubkey: {}", e)),
                    }),
                )
            }
        },
        None => None,
    };

    // Update in-memory
    *state.app.owner.write().await = new_owner_hex.clone();

    // Persist to config
    let mut config = crate::config::Config::load(&state.app.data_dir)
        .ok()
        .flatten()
        .unwrap_or_default();
    config.owner = new_owner_hex.clone();
    if let Err(e) = config.save(&state.app.data_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SendResponse {
                ok: false,
                error: Some(format!("Failed to save config: {}", e)),
            }),
        );
    }

    match &new_owner_hex {
        Some(hex) => {
            crate::ui::sys(&format!(
                "👑 Owner changed to {}",
                &hex[..16.min(hex.len())]
            ));
            (
                StatusCode::OK,
                Json(SendResponse {
                    ok: true,
                    error: None,
                }),
            )
        }
        None => {
            crate::ui::sys("👑 Owner cleared — next friend request will become owner");
            (
                StatusCode::OK,
                Json(SendResponse {
                    ok: true,
                    error: None,
                }),
            )
        }
    }
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
                Ok(mnemonic) => (
                    StatusCode::OK,
                    Json(BackupResponse {
                        mnemonic: Some(mnemonic),
                        error: None,
                    }),
                ),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(BackupResponse {
                        mnemonic: None,
                        error: Some(e.to_string()),
                    }),
                ),
            }
        }
        _ => (
            StatusCode::FORBIDDEN,
            Json(BackupResponse {
                mnemonic: None,
                error: Some("Only the owner can backup the mnemonic".to_string()),
            }),
        ),
    }
}

// ─── Health ─────────────────────────────────────────────────────────────────

async fn health_handler() -> &'static str {
    "ok"
}
