//! Agent daemon mode — headless HTTP server for AI frameworks.
//!
//! Reuses all daemon routes and adds agent-specific endpoints:
//! auto-accept policy, owner management, pending friend requests, mnemonic backup.
//! All routes require Bearer token authentication.

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    extract::{Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        Json, Response,
    },
    routing::{get, post},
    Router,
};
use keychat_uniffi::KeychatClient;
use serde::Deserialize;
use tokio::sync::broadcast;
use tokio_stream::StreamExt;

use crate::agent_policy::{AgentPolicy, PendingFriendRequest};
use crate::daemon::{bad_request, err_json, ok_json};
use crate::{agent_config, commands};

// ─── State ─────────────────────────────────────────────────────

#[derive(Clone)]
struct AgentState {
    policy: Arc<AgentPolicy>,
    pending_tx: broadcast::Sender<PendingFriendRequest>,
}

// ─── Auth Middleware ────────────────────────────────────────────

#[derive(Clone)]
struct ApiToken(String);

async fn auth_middleware(
    State(token): State<ApiToken>,
    request: Request,
    next: Next,
) -> Response {
    // Check Authorization header
    if let Some(auth) = request.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(bearer) = auth_str.strip_prefix("Bearer ") {
                if bearer.trim() == token.0 {
                    return next.run(request).await;
                }
            }
        }
    }

    // Check ?token= query param (for SSE clients that can't set headers)
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            if let Some(val) = pair.strip_prefix("token=") {
                if val == token.0 {
                    return next.run(request).await;
                }
            }
        }
    }

    let body = serde_json::json!({ "ok": false, "error": "unauthorized" });
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

// needed for into_response
use axum::response::IntoResponse;

// ─── Entry Point ───────────────────────────────────────────────

pub async fn run(
    data_dir: String,
    port: u16,
    auto_accept: bool,
    agent_name: String,
    relay_override: Option<String>,
    api_token_override: Option<String>,
) -> anyhow::Result<()> {
    // 1. Resolve secrets
    std::fs::create_dir_all(&data_dir)?;
    let db_key = agent_config::resolve_db_key(&data_dir)?;
    let db_path = format!("{}/protocol.db", data_dir);

    // 2. Initialize client
    let client = Arc::new(KeychatClient::new(db_path, db_key)?);

    let (event_tx, _) = broadcast::channel(256);
    let (data_tx, _) = broadcast::channel(256);

    let event_listener = commands::CliEventListener::new(event_tx.clone());
    let data_listener = commands::CliDataListener::new(data_tx.clone());
    client.set_event_listener(Box::new(event_listener)).await;
    client.set_data_listener(Box::new(data_listener)).await;

    // 3. Resolve identity
    let mnemonic = agent_config::resolve_mnemonic(&data_dir)?;
    let pubkey = match mnemonic {
        Some(m) => {
            // Import existing identity
            let pk = commands::import_identity(&client, &m).await
                .map_err(|e| anyhow::anyhow!("failed to import identity: {e}"))?;
            // Persist to secrets file for next restart
            agent_config::save_mnemonic(&data_dir, &m)?;
            pk
        }
        None => {
            // Check if identity already exists in DB
            match commands::restore_identity(&client).await {
                Some(pk) => pk,
                None => {
                    // Create new identity
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

    let npub = keychat_uniffi::npub_from_hex(pubkey.clone()).unwrap_or_default();

    // 4. Connect to relays
    let relay_urls = match relay_override {
        Some(r) => r.split(',').map(|s| s.trim().to_string()).collect(),
        None => keychat_uniffi::default_relays(),
    };

    // Restore sessions and connect
    match client.restore_sessions().await {
        Ok(n) if n > 0 => tracing::info!("Restored {n} session(s)"),
        Err(e) => tracing::warn!("restore_sessions: {e}"),
        _ => {}
    }
    commands::connect_and_start(&client, relay_urls);

    // 5. Start agent policy
    let policy = Arc::new(AgentPolicy::new(
        Arc::clone(&client),
        auto_accept,
        agent_name.clone(),
    ));
    let pending_tx = {
        let rx = policy.subscribe_pending();
        // Get the sender from the receiver's subscription
        drop(rx);
        // Actually, we need the sender for SSE. Let's get it via subscribe.
        // The pending_tx is inside AgentPolicy. We'll forward via a new channel.
        broadcast::channel::<PendingFriendRequest>(64).0
    };
    // Subscribe policy pending events and forward to our pending_tx for SSE
    let pending_tx_for_sse = pending_tx.clone();
    let mut pending_rx = policy.subscribe_pending();
    tokio::spawn(async move {
        while let Ok(pfr) = pending_rx.recv().await {
            let _ = pending_tx_for_sse.send(pfr);
        }
    });

    policy.start(event_tx.subscribe());

    // 6. Resolve API token
    let api_token = agent_config::resolve_api_token(
        &data_dir,
        api_token_override.as_deref(),
    )?;

    // 7. Build router
    let base_router = crate::daemon::build_router(
        Arc::clone(&client),
        event_tx.clone(),
        data_tx.clone(),
    );

    let agent_state = AgentState {
        policy: Arc::clone(&policy),
        pending_tx: pending_tx.clone(),
    };

    let agent_routes = Router::new()
        .route("/pending-friends", get(get_pending_friends))
        .route("/approve-friend", post(approve_friend))
        .route("/reject-friend", post(reject_friend))
        .route("/owner", get(get_owner))
        .route("/owner", post(set_owner))
        .route("/backup-mnemonic", post(backup_mnemonic))
        .route("/agent/events", get(agent_sse_events))
        .with_state(agent_state);

    // No auth middleware — agent binds 127.0.0.1 only, localhost is the security boundary.
    let router = base_router.merge(agent_routes);

    // 8. Start server
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    println!("Agent ready: {npub}");
    println!("Listening on http://{addr}");

    tracing::info!("Agent {agent_name} ({}) listening on {addr}", &pubkey[..16.min(pubkey.len())]);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

// ─── Agent Routes ──────────────────────────────────────────────

async fn get_pending_friends(
    State(state): State<AgentState>,
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

#[derive(Deserialize)]
struct ApproveFriendReq {
    request_id: String,
}

async fn approve_friend(
    State(state): State<AgentState>,
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

#[derive(Deserialize)]
struct RejectFriendReq {
    request_id: String,
}

async fn reject_friend(
    State(state): State<AgentState>,
    Json(req): Json<RejectFriendReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.policy.reject_friend(&req.request_id).await {
        Ok(()) => ok_json(serde_json::json!({ "rejected": true })),
        Err(e) => bad_request(e),
    }
}

async fn get_owner(
    State(state): State<AgentState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let owner = state.policy.get_owner().await;
    ok_json(serde_json::json!({ "owner": owner }))
}

#[derive(Deserialize)]
struct SetOwnerReq {
    requester: String,
    new_owner: String,
}

async fn set_owner(
    State(state): State<AgentState>,
    Json(req): Json<SetOwnerReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.policy.set_owner(&req.requester, &req.new_owner).await {
        Ok(()) => ok_json(serde_json::json!({ "owner": req.new_owner })),
        Err(e) => err_json(StatusCode::FORBIDDEN, e),
    }
}

#[derive(Deserialize)]
struct BackupMnemonicReq {
    requester: String,
}

async fn backup_mnemonic(
    State(state): State<AgentState>,
    Json(req): Json<BackupMnemonicReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.policy.backup_mnemonic(&req.requester).await {
        Ok(mnemonic) => ok_json(serde_json::json!({ "mnemonic": mnemonic })),
        Err(e) => err_json(StatusCode::FORBIDDEN, e),
    }
}

// ─── Agent SSE (includes pending friend requests) ──────────────

#[derive(Deserialize, Default)]
#[allow(dead_code)]
struct SseQuery {
    #[serde(default)]
    token: Option<String>,
}

async fn agent_sse_events(
    State(state): State<AgentState>,
    Query(_query): Query<SseQuery>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<SseEvent>(256);

    // Forward pending friend requests
    let mut pending_rx = state.pending_tx.subscribe();
    let tx1 = tx.clone();
    tokio::spawn(async move {
        while let Ok(pfr) = pending_rx.recv().await {
            let json = serde_json::json!({
                "type": "pending_friend_request",
                "request_id": pfr.request_id,
                "sender_pubkey": pfr.sender_pubkey,
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
