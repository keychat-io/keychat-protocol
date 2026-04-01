//! HTTP daemon mode for keychat-cli.
//!
//! Provides a REST API + SSE event stream backed by `KeychatClient`.

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
use keychat_uniffi::{
    ClientEvent, ConnectionStatus, DataChange, GroupChangeKind, GroupMemberInput, KeychatClient,
    MessageKind, MessageStatus, RoomStatus, RoomType,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;

// ─── Shared State ───────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    client: Arc<KeychatClient>,
    event_tx: broadcast::Sender<ClientEvent>,
    data_tx: broadcast::Sender<DataChange>,
}

// ─── JSON Envelope ──────────────────────────────────────────────

pub(crate) fn ok_json<T: Serialize>(data: T) -> (StatusCode, Json<serde_json::Value>) {
    let body = serde_json::json!({ "ok": true, "data": data });
    (StatusCode::OK, Json(body))
}

pub(crate) fn err_json(status: StatusCode, msg: impl ToString) -> (StatusCode, Json<serde_json::Value>) {
    let body = serde_json::json!({ "ok": false, "error": msg.to_string() });
    (status, Json(body))
}

fn internal_err(msg: impl ToString) -> (StatusCode, Json<serde_json::Value>) {
    err_json(StatusCode::INTERNAL_SERVER_ERROR, msg)
}

pub(crate) fn bad_request(msg: impl ToString) -> (StatusCode, Json<serde_json::Value>) {
    err_json(StatusCode::BAD_REQUEST, msg)
}

// ─── Enum String Helpers ────────────────────────────────────────

fn room_status_str(s: &RoomStatus) -> &'static str {
    match s {
        RoomStatus::Requesting => "requesting",
        RoomStatus::Enabled => "enabled",
        RoomStatus::Approving => "approving",
        RoomStatus::Rejected => "rejected",
    }
}

fn room_type_str(t: &RoomType) -> &'static str {
    match t {
        RoomType::Dm => "dm",
        RoomType::SignalGroup => "signal_group",
        RoomType::MlsGroup => "mls_group",
    }
}

fn message_status_str(s: &MessageStatus) -> &'static str {
    match s {
        MessageStatus::Sending => "sending",
        MessageStatus::Success => "success",
        MessageStatus::Failed => "failed",
    }
}

fn message_kind_str(k: &MessageKind) -> &'static str {
    match k {
        MessageKind::Text => "text",
        MessageKind::Files => "files",
        MessageKind::Cashu => "cashu",
        MessageKind::LightningInvoice => "lightning_invoice",
        MessageKind::FriendRequest => "friend_request",
        MessageKind::FriendApprove => "friend_approve",
        MessageKind::FriendReject => "friend_reject",
        MessageKind::ProfileSync => "profile_sync",
        MessageKind::RelaySyncInvite => "relay_sync_invite",
        MessageKind::SignalGroupInvite => "signal_group_invite",
        MessageKind::SignalGroupMemberRemoved => "signal_group_member_removed",
        MessageKind::SignalGroupSelfLeave => "signal_group_self_leave",
        MessageKind::SignalGroupDissolve => "signal_group_dissolve",
        MessageKind::SignalGroupNameChanged => "signal_group_name_changed",
        MessageKind::SignalGroupNicknameChanged => "signal_group_nickname_changed",
        MessageKind::MlsGroupInvite => "mls_group_invite",
        MessageKind::AgentActions => "agent_actions",
        MessageKind::AgentOptions => "agent_options",
        MessageKind::AgentConfirm => "agent_confirm",
        MessageKind::AgentReply => "agent_reply",
        MessageKind::TaskRequest => "task_request",
        MessageKind::TaskResponse => "task_response",
        MessageKind::SkillQuery => "skill_query",
        MessageKind::SkillDeclare => "skill_declare",
        MessageKind::EventNotify => "event_notify",
        MessageKind::StreamChunk => "stream_chunk",
        MessageKind::Location => "location",
        MessageKind::Contact => "contact",
        MessageKind::Sticker => "sticker",
        MessageKind::Reaction => "reaction",
        MessageKind::MessageDelete => "message_delete",
        MessageKind::MessageEdit => "message_edit",
        MessageKind::ReadReceipt => "read_receipt",
        MessageKind::Typing => "typing",
        MessageKind::Poll => "poll",
        MessageKind::PollVote => "poll_vote",
        MessageKind::CallSignal => "call_signal",
        MessageKind::GroupPinMessage => "group_pin_message",
        MessageKind::GroupAnnouncement => "group_announcement",
    }
}

fn group_change_kind_str(k: &GroupChangeKind) -> &'static str {
    match k {
        GroupChangeKind::MemberRemoved => "member_removed",
        GroupChangeKind::SelfLeave => "self_leave",
        GroupChangeKind::NameChanged => "name_changed",
    }
}

// ─── Router Builder ─────────────────────────────────────────────

/// Build the axum Router with all routes. Extracted so tests can call it
/// without starting a TCP listener.
pub fn build_router(
    client: Arc<KeychatClient>,
    event_tx: broadcast::Sender<ClientEvent>,
    data_tx: broadcast::Sender<DataChange>,
) -> Router {
    let state = AppState {
        client,
        event_tx,
        data_tx,
    };

    Router::new()
        // Identity
        .route("/identity", get(get_identity))
        .route("/identity/create", post(create_identity))
        .route("/identity/import", post(import_identity))
        // Connection
        .route("/connect", post(connect_relays))
        .route("/disconnect", post(disconnect_relays))
        .route("/relays", get(get_relays))
        .route("/status", get(get_status))
        // Friends
        .route("/friend-request", post(send_friend_request))
        .route("/friend-request/accept", post(accept_friend_request))
        .route("/friend-request/reject", post(reject_friend_request))
        // Messaging
        .route("/send", post(send_message))
        .route("/rooms", get(list_rooms))
        .route("/rooms/{room_id}/messages", get(get_messages))
        .route("/retry", post(retry_failed))
        // Groups
        .route("/group/create", post(create_group))
        .route("/group/{id}/send", post(send_group_message))
        .route("/group/{id}/leave", post(leave_group))
        .route("/group/{id}/dissolve", post(dissolve_group))
        .route("/group/{id}/rename", post(rename_group))
        .route("/group/{id}/kick", post(kick_member))
        // Events
        .route("/events", get(sse_events))
        // Contacts
        .route("/contacts", get(list_contacts))
        .with_state(state)
}

// ─── Entry Point ────────────────────────────────────────────────

pub async fn run(
    client: Arc<KeychatClient>,
    event_tx: broadcast::Sender<ClientEvent>,
    data_tx: broadcast::Sender<DataChange>,
    port: u16,
) -> anyhow::Result<()> {
    // Shared startup: restore identity → sessions → connect → event loop
    let relay_urls = keychat_uniffi::default_relays();
    crate::commands::init_and_connect(&client, relay_urls).await;

    let router = build_router(client, event_tx, data_tx);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("daemon listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Identity
// ═══════════════════════════════════════════════════════════════

async fn get_identity(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.get_pubkey_hex().await {
        Ok(pubkey) => {
            let identities = state.client.get_identities().await.unwrap_or_default();
            let current = identities.iter().find(|i| i.nostr_pubkey_hex == pubkey);
            ok_json(serde_json::json!({
                "pubkey_hex": pubkey,
                "name": current.map(|i| i.name.clone()).unwrap_or_default(),
                "npub": current.map(|i| i.npub.clone()).unwrap_or_default(),
            }))
        }
        Err(_) => err_json(StatusCode::NOT_FOUND, "no identity set"),
    }
}

async fn create_identity(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    match crate::commands::create_identity(&state.client, "CLI User").await {
        Ok((pubkey_hex, npub, mnemonic)) => {
            tracing::warn!("⚠️  Mnemonic returned in HTTP response — save it immediately, it will not be shown again");
            ok_json(serde_json::json!({
                "pubkey_hex": pubkey_hex,
                "npub": npub,
                "mnemonic": mnemonic,
                "warning": "Save this mnemonic immediately. It will not be shown again.",
            }))
        }
        Err(e) => internal_err(e),
    }
}

#[derive(Deserialize)]
struct ImportIdentityReq {
    mnemonic: String,
}

async fn import_identity(
    State(state): State<AppState>,
    Json(req): Json<ImportIdentityReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match crate::commands::import_identity(&state.client, &req.mnemonic).await {
        Ok(pubkey) => ok_json(serde_json::json!({ "pubkey_hex": pubkey })),
        Err(e) => bad_request(e),
    }
}

// ═══════════════════════════════════════════════════════════════
// Connection
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize, Default)]
struct ConnectReq {
    #[serde(default)]
    relays: Vec<String>,
}

async fn connect_relays(
    State(state): State<AppState>,
    Json(req): Json<ConnectReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.connect(req.relays).await {
        Ok(()) => {
            ok_json(serde_json::json!({ "connected": true }))
        }
        Err(e) => internal_err(e),
    }
}

async fn disconnect_relays(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.disconnect().await {
        Ok(()) => ok_json(serde_json::json!({ "disconnected": true })),
        Err(e) => internal_err(e),
    }
}

async fn get_relays(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.get_relay_statuses().await {
        Ok(statuses) => {
            let list: Vec<_> = statuses
                .into_iter()
                .map(|s| serde_json::json!({ "url": s.url, "status": s.status }))
                .collect();
            ok_json(list)
        }
        Err(e) => internal_err(e),
    }
}

async fn get_status(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let identity = state.client.get_pubkey_hex().await.ok();
    let relay_statuses = state.client.get_relay_statuses().await.unwrap_or_default();
    let connected_count = relay_statuses.iter().filter(|s| s.status == "connected").count();
    let connection_status = if identity.is_none() {
        "no_identity"
    } else if connected_count > 0 {
        "connected"
    } else if !relay_statuses.is_empty() {
        "disconnected"
    } else {
        "not_connected"
    };

    ok_json(serde_json::json!({
        "identity": identity,
        "connection": connection_status,
        "relays_connected": connected_count,
        "relays_total": relay_statuses.len(),
    }))
}

// ═══════════════════════════════════════════════════════════════
// Friends
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct FriendRequestReq {
    pubkey: String,
    name: String,
}

async fn send_friend_request(
    State(state): State<AppState>,
    Json(req): Json<FriendRequestReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Use a default device_id string for CLI mode
    match state
        .client
        .send_friend_request(req.pubkey, req.name, "cli-device".to_string())
        .await
    {
        Ok(result) => ok_json(serde_json::json!({
            "request_id": result.request_id,
            "peer_nostr_pubkey": result.peer_nostr_pubkey,
        })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct AcceptFriendReq {
    request_id: String,
    name: String,
}

async fn accept_friend_request(
    State(state): State<AppState>,
    Json(req): Json<AcceptFriendReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state
        .client
        .accept_friend_request(req.request_id, req.name)
        .await
    {
        Ok(info) => ok_json(serde_json::json!({
            "nostr_pubkey_hex": info.nostr_pubkey_hex,
            "signal_id_hex": info.signal_id_hex,
            "display_name": info.display_name,
        })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct RejectFriendReq {
    request_id: String,
    #[serde(default)]
    message: Option<String>,
}

async fn reject_friend_request(
    State(state): State<AppState>,
    Json(req): Json<RejectFriendReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state
        .client
        .reject_friend_request(req.request_id, req.message)
        .await
    {
        Ok(()) => ok_json(serde_json::json!({ "rejected": true })),
        Err(e) => bad_request(e),
    }
}

// ═══════════════════════════════════════════════════════════════
// Messaging
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct SendMessageReq {
    room_id: String,
    text: String,
}

async fn send_message(
    State(state): State<AppState>,
    Json(req): Json<SendMessageReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match crate::commands::send_message(&state.client, &req.room_id, &req.text).await {
        Ok(crate::commands::SendResult::Dm { event_id, relay_count }) => {
            ok_json(serde_json::json!({
                "event_id": event_id,
                "relay_count": relay_count,
            }))
        }
        Ok(crate::commands::SendResult::Group { event_count }) => {
            ok_json(serde_json::json!({
                "type": "group",
                "event_count": event_count,
            }))
        }
        Ok(crate::commands::SendResult::MlsNotSupported) => {
            bad_request(keychat_uniffi::KeychatUniError::InvalidArgument {
                msg: "MLS groups not yet supported".into(),
            })
        }
        Err(e) => bad_request(e),
    }
}

async fn list_rooms(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = match state.client.get_pubkey_hex().await {
        Ok(pk) => pk,
        Err(e) => return bad_request(e),
    };

    match state.client.get_rooms(pubkey).await {
        Ok(rooms) => {
            let list: Vec<_> = rooms
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "to_main_pubkey": r.to_main_pubkey,
                        "status": room_status_str(&r.status),
                        "room_type": room_type_str(&r.room_type),
                        "last_message_content": r.last_message_content,
                        "last_message_at": r.last_message_at,
                        "unread_count": r.unread_count,
                        "created_at": r.created_at,
                    })
                })
                .collect();
            ok_json(list)
        }
        Err(e) => internal_err(e),
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

async fn get_messages(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Query(query): Query<MessageQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.get_messages(room_id, query.limit, query.offset).await {
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
                        "status": message_status_str(&m.status),
                        "reply_to_event_id": m.reply_to_event_id,
                        "created_at": m.created_at,
                    })
                })
                .collect();
            ok_json(list)
        }
        Err(e) => internal_err(e),
    }
}

async fn retry_failed(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.retry_failed_messages().await {
        Ok(count) => ok_json(serde_json::json!({ "retried": count })),
        Err(e) => internal_err(e),
    }
}

// ═══════════════════════════════════════════════════════════════
// Groups
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct CreateGroupReq {
    name: String,
    members: Vec<GroupMemberReq>,
}

#[derive(Deserialize)]
struct GroupMemberReq {
    pubkey: String,
    name: String,
}

async fn create_group(
    State(state): State<AppState>,
    Json(req): Json<CreateGroupReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let members: Vec<GroupMemberInput> = req
        .members
        .into_iter()
        .map(|m| GroupMemberInput {
            nostr_pubkey: m.pubkey,
            name: m.name,
        })
        .collect();

    match state.client.create_signal_group(req.name, members).await {
        Ok(info) => ok_json(serde_json::json!({
            "group_id": info.group_id,
            "name": info.name,
            "member_count": info.member_count,
        })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct GroupTextReq {
    text: String,
}

async fn send_group_message(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    Json(req): Json<GroupTextReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.send_group_text(group_id, req.text, None).await {
        Ok(sent) => ok_json(serde_json::json!({
            "group_id": sent.group_id,
            "event_ids": sent.event_ids,
        })),
        Err(e) => bad_request(e),
    }
}

async fn leave_group(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.leave_signal_group(group_id).await {
        Ok(()) => ok_json(serde_json::json!({ "left": true })),
        Err(e) => bad_request(e),
    }
}

async fn dissolve_group(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.dissolve_signal_group(group_id).await {
        Ok(()) => ok_json(serde_json::json!({ "dissolved": true })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct RenameGroupReq {
    name: String,
}

async fn rename_group(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    Json(req): Json<RenameGroupReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.rename_signal_group(group_id, req.name).await {
        Ok(()) => ok_json(serde_json::json!({ "renamed": true })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct KickMemberReq {
    pubkey: String,
}

async fn kick_member(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    Json(req): Json<KickMemberReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state
        .client
        .remove_group_member(group_id, req.pubkey)
        .await
    {
        Ok(()) => ok_json(serde_json::json!({ "kicked": true })),
        Err(e) => bad_request(e),
    }
}

// ═══════════════════════════════════════════════════════════════
// SSE Events
// ═══════════════════════════════════════════════════════════════

async fn sse_events(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    // Merge both broadcast channels into a single mpsc for the SSE stream
    let (tx, rx) = tokio::sync::mpsc::channel::<SseEvent>(256);

    // Forward ClientEvent
    let mut event_rx = state.event_tx.subscribe();
    let tx1 = tx.clone();
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let event_type = client_event_type(&event);
            let json = serialize_client_event(&event);
            let sse = SseEvent::default().event(event_type).data(json);
            if tx1.send(sse).await.is_err() {
                break;
            }
        }
    });

    // Forward DataChange
    let mut data_rx = state.data_tx.subscribe();
    tokio::spawn(async move {
        while let Ok(change) = data_rx.recv().await {
            let event_type = data_change_type(&change);
            let json = serialize_data_change(&change);
            let sse = SseEvent::default().event(event_type).data(json);
            if tx.send(sse).await.is_err() {
                break;
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(|e| Ok::<_, Infallible>(e));
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Public accessor for agent_daemon to reuse event type strings.
pub fn client_event_type_str(event: &ClientEvent) -> &'static str {
    client_event_type(event)
}

/// Public accessor for agent_daemon to reuse event serialization.
pub fn serialize_client_event_str(event: &ClientEvent) -> String {
    serialize_client_event(event)
}

fn client_event_type(event: &ClientEvent) -> &'static str {
    match event {
        ClientEvent::FriendRequestReceived { .. } => "friend_request_received",
        ClientEvent::FriendRequestAccepted { .. } => "friend_request_accepted",
        ClientEvent::FriendRequestRejected { .. } => "friend_request_rejected",
        ClientEvent::MessageReceived { .. } => "message_received",
        ClientEvent::GroupInviteReceived { .. } => "group_invite_received",
        ClientEvent::GroupMemberChanged { .. } => "group_member_changed",
        ClientEvent::GroupDissolved { .. } => "group_dissolved",
        ClientEvent::EventLoopError { .. } => "event_loop_error",
        ClientEvent::RelayOk { .. } => "relay_ok",
    }
}

fn serialize_client_event(event: &ClientEvent) -> String {
    match event {
        ClientEvent::FriendRequestReceived {
            request_id,
            sender_pubkey,
            sender_name,
            message,
            created_at,
        } => serde_json::json!({
            "type": "friend_request_received",
            "request_id": request_id,
            "sender_pubkey": sender_pubkey,
            "sender_name": sender_name,
            "message": message,
            "created_at": created_at,
        })
        .to_string(),
        ClientEvent::FriendRequestAccepted {
            peer_pubkey,
            peer_name,
        } => serde_json::json!({
            "type": "friend_request_accepted",
            "peer_pubkey": peer_pubkey,
            "peer_name": peer_name,
        })
        .to_string(),
        ClientEvent::FriendRequestRejected { peer_pubkey } => serde_json::json!({
            "type": "friend_request_rejected",
            "peer_pubkey": peer_pubkey,
        })
        .to_string(),
        ClientEvent::MessageReceived {
            room_id,
            sender_pubkey,
            kind,
            content,
            payload,
            event_id,
            fallback,
            reply_to_event_id,
            group_id,
            thread_id,
            nostr_event_json: _,
            relay_url,
        } => serde_json::json!({
            "type": "message_received",
            "room_id": room_id,
            "sender_pubkey": sender_pubkey,
            "kind": message_kind_str(kind),
            "content": content,
            "payload": payload,
            "event_id": event_id,
            "fallback": fallback,
            "reply_to_event_id": reply_to_event_id,
            "group_id": group_id,
            "thread_id": thread_id,
            "relay_url": relay_url,
        })
        .to_string(),
        ClientEvent::GroupInviteReceived {
            room_id,
            group_type,
            group_name,
            inviter_pubkey,
        } => serde_json::json!({
            "type": "group_invite_received",
            "room_id": room_id,
            "group_type": group_type,
            "group_name": group_name,
            "inviter_pubkey": inviter_pubkey,
        })
        .to_string(),
        ClientEvent::GroupMemberChanged {
            room_id,
            kind,
            member_pubkey,
            new_value,
        } => serde_json::json!({
            "type": "group_member_changed",
            "room_id": room_id,
            "kind": group_change_kind_str(kind),
            "member_pubkey": member_pubkey,
            "new_value": new_value,
        })
        .to_string(),
        ClientEvent::GroupDissolved { room_id } => serde_json::json!({
            "type": "group_dissolved",
            "room_id": room_id,
        })
        .to_string(),
        ClientEvent::EventLoopError { description } => serde_json::json!({
            "type": "event_loop_error",
            "description": description,
        })
        .to_string(),
        ClientEvent::RelayOk {
            event_id,
            relay_url,
            success,
            message,
        } => serde_json::json!({
            "type": "relay_ok",
            "event_id": event_id,
            "relay_url": relay_url,
            "success": success,
            "message": message,
        })
        .to_string(),
    }
}

fn data_change_type(change: &DataChange) -> &'static str {
    match change {
        DataChange::RoomUpdated { .. } => "room_updated",
        DataChange::RoomDeleted { .. } => "room_deleted",
        DataChange::RoomListChanged => "room_list_changed",
        DataChange::MessageAdded { .. } => "message_added",
        DataChange::MessageUpdated { .. } => "message_updated",
        DataChange::ContactUpdated { .. } => "contact_updated",
        DataChange::ContactListChanged => "contact_list_changed",
        DataChange::IdentityListChanged => "identity_list_changed",
        DataChange::ConnectionStatusChanged { .. } => "connection_status_changed",
    }
}

fn serialize_data_change(change: &DataChange) -> String {
    match change {
        DataChange::RoomUpdated { room_id } => serde_json::json!({
            "type": "room_updated",
            "room_id": room_id,
        })
        .to_string(),
        DataChange::RoomDeleted { room_id } => serde_json::json!({
            "type": "room_deleted",
            "room_id": room_id,
        })
        .to_string(),
        DataChange::RoomListChanged => serde_json::json!({
            "type": "room_list_changed",
        })
        .to_string(),
        DataChange::MessageAdded { room_id, msgid } => serde_json::json!({
            "type": "message_added",
            "room_id": room_id,
            "msgid": msgid,
        })
        .to_string(),
        DataChange::MessageUpdated { room_id, msgid } => serde_json::json!({
            "type": "message_updated",
            "room_id": room_id,
            "msgid": msgid,
        })
        .to_string(),
        DataChange::ContactUpdated { pubkey } => serde_json::json!({
            "type": "contact_updated",
            "pubkey": pubkey,
        })
        .to_string(),
        DataChange::ContactListChanged => serde_json::json!({
            "type": "contact_list_changed",
        })
        .to_string(),
        DataChange::IdentityListChanged => serde_json::json!({
            "type": "identity_list_changed",
        })
        .to_string(),
        DataChange::ConnectionStatusChanged { status, message } => {
            let status_str = match status {
                ConnectionStatus::Disconnected => "disconnected",
                ConnectionStatus::Connecting => "connecting",
                ConnectionStatus::Connected => "connected",
                ConnectionStatus::Reconnecting => "reconnecting",
                ConnectionStatus::Failed => "failed",
            };
            serde_json::json!({
                "type": "connection_status_changed",
                "status": status_str,
                "message": message,
            })
            .to_string()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Contacts
// ═══════════════════════════════════════════════════════════════

async fn list_contacts(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let pubkey = match state.client.get_pubkey_hex().await {
        Ok(pk) => pk,
        Err(e) => return bad_request(e),
    };

    match state.client.get_contacts(pubkey).await {
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
            ok_json(list)
        }
        Err(e) => internal_err(e),
    }
}
