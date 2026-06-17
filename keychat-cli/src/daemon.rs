//! HTTP daemon mode for keychat-cli.
//!
//! Provides a REST API + SSE event stream backed by `AppClient`.

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        Html, Json,
    },
    routing::{delete, get, post},
    Router,
};
use keychat_app_core::{
    AppClient, ClientEvent, ConnectionStatus, DataChange, FileCategory, GroupChangeKind,
    GroupMemberInput, MessageKind, MessageStatus, RoomStatus, RoomType,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::StreamExt;

// ─── Shared State ───────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    client: Arc<AppClient>,
    event_tx: broadcast::Sender<ClientEvent>,
    data_tx: broadcast::Sender<DataChange>,
}

// ─── JSON Envelope ──────────────────────────────────────────────

pub(crate) fn ok_json<T: Serialize>(data: T) -> (StatusCode, Json<serde_json::Value>) {
    let body = serde_json::json!({ "ok": true, "data": data });
    (StatusCode::OK, Json(body))
}

pub(crate) fn err_json(
    status: StatusCode,
    msg: impl ToString,
) -> (StatusCode, Json<serde_json::Value>) {
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
        RoomType::MlsGroup | RoomType::Nip17Dm => "mls_group",
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
    client: Arc<AppClient>,
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
        .route("/debug/identities", get(debug_identities_page))
        .route("/identity", get(get_identity))
        .route("/identities", get(list_identities))
        .route("/identity/create", post(create_identity))
        .route("/identity/import", post(import_identity))
        .route("/identity/switch", post(switch_identity))
        .route("/identity/create-derived", post(create_derived_identity))
        .route("/identity/import-nsec", post(import_nsec_identity))
        .route("/identity/{pubkey}", delete(delete_identity))
        // Connection
        .route("/connect", post(connect_relays))
        .route("/disconnect", post(disconnect_relays))
        .route("/relays", get(get_relays))
        .route("/status", get(get_status))
        // Friends
        .route("/friend-request", post(send_friend_request))
        .route("/friend-request/accept", post(accept_friend_request))
        .route("/friend-request/reject", post(reject_friend_request))
        .route("/bundle/export", post(export_bundle))
        .route("/bundle/add", post(add_bundle))
        // Messaging
        .route("/send", post(send_message))
        .route("/send-file", post(send_file))
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
        // File Transfer
        .route("/upload", post(upload_file))
        .route("/download", post(download_file))
        .route("/files", get(list_files))
        .with_state(state)
}

// ─── Entry Point ────────────────────────────────────────────────

pub async fn run(
    client: Arc<AppClient>,
    event_tx: broadcast::Sender<ClientEvent>,
    data_tx: broadcast::Sender<DataChange>,
    port: u16,
) -> anyhow::Result<()> {
    // AppClient owns an internal Tokio runtime. The daemon is process-lifetime,
    // so keep one strong reference alive to avoid dropping that runtime from
    // inside the async server shutdown/error path.
    let client = {
        let keep_alive = Arc::clone(&client);
        let _ = Arc::into_raw(client);
        keep_alive
    };

    // Shared startup: restore identity → sessions → connect → event loop
    let relay_urls = keychat_app_core::default_relays();
    crate::commands::init_and_connect(&client, relay_urls).await;

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    let router = build_router(client, event_tx, data_tx);

    tracing::info!("daemon listening on http://{addr}");
    axum::serve(listener, router).await?;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Identity
// ═══════════════════════════════════════════════════════════════

async fn debug_identities_page() -> Html<&'static str> {
    Html(DEBUG_IDENTITIES_HTML)
}

async fn get_identity(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
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

const DEBUG_IDENTITIES_HTML: &str = r###"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Multi-Identity Debug</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1d2430;
      --muted: #637083;
      --line: #dbe1ea;
      --primary: #0c6b58;
      --primary-strong: #07483d;
      --danger: #b42318;
      --danger-bg: #fff1f0;
      --ok-bg: #ecfdf5;
      --shadow: 0 10px 30px rgba(24, 39, 75, 0.08);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 15px;
      line-height: 1.45;
    }

    main {
      width: min(1160px, calc(100% - 32px));
      margin: 0 auto;
      padding: 28px 0 40px;
    }

    header {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 20px;
      margin-bottom: 20px;
    }

    h1 {
      margin: 0;
      font-size: 28px;
      line-height: 1.15;
      font-weight: 760;
    }

    h2 {
      margin: 0 0 12px;
      font-size: 17px;
      line-height: 1.25;
    }

    p {
      margin: 0;
      color: var(--muted);
    }

    button,
    input,
    textarea {
      font: inherit;
    }

    button {
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel);
      color: var(--text);
      padding: 0 14px;
      cursor: pointer;
      white-space: nowrap;
    }

    button.primary {
      border-color: var(--primary);
      background: var(--primary);
      color: #ffffff;
    }

    button.primary:hover {
      background: var(--primary-strong);
    }

    button.danger {
      border-color: #fecaca;
      background: var(--danger-bg);
      color: var(--danger);
    }

    button:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }

    input,
    textarea {
      width: 100%;
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: #ffffff;
      color: var(--text);
      padding: 8px 10px;
      outline: none;
    }

    input:focus,
    textarea:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(12, 107, 88, 0.13);
    }

    textarea {
      min-height: 76px;
      resize: vertical;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 13px;
    }

    .toolbar {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .grid {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 360px;
      gap: 18px;
      align-items: start;
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 18px;
    }

    .active {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      min-height: 88px;
      margin-bottom: 18px;
    }

    .label {
      display: block;
      margin-bottom: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }

    .mono {
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 13px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 0 10px;
      background: var(--ok-bg);
      color: #047857;
      font-size: 12px;
      font-weight: 700;
    }

    .identity-list {
      display: grid;
      gap: 10px;
      min-height: 112px;
    }

    .identity {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 13px;
      background: #ffffff;
    }

    .identity.current {
      border-color: rgba(12, 107, 88, 0.5);
      background: #fbfffd;
    }

    .identity-actions {
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .name-row {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 4px;
    }

    .name {
      min-width: 0;
      overflow-wrap: anywhere;
      font-weight: 750;
    }

    .forms {
      display: grid;
      gap: 14px;
    }

    .form {
      display: grid;
      gap: 9px;
      border-top: 1px solid var(--line);
      padding-top: 14px;
    }

    .form:first-child {
      border-top: 0;
      padding-top: 0;
    }

    .row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 8px;
      align-items: end;
    }

    .mnemonic {
      margin-top: 18px;
      border-color: #fbbf24;
      background: #fffbeb;
    }

    .log {
      margin-top: 18px;
      min-height: 120px;
      max-height: 260px;
      overflow: auto;
      white-space: pre-wrap;
      color: #354052;
      background: #101828;
      border-radius: 8px;
      padding: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
    }

    .log span {
      color: #d1fadf;
    }

    .empty {
      display: grid;
      place-items: center;
      min-height: 160px;
      border: 1px dashed var(--line);
      border-radius: 8px;
      color: var(--muted);
      text-align: center;
      padding: 20px;
    }

    @media (max-width: 880px) {
      main {
        width: min(100% - 20px, 680px);
        padding-top: 18px;
      }

      header,
      .grid,
      .active,
      .identity,
      .row {
        grid-template-columns: 1fr;
      }

      header {
        align-items: stretch;
      }

      .toolbar,
      .identity-actions {
        justify-content: flex-start;
      }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Multi-Identity Debug</h1>
        <p>Local daemon identity controls for manual testing.</p>
      </div>
      <div class="toolbar">
        <button id="refreshBtn" type="button">Refresh</button>
        <button id="createFirstBtn" class="primary" type="button">Create First Identity</button>
      </div>
    </header>

    <section class="active panel" aria-live="polite">
      <div>
        <span class="label">Active identity</span>
        <div id="activeName" class="name">Loading...</div>
        <div id="activePubkey" class="mono"></div>
      </div>
      <div id="activeBadge" class="badge" hidden>Active</div>
    </section>

    <div class="grid">
      <section class="panel">
        <h2>Identities</h2>
        <div id="identityList" class="identity-list"></div>
      </section>

      <aside class="panel">
        <h2>Actions</h2>
        <div class="forms">
          <form id="derivedForm" class="form">
            <div>
              <label class="label" for="derivedName">Derived identity name</label>
              <div class="row">
                <input id="derivedName" name="name" autocomplete="off" placeholder="Work">
                <button class="primary" type="submit">Add Derived</button>
              </div>
            </div>
          </form>

          <form id="nsecForm" class="form">
            <div>
              <label class="label" for="nsecName">Imported identity name</label>
              <input id="nsecName" name="name" autocomplete="off" placeholder="Imported">
            </div>
            <div>
              <label class="label" for="nsecValue">nsec private key</label>
              <textarea id="nsecValue" name="nsec" autocomplete="off" spellcheck="false" placeholder="nsec1..."></textarea>
            </div>
            <button class="primary" type="submit">Import nsec</button>
          </form>
        </div>

        <section id="mnemonicPanel" class="panel mnemonic" hidden>
          <h2>Save Mnemonic Now</h2>
          <p>This seed is returned once by the daemon.</p>
          <textarea id="mnemonicValue" readonly></textarea>
        </section>

        <pre id="log" class="log"><span>Ready.</span></pre>
      </aside>
    </div>
  </main>

  <script>
    const state = {
      active: null,
      identities: []
    };

    const els = {
      refreshBtn: document.getElementById("refreshBtn"),
      createFirstBtn: document.getElementById("createFirstBtn"),
      activeName: document.getElementById("activeName"),
      activePubkey: document.getElementById("activePubkey"),
      activeBadge: document.getElementById("activeBadge"),
      identityList: document.getElementById("identityList"),
      derivedForm: document.getElementById("derivedForm"),
      derivedName: document.getElementById("derivedName"),
      nsecForm: document.getElementById("nsecForm"),
      nsecName: document.getElementById("nsecName"),
      nsecValue: document.getElementById("nsecValue"),
      mnemonicPanel: document.getElementById("mnemonicPanel"),
      mnemonicValue: document.getElementById("mnemonicValue"),
      log: document.getElementById("log")
    };

    function log(message, data) {
      const time = new Date().toLocaleTimeString();
      const extra = data ? "\n" + JSON.stringify(data, null, 2) : "";
      els.log.textContent = `[${time}] ${message}${extra}`;
    }

    async function api(path, options = {}) {
      const response = await fetch(path, {
        headers: { "content-type": "application/json" },
        ...options
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || payload.ok === false) {
        throw new Error(payload.error || response.statusText || `HTTP ${response.status}`);
      }
      return payload.data;
    }

    function identityTitle(identity) {
      return identity.name || identity.npub || identity.pubkey_hex || "Unnamed identity";
    }

    function render() {
      const active = state.identities.find((identity) => identity.pubkey_hex === state.active);
      els.activeName.textContent = active ? identityTitle(active) : "No active identity";
      els.activePubkey.textContent = active ? active.pubkey_hex : "Create or import an identity to begin.";
      els.activeBadge.hidden = !active;
      els.createFirstBtn.disabled = state.identities.length > 0;

      if (!state.identities.length) {
        els.identityList.innerHTML = '<div class="empty">No local identities yet.</div>';
        return;
      }

      els.identityList.replaceChildren(
        ...state.identities.map((identity) => {
          const current = identity.pubkey_hex === state.active;
          const item = document.createElement("article");
          item.className = `identity${current ? " current" : ""}`;

          const details = document.createElement("div");
          const nameRow = document.createElement("div");
          nameRow.className = "name-row";

          const name = document.createElement("div");
          name.className = "name";
          name.textContent = identityTitle(identity);
          nameRow.append(name);

          if (current) {
            const badge = document.createElement("span");
            badge.className = "badge";
            badge.textContent = "Active";
            nameRow.append(badge);
          }

          const pubkey = document.createElement("div");
          pubkey.className = "mono";
          pubkey.textContent = identity.pubkey_hex;

          const meta = document.createElement("p");
          meta.textContent = `index ${identity.index}${identity.is_default ? " / default" : ""}`;

          details.append(nameRow, pubkey, meta);

          const actions = document.createElement("div");
          actions.className = "identity-actions";

          const switchBtn = document.createElement("button");
          switchBtn.type = "button";
          switchBtn.textContent = "Switch";
          switchBtn.disabled = current;
          switchBtn.addEventListener("click", () => switchIdentity(identity.pubkey_hex));

          const deleteBtn = document.createElement("button");
          deleteBtn.type = "button";
          deleteBtn.className = "danger";
          deleteBtn.textContent = "Delete";
          deleteBtn.addEventListener("click", () => deleteIdentity(identity.pubkey_hex));

          actions.append(switchBtn, deleteBtn);
          item.append(details, actions);
          return item;
        })
      );
    }

    async function refresh() {
      try {
        const data = await api("/identities");
        state.active = data.active;
        state.identities = data.identities || [];
        render();
        log("Loaded identities.", data);
      } catch (error) {
        log(`Refresh failed: ${error.message}`);
      }
    }

    async function createFirstIdentity() {
      try {
        const data = await api("/identity/create", { method: "POST" });
        if (data.mnemonic) {
          els.mnemonicValue.value = data.mnemonic;
          els.mnemonicPanel.hidden = false;
        }
        log("Created first identity.", data);
        await refresh();
      } catch (error) {
        log(`Create failed: ${error.message}`);
      }
    }

    async function createDerivedIdentity(event) {
      event.preventDefault();
      try {
        const name = els.derivedName.value.trim() || "Derived Identity";
        const data = await api("/identity/create-derived", {
          method: "POST",
          body: JSON.stringify({ name })
        });
        els.derivedName.value = "";
        log("Created derived identity.", data);
        await refresh();
      } catch (error) {
        log(`Create derived failed: ${error.message}`);
      }
    }

    async function importNsecIdentity(event) {
      event.preventDefault();
      try {
        const nsec = els.nsecValue.value.trim();
        if (!nsec) {
          throw new Error("nsec is required");
        }
        const name = els.nsecName.value.trim() || "Imported Identity";
        const data = await api("/identity/import-nsec", {
          method: "POST",
          body: JSON.stringify({ nsec, name })
        });
        els.nsecName.value = "";
        els.nsecValue.value = "";
        log("Imported nsec identity.", data);
        await refresh();
      } catch (error) {
        log(`Import failed: ${error.message}`);
      }
    }

    async function switchIdentity(pubkey) {
      try {
        const data = await api("/identity/switch", {
          method: "POST",
          body: JSON.stringify({ identity: pubkey })
        });
        log("Switched identity.", data);
        await refresh();
      } catch (error) {
        log(`Switch failed: ${error.message}`);
      }
    }

    async function deleteIdentity(pubkey) {
      if (!window.confirm("Delete this identity and its local scoped data?")) {
        return;
      }

      try {
        const data = await api(`/identity/${encodeURIComponent(pubkey)}`, {
          method: "DELETE"
        });
        log("Deleted identity.", data);
        await refresh();
      } catch (error) {
        log(`Delete failed: ${error.message}`);
      }
    }

    els.refreshBtn.addEventListener("click", refresh);
    els.createFirstBtn.addEventListener("click", createFirstIdentity);
    els.derivedForm.addEventListener("submit", createDerivedIdentity);
    els.nsecForm.addEventListener("submit", importNsecIdentity);
    refresh();
  </script>
</body>
</html>
"###;

async fn list_identities(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.get_identities().await {
        Ok(identities) => {
            let active = state.client.get_pubkey_hex().await.ok();
            ok_json(serde_json::json!({
                "active": active,
                "identities": identities.into_iter().map(|identity| {
                    serde_json::json!({
                        "pubkey_hex": identity.nostr_pubkey_hex,
                        "npub": identity.npub,
                        "name": identity.name,
                        "index": identity.index,
                        "is_default": identity.is_default,
                    })
                }).collect::<Vec<_>>()
            }))
        }
        Err(e) => internal_err(e),
    }
}

async fn create_identity(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
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

#[derive(Deserialize)]
struct SwitchIdentityReq {
    identity: String,
}

async fn switch_identity(
    State(state): State<AppState>,
    Json(req): Json<SwitchIdentityReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match crate::commands::switch_identity(&state.client, &req.identity).await {
        Ok(pubkey) => ok_json(serde_json::json!({ "pubkey_hex": pubkey })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct CreateDerivedIdentityReq {
    name: Option<String>,
}

async fn create_derived_identity(
    State(state): State<AppState>,
    Json(req): Json<CreateDerivedIdentityReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let name = req.name.as_deref().unwrap_or("CLI User");
    match crate::commands::create_additional_identity(&state.client, name).await {
        Ok((pubkey_hex, npub)) => ok_json(serde_json::json!({
            "pubkey_hex": pubkey_hex,
            "npub": npub,
        })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct ImportNsecIdentityReq {
    nsec: String,
    name: Option<String>,
}

async fn import_nsec_identity(
    State(state): State<AppState>,
    Json(req): Json<ImportNsecIdentityReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let name = req.name.as_deref().unwrap_or("Imported Identity");
    match crate::commands::import_identity_from_nsec(&state.client, &req.nsec, name).await {
        Ok((pubkey_hex, npub)) => ok_json(serde_json::json!({
            "pubkey_hex": pubkey_hex,
            "npub": npub,
        })),
        Err(e) => bad_request(e),
    }
}

async fn delete_identity(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match crate::commands::delete_identity(&state.client, &pubkey).await {
        Ok(pubkey_hex) => ok_json(serde_json::json!({ "deleted": pubkey_hex })),
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
        Ok(()) => ok_json(serde_json::json!({ "connected": true })),
        Err(e) => internal_err(e),
    }
}

async fn disconnect_relays(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match state.client.disconnect().await {
        Ok(()) => ok_json(serde_json::json!({ "disconnected": true })),
        Err(e) => internal_err(e),
    }
}

async fn get_relays(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
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

async fn get_status(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let identity = state.client.get_pubkey_hex().await.ok();
    let relay_statuses = state.client.get_relay_statuses().await.unwrap_or_default();
    let connected_count = relay_statuses
        .iter()
        .filter(|s| s.status == "connected")
        .count();
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

#[derive(Deserialize)]
struct ExportBundleReq {
    #[serde(default = "default_cli_name")]
    name: String,
    #[serde(default = "default_cli_device")]
    device_id: String,
}

fn default_cli_name() -> String {
    "CLI User".to_string()
}
fn default_cli_device() -> String {
    "cli-device".to_string()
}

async fn export_bundle(
    State(state): State<AppState>,
    Json(req): Json<ExportBundleReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state
        .client
        .export_contact_bundle(req.name, req.device_id)
        .await
    {
        Ok(json) => ok_json(serde_json::json!({ "bundle": json })),
        Err(e) => bad_request(e),
    }
}

#[derive(Deserialize)]
struct AddBundleReq {
    /// Raw JSON bundle string. Callers that have base64 should decode first.
    bundle: String,
    #[serde(default = "default_cli_name")]
    name: String,
}

async fn add_bundle(
    State(state): State<AppState>,
    Json(req): Json<AddBundleReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state
        .client
        .add_contact_via_bundle(req.bundle, req.name)
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
        Ok(crate::commands::SendResult::Dm {
            event_id,
            relay_count,
        }) => ok_json(serde_json::json!({
            "event_id": event_id,
            "relay_count": relay_count,
        })),
        Ok(crate::commands::SendResult::Group { event_count }) => ok_json(serde_json::json!({
            "type": "group",
            "event_count": event_count,
        })),
        Ok(crate::commands::SendResult::MlsNotSupported) => bad_request(
            keychat_app_core::AppError::InvalidArgument("MLS groups not yet supported".into()),
        ),
        Err(e) => bad_request(e),
    }
}

// ─── Send File ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct SendFileReq {
    room_id: String,
    /// Local file paths to upload and send.
    file_paths: Vec<String>,
    /// Optional text message to include with the files.
    #[serde(default)]
    message: Option<String>,
    /// Blossom server URL (optional, defaults to blossom.band).
    #[serde(default)]
    server: Option<String>,
}

fn file_category_str(c: &FileCategory) -> &'static str {
    match c {
        FileCategory::Image => "image",
        FileCategory::Video => "video",
        FileCategory::Voice => "voice",
        FileCategory::Audio => "audio",
        FileCategory::Document => "document",
        FileCategory::Text => "text",
        FileCategory::Archive => "archive",
        FileCategory::Other => "other",
    }
}

async fn send_file(
    State(state): State<AppState>,
    Json(req): Json<SendFileReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.file_paths.is_empty() {
        return bad_request("file_paths cannot be empty");
    }

    let server = req
        .server
        .unwrap_or_else(|| "https://blossom.band".to_string());

    // Upload each file
    let mut payloads = Vec::with_capacity(req.file_paths.len());
    for path_str in &req.file_paths {
        let path = std::path::Path::new(path_str);
        if !path.exists() {
            return bad_request(format!("File not found: {path_str}"));
        }
        match crate::commands::upload_and_prepare_file(path, &server).await {
            Ok(payload) => payloads.push(payload),
            Err(e) => return bad_request(format!("Upload failed for {path_str}: {e}")),
        }
    }

    // Build summary before sending (payloads will be moved)
    let files_json: Vec<_> = payloads
        .iter()
        .map(|p| {
            serde_json::json!({
                "url": p.url,
                "category": file_category_str(&p.category),
                "size": p.size,
                "source_name": p.source_name,
            })
        })
        .collect();

    // Send the file message
    match crate::commands::send_file_message(&state.client, &req.room_id, payloads, req.message)
        .await
    {
        Ok(crate::commands::SendResult::Dm {
            event_id,
            relay_count,
        }) => ok_json(serde_json::json!({
            "event_id": event_id,
            "relay_count": relay_count,
            "files": files_json,
        })),
        Ok(crate::commands::SendResult::Group { event_count }) => ok_json(serde_json::json!({
            "type": "group",
            "event_count": event_count,
        })),
        Ok(crate::commands::SendResult::MlsNotSupported) => {
            bad_request("MLS groups not yet supported")
        }
        Err(e) => bad_request(e),
    }
}

async fn list_rooms(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
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
    match state
        .client
        .get_messages(room_id, query.limit, query.offset)
        .await
    {
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

async fn retry_failed(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
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
    match state.client.remove_group_member(group_id, req.pubkey).await {
        Ok(()) => ok_json(serde_json::json!({ "kicked": true })),
        Err(e) => bad_request(e),
    }
}

// ═══════════════════════════════════════════════════════════════
// SSE Events
// ═══════════════════════════════════════════════════════════════

/// Handle auto-download for file messages in daemon mode.
fn spawn_file_auto_download_daemon(
    client: Arc<AppClient>,
    room_id: String,
    event_id: String,
    payload_json: String,
) {
    tokio::spawn(async move {
        // Parse file message
        let parsed = match crate::commands::parse_file_message(&payload_json) {
            Some(p) => p,
            None => return,
        };

        // Process each file item
        for item in &parsed.items {
            // Check if already downloaded
            if client
                .resolve_local_file(event_id.clone(), item.hash.clone())
                .await
                .is_some()
            {
                continue;
            }

            // Check if should auto-download
            match client.should_auto_download(item.size).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::info!(
                        "[daemon] Skipping auto-download for {} (size {} exceeds limit)",
                        item.display_name(),
                        item.size
                    );
                    continue;
                }
                Err(e) => {
                    tracing::warn!("[daemon] Failed to check auto-download setting: {e}");
                    continue;
                }
            }

            // Download the file
            tracing::info!("[daemon] Auto-downloading file: {}", item.display_name());
            match client
                .download_and_save(
                    item.url.clone(),
                    item.key.clone(),
                    item.iv.clone(),
                    item.hash.clone(),
                    item.source_name.clone(),
                    item.suffix.clone(),
                    room_id.clone(),
                    Some(event_id.clone()),
                )
                .await
            {
                Ok(path) => {
                    tracing::info!("[daemon] Auto-downloaded file to: {path}");
                }
                Err(e) => {
                    tracing::warn!(
                        "[daemon] Failed to auto-download file {}: {e}",
                        item.display_name()
                    );
                }
            }
        }
    });
}

async fn sse_events(
    State(state): State<AppState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<SseEvent, Infallible>>> {
    // Merge both broadcast channels into a single mpsc for the SSE stream
    let (tx, rx) = tokio::sync::mpsc::channel::<SseEvent>(256);

    // Forward ClientEvent with auto-download for file messages
    let mut event_rx = state.event_tx.subscribe();
    let tx1 = tx.clone();
    let client = Arc::clone(&state.client);
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            // Trigger auto-download for file messages
            if let ClientEvent::MessageReceived {
                ref room_id,
                kind: MessageKind::Files,
                payload: Some(ref payload_json),
                ref event_id,
                ..
            } = event
            {
                spawn_file_auto_download_daemon(
                    Arc::clone(&client),
                    room_id.clone(),
                    event_id.clone(),
                    payload_json.clone(),
                );
            }

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

async fn list_contacts(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
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

// ═══════════════════════════════════════════════════════════════
// File Transfer
// ═══════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct UploadFileReq {
    /// Local file path to upload.
    file_path: String,
    /// Blossom server URL (optional, defaults to blossom.band).
    #[serde(default)]
    server: Option<String>,
}

async fn upload_file(
    State(_state): State<AppState>,
    Json(req): Json<UploadFileReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    let path = std::path::Path::new(&req.file_path);
    if !path.exists() {
        return bad_request(format!("File not found: {}", req.file_path));
    }

    // Get server URL
    let server = req
        .server
        .unwrap_or_else(|| keychat_app_core::default_blossom_server());

    // Upload file
    match crate::commands::upload_and_prepare_file(path, &server).await {
        Ok(payload) => ok_json(serde_json::json!({
            "url": payload.url,
            "key": payload.key,
            "iv": payload.iv,
            "hash": payload.hash,
            "size": payload.size,
            "category": file_category_str(&payload.category),
            "mime_type": payload.mime_type,
            "suffix": payload.suffix,
            "source_name": payload.source_name,
        })),
        Err(e) => bad_request(format!("Upload failed: {e}")),
    }
}

#[derive(Deserialize)]
struct DownloadFileReq {
    /// File URL to download.
    url: String,
    /// AES key (hex).
    key: String,
    /// IV (hex).
    iv: String,
    /// Hash (hex).
    hash: String,
    /// Room ID to save file to.
    room_id: String,
    /// Original source name (optional).
    #[serde(default)]
    source_name: Option<String>,
    /// File suffix/extension (optional).
    #[serde(default)]
    suffix: Option<String>,
    /// Event ID for tracking (optional).
    #[serde(default)]
    event_id: Option<String>,
}

async fn download_file(
    State(state): State<AppState>,
    Json(req): Json<DownloadFileReq>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state
        .client
        .download_and_save(
            req.url,
            req.key,
            req.iv,
            req.hash,
            req.source_name,
            req.suffix,
            req.room_id,
            req.event_id,
        )
        .await
    {
        Ok(path) => ok_json(serde_json::json!({ "path": path })),
        Err(e) => bad_request(format!("Download failed: {e}")),
    }
}

#[derive(Deserialize)]
struct ListFilesQuery {
    room_id: String,
}

async fn list_files(
    State(state): State<AppState>,
    Query(query): Query<ListFilesQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Fetch messages and find file messages
    match state
        .client
        .get_messages(query.room_id.clone(), 100, 0)
        .await
    {
        Ok(messages) => {
            let mut files: Vec<serde_json::Value> = Vec::new();

            for msg in messages {
                if let Some(ref payload_json) = msg.payload_json {
                    if let Some(parsed) = crate::commands::parse_file_message(payload_json) {
                        for item in &parsed.items {
                            // Check if downloaded
                            let is_downloaded = state
                                .client
                                .resolve_local_file(msg.msgid.clone(), item.hash.clone())
                                .await
                                .is_some();

                            files.push(serde_json::json!({
                                "event_id": msg.msgid,
                                "sender_pubkey": msg.sender_pubkey,
                                "created_at": msg.created_at,
                                "url": item.url,
                                "hash": item.hash,
                                "source_name": item.source_name,
                                "category": file_category_str(&item.category),
                                "size": item.size,
                                "is_downloaded": is_downloaded,
                            }));
                        }
                    }
                }
            }

            ok_json(files)
        }
        Err(e) => bad_request(format!("Failed to list files: {e}")),
    }
}
