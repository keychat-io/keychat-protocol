//! C FFI bindings for libkeychat.
//!
//! Provides a minimal C-compatible API for identity management, friend requests,
//! encrypted messaging, and address management. All functions are `extern "C"`
//! and use raw pointers + length pairs for data exchange.
//!
//! ## Memory ownership
//! - Strings returned by libkeychat must be freed with `keychat_free_string()`.
//! - Byte buffers returned via `KeychatBuffer` must be freed with `keychat_free_buffer()`.
//! - The opaque `KeychatContext` is created with `keychat_init()` and destroyed with `keychat_destroy()`.
//!
//! ## Thread safety
//! All functions take `*mut KeychatContext`. The context is NOT thread-safe —
//! callers must serialize access (e.g., with a mutex) if used from multiple threads.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::{
    accept_friend_request, receive_friend_request, send_friend_request, AddressManager, Identity,
    KCMessage, SignalParticipant,
};
use libsignal_protocol::{DeviceId, ProtocolAddress};
use nostr::prelude::*;

// ─── Opaque context ─────────────────────────────────────────────────────────

/// Opaque handle holding all keychat state.
pub struct KeychatContext {
    identity: Identity,
    peers: Vec<PeerState>,
    pending_frs: Vec<PendingFR>,
    rt: tokio::runtime::Runtime,
}

struct PeerState {
    nostr_pubkey: String,
    signal_id: String,
    name: String,
    signal: SignalParticipant,
    address_manager: AddressManager,
}

struct PendingFR {
    first_inbox: String,
    signal: SignalParticipant,
}

/// Byte buffer returned from FFI. Caller must free with `keychat_free_buffer()`.
#[repr(C)]
pub struct KeychatBuffer {
    pub data: *mut u8,
    pub len: usize,
}

/// Result from sending a friend request.
#[repr(C)]
pub struct KeychatFriendRequestResult {
    /// Serialized Nostr event JSON (must free with keychat_free_string).
    pub event_json: *mut c_char,
    /// The firstInbox address to subscribe to (must free with keychat_free_string).
    pub first_inbox: *mut c_char,
    /// 0 on success, non-zero on error.
    pub error: i32,
}

/// Result from receiving a friend request.
#[repr(C)]
pub struct KeychatFriendReceived {
    pub sender_npub: *mut c_char,
    pub sender_name: *mut c_char,
    pub sender_signal_id: *mut c_char,
    pub error: i32,
}

/// Incoming decrypted message.
#[repr(C)]
pub struct KeychatMessage {
    pub sender_npub: *mut c_char,
    pub content: *mut c_char,
    pub kind: *mut c_char,
    /// New addresses to subscribe to (JSON array string). May be null.
    pub new_addresses_json: *mut c_char,
    pub error: i32,
}

/// Send result.
#[repr(C)]
pub struct KeychatSendResult {
    pub event_json: *mut c_char,
    /// New addresses to subscribe to (JSON array string). May be null.
    pub new_addresses_json: *mut c_char,
    pub error: i32,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn to_cstring(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn null_str() -> *mut c_char {
    ptr::null_mut()
}

unsafe fn from_cstr(p: *const c_char) -> &'static str {
    if p.is_null() {
        return "";
    }
    CStr::from_ptr(p).to_str().unwrap_or("")
}

fn find_peer<'a>(ctx: &'a mut KeychatContext, npub: &str) -> Option<&'a mut PeerState> {
    ctx.peers.iter_mut().find(|p| p.nostr_pubkey == npub)
}

// ─── Lifecycle ──────────────────────────────────────────────────────────────

/// Create a new keychat context from a BIP-39 mnemonic.
/// Returns null on error. The returned pointer must be freed with `keychat_destroy()`.
#[no_mangle]
pub unsafe extern "C" fn keychat_init(mnemonic: *const c_char) -> *mut KeychatContext {
    let words = from_cstr(mnemonic);
    let identity = match Identity::from_mnemonic_str(words) {
        Ok(id) => id,
        Err(_) => return ptr::null_mut(),
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };
    Box::into_raw(Box::new(KeychatContext {
        identity,
        peers: Vec::new(),
        pending_frs: Vec::new(),
        rt,
    }))
}

/// Create a new keychat context with a freshly generated identity.
///
/// The mnemonic is written into `mnemonic_out` (caller-allocated buffer).
/// The caller MUST persist it in secure storage (OS keychain) and then
/// securely erase the buffer. Returns null on error.
///
/// `mnemonic_out`: caller-allocated buffer (at least 256 bytes).
/// `mnemonic_out_len`: size of the buffer.
/// Returns: pointer to KeychatContext, or null on error.
#[no_mangle]
pub unsafe extern "C" fn keychat_init_generate(
    mnemonic_out: *mut c_char,
    mnemonic_out_len: usize,
) -> *mut KeychatContext {
    let gen = match Identity::generate() {
        Ok(g) => g,
        Err(_) => return ptr::null_mut(),
    };

    // Write mnemonic to caller's buffer
    if !mnemonic_out.is_null() && mnemonic_out_len > 0 {
        let bytes = gen.mnemonic.as_bytes();
        let copy_len = bytes.len().min(mnemonic_out_len - 1);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mnemonic_out as *mut u8, copy_len);
        *mnemonic_out.add(copy_len) = 0; // null terminator
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ptr::null_mut(),
    };
    Box::into_raw(Box::new(KeychatContext {
        identity: gen.identity,
        peers: Vec::new(),
        pending_frs: Vec::new(),
        rt,
    }))
}

/// Destroy a keychat context and free all associated memory.
#[no_mangle]
pub unsafe extern "C" fn keychat_destroy(ctx: *mut KeychatContext) {
    if !ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
}

// ─── Identity ───────────────────────────────────────────────────────────────

/// Get the nostr public key (hex). Caller must free with `keychat_free_string()`.
#[no_mangle]
pub unsafe extern "C" fn keychat_get_npub(ctx: *const KeychatContext) -> *mut c_char {
    if ctx.is_null() {
        return null_str();
    }
    to_cstring(&(*ctx).identity.pubkey_hex())
}

// keychat_get_mnemonic() removed — mnemonic is only returned at generation time
// via keychat_init_generate(). Clients must store it in secure storage.

// ─── Friend Request ─────────────────────────────────────────────────────────

/// Send a friend request to a peer.
/// `peer_npub`: hex nostr pubkey of the peer.
/// `display_name`: your display name.
///
/// Returns event JSON to publish to relay + firstInbox address to subscribe to.
#[no_mangle]
pub unsafe extern "C" fn keychat_send_friend_request(
    ctx: *mut KeychatContext,
    peer_npub: *const c_char,
    display_name: *const c_char,
) -> KeychatFriendRequestResult {
    let err_result = KeychatFriendRequestResult {
        event_json: null_str(),
        first_inbox: null_str(),
        error: -1,
    };
    if ctx.is_null() {
        return err_result;
    }
    let ctx = &mut *ctx;
    let peer = from_cstr(peer_npub);
    let name = from_cstr(display_name);

    let result = ctx
        .rt
        .block_on(send_friend_request(&ctx.identity, peer, name, "ffi"));
    match result {
        Ok((event, fr_state)) => {
            let event_json = match event.as_json() {
                s => to_cstring(&s),
            };
            let first_inbox = fr_state.first_inbox_keys.pubkey_hex();

            ctx.pending_frs.push(PendingFR {
                first_inbox: first_inbox.clone(),
                signal: fr_state.signal_participant,
            });

            KeychatFriendRequestResult {
                event_json,
                first_inbox: to_cstring(&first_inbox),
                error: 0,
            }
        }
        Err(_) => err_result,
    }
}

/// Try to parse an incoming event as a friend request. Auto-accepts if it is one.
/// `event_json`: the kind:1059 Nostr event as JSON.
///
/// Returns sender info on success, error != 0 if not a friend request.
#[no_mangle]
pub unsafe extern "C" fn keychat_receive_friend_request(
    ctx: *mut KeychatContext,
    event_json: *const c_char,
) -> KeychatFriendReceived {
    let err = KeychatFriendReceived {
        sender_npub: null_str(),
        sender_name: null_str(),
        sender_signal_id: null_str(),
        error: -1,
    };
    if ctx.is_null() {
        return err;
    }
    let ctx = &mut *ctx;
    let json = from_cstr(event_json);

    let event = match nostr::Event::from_json(json) {
        Ok(e) => e,
        Err(_) => return err,
    };

    let fr = match receive_friend_request(&ctx.identity, &event) {
        Ok(f) => f,
        Err(_) => return err,
    };

    let sender_hex = fr.sender_pubkey.to_hex();
    let peer_signal_id = fr.payload.signal_identity_key.clone();
    let peer_name = fr.payload.name.clone();
    let first_inbox = fr.payload.first_inbox.clone();

    // Auto-accept
    let accepted = match ctx
        .rt
        .block_on(accept_friend_request(&ctx.identity, &fr, "ffi"))
    {
        Ok(a) => a,
        Err(_) => return err,
    };

    let accept_event_json = accepted.event.as_json();

    // Register peer
    let mut addr_mgr = AddressManager::new();
    addr_mgr.add_peer(&peer_signal_id, Some(first_inbox), Some(sender_hex.clone()));

    ctx.peers.push(PeerState {
        nostr_pubkey: sender_hex.clone(),
        signal_id: peer_signal_id.clone(),
        name: peer_name.clone(),
        signal: accepted.signal_participant,
        address_manager: addr_mgr,
    });

    KeychatFriendReceived {
        sender_npub: to_cstring(&sender_hex),
        sender_name: to_cstring(&peer_name),
        sender_signal_id: to_cstring(&accept_event_json), // piggyback: acceptance event JSON
        error: 0,
    }
}

// ─── Messaging ──────────────────────────────────────────────────────────────

/// Encrypt and build a send event for a text message.
/// `peer_npub`: hex nostr pubkey of the recipient (must be an established peer).
/// `text`: message content.
///
/// Returns the event JSON to publish + any new addresses to subscribe to.
#[no_mangle]
pub unsafe extern "C" fn keychat_send_text(
    ctx: *mut KeychatContext,
    peer_npub: *const c_char,
    text: *const c_char,
) -> KeychatSendResult {
    let err = KeychatSendResult {
        event_json: null_str(),
        new_addresses_json: null_str(),
        error: -1,
    };
    if ctx.is_null() {
        return err;
    }
    let ctx = &mut *ctx;
    let npub = from_cstr(peer_npub);
    let content = from_cstr(text);

    let peer = match find_peer(ctx, npub) {
        Some(p) => p,
        None => return err,
    };

    let msg = KCMessage::text(content);
    let json = match msg.to_json() {
        Ok(j) => j,
        Err(_) => return err,
    };

    let addr = ProtocolAddress::new(peer.signal_id.clone(), DeviceId::new(1).unwrap());
    let ct = match peer.signal.encrypt(&addr, json.as_bytes()) {
        Ok(c) => c,
        Err(_) => return err,
    };

    let to_address = peer
        .address_manager
        .resolve_send_address(&peer.signal_id)
        .unwrap_or_else(|_| peer.nostr_pubkey.clone());

    let update = peer
        .address_manager
        .on_encrypt(&peer.signal_id, ct.sender_address.as_deref())
        .unwrap_or_default();

    // Build Mode 1 event
    let event = match ctx.rt.block_on(build_mode1_event(&ct.bytes, &to_address)) {
        Ok(e) => e,
        Err(_) => return err,
    };

    let new_addrs = if update.new_receiving.is_empty() {
        null_str()
    } else {
        to_cstring(&serde_json::to_string(&update.new_receiving).unwrap_or_default())
    };

    KeychatSendResult {
        event_json: to_cstring(&event.as_json()),
        new_addresses_json: new_addrs,
        error: 0,
    }
}

/// Try to decrypt an incoming event from any known peer.
/// `event_json`: the kind:1059 Nostr event as JSON.
///
/// Returns the decrypted message content + sender + any new addresses.
#[no_mangle]
pub unsafe extern "C" fn keychat_receive_event(
    ctx: *mut KeychatContext,
    event_json: *const c_char,
) -> KeychatMessage {
    let err = KeychatMessage {
        sender_npub: null_str(),
        content: null_str(),
        kind: null_str(),
        new_addresses_json: null_str(),
        error: -1,
    };
    if ctx.is_null() {
        return err;
    }
    let ctx = &mut *ctx;
    let json = from_cstr(event_json);

    let event = match nostr::Event::from_json(json) {
        Ok(e) => e,
        Err(_) => return err,
    };

    // Try base64 decode
    let ciphertext =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &event.content) {
            Ok(ct) => ct,
            Err(_) => return err,
        };

    // Try each peer
    for peer in &mut ctx.peers {
        let addr = ProtocolAddress::new(peer.signal_id.clone(), DeviceId::new(1).unwrap());
        if let Ok(result) = peer.signal.decrypt(&addr, &ciphertext) {
            let update = peer
                .address_manager
                .on_decrypt(
                    &peer.signal_id,
                    result.bob_derived_address.as_deref(),
                    result.alice_addrs.as_deref(),
                )
                .unwrap_or_default();

            let text = String::from_utf8_lossy(&result.plaintext);
            let (content, kind) = if let Some(msg) = KCMessage::try_parse(&text) {
                match &msg.text {
                    Some(t) => (t.content.clone(), "text".to_string()),
                    None => (text.to_string(), format!("{:?}", msg.kind)),
                }
            } else {
                (text.to_string(), "raw".to_string())
            };

            let new_addrs = if update.new_receiving.is_empty() {
                null_str()
            } else {
                to_cstring(&serde_json::to_string(&update.new_receiving).unwrap_or_default())
            };

            return KeychatMessage {
                sender_npub: to_cstring(&peer.nostr_pubkey),
                content: to_cstring(&content),
                kind: to_cstring(&kind),
                new_addresses_json: new_addrs,
                error: 0,
            };
        }
    }

    // Try pending friend request responses
    if libkeychat_try_pending_response(ctx, &ciphertext) {
        // Peer was added; return a friend_accepted event
        if let Some(peer) = ctx.peers.last() {
            return KeychatMessage {
                sender_npub: to_cstring(&peer.nostr_pubkey),
                content: to_cstring(&peer.name),
                kind: to_cstring("friend_accepted"),
                new_addresses_json: null_str(),
                error: 0,
            };
        }
    }

    err
}

fn libkeychat_try_pending_response(ctx: &mut KeychatContext, ciphertext: &[u8]) -> bool {
    if !SignalParticipant::is_prekey_message(ciphertext) {
        return false;
    }

    let prekey_msg = match libsignal_protocol::PreKeySignalMessage::try_from(ciphertext) {
        Ok(m) => m,
        Err(_) => return false,
    };

    let sender_identity = hex::encode(prekey_msg.identity_key().serialize());
    let remote_addr = ProtocolAddress::new(sender_identity.clone(), DeviceId::new(1).unwrap());

    for i in 0..ctx.pending_frs.len() {
        if let Ok(result) = ctx.pending_frs[i].signal.decrypt(&remote_addr, ciphertext) {
            let text = String::from_utf8_lossy(&result.plaintext);
            if let Some(msg) = KCMessage::try_parse(&text) {
                if let Some(ref auth) = msg.signal_prekey_auth {
                    let mut signal = std::mem::replace(
                        &mut ctx.pending_frs[i].signal,
                        SignalParticipant::new("_", 1).unwrap(),
                    );
                    ctx.pending_frs.remove(i);

                    let mut addr_mgr = AddressManager::new();
                    addr_mgr.add_peer(&auth.signal_id, None, Some(auth.nostr_id.clone()));
                    let _ = addr_mgr.on_decrypt(
                        &auth.signal_id,
                        result.bob_derived_address.as_deref(),
                        result.alice_addrs.as_deref(),
                    );

                    ctx.peers.push(PeerState {
                        nostr_pubkey: auth.nostr_id.clone(),
                        signal_id: auth.signal_id.clone(),
                        name: auth.name.clone(),
                        signal,
                        address_manager: addr_mgr,
                    });
                    return true;
                }
            }
        }
    }
    false
}

/// Get the list of peer nostr pubkeys as a JSON array string.
/// Caller must free with `keychat_free_string()`.
#[no_mangle]
pub unsafe extern "C" fn keychat_list_peers(ctx: *const KeychatContext) -> *mut c_char {
    if ctx.is_null() {
        return null_str();
    }
    let peers: Vec<serde_json::Value> = (*ctx)
        .peers
        .iter()
        .map(|p| {
            serde_json::json!({
                "npub": p.nostr_pubkey,
                "name": p.name,
                "signal_id": p.signal_id,
            })
        })
        .collect();
    to_cstring(&serde_json::to_string(&peers).unwrap_or_default())
}

/// Resolve the correct sending address for a peer.
/// Returns the address string. Caller must free with `keychat_free_string()`.
#[no_mangle]
pub unsafe extern "C" fn keychat_resolve_send_address(
    ctx: *mut KeychatContext,
    peer_npub: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        return null_str();
    }
    let ctx = &mut *ctx;
    let npub = from_cstr(peer_npub);
    match find_peer(ctx, npub) {
        Some(peer) => {
            let addr = peer
                .address_manager
                .resolve_send_address(&peer.signal_id)
                .unwrap_or_else(|_| peer.nostr_pubkey.clone());
            to_cstring(&addr)
        }
        None => null_str(),
    }
}

// ─── Memory management ─────────────────────────────────────────────────────

/// Free a string returned by any keychat_* function.
#[no_mangle]
pub unsafe extern "C" fn keychat_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Free a buffer returned by any keychat_* function.
#[no_mangle]
pub unsafe extern "C" fn keychat_free_buffer(buf: KeychatBuffer) {
    if !buf.data.is_null() && buf.len > 0 {
        drop(Vec::from_raw_parts(buf.data, buf.len, buf.len));
    }
}

// ─── Internal helper ────────────────────────────────────────────────────────

async fn build_mode1_event(ciphertext: &[u8], to_address: &str) -> Result<nostr::Event, String> {
    use crate::EphemeralKeypair;
    use nostr::prelude::*;

    let sender = EphemeralKeypair::generate();
    let content = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ciphertext);
    let to_pubkey =
        PublicKey::from_hex(to_address).map_err(|e| format!("invalid to_address: {e}"))?;

    EventBuilder::new(Kind::GiftWrap, &content)
        .tag(Tag::public_key(to_pubkey))
        .sign(sender.keys())
        .await
        .map_err(|e| format!("sign: {e}"))
}

use base64::Engine as _;

// ─── Ecash Stamp FFI (not yet wired in Dart — available for future use) ─────

/// Fetch relay info (NIP-11) and return JSON with fee rules.
/// Returns JSON: {"name":"...","fees":{"publication":[...]}} or error.
/// Caller must free the returned string with keychat_free_string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keychat_fetch_relay_info(relay_url: *const c_char) -> *mut c_char {
    let url = unsafe { CStr::from_ptr(relay_url) }.to_str().unwrap_or("");
    let rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(crate::stamp::fetch_relay_info(url)) {
        Ok(info) => {
            let json = serde_json::to_string(&info).unwrap_or_default();
            CString::new(json).unwrap().into_raw()
        }
        Err(e) => {
            let err = format!(r#"{{"error":"{}"}}"#, e);
            CString::new(err).unwrap().into_raw()
        }
    }
}

/// Check if a relay requires a stamp for a given event kind.
/// Returns JSON: {"required":true,"amount":1,"unit":"sat","mints":["..."]} or {"required":false}
/// Caller must free the returned string with keychat_free_string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keychat_check_relay_fee(
    ctx: *const KeychatContext,
    relay_url: *const c_char,
    event_kind: u16,
) -> *mut c_char {
    let _ctx = unsafe { &*ctx };
    let url = unsafe { CStr::from_ptr(relay_url) }.to_str().unwrap_or("");
    // For now return not-required since stamp manager is not in context yet
    let result = format!(
        r#"{{"required":false,"relay":"{}","kind":{}}}"#,
        url, event_kind
    );
    CString::new(result).unwrap().into_raw()
}
