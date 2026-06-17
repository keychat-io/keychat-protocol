# Multi-Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add real multi-identity support to `keychat-protocol`, matching the iOS v1.5 model where one runtime can register multiple Nostr identities, switch the active identity, isolate protocol/app data by identity, and subscribe/decrypt inbound events for all enabled identities.

**Architecture:** Port the iOS Rust-layer shape rather than only adding CLI tabs. `libkeychat::ProtocolClient` gets an identity registry plus checkout/checkin active-state swapping; protocol storage gains local-identity ownership columns; `keychat-app-core::AppClient` replaces the one-shot cached identity with a mutable active identity; UniFFI, CLI, TUI, and daemon expose list/switch/create/delete operations. Existing single-identity behavior remains the compatibility path.

**Tech Stack:** Rust, tokio, rusqlite/SQLCipher, libsignal-protocol, nostr 0.37, UniFFI, keychat-cli TUI/daemon.

---

## Source Findings

Reference implementation:

- Product/domain rules: `/Users/nuannuan/project/rust/keychat-ios-1.5/docs/domains/identity.md`
- Identity derivation and imported nsec support: `/Users/nuannuan/project/rust/keychat-ios-1.5/rust/libkeychat/src/identity.rs`
- Protocol multi-identity registry and active-state swap: `/Users/nuannuan/project/rust/keychat-ios-1.5/rust/libkeychat/src/orchestrator.rs`
- Protocol storage owner columns: `/Users/nuannuan/project/rust/keychat-ios-1.5/rust/libkeychat/src/storage.rs`
- AppClient active identity lock and set-active API: `/Users/nuannuan/project/rust/keychat-ios-1.5/rust/keychat-app-core/src/app_client.rs`
- UniFFI multi-identity APIs: `/Users/nuannuan/project/rust/keychat-ios-1.5/rust/keychat-uniffi/src/client.rs`
- Swift app-state model: `/Users/nuannuan/project/rust/keychat-ios-1.5/Keychat/Models/AppState.swift`
- Swift identity service flow: `/Users/nuannuan/project/rust/keychat-ios-1.5/Keychat/Services/KeychatService/KeychatService+Identity.swift`

Current gaps in this repo:

- `libkeychat::ProtocolClient` stores one `identity: Option<Identity>` and one set of session maps.
- `keychat-app-core::AppClient.identity_pubkey_hex` is a `OnceCell`, so it cannot switch after create/import.
- Protocol storage tables such as `peer_mappings`, `signal_participants`, `peer_addresses`, and `pending_friend_requests` are not scoped by the local identity.
- CLI persistence has one `identity_mnemonic` setting, so restore/import overwrites the previous identity.
- App storage already has `app_identities` and `identity_pubkey` on rooms/messages/contacts, so the app-layer schema is partially ready.

## Assumptions

- This plan targets the Rust protocol/app-core/UniFFI/CLI repository. It does not add SwiftUI views.
- CLI secrets can remain in encrypted app storage for this repo because the current CLI already stores `identity_mnemonic` there. The plan keeps the storage API narrow so a later OS-keyring-backed secret store can replace it.
- MLS support in this repo is behind features and smaller than the iOS app; the first implementation must preserve current MLS behavior and key MLS participant state by active identity where this repo already does so.
- Existing single-identity databases must keep working. Legacy protocol rows without an owner are assigned to the first restored identity.

## File Map

- Modify `libkeychat/src/identity.rs`: account-index mnemonic derivation plus secret hex/nsec imports.
- Modify `libkeychat/src/orchestrator.rs`: `IdentityState`, registry, active switch, multi-identity restore, any-identity decrypt helpers, subscribe pubkey fanout.
- Modify `libkeychat/src/storage.rs`: schema migrations, owner-scoped save/load/delete APIs, tests.
- Modify `libkeychat/src/lib.rs`: export `IdentityState` if needed by tests/diagnostics.
- Create `libkeychat/tests/multi_identity_test.rs`: protocol-level target behavior.
- Modify `keychat-app-core/src/app_client.rs`: mutable active identity and identity registration APIs.
- Modify `keychat-app-core/src/event_loop.rs`: route incoming events across registered identities.
- Modify `keychat-app-core/src/data_store.rs` and `keychat-app-core/src/app_storage.rs`: safe identity delete and app state consistency.
- Modify `keychat-uniffi/src/client.rs`, `keychat-uniffi/src/data_store.rs`, `keychat-uniffi/src/types.rs`: expose multi-identity APIs.
- Modify `keychat-cli/src/commands.rs`, `keychat-cli/src/repl.rs`, `keychat-cli/src/tui.rs`, `keychat-cli/src/daemon.rs`: list/switch/create/delete identities and restore all identities on startup.
- Add or modify tests under `libkeychat/tests`, `keychat-app-core/tests`, `keychat-uniffi/tests`, and `keychat-cli/tests`.

---

### Task 1: Add Identity Import Variants

**Files:**
- Modify: `libkeychat/src/identity.rs`

- [ ] **Step 1: Write failing tests**

Add these tests to the existing `#[cfg(test)] mod tests` in `libkeychat/src/identity.rs`:

```rust
#[test]
fn derive_mnemonic_accounts_are_distinct_and_stable() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let account0 = Identity::from_mnemonic_with_account_str(phrase, 0).unwrap();
    let account1 = Identity::from_mnemonic_with_account_str(phrase, 1).unwrap();
    let account1_again = Identity::from_mnemonic_with_account_str(phrase, 1).unwrap();

    assert_ne!(account0.pubkey_hex(), account1.pubkey_hex());
    assert_eq!(account1.pubkey_hex(), account1_again.pubkey_hex());
}

#[test]
fn import_secret_hex_and_nsec_roundtrip() {
    let generated = Identity::generate().unwrap().identity;
    let secret_hex = generated.secret_hex();
    let nsec = generated.nsec().unwrap();

    let from_hex = Identity::from_secret_hex(&secret_hex).unwrap();
    let from_nsec = Identity::from_nsec(&nsec).unwrap();

    assert_eq!(generated.pubkey_hex(), from_hex.pubkey_hex());
    assert_eq!(generated.pubkey_hex(), from_nsec.pubkey_hex());
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p libkeychat derive_mnemonic_accounts_are_distinct_and_stable
cargo test -p libkeychat import_secret_hex_and_nsec_roundtrip
```

Expected: compile failure because `from_mnemonic_with_account_str`, `from_secret_hex`, or `from_nsec` do not exist.

- [ ] **Step 3: Implement the identity APIs**

Add these methods to `impl Identity`:

```rust
pub fn from_mnemonic_with_account_str(phrase: &str, account: u32) -> Result<Self> {
    let mnemonic: Mnemonic = phrase
        .parse()
        .map_err(|e: bip39::Error| KeychatError::InvalidMnemonic(e.to_string()))?;
    Self::from_mnemonic(mnemonic, account)
}

pub fn from_secret_hex(hex: &str) -> Result<Self> {
    let sk = SecretKey::from_hex(hex.trim())
        .map_err(|e| KeychatError::Identity(format!("invalid secret hex: {e}")))?;
    Ok(Self { keys: Keys::new(sk) })
}

pub fn from_nsec(nsec: &str) -> Result<Self> {
    let sk = SecretKey::from_bech32(nsec.trim())
        .map_err(|e| KeychatError::Identity(format!("invalid nsec: {e}")))?;
    Ok(Self { keys: Keys::new(sk) })
}
```

Change `from_mnemonic_str` to call account `0`, and change the private `from_mnemonic` signature:

```rust
pub fn from_mnemonic_str(phrase: &str) -> Result<Self> {
    Self::from_mnemonic_with_account_str(phrase, 0)
}

fn from_mnemonic(mnemonic: Mnemonic, account: u32) -> Result<Self> {
    use nostr::nips::nip06::FromMnemonic;
    let keys = Keys::from_mnemonic_with_account(mnemonic.to_string(), None::<String>, Some(account))
        .map_err(|e| KeychatError::KeyDerivation(e.to_string()))?;
    Ok(Self { keys })
}
```

- [ ] **Step 4: Run tests and verify they pass**

Run:

```bash
cargo test -p libkeychat identity
```

Expected: all identity tests pass.

- [ ] **Step 5: Commit**

```bash
git add libkeychat/src/identity.rs
git commit -m "feat: support multi-account identity imports"
```

### Task 2: Add ProtocolClient Identity Registry

**Files:**
- Modify: `libkeychat/src/orchestrator.rs`
- Modify: `libkeychat/src/lib.rs`
- Create: `libkeychat/tests/multi_identity_test.rs`

- [ ] **Step 1: Write failing protocol registry tests**

Create `libkeychat/tests/multi_identity_test.rs` with the iOS reference cases adapted to current fields:

```rust
use std::sync::{Arc, Mutex};

use libkeychat::{Identity, ProtocolClient, SecureStorage};

fn new_client() -> ProtocolClient {
    let storage = Arc::new(Mutex::new(
        SecureStorage::open_in_memory("pw:multi-id-test-key").unwrap(),
    ));
    ProtocolClient::new(storage)
}

#[test]
fn add_identity_and_list() {
    let mut client = new_client();
    let id_a = Identity::generate().unwrap().identity;
    let id_b = Identity::generate().unwrap().identity;
    let a_hex = id_a.pubkey_hex();
    let b_hex = id_b.pubkey_hex();

    client.add_identity(id_a);
    client.add_identity(id_b);

    let listed: Vec<String> = client
        .list_identities()
        .into_iter()
        .map(|id| id.pubkey_hex())
        .collect();
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&a_hex));
    assert!(listed.contains(&b_hex));
    assert!(client.identity_state(&a_hex).is_some());
    assert!(client.identity_state(&b_hex).is_some());
}

#[test]
fn set_identity_activates_target_and_preserves_registry() {
    let mut client = new_client();
    let id_a = Identity::generate().unwrap().identity;
    let id_b = Identity::generate().unwrap().identity;
    let a_hex = id_a.pubkey_hex();
    let b_hex = id_b.pubkey_hex();

    client.add_identity(id_a.clone());
    client.add_identity(id_b.clone());
    client.set_identity(Some(id_a));
    assert_eq!(client.identity().map(|id| id.pubkey_hex()), Some(a_hex.clone()));

    client.set_identity(Some(id_b));
    assert_eq!(client.identity().map(|id| id.pubkey_hex()), Some(b_hex.clone()));
    assert!(client.identity_state(&a_hex).is_some());
    assert!(client.identity_state(&b_hex).is_some());

    client.set_identity(None);
    assert!(client.identity().is_none());
    assert_eq!(client.list_identities().len(), 2);
}

#[test]
fn with_identity_scopes_to_target_then_restores_prior_active() {
    let mut client = new_client();
    let id_a = Identity::generate().unwrap().identity;
    let id_b = Identity::generate().unwrap().identity;
    let a_hex = id_a.pubkey_hex();
    let b_hex = id_b.pubkey_hex();

    client.add_identity(id_a.clone());
    client.add_identity(id_b);
    client.set_identity(Some(id_a));

    let inner_hex = client
        .with_identity(&b_hex, |c| c.identity().map(|id| id.pubkey_hex()))
        .unwrap();

    assert_eq!(inner_hex, Some(b_hex));
    assert_eq!(client.identity().map(|id| id.pubkey_hex()), Some(a_hex));
}

#[test]
fn remove_identity_drops_only_that_identity_state() {
    let mut client = new_client();
    let id_a = Identity::generate().unwrap().identity;
    let id_b = Identity::generate().unwrap().identity;
    let a_hex = id_a.pubkey_hex();
    let b_hex = id_b.pubkey_hex();

    client.add_identity(id_a);
    client.add_identity(id_b);
    assert!(client.remove_identity(&a_hex).is_some());
    assert!(client.identity_state(&a_hex).is_none());
    assert!(client.identity_state(&b_hex).is_some());
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p libkeychat --test multi_identity_test
```

Expected: compile failure for missing registry APIs.

- [ ] **Step 3: Implement `IdentityState` and registry APIs**

Add `IdentityState` near `ProtocolClient`. Include every current per-identity field, not only the fields present in iOS, so public-agent state does not leak across identities:

```rust
pub struct IdentityState {
    identity: Identity,
    pub(crate) sessions: HashMap<String, Arc<tokio::sync::Mutex<ChatSession>>>,
    pub(crate) peer_nostr_to_signal: HashMap<String, String>,
    pub(crate) peer_signal_to_nostr: HashMap<String, String>,
    pub(crate) receiving_addr_to_peer: HashMap<String, String>,
    pub(crate) peer_is_public_agent: HashMap<String, bool>,
    pub(crate) peer_uses_dual_p_tag: HashMap<String, bool>,
    pub(crate) pending_outbound: HashMap<String, FriendRequestState>,
    pub(crate) peer_pending_first_inbox: HashMap<String, String>,
    pub(crate) self_is_public_agent: bool,
}
```

Add these methods on `ProtocolClient`:

```rust
pub fn add_identity(&mut self, identity: Identity);
pub fn list_identities(&self) -> Vec<&Identity>;
pub fn identity_state(&self, identity_hex: &str) -> Option<&IdentityState>;
pub fn identity_state_mut(&mut self, identity_hex: &str) -> Option<&mut IdentityState>;
pub fn set_active_identity(&mut self, identity_hex: &str) -> Result<()>;
pub fn with_identity<F, R>(&mut self, identity_hex: &str, f: F) -> Result<R>
where
    F: FnOnce(&mut Self) -> R;
pub fn remove_identity(&mut self, identity_hex: &str) -> Option<IdentityState>;
```

Implement `checkpoint_active()` and `activate_identity()` using `std::mem::take` for all per-identity maps. `transport`, `storage`, `group_manager`, `subscription_ids`, and `last_relay_urls` remain on `ProtocolClient`.

- [ ] **Step 4: Export state type if needed**

In `libkeychat/src/lib.rs`, add `IdentityState` to the existing `pub use` list for orchestrator types if integration tests or diagnostics need it:

```rust
pub use orchestrator::{IdentityState, ProtocolClient};
```

- [ ] **Step 5: Run tests and verify they pass**

Run:

```bash
cargo test -p libkeychat --test multi_identity_test
cargo test -p libkeychat
```

Expected: all libkeychat tests pass.

- [ ] **Step 6: Commit**

```bash
git add libkeychat/src/orchestrator.rs libkeychat/src/lib.rs libkeychat/tests/multi_identity_test.rs
git commit -m "feat: add protocol identity registry"
```

### Task 3: Scope Protocol Storage by Local Identity

**Files:**
- Modify: `libkeychat/src/storage.rs`
- Modify: `libkeychat/src/orchestrator.rs`

- [ ] **Step 1: Write failing storage tests**

Add tests in `libkeychat/src/storage.rs` for owner-scoped peer mappings and pending friend requests:

```rust
#[test]
fn peer_mappings_are_scoped_by_my_pubkey() {
    let store = SecureStorage::open_in_memory("pw:scope-test").unwrap();
    store
        .save_peer_mapping("me-a", "peer", "sig-a", "Peer A")
        .unwrap();
    store
        .save_peer_mapping("me-b", "peer", "sig-b", "Peer B")
        .unwrap();

    let a = store.list_peers_for_identity("me-a", false).unwrap();
    let b = store.list_peers_for_identity("me-b", false).unwrap();

    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!(a[0].signal_id, "sig-a");
    assert_eq!(b[0].signal_id, "sig-b");
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```bash
cargo test -p libkeychat peer_mappings_are_scoped_by_my_pubkey
```

Expected: compile failure or assertion failure because `save_peer_mapping` does not accept `my_pubkey` and `list_peers_for_identity` does not exist.

- [ ] **Step 3: Add schema migrations**

Change `SecureStorage::SCHEMA_VERSION` from `1` to `4`, and add `run_migrations` steps equivalent to the iOS implementation:

```rust
if current < 2 {
    Self::migrate_v1_to_v2(conn)?;
}
if current < 3 {
    Self::migrate_v2_to_v3(conn)?;
}
if current < 4 {
    Self::migrate_v3_to_v4(conn)?;
}
```

The final schema must contain:

```sql
peer_mappings(my_pubkey TEXT NOT NULL DEFAULT '', peer_pubkey TEXT NOT NULL, signal_id TEXT NOT NULL, name TEXT NOT NULL, ..., PRIMARY KEY (my_pubkey, peer_pubkey))
signal_participants(..., my_pubkey TEXT NOT NULL DEFAULT '')
peer_addresses(..., my_pubkey TEXT NOT NULL DEFAULT '')
pending_friend_requests(..., my_pubkey TEXT NOT NULL DEFAULT '', peer_pubkey TEXT NOT NULL DEFAULT '')
```

Keep legacy row handling by allowing empty `my_pubkey` during migration.

- [ ] **Step 4: Add owner-scoped storage methods**

Update these signatures:

```rust
pub fn save_peer_mapping(&self, my_pubkey: &str, peer_pubkey: &str, signal_id: &str, name: &str) -> Result<()>;
pub fn save_signal_participant(&self, my_pubkey: &str, peer_signal_id: &str, device_id: u32, identity_public: &[u8], identity_private: &[u8], registration_id: u32, signed_prekey_id: u32, signed_prekey_record: &[u8]) -> Result<()>;
pub fn save_peer_addresses(&self, peer_signal_id: &str, state: &PeerAddressStateSerialized, my_pubkey: &str) -> Result<()>;
pub fn save_pending_fr(&self, my_pubkey: &str, request_id: &str, device_id: u32, identity_public: &[u8], identity_private: &[u8], registration_id: u32, signed_prekey_id: u32, signed_prekey_record: &[u8], prekey_id: u32, prekey_record: &[u8], kyber_prekey_id: u32, kyber_prekey_record: &[u8], first_inbox_secret: &str, peer_pubkey: &str, uses_pqxdh: bool) -> Result<()>;
```

Add these restore helpers:

```rust
pub fn list_peers_for_identity(&self, my_pubkey: &str, include_legacy: bool) -> Result<Vec<PeerMapping>>;
pub fn list_signal_participants_for_identity(&self, my_pubkey: &str, include_legacy: bool) -> Result<Vec<String>>;
pub fn load_peer_addresses_for_identity(&self, my_pubkey: &str, include_legacy: bool) -> Result<Vec<(String, PeerAddressStateSerialized)>>;
pub fn list_pending_frs_for_identity(&self, my_pubkey: &str, include_legacy: bool) -> Result<Vec<String>>;
```

Keep compatibility wrappers where external callers still need legacy names:

```rust
pub fn list_peers(&self) -> Result<Vec<PeerMapping>>;
pub fn list_signal_participants(&self) -> Result<Vec<String>>;
pub fn list_pending_frs(&self) -> Result<Vec<String>>;
```

- [ ] **Step 5: Update protocol write call sites**

In `libkeychat/src/orchestrator.rs`, derive `my_pubkey` from the active identity before every scoped storage write:

```rust
let my_pubkey = self
    .identity
    .as_ref()
    .ok_or_else(|| KeychatError::Identity("call import_identity first".into()))?
    .pubkey_hex();
```

Pass `&my_pubkey` into `save_peer_mapping`, `save_signal_participant`, `save_peer_addresses`, and `save_pending_fr`.

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p libkeychat storage
cargo test -p libkeychat
```

Expected: all libkeychat tests pass.

- [ ] **Step 7: Commit**

```bash
git add libkeychat/src/storage.rs libkeychat/src/orchestrator.rs
git commit -m "feat: scope protocol storage by identity"
```

### Task 4: Restore Sessions and Decrypt Across All Identities

**Files:**
- Modify: `libkeychat/src/orchestrator.rs`
- Modify: `keychat-app-core/src/event_loop.rs`

- [ ] **Step 1: Add restore and subscription tests**

Extend `libkeychat/tests/multi_identity_test.rs`:

```rust
#[tokio::test]
async fn subscription_pubkeys_include_all_registered_identities() {
    let mut client = new_client();
    let id_a = Identity::generate().unwrap().identity;
    let id_b = Identity::generate().unwrap().identity;
    let a_hex = id_a.pubkey_hex();
    let b_hex = id_b.pubkey_hex();

    client.add_identity(id_a.clone());
    client.add_identity(id_b);
    client.set_identity(Some(id_a));

    let (identity_pubkeys, _) = client.collect_subscribe_pubkeys().await;
    let hexes: Vec<String> = identity_pubkeys.into_iter().map(|pk| pk.to_hex()).collect();

    assert!(hexes.contains(&a_hex));
    assert!(hexes.contains(&b_hex));
}
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
cargo test -p libkeychat --test multi_identity_test subscription_pubkeys_include_all_registered_identities
```

Expected: failure because subscriptions include only the active identity.

- [ ] **Step 3: Implement multi-identity restore**

Refactor `ProtocolClient::restore_sessions` to:

1. Require at least one active or registered identity.
2. Build a stable ordered list with the active identity first.
3. Call `checkpoint_active()` before restore.
4. For each identity, load peers, participants, peer addresses, and pending friend requests via the new `*_for_identity` storage helpers.
5. Use `include_legacy = true` only for the first identity.
6. Reactivate the original active identity at the end.

- [ ] **Step 4: Implement subscription fanout**

Change `collect_subscribe_pubkeys` to include:

1. Active identity master pubkey.
2. Every registered inactive identity master pubkey.
3. Pending first inbox keys for every identity.
4. Ratchet receiving addresses for sessions in every identity state.

Add optional subscription filtering:

```rust
pub fn set_subscription_identity_filter(&mut self, enabled_identity_hexes: Vec<String>);
pub fn clear_subscription_identity_filter(&mut self);
```

- [ ] **Step 5: Implement any-identity decrypt helpers**

Add helpers mirroring iOS:

```rust
pub fn try_decrypt_friend_request_any(&mut self, event: &Event) -> Option<(String, FriendRequestContext)>;
pub fn try_decrypt_pending_outbound_any(&mut self, event: &Event) -> Option<(String, String, KCMessage, SignalDecryptResult)>;
pub async fn try_decrypt_session_message_any(&mut self, event: &Event) -> Option<(String, String, KCMessage, MessageMetadata, AddressUpdate, Arc<tokio::sync::Mutex<ChatSession>>)>;
pub fn try_decrypt_nip17_dm_any(&mut self, event: &Event) -> Option<(String, Nip17DmContext)>;
```

Each helper must iterate `list_identities()`, call `with_identity`, and return the matched identity hex with the decrypted context.

- [ ] **Step 6: Update app event loop routing**

In `keychat-app-core/src/event_loop.rs`, replace active-identity-only decrypt attempts with the any-identity helpers. After a helper returns, call `inner.protocol.set_active_identity(&identity_hex)` before follow-up operations that mutate sessions, addresses, pending outbound state, rooms, or contacts.

- [ ] **Step 7: Run tests**

Run:

```bash
cargo test -p libkeychat --test multi_identity_test
cargo test -p keychat-app-core
cargo test --workspace
```

Expected: all workspace tests pass.

- [ ] **Step 8: Commit**

```bash
git add libkeychat/src/orchestrator.rs keychat-app-core/src/event_loop.rs libkeychat/tests/multi_identity_test.rs
git commit -m "feat: route inbound events across identities"
```

### Task 5: Make AppClient Active Identity Switchable

**Files:**
- Modify: `keychat-app-core/src/app_client.rs`
- Modify: `keychat-app-core/src/data_store.rs`
- Modify: `keychat-uniffi/src/client.rs`

- [ ] **Step 1: Add failing app-core tests**

Create or extend `keychat-app-core/tests/multi_identity_test.rs`:

```rust
use keychat_app_core::AppClient;

fn new_app_client() -> AppClient {
    AppClient::new(":memory:".to_string(), "pw:app-multi-id".to_string()).unwrap()
}

#[tokio::test]
async fn app_client_can_switch_active_identity() {
    let client = new_app_client();
    let first = client.create_identity().await.unwrap().pubkey_hex;
    let second = client.create_identity().await.unwrap().pubkey_hex;

    client.set_active_identity(first.clone()).await.unwrap();
    assert_eq!(client.get_pubkey_hex().await.unwrap(), first);

    client.set_active_identity(second.clone()).await.unwrap();
    assert_eq!(client.get_pubkey_hex().await.unwrap(), second);
}
```

- [ ] **Step 2: Run test and verify it fails**

Run:

```bash
cargo test -p keychat-app-core app_client_can_switch_active_identity
```

Expected: failure because the cached identity is a `OnceCell`.

- [ ] **Step 3: Replace `OnceCell` with `RwLock<String>`**

Change:

```rust
pub identity_pubkey_hex: tokio::sync::OnceCell<String>,
```

to:

```rust
pub identity_pubkey_hex: std::sync::RwLock<String>,
```

Update `cached_identity_pubkey()` and `get_pubkey_hex()` to read the lock and return `NotInitialized` when empty.

- [ ] **Step 4: Add app-core identity registration and switch APIs**

Add to `impl AppClient`:

```rust
pub async fn set_active_identity(&self, identity_hex: String) -> AppResult<()>;
pub async fn add_identity_from_mnemonic_account(&self, mnemonic: String, account: u32) -> AppResult<String>;
pub async fn add_identity_from_secret_hex(&self, secret_hex: String) -> AppResult<String>;
pub async fn add_identity_from_nsec(&self, nsec: String) -> AppResult<String>;
pub async fn list_identity_pubkeys(&self) -> Vec<String>;
```

`create_identity` and `import_identity` must call `inner.protocol.set_identity(Some(identity))` and write the active lock.

- [ ] **Step 5: Expose UniFFI methods**

In `keychat-uniffi/src/client.rs`, add exported methods:

```rust
pub async fn add_identity(&self, mnemonic: String, account: u32) -> Result<String, KeychatUniError>;
pub async fn add_identity_from_secret_hex(&self, secret_hex: String) -> Result<String, KeychatUniError>;
pub async fn add_identity_from_nsec(&self, nsec: String) -> Result<String, KeychatUniError>;
pub async fn list_identity_pubkeys(&self) -> Vec<String>;
pub async fn set_active_identity(&self, identity_hex: String) -> Result<(), KeychatUniError>;
```

- [ ] **Step 6: Run tests**

Run:

```bash
cargo test -p keychat-app-core app_client_can_switch_active_identity
cargo test -p keychat-uniffi
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add keychat-app-core/src/app_client.rs keychat-app-core/src/data_store.rs keychat-uniffi/src/client.rs keychat-app-core/tests/multi_identity_test.rs
git commit -m "feat: support active identity switching in app client"
```

### Task 6: Persist and Restore Multiple CLI Identities

**Files:**
- Modify: `keychat-cli/src/commands.rs`
- Modify: `keychat-cli/src/repl.rs`
- Modify: `keychat-cli/src/tui.rs`
- Modify: `keychat-cli/src/daemon.rs`
- Modify: `keychat-cli/tests/integration_test.rs`

- [ ] **Step 1: Add CLI identity secret model tests**

Add command-level tests for these behaviors:

1. Creating the first identity stores the seed mnemonic and app identity row with index `0`.
2. Creating an additional identity derives from the stored seed at the next non-negative index.
3. Restoring registers all stored identities and activates the default identity.
4. Switching active identity changes `client.get_pubkey_hex()`.

- [ ] **Step 2: Replace single restore with all-identity restore**

Keep the existing setting for compatibility:

```rust
pub const SETTING_MNEMONIC: &str = "identity_mnemonic";
```

Add scoped secret keys:

```rust
pub const SETTING_IDENTITY_SEED_MNEMONIC: &str = "identity_seed_mnemonic";

pub fn setting_identity_secret_hex(pubkey: &str) -> String {
    format!("identity_secret_hex:{pubkey}")
}
```

Add:

```rust
pub async fn restore_identities(client: &Arc<AppClient>) -> Result<Option<String>, AppError>;
pub async fn switch_identity(client: &AppClient, identity_hex_or_index: &str) -> Result<String, AppError>;
pub async fn create_additional_identity(client: &AppClient, display_name: &str) -> Result<(String, String), AppError>;
```

Restore algorithm:

1. Load `get_identities()`.
2. If empty, fall back to legacy `identity_mnemonic`.
3. Register per-identity secret hex first when present.
4. Otherwise register from seed mnemonic and `IdentityInfo.index`.
5. Pick `is_default == true`, otherwise first identity.
6. Call `set_active_identity`.
7. Call `restore_sessions`.

- [ ] **Step 3: Add REPL/TUI commands**

Add commands:

```text
/identities
/switch <index|pubkey>
/create-id <name>
/import-nsec <nsec> <name>
/delete-identity <index|pubkey>
```

Keep existing `/create` and `/import` behavior for first-run compatibility. When identities already exist, `/create <name>` should return a message telling users to use `/create-id <name>`.

- [ ] **Step 4: Add daemon routes**

Add routes in `keychat-cli/src/daemon.rs`:

```text
GET  /identities
POST /identity/switch
POST /identity/create-derived
POST /identity/import-nsec
DELETE /identity/{pubkey}
```

The switch body:

```rust
#[derive(Deserialize)]
struct SwitchIdentityReq {
    identity: String,
}
```

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p keychat-cli
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add keychat-cli/src/commands.rs keychat-cli/src/repl.rs keychat-cli/src/tui.rs keychat-cli/src/daemon.rs keychat-cli/tests/integration_test.rs
git commit -m "feat: add CLI multi-identity commands"
```

### Task 7: Safe Identity Deletion and App Storage Cleanup

**Files:**
- Modify: `keychat-app-core/src/app_storage.rs`
- Modify: `keychat-app-core/src/data_store.rs`
- Modify: `keychat-app-core/src/app_client.rs`
- Modify: `libkeychat/src/storage.rs`

- [ ] **Step 1: Add deletion tests**

Add app-storage tests asserting:

1. Deleting one identity removes its rooms, child rooms, messages, contacts, attachments, and settings.
2. Deleting one identity does not remove another identity's rooms or contacts.
3. Deleting the active identity chooses another identity or returns `NotInitialized` if none remain.

- [ ] **Step 2: Implement app storage deletion through room collection**

Update `delete_app_identity` to:

1. Collect all room IDs where `identity_pubkey = ?`.
2. Delete child rooms before parent rooms.
3. Delete file attachments whose `msgid` belongs to those messages.
4. Delete messages, contacts, and identity row.
5. Delete scoped settings keys for that identity.

Do not directly delete `app_rooms` before child room cleanup.

- [ ] **Step 3: Add protocol identity data deletion**

Add to `SecureStorage`:

```rust
pub fn delete_identity_data(&self, my_pubkey: &str) -> Result<()>;
```

Delete rows from:

```sql
signal_sessions
pre_keys
signed_pre_keys
kyber_pre_keys
identity_keys
peer_addresses
peer_mappings
signal_participants
pending_friend_requests
inbound_friend_requests
pending_first_inbox
```

Only delete records owned by `my_pubkey` where ownership exists. Keep relays and processed events.

- [ ] **Step 4: Wire app client deletion**

Add:

```rust
pub async fn delete_identity(&self, identity_hex: String) -> AppResult<()>;
```

It must:

1. Stop or pause event loop mutation while deleting.
2. Remove protocol state via `ProtocolClient::remove_identity`.
3. Delete protocol DB rows via `delete_identity_data`.
4. Delete app DB rows via `delete_app_identity`.
5. Select remaining default/first identity and call `set_active_identity`, or clear active identity if none remain.
6. Refresh subscriptions if connected.

- [ ] **Step 5: Run tests**

Run:

```bash
cargo test -p keychat-app-core identity
cargo test -p libkeychat storage
cargo test --workspace
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add keychat-app-core/src/app_storage.rs keychat-app-core/src/data_store.rs keychat-app-core/src/app_client.rs libkeychat/src/storage.rs
git commit -m "feat: safely delete one identity"
```

### Task 8: Documentation and Verification

**Files:**
- Modify: `README.md`
- Modify: `keychat-cli/README.md`
- Modify: `keychat-protocol-spec-v2.md` if implementation details clarify the app-level behavior.

- [ ] **Step 1: Document CLI usage**

Add a CLI section with:

```text
/identities                 List local identities
/switch <index|pubkey>      Switch active identity
/create-id <name>           Derive another identity from the saved seed
/import-nsec <nsec> <name>  Import an independent identity
/delete-identity <id>       Delete one identity, keeping others
```

- [ ] **Step 2: Document invariants**

Document these invariants:

1. Nostr identity pubkeys are the identity keys shown to users.
2. Signal identities remain per-peer encryption state.
3. Rooms, contacts, messages, and protocol sessions are scoped by local identity pubkey.
4. The relay subscription set includes all chat-enabled identities, not only the selected one.
5. Deleting an identity must remove subscriptions and persisted rows for that identity.

- [ ] **Step 3: Run full verification**

Run:

```bash
cargo fmt --all -- --check
cargo test --workspace
```

If formatting fails, run:

```bash
cargo fmt --all
cargo test --workspace
```

Expected: format check and tests pass.

- [ ] **Step 4: Manual smoke test**

Run the CLI in a temporary data directory:

```bash
cargo run -p keychat-cli -- --data-dir /tmp/keychat-multi-id-smoke interactive
```

Then execute:

```text
/create Alice
/create-id Bob
/identities
/switch 0
/whoami
/switch 1
/whoami
```

Expected:

1. `/identities` shows two identities.
2. `/whoami` changes after `/switch`.
3. Restarting the CLI restores both identities.

- [ ] **Step 5: Commit**

```bash
git add README.md keychat-cli/README.md keychat-protocol-spec-v2.md
git commit -m "docs: describe multi-identity behavior"
```

## Risks and Mitigations

- **Risk:** Current public-agent maps are identity-scoped but the iOS reference `IdentityState` does not include them.  
  **Mitigation:** Include the current repo's additional per-peer maps in `IdentityState`.

- **Risk:** Storage migrations can corrupt existing single-identity data.  
  **Mitigation:** Keep empty-owner legacy rows and assign them to the first restored identity; add in-memory migration tests before touching restore code.

- **Risk:** Event-loop follow-up operations mutate the wrong identity after any-identity decrypt.  
  **Mitigation:** After every `try_decrypt_*_any` match, immediately call `set_active_identity(identity_hex)` before session/address persistence.

- **Risk:** CLI stores secrets differently from iOS Keychain.  
  **Mitigation:** Keep the secret persistence layer small and isolated in `keychat-cli/src/commands.rs`; app-core and protocol accept identities from callers and do not own secret storage.

## Self-Review

- Spec coverage: The plan covers identity derivation/import, registry, active switching, storage ownership, app-core/UniFFI exposure, CLI commands, deletion, subscriptions, and inbound event routing.
- Placeholder scan: No step requires unspecified behavior; method names, files, and verification commands are listed.
- Type consistency: `identity_hex`, `my_pubkey`, `peer_pubkey`, and `identity_pubkey` are used consistently by layer: protocol storage uses `my_pubkey`; app storage keeps `identity_pubkey`; UI/CLI command input uses identity hex or index.
