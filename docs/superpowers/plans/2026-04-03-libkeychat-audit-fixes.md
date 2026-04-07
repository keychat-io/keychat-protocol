# libkeychat Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 13 audit findings across libkeychat and keychat-uniffi — security hardening, atomicity, correctness, and code quality.

**Architecture:** All changes are backward-compatible. DB schema bumps from v4 to v5. Key material zeroization is added via `Zeroize`/`ZeroizeOnDrop` derives. Non-atomic operations wrapped in existing `transaction()`. No public API changes.

**Tech Stack:** Rust, SQLCipher, libsignal-protocol, zeroize crate, secp256k1

---

## File Structure

| File | Changes |
|------|---------|
| `libkeychat/src/storage.rs` | Migration v4→v5, delete_all_data fix, promote_pending_fr atomicity, delete_peer_data atomicity, named return structs |
| `libkeychat/src/signal_keys.rs` | ZeroizeOnDrop on key types, cache Secp256k1 context |
| `libkeychat/src/signal_session.rs` | Zeroize on SignalPreKeyMaterial drop |
| `libkeychat/src/signal_store.rs` | Remove dead field, document block_on invariant |
| `libkeychat/src/chat.rs` | Timestamp window check on prekey auth |
| `libkeychat/src/friend_request.rs` | Strict device_id validation |
| `libkeychat/src/address.rs` | Zeroize on DerivedAddress drop |
| `libkeychat/Cargo.toml` | Add zeroize `derive` feature |

---

### Task 1: Migration v5 — zero identity_private + delete_all_data fix (Findings #1, #11)

**Files:**
- Modify: `libkeychat/src/storage.rs`

- [ ] **Step 1: Write failing test for delete_all_data clearing device_identity**

```rust
// In storage.rs tests module:
#[test]
fn test_delete_all_data_clears_device_identity() {
    let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();
    store.save_device_identity(b"pub", b"priv", 42).unwrap();
    assert!(store.load_device_identity().unwrap().is_some());

    store.delete_all_data().unwrap();
    assert!(
        store.load_device_identity().unwrap().is_none(),
        "delete_all_data must clear device_identity"
    );
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cargo test --package libkeychat -- test_delete_all_data_clears_device_identity`
Expected: FAIL — device_identity not cleared

- [ ] **Step 3: Write failing test for migration zeroing identity_private**

```rust
#[test]
fn test_migration_v5_zeros_identity_private_in_participants() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v5_test.db");
    let path_str = path.to_str().unwrap();

    // Create v4 DB with identity_private still in signal_participants
    {
        let conn = rusqlite::Connection::open(path_str).unwrap();
        conn.pragma_update(None, "key", TEST_KEY).unwrap();
        conn.execute_batch("PRAGMA cipher_page_size = 4096; PRAGMA journal_mode = WAL;").unwrap();
        SecureStorage::migrate_v0_to_v1(&conn).unwrap();
        SecureStorage::migrate_v1_to_v2(&conn).unwrap();
        SecureStorage::migrate_v2_to_v3(&conn).unwrap();
        SecureStorage::migrate_v3_to_v4(&conn).unwrap();
        // Manually re-insert identity_private (simulating pre-v5 data)
        conn.execute(
            "UPDATE signal_participants SET identity_private = X'DEADBEEF' WHERE 1=1",
            [],
        ).ok(); // may be 0 rows, that's fine
        // Insert a row if none exist
        conn.execute(
            "INSERT OR IGNORE INTO signal_participants (peer_signal_id, device_id, identity_public, identity_private, registration_id, signed_prekey_id, signed_prekey_record, prekey_id, prekey_record, kyber_prekey_id, kyber_prekey_record)
             VALUES ('peer-v5', 1, X'AA', X'DEADBEEF', 1, 1, X'BB', 0, X'', 0, X'')",
            [],
        ).unwrap();
    }

    // Reopen — runs v4→v5 migration
    let store = SecureStorage::open(path_str, TEST_KEY).unwrap();
    let (_, _, id_priv, _, _, _, _, _, _, _) =
        store.load_signal_participant("peer-v5").unwrap().expect("should exist");
    assert!(id_priv.is_empty(), "identity_private must be zeroed after v5 migration");
}
```

- [ ] **Step 4: Run test — expect FAIL**

Run: `cargo test --package libkeychat -- test_migration_v5`
Expected: FAIL — no v5 migration yet

- [ ] **Step 5: Implement migration v4→v5 and fix delete_all_data**

In `libkeychat/src/storage.rs`:

1. Change `SCHEMA_VERSION` from 4 to 5
2. Add migration call in `run_migrations`:
```rust
if current < 5 {
    Self::migrate_v4_to_v5(conn)?;
}
```
3. Add migration function:
```rust
fn migrate_v4_to_v5(conn: &Connection) -> Result<()> {
    tracing::info!("running migration v4 → v5: zero identity_private in signal_participants");
    let _ = conn.execute_batch(
        "UPDATE signal_participants SET identity_private = X'';"
    );
    conn.pragma_update(None, "user_version", 5)
        .map_err(|e| KeychatError::Storage(format!("Failed to update user_version: {e}")))?;
    tracing::info!("migration v4 → v5 complete");
    Ok(())
}
```
4. Fix `delete_all_data` — add `DELETE FROM device_identity;` to the batch:
```rust
pub fn delete_all_data(&self) -> Result<()> {
    self.transaction(|conn| {
        conn.execute_batch(
            "DELETE FROM signal_sessions;
             DELETE FROM pre_keys;
             DELETE FROM signed_pre_keys;
             DELETE FROM kyber_pre_keys;
             DELETE FROM identity_keys;
             DELETE FROM peer_addresses;
             DELETE FROM processed_events;
             DELETE FROM peer_mappings;
             DELETE FROM signal_participants;
             DELETE FROM pending_friend_requests;
             DELETE FROM inbound_friend_requests;
             DELETE FROM signal_groups;
             DELETE FROM mls_group_ids;
             DELETE FROM device_identity;",
        )
        .map_err(|e| KeychatError::Storage(format!("Failed to delete all data: {e}")))?;
        Ok(())
    })
}
```

- [ ] **Step 6: Run tests — expect PASS**

Run: `cargo test --package libkeychat -- test_delete_all_data_clears_device_identity test_migration_v5`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add libkeychat/src/storage.rs
git commit -m "fix: migration v5 zeros identity_private, delete_all_data clears device_identity"
```

---

### Task 2: Atomic promote_pending_fr and delete_peer_data (Finding #5)

**Files:**
- Modify: `libkeychat/src/storage.rs`

- [ ] **Step 1: Write failing test for promote_pending_fr atomicity**

```rust
#[test]
fn test_promote_pending_fr_is_atomic() {
    let store = SecureStorage::open_in_memory(TEST_KEY).unwrap();

    // Save a pending FR
    store.save_pending_fr(
        "req-atomic", 1,
        b"pub", b"priv", 42,
        1, b"spk", 2, b"pk", 3, b"kpk",
        "inbox-secret", "peer-nostr",
    ).unwrap();
    assert_eq!(store.list_pending_frs().unwrap().len(), 1);

    // Promote it
    store.promote_pending_fr("req-atomic", "peer-sig-1").unwrap();

    // Pending FR should be gone
    assert!(store.list_pending_frs().unwrap().is_empty(), "pending FR must be deleted after promote");
    // Signal participant should exist
    assert!(store.load_signal_participant("peer-sig-1").unwrap().is_some(), "participant must exist after promote");
}
```

- [ ] **Step 2: Run test — expect PASS (existing behavior works)**

Run: `cargo test --package libkeychat -- test_promote_pending_fr_is_atomic`
Expected: PASS (current code works functionally, just not transactionally)

- [ ] **Step 3: Wrap promote_pending_fr in transaction**

```rust
pub fn promote_pending_fr(&self, request_id: &str, peer_signal_id: &str) -> Result<()> {
    self.transaction(|_conn| {
        if let Some((
            device_id, id_pub, id_priv, reg_id,
            spk_id, spk_rec, pk_id, pk_rec, kpk_id, kpk_rec,
            _first_inbox, _peer_nostr,
        )) = self.load_pending_fr(request_id)?
        {
            self.save_signal_participant(
                peer_signal_id, device_id,
                &id_pub, &id_priv, reg_id,
                spk_id, &spk_rec, pk_id, &pk_rec, kpk_id, &kpk_rec,
            )?;
            self.delete_pending_fr(request_id)?;
        }
        Ok(())
    })
}
```

- [ ] **Step 4: Wrap delete_peer_data in transaction**

```rust
pub fn delete_peer_data(&self, signal_id: &str, nostr_pubkey: &str) -> Result<()> {
    self.transaction(|conn| {
        conn.execute(
            "DELETE FROM signal_sessions WHERE address = ?1",
            rusqlite::params![signal_id],
        ).map_err(|e| KeychatError::Storage(format!("Failed to delete sessions: {e}")))?;
        conn.execute(
            "DELETE FROM signal_participants WHERE peer_signal_id = ?1",
            rusqlite::params![signal_id],
        ).map_err(|e| KeychatError::Storage(format!("Failed to delete signal participant: {e}")))?;
        conn.execute(
            "DELETE FROM peer_mappings WHERE nostr_pubkey = ?1",
            rusqlite::params![nostr_pubkey],
        ).map_err(|e| KeychatError::Storage(format!("Failed to delete peer mapping: {e}")))?;
        conn.execute(
            "DELETE FROM peer_addresses WHERE peer_signal_id = ?1",
            rusqlite::params![signal_id],
        ).map_err(|e| KeychatError::Storage(format!("Failed to delete peer addresses: {e}")))?;
        Ok(())
    })
}
```

- [ ] **Step 5: Run tests — expect PASS**

Run: `cargo test --package libkeychat -- test_promote_pending_fr_is_atomic`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add libkeychat/src/storage.rs
git commit -m "fix: wrap promote_pending_fr and delete_peer_data in transactions"
```

---

### Task 3: Zeroize key types properly (Findings #2, #3, #9)

**Files:**
- Modify: `libkeychat/Cargo.toml`
- Modify: `libkeychat/src/signal_keys.rs`
- Modify: `libkeychat/src/signal_session.rs`
- Modify: `libkeychat/src/address.rs`
- Modify: `libkeychat/src/storage.rs` (DerivedAddressSerialized)

- [ ] **Step 1: Enable zeroize derive feature**

In `libkeychat/Cargo.toml`, change:
```toml
zeroize = { version = "1", features = ["derive"] }
```

- [ ] **Step 2: Write test for SignalPreKeyMaterial zeroize**

In `libkeychat/src/signal_session.rs` test section (or storage.rs tests):
```rust
#[test]
fn test_signal_prekey_material_implements_zeroize() {
    use zeroize::Zeroize;
    let mut keys = generate_prekey_material().unwrap();
    let reg_id_before = keys.registration_id;
    assert_ne!(reg_id_before, 0);
    keys.zeroize();
    assert_eq!(keys.registration_id, 0, "registration_id must be zeroed");
}
```

- [ ] **Step 3: Run test — expect FAIL**

Run: `cargo test --package libkeychat -- test_signal_prekey_material_implements_zeroize`
Expected: FAIL — Zeroize not implemented

- [ ] **Step 4: Add Zeroize + ZeroizeOnDrop to key types**

In `libkeychat/src/signal_keys.rs`, replace manual Drop impls with derives:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignalIdentity {
    pub private_key: [u8; 32],
    #[zeroize(skip)]
    pub public_key: [u8; 33],
}
// Remove the manual Drop impl for SignalIdentity

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignedPrekey {
    #[zeroize(skip)]
    pub id: u32,
    #[zeroize(skip)]
    pub public_key: [u8; 33],
    #[zeroize(skip)]
    pub signature: Vec<u8>,
    pub private_key: [u8; 32],
}
// Remove the manual Drop impl for SignedPrekey

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OneTimePrekey {
    #[zeroize(skip)]
    pub id: u32,
    #[zeroize(skip)]
    pub public_key: [u8; 33],
    pub private_key: [u8; 32],
}
// Remove the manual Drop impl for OneTimePrekey

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KyberPrekey {
    #[zeroize(skip)]
    pub id: u32,
    #[zeroize(skip)]
    pub public_key: Vec<u8>,
    #[zeroize(skip)]
    pub signature: Vec<u8>,
    pub secret_key: Vec<u8>,
}
// Remove the manual Drop impl for KyberPrekey
```

- [ ] **Step 5: Add Zeroize to SignalPreKeyMaterial**

In `libkeychat/src/signal_session.rs`:
```rust
use zeroize::Zeroize;

impl Zeroize for SignalPreKeyMaterial {
    fn zeroize(&mut self) {
        self.registration_id = 0;
        // IdentityKeyPair, PreKeyRecord, etc. are libsignal types
        // that don't implement Zeroize — we zero what we can.
    }
}

impl Drop for SignalPreKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}
```

- [ ] **Step 6: Add Zeroize to DerivedAddress**

In `libkeychat/src/address.rs`:
```rust
use zeroize::Zeroize;

impl Drop for DerivedAddress {
    fn drop(&mut self) {
        self.secret_key.zeroize();
        self.ratchet_key.zeroize();
    }
}
```

And in `libkeychat/src/storage.rs` for `DerivedAddressSerialized`:
```rust
use zeroize::Zeroize;

impl Drop for DerivedAddressSerialized {
    fn drop(&mut self) {
        self.secret_key.zeroize();
        self.ratchet_key.zeroize();
    }
}
```

- [ ] **Step 7: Run tests — expect PASS**

Run: `cargo test --package libkeychat`
Expected: All 242+ tests pass

- [ ] **Step 8: Commit**

```bash
git add libkeychat/Cargo.toml libkeychat/src/signal_keys.rs libkeychat/src/signal_session.rs libkeychat/src/address.rs libkeychat/src/storage.rs
git commit -m "fix: add ZeroizeOnDrop to key types, Zeroize to SignalPreKeyMaterial and DerivedAddress"
```

---

### Task 4: Remove dead code + document block_on invariant (Findings #4, #6)

**Files:**
- Modify: `libkeychat/src/signal_store.rs`

- [ ] **Step 1: Remove dead `sender_public` field from RatchetSnapshot**

In `libkeychat/src/signal_store.rs`, change:
```rust
#[derive(Clone, Debug, Default)]
struct RatchetSnapshot {
    sender_private: Option<String>,
    their_public: Option<String>,
}
```
Remove `sender_public: Option<String>` field and any code that writes to it.

- [ ] **Step 2: Add doc comment on block_on invariant**

Add to the top of `signal_store.rs`:
```rust
//! # SAFETY: block_on usage
//!
//! This module uses `futures::executor::block_on()` to call async libsignal
//! store trait methods from synchronous contexts. This is safe ONLY because
//! the `Persistent*Store` backends perform synchronous SQLite I/O behind the
//! async facade — they never yield. If libsignal changes its stores to be
//! truly async (e.g., network-backed), these calls WILL deadlock under tokio.
//! In that case, replace with `tokio::task::block_in_place`.
```

- [ ] **Step 3: Run tests — expect PASS**

Run: `cargo test --package libkeychat`
Expected: All tests pass, `sender_public` warning gone

- [ ] **Step 4: Commit**

```bash
git add libkeychat/src/signal_store.rs
git commit -m "refactor: remove dead sender_public field, document block_on safety invariant"
```

---

### Task 5: Timestamp replay protection on SignalPrekeyAuth (Finding #13)

**Files:**
- Modify: `libkeychat/src/chat.rs`

- [ ] **Step 1: Write failing test**

In `libkeychat/src/chat.rs` tests:
```rust
#[test]
fn test_verify_prekey_auth_rejects_stale_timestamp() {
    use crate::signal_keys::compute_global_sign;

    let identity = Identity::generate().unwrap().identity;
    let nostr_pubkey = identity.pubkey_hex();
    let signal_pubkey = "05aabbccdd"; // dummy signal key

    // Create auth with timestamp 10 minutes in the past
    let stale_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        - 600_001; // 10 min + 1ms ago

    let sig = compute_global_sign(
        identity.secret_key(), &nostr_pubkey, signal_pubkey, stale_time,
    ).unwrap();

    let auth = SignalPrekeyAuth {
        nostr_id: nostr_pubkey.clone(),
        signal_id: signal_pubkey.into(),
        time: stale_time,
        name: "test".into(),
        sig,
        avatar: None,
        lightning: None,
    };

    let result = verify_signal_prekey_auth(&auth);
    assert!(result.is_err(), "stale prekey auth (>10 min old) must be rejected");
}

#[test]
fn test_verify_prekey_auth_accepts_fresh_timestamp() {
    use crate::signal_keys::compute_global_sign;

    let identity = Identity::generate().unwrap().identity;
    let nostr_pubkey = identity.pubkey_hex();
    let signal_pubkey = "05aabbccdd";

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let sig = compute_global_sign(
        identity.secret_key(), &nostr_pubkey, signal_pubkey, now_ms,
    ).unwrap();

    let auth = SignalPrekeyAuth {
        nostr_id: nostr_pubkey.clone(),
        signal_id: signal_pubkey.into(),
        time: now_ms,
        name: "test".into(),
        sig,
        avatar: None,
        lightning: None,
    };

    let result = verify_signal_prekey_auth(&auth);
    assert!(result.is_ok(), "fresh prekey auth must be accepted");
}
```

- [ ] **Step 2: Run tests — expect stale test FAIL**

Run: `cargo test --package libkeychat -- test_verify_prekey_auth`
Expected: `test_verify_prekey_auth_rejects_stale_timestamp` FAIL, fresh one PASS

- [ ] **Step 3: Add timestamp validation to verify_signal_prekey_auth**

In `libkeychat/src/chat.rs`, add before the signature check:
```rust
// Reject stale timestamps (replay protection: 10-minute window)
const MAX_AUTH_AGE_MS: u64 = 10 * 60 * 1000; // 10 minutes
let now_ms = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis() as u64;
if now_ms.saturating_sub(auth.time) > MAX_AUTH_AGE_MS {
    return Err(KeychatError::Signal(format!(
        "SignalPrekeyAuth timestamp too old: {}ms ago (max {}ms)",
        now_ms.saturating_sub(auth.time),
        MAX_AUTH_AGE_MS
    )));
}
// Also reject timestamps from the future (clock skew tolerance: 2 min)
const MAX_FUTURE_MS: u64 = 2 * 60 * 1000;
if auth.time.saturating_sub(now_ms) > MAX_FUTURE_MS {
    return Err(KeychatError::Signal(format!(
        "SignalPrekeyAuth timestamp too far in future: {}ms ahead",
        auth.time.saturating_sub(now_ms)
    )));
}
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `cargo test --package libkeychat -- test_verify_prekey_auth`
Expected: Both tests PASS

- [ ] **Step 5: Commit**

```bash
git add libkeychat/src/chat.rs
git commit -m "fix: add timestamp replay protection to SignalPrekeyAuth verification"
```

---

### Task 6: Strict device_id validation (Finding #8)

**Files:**
- Modify: `libkeychat/src/friend_request.rs`

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn test_device_id_overflow_rejected() {
    // device_id 256 would silently truncate to 0 via `as u8`, which is invalid
    // We want an explicit error, not a silent fallback
    let parsed: u32 = 256;
    let result = super::validate_device_id(parsed);
    assert!(result.is_err(), "device_id 256 must be rejected, not silently truncated");
}

#[test]
fn test_device_id_valid_range() {
    for id in [1u32, 2, 50, 127] {
        let result = super::validate_device_id(id);
        assert!(result.is_ok(), "device_id {id} should be valid");
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

Expected: FAIL — `validate_device_id` doesn't exist yet

- [ ] **Step 3: Extract validation function and use Result instead of fallback**

In `libkeychat/src/friend_request.rs`:
```rust
/// Validate and convert a u32 device_id to DeviceId.
/// Returns error if out of valid Signal range (1..=127).
pub(crate) fn validate_device_id(id: u32) -> Result<DeviceId> {
    if id == 0 || id > 127 {
        return Err(KeychatError::Signal(format!(
            "device_id {id} out of valid range 1..=127"
        )));
    }
    DeviceId::new(id as u8)
        .map_err(|e| KeychatError::Signal(format!("invalid device_id {id}: {e}")))
}
```

Then update the parsing site:
```rust
let remote_device_id: u32 = payload.device_id.parse().map_err(|_| {
    KeychatError::Signal(format!("device_id parse failed for '{}'", payload.device_id))
})?;
let device_id = validate_device_id(remote_device_id)?;
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `cargo test --package libkeychat -- test_device_id`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add libkeychat/src/friend_request.rs
git commit -m "fix: strict device_id validation, reject out-of-range instead of silent fallback"
```

---

### Task 7: Cache Secp256k1 context (Finding #12)

**Files:**
- Modify: `libkeychat/src/signal_keys.rs`

- [ ] **Step 1: Add cached Secp256k1 context**

In `libkeychat/src/signal_keys.rs`, add a `once_cell::sync::Lazy` or `std::sync::LazyLock` for the signing context:

```rust
use std::sync::LazyLock;
use nostr::secp256k1::Secp256k1;

/// Cached secp256k1 context for Schnorr signing.
/// Secp256k1::new() allocates ~500KB — reuse across calls.
static SECP_SIGNING: LazyLock<Secp256k1<nostr::secp256k1::All>> =
    LazyLock::new(Secp256k1::new);
```

Then in `compute_global_sign`, replace:
```rust
let secp = Secp256k1::new();
```
with:
```rust
let secp = &*SECP_SIGNING;
```

- [ ] **Step 2: Run tests — expect PASS**

Run: `cargo test --package libkeychat`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add libkeychat/src/signal_keys.rs
git commit -m "perf: cache Secp256k1 context to avoid repeated ~500KB allocation"
```

---

### Task 8: Run full test suite and clippy

- [ ] **Step 1: Run all tests**

```bash
cargo test
```
Expected: All tests pass (242+ libkeychat, 21+ uniffi, 13 integration)

- [ ] **Step 2: Run clippy**

```bash
cargo clippy --package libkeychat --package keychat-uniffi
```
Expected: No errors, warnings only for pre-existing dead code

- [ ] **Step 3: Build release**

```bash
cargo build -p keychat-cli --release
```
Expected: Build succeeds
