# keychat-cli-agent Secret Storage — Security Audit & Fix Plan

> Date: 2026-03-29
> Severity: High
> Scope: `keychat-cli-agent/src/config.rs` + `multi_agent.rs`

## Current Issues

### 1. Plaintext mnemonic on disk (Critical)

`multi_agent.rs:99`:
```rust
std::fs::write(secrets_dir.join("mnemonic"), &gen.mnemonic)?;
```

BIP-39 mnemonic (root of all identity) written as plaintext file. Any process running as the same user can read it. Confirmed accessible by LLM agent on the same host.

**Evidence**: `/Users/kc/.openclaw/workspace/vending-machine-agent/vma-data/secrets/mnemonic` — 72 bytes, plaintext, readable by agent process.

### 2. Plaintext DB key on disk (High)

`multi_agent.rs:109`:
```rust
std::fs::write(secrets_dir.join("dbkey"), &db_key)?;
```

SQLCipher encryption key written as plaintext. With this key + the `.db` file, all Signal session state and ratchet keys are exposed.

### 3. Environment variable as primary secret source (High)

`config.rs` `load_mnemonic()` / `load_db_key()`:
```rust
if let Ok(m) = std::env::var("KEYCHAT_MNEMONIC") { return Ok(m) }
```

Environment variables are the **first** resolution path, above Keychain. Problems:
- `/proc/<pid>/environ` readable by same-user processes (Linux)
- `ps eww` exposes env vars
- Container orchestrators often log env vars
- Crash/core dumps include environment

### 4. Misleading security comments

File header says:
> **Security**: Mnemonic and DB encryption key are stored in the OS keychain

But code prioritizes env vars and plaintext files over Keychain.

### 5. Load order inverted

Current: env var → plaintext file → Keychain (least secure first)
Should be: Keychain → encrypted file → error

### 6. No zeroize on key material

`generate_db_key()` leaves key bytes on stack after function return.

---

## Fix Plan

### Phase 1: Reverse load order + encrypt files

1. **Load order**: Keychain → encrypted file → error (no env var path)
2. **Store order**: Keychain (if available) → encrypted file (with warning)
3. **File encryption**: ChaCha20-Poly1305, key derived from `machine-id + pubkey`
4. **Migration**: detect plaintext `secrets/mnemonic`, encrypt in place, delete plaintext
5. **Warning**: log warning when Keychain unavailable and falling back to encrypted file

### Phase 2: Cleanup

6. **Remove** `KEYCHAT_MNEMONIC` / `KEYCHAT_DB_KEY` env var paths
7. **Fix comments** to match actual behavior
8. **Add zeroize** to `generate_db_key()` and `load_*` return paths
9. **Update spec** §2.1 Key Storage Security to reflect actual implementation

### Files to modify

| File | Changes |
|------|---------|
| `keychat-cli-agent/src/config.rs` | Rewrite `load_mnemonic`, `load_db_key`, `store_mnemonic`, `store_db_key`. Add `keyring_available()`, `derive_file_key()`, `encrypt_secret()`, `decrypt_secret()`. Remove env var paths. |
| `keychat-cli-agent/src/multi_agent.rs` | Replace `std::fs::write(secrets_dir.join("mnemonic"), ...)` with `config::store_mnemonic()`. Same for dbkey. Remove direct file writes. |
| `keychat-cli-agent/Cargo.toml` | Add `chacha20poly1305` dependency (or reuse existing `chacha20` + `poly1305`) |

### Affected deployments

| Environment | Current | After fix |
|-------------|---------|-----------|
| macOS (dev) | Keychain works, but plaintext file also written | Keychain only, no file |
| Linux desktop | Keychain works (libsecret), plaintext file also written | Keychain only, no file |
| Linux VPS (headless) | Keychain fails silently, plaintext file is sole storage | Encrypted file + warning |
| Docker | Env var or plaintext file | Encrypted file + warning |

### Testing

- [ ] macOS: verify Keychain-only path, no file created
- [ ] Linux with keyring daemon: same as macOS
- [ ] Linux without keyring: verify encrypted file created + warning logged
- [ ] Migration: place plaintext `secrets/mnemonic`, run agent, verify it's encrypted + plaintext deleted
- [ ] Wrong machine: copy encrypted file to different host, verify decryption fails
