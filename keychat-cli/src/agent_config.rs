//! Headless-friendly secret resolution for agent mode.
//!
//! Each secret follows the same priority chain:
//! 1. Environment variable (container/CI injection)
//! 2. Secrets file in data directory (persistent volume)
//! 3. OS keyring or fallback (desktop environment)
//! 4. Auto-generate and persist

use std::fs;
use std::path::Path;

use crate::commands;

const SECRETS_DIR: &str = "secrets";

// ─── DB Encryption Key ─────────────────────────────────────────

/// Resolve the database encryption key.
///
/// Priority:
/// 1. `KEYCHAT_DB_KEY` env var (container/CI injection)
/// 2. System keychain (via commands::get_or_create_db_key, which also handles legacy file migration)
pub fn resolve_db_key(data_dir: &str) -> anyhow::Result<String> {
    // 1. Environment variable
    if let Ok(key) = std::env::var("KEYCHAT_DB_KEY") {
        let key = key.trim().to_string();
        if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
            tracing::info!("DB key loaded from KEYCHAT_DB_KEY env var");
            return Ok(key);
        }
        tracing::warn!("KEYCHAT_DB_KEY env var invalid (expected 64 hex chars), trying next source");
    }

    // 2. Keychain (handles legacy file migration internally)
    commands::get_or_create_db_key(data_dir)
}

// ─── Mnemonic (Identity) ───────────────────────────────────────

/// Resolve mnemonic for identity restoration.
///
/// Priority:
/// 1. `KEYCHAT_MNEMONIC` env var
/// 2. `{data_dir}/secrets/mnemonic` file
/// 3. `None` (caller should check DB or create new identity)
pub fn resolve_mnemonic(data_dir: &str) -> anyhow::Result<Option<String>> {
    // 1. Environment variable
    if let Ok(mnemonic) = std::env::var("KEYCHAT_MNEMONIC") {
        let mnemonic = mnemonic.trim().to_string();
        if !mnemonic.is_empty() {
            tracing::info!("Mnemonic loaded from KEYCHAT_MNEMONIC env var");
            return Ok(Some(mnemonic));
        }
    }

    // 2. System keychain (macOS Keychain / Linux keyring)
    match crate::secrets::retrieve("mnemonic") {
        Ok(Some(mnemonic)) if !mnemonic.is_empty() => {
            tracing::info!("Mnemonic loaded from system keychain");
            return Ok(Some(mnemonic));
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("Keychain mnemonic read failed: {e}"),
    }

    // 3. Not found — caller decides what to do
    Ok(None)
}

/// Persist mnemonic to system keychain only (never to file).
pub fn save_mnemonic(_data_dir: &str, mnemonic: &str) -> anyhow::Result<()> {
    match crate::secrets::store("mnemonic", mnemonic) {
        Ok(true) => {
            tracing::info!("Mnemonic stored in system keychain");
            Ok(())
        }
        Ok(false) => Err(anyhow::anyhow!("System keychain not available — cannot store mnemonic securely")),
        Err(e) => Err(anyhow::anyhow!("Keychain store failed: {e}")),
    }
}

// ─── API Token ─────────────────────────────────────────────────

/// Resolve the API authentication token.
///
/// Priority:
/// 1. CLI `--api-token` argument
/// 2. `KEYCHAT_API_TOKEN` env var
/// 3. `{data_dir}/secrets/api-token` file
/// 4. Auto-generate and persist
pub fn resolve_api_token(data_dir: &str, cli_override: Option<&str>) -> anyhow::Result<String> {
    // 1. CLI argument
    if let Some(token) = cli_override {
        let token = token.trim().to_string();
        if !token.is_empty() {
            tracing::info!("API token provided via CLI argument");
            return Ok(token);
        }
    }

    // 2. Environment variable
    if let Ok(token) = std::env::var("KEYCHAT_API_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            tracing::info!("API token loaded from KEYCHAT_API_TOKEN env var");
            return Ok(token);
        }
    }

    // 3. Secrets file
    if let Some(token) = read_secret_file(data_dir, "api-token")? {
        if !token.is_empty() {
            tracing::info!("API token loaded from secrets/api-token");
            return Ok(token);
        }
    }

    // 4. Auto-generate
    let token = generate_api_token()?;
    write_secret_file(data_dir, "api-token", &token)?;
    tracing::info!("Generated new API token, saved to secrets/api-token");
    Ok(token)
}

/// Generate an API token with `kc_` prefix + 32 hex chars.
fn generate_api_token() -> anyhow::Result<String> {
    let mut buf = [0u8; 16];

    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = fs::File::open("/dev/urandom")?;
        f.read_exact(&mut buf)?;
    }

    #[cfg(not(unix))]
    {
        compile_error!("keychat-cli requires Unix for /dev/urandom");
    }

    Ok(format!("kc_{}", commands::bytes_to_hex(&buf)))
}

// ─── File Helpers ──────────────────────────────────────────────

/// Read a secret from `{data_dir}/secrets/{name}`.
fn read_secret_file(data_dir: &str, name: &str) -> anyhow::Result<Option<String>> {
    let path = Path::new(data_dir).join(SECRETS_DIR).join(name);
    if path.exists() {
        let content = fs::read_to_string(&path)?.trim().to_string();
        if !content.is_empty() {
            return Ok(Some(content));
        }
    }
    Ok(None)
}

/// Write a secret to `{data_dir}/secrets/{name}` with restricted permissions.
fn write_secret_file(data_dir: &str, name: &str, value: &str) -> anyhow::Result<()> {
    let secrets_dir = Path::new(data_dir).join(SECRETS_DIR);

    if !secrets_dir.exists() {
        fs::create_dir_all(&secrets_dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&secrets_dir, fs::Permissions::from_mode(0o700)) {
                tracing::warn!("Failed to set secrets dir permissions: {e}");
            }
        }
    }

    let path = secrets_dir.join(name);
    fs::write(&path, value)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            tracing::warn!("Failed to set {name} file permissions: {e}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        // Initially no file
        assert!(read_secret_file(data_dir, "test-key").unwrap().is_none());

        // Write and read back
        write_secret_file(data_dir, "test-key", "hello123").unwrap();
        let val = read_secret_file(data_dir, "test-key").unwrap();
        assert_eq!(val, Some("hello123".to_string()));
    }

    #[test]
    fn test_generate_api_token() {
        let token = generate_api_token().unwrap();
        assert!(token.starts_with("kc_"), "token should have kc_ prefix");
        assert_eq!(token.len(), 3 + 32, "kc_ + 32 hex chars");
        assert!(token[3..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_resolve_api_token_cli_override() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        let token = resolve_api_token(data_dir, Some("my-custom-token")).unwrap();
        assert_eq!(token, "my-custom-token");
    }

    #[test]
    fn test_resolve_api_token_auto_generate() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        // No CLI, no env, no file → auto-generate
        let token1 = resolve_api_token(data_dir, None).unwrap();
        assert!(token1.starts_with("kc_"));

        // Second call reads from file
        let token2 = resolve_api_token(data_dir, None).unwrap();
        assert_eq!(token1, token2, "should return same token from file");
    }

    #[test]
    fn test_resolve_mnemonic_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        // No mnemonic
        assert!(resolve_mnemonic(data_dir).unwrap().is_none());

        // Write mnemonic
        save_mnemonic(data_dir, "word1 word2 word3").unwrap();
        let m = resolve_mnemonic(data_dir).unwrap();
        assert_eq!(m, Some("word1 word2 word3".to_string()));
    }

    #[test]
    fn test_secrets_dir_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();

        write_secret_file(data_dir, "test", "value").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let secrets_dir = dir.path().join(SECRETS_DIR);
            let dir_mode = fs::metadata(&secrets_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "secrets dir should be 0700");

            let file_mode = fs::metadata(secrets_dir.join("test"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o600, "secret file should be 0600");
        }
    }
}
