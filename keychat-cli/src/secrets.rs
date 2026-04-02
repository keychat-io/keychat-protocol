//! Cross-platform keychain access via system CLI tools.
//!
//! macOS: Uses `security` CLI (no popup, no Keychain Access prompt)
//! Linux: Uses `secret-tool` (libsecret / GNOME Keyring)
//!
//! This avoids the Rust `keyring` crate which calls SecItemCopyMatching
//! on macOS — that API triggers authorization popups in headless environments.

use std::process::Command;

const SERVICE: &str = "keychat-cli";

/// Check if the system keychain is available.
pub fn is_available() -> bool {
    if cfg!(target_os = "macos") {
        Command::new("security")
            .arg("help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else if cfg!(target_os = "linux") {
        Command::new("which")
            .arg("secret-tool")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        false
    }
}

/// Store a value in the system keychain. Returns true on success.
pub fn store(key: &str, value: &str) -> anyhow::Result<bool> {
    if cfg!(target_os = "macos") {
        // -U flag updates if exists
        let output = Command::new("security")
            .args([
                "add-generic-password",
                "-a", key,
                "-s", SERVICE,
                "-w", value,
                "-U",
            ])
            .output()?;
        Ok(output.status.success())
    } else if cfg!(target_os = "linux") {
        let output = Command::new("secret-tool")
            .args([
                "store",
                "--label", SERVICE,
                "service", SERVICE,
                "account", key,
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(value.as_bytes())?;
                }
                child.wait_with_output()
            })?;
        Ok(output.status.success())
    } else {
        Ok(false)
    }
}

/// Retrieve a value from the system keychain.
pub fn retrieve(key: &str) -> anyhow::Result<Option<String>> {
    if cfg!(target_os = "macos") {
        // Step 1: Check if item exists (without -w, never blocks)
        let check = Command::new("security")
            .args([
                "find-generic-password",
                "-a", key,
                "-s", SERVICE,
            ])
            .output()?;
        if !check.status.success() {
            return Ok(None); // Item doesn't exist
        }

        // Step 2: Read value with -w (safe because item exists)
        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-a", key,
                "-s", SERVICE,
                "-w",
            ])
            .output()?;
        if output.status.success() {
            let value = String::from_utf8(output.stdout)?.trim().to_string();
            if !value.is_empty() {
                return Ok(Some(value));
            }
        }
        Ok(None)
    } else if cfg!(target_os = "linux") {
        let output = Command::new("secret-tool")
            .args([
                "lookup",
                "service", SERVICE,
                "account", key,
            ])
            .output()?;
        if output.status.success() {
            let value = String::from_utf8(output.stdout)?.trim().to_string();
            if !value.is_empty() {
                return Ok(Some(value));
            }
        }
        Ok(None)
    } else {
        Ok(None)
    }
}

/// Delete a value from the system keychain. Returns true on success.
pub fn delete(key: &str) -> anyhow::Result<bool> {
    if cfg!(target_os = "macos") {
        let output = Command::new("security")
            .args([
                "delete-generic-password",
                "-a", key,
                "-s", SERVICE,
            ])
            .output()?;
        Ok(output.status.success())
    } else if cfg!(target_os = "linux") {
        let output = Command::new("secret-tool")
            .args([
                "clear",
                "service", SERVICE,
                "account", key,
            ])
            .output()?;
        Ok(output.status.success())
    } else {
        Ok(false)
    }
}
