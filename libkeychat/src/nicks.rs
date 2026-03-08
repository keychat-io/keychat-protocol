use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Simple nickname store: hex_pubkey -> nickname, persisted as JSON next to the DB.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NickStore {
    path: PathBuf,
    nicks: HashMap<String, String>,
}

impl NickStore {
    pub fn load(db_path: &str) -> Self {
        let path = Path::new(db_path).with_extension("nicks.json");
        let nicks = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path, nicks }
    }

    pub fn save(&self) -> DynResult<()> {
        let json = serde_json::to_string_pretty(&self.nicks)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    pub fn set(&mut self, hex: &str, nick: &str) {
        self.nicks.insert(hex.to_owned(), nick.to_owned());
    }

    pub fn get(&self, hex: &str) -> Option<&str> {
        self.nicks.get(hex).map(|s| s.as_str())
    }

    pub fn remove(&mut self, hex: &str) {
        self.nicks.remove(hex);
    }

    /// Resolve a nickname to hex pubkey. Returns None if not found.
    pub fn resolve(&self, name: &str) -> Option<String> {
        for (hex, nick) in &self.nicks {
            if nick.eq_ignore_ascii_case(name) {
                return Some(hex.clone());
            }
        }
        None
    }

    /// Get display name: nickname if set, otherwise truncated hex.
    pub fn display(&self, hex: &str) -> String {
        if let Some(nick) = self.get(hex) {
            nick.to_owned()
        } else {
            truncate(hex, 12).to_owned()
        }
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
}
