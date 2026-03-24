//! Multi-agent daemon — manages multiple independent agent identities
//! in a single process.
//!
//! Directory layout:
//!   <root>/agents/<agent_id>/config.json   — non-sensitive config
//!   <root>/agents/<agent_id>/keychat.db    — encrypted database
//!   OS Keychain: mnemonic:<pubkey>, dbkey:<pubkey>
//!
//! Each agent has its own Nostr client, Signal sessions, and address manager.
//! Adding a new agent: POST /agents or create a directory — daemon auto-detects.

use anyhow::{Context, Result};
use nostr::nips::nip19::ToBech32;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::chat::{self, IncomingEvent};
use crate::config::{self, Config};
use crate::state::AppState;

/// Metadata for a running agent.
pub struct AgentHandle {
    pub id: String,
    pub npub: String,
    pub name: String,
    pub state: Arc<AppState>,
}

/// Manages multiple agents in a single daemon.
pub struct MultiAgentManager {
    root_dir: PathBuf,
    agents: Arc<RwLock<HashMap<String, AgentHandle>>>,
    event_tx: broadcast::Sender<AgentEvent>,
    relay_urls: Vec<String>,
}

/// An event tagged with its source agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentEvent {
    pub agent_id: String,
    pub agent_npub: String,
    #[serde(flatten)]
    pub event: IncomingEvent,
}

impl MultiAgentManager {
    pub fn new(root_dir: &Path, relay_urls: Vec<String>) -> Self {
        let (event_tx, _) = broadcast::channel::<AgentEvent>(512);
        Self {
            root_dir: root_dir.to_path_buf(),
            agents: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            relay_urls,
        }
    }

    pub fn event_tx(&self) -> &broadcast::Sender<AgentEvent> {
        &self.event_tx
    }

    /// Scan the agents/ directory and start all found agents.
    pub async fn load_all(&self) -> Result<()> {
        let agents_dir = self.root_dir.join("agents");
        std::fs::create_dir_all(&agents_dir)?;

        let mut entries: Vec<_> = std::fs::read_dir(&agents_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let agent_id = entry.file_name().to_string_lossy().to_string();
            if let Err(e) = self.start_agent(&agent_id).await {
                eprintln!("  ⚠️  Failed to start agent '{}': {}", agent_id, e);
            }
        }
        Ok(())
    }

    /// Create and start a new agent.
    pub async fn create_agent(&self, agent_id: &str, name: &str) -> Result<String> {
        let agent_dir = self.root_dir.join("agents").join(agent_id);
        if agent_dir.exists() {
            anyhow::bail!("Agent '{}' already exists", agent_id);
        }
        std::fs::create_dir_all(&agent_dir)?;

        // Generate identity
        let gen = libkeychat::Identity::generate()?;
        let pubkey_hex = gen.identity.pubkey_hex();

        // Store secrets in files (daemon-friendly) + best-effort keychain
        let secrets_dir = agent_dir.join("secrets");
        std::fs::create_dir_all(&secrets_dir)?;

        std::fs::write(secrets_dir.join("mnemonic"), &gen.mnemonic)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                secrets_dir.join("mnemonic"),
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        let _ = config::store_mnemonic(&pubkey_hex, &gen.mnemonic);

        let db_key = config::generate_db_key();
        std::fs::write(secrets_dir.join("dbkey"), &db_key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                secrets_dir.join("dbkey"),
                std::fs::Permissions::from_mode(0o600),
            )?;
        }
        let _ = config::store_db_key(&pubkey_hex, &db_key);

        // Write config (no secrets)
        let config = Config {
            name: name.to_string(),
            relays: self.relay_urls.clone(),
            auto_accept_friends: true,
            owner: None,
            pubkey_hex: Some(pubkey_hex.clone()),
        };
        config.save(&agent_dir)?;

        // Start it
        self.start_agent(agent_id).await?;

        Ok(pubkey_hex)
    }

    /// Start an existing agent from its directory.
    async fn start_agent(&self, agent_id: &str) -> Result<()> {
        let agent_dir = self.root_dir.join("agents").join(agent_id);

        // Set KEYCHAT_DATA_DIR for secrets file fallback (headless/daemon mode)
        std::env::set_var("KEYCHAT_DATA_DIR", &agent_dir);

        // If no config.json but secrets/mnemonic exists, do first-run setup
        let config = match Config::load(&agent_dir)? {
            Some(c) => c,
            None => {
                let mnemonic_file = agent_dir.join("secrets").join("mnemonic");
                if mnemonic_file.exists() {
                    let m = std::fs::read_to_string(&mnemonic_file)?.trim().to_string();
                    let id = libkeychat::Identity::from_mnemonic_str(&m)?;
                    let pubkey_hex = id.pubkey_hex();

                    // Generate DB key if missing
                    let dbkey_file = agent_dir.join("secrets").join("dbkey");
                    if !dbkey_file.exists() {
                        let dk = config::generate_db_key();
                        std::fs::write(&dbkey_file, &dk)?;
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(
                                &dbkey_file,
                                std::fs::Permissions::from_mode(0o600),
                            )?;
                        }
                    }

                    let config = Config {
                        name: agent_id.to_string(),
                        relays: self.relay_urls.clone(),
                        auto_accept_friends: true,
                        owner: None,
                        pubkey_hex: Some(pubkey_hex),
                    };
                    config.save(&agent_dir)?;
                    config
                } else {
                    anyhow::bail!("No config.json or secrets/mnemonic in agent '{}'", agent_id);
                }
            }
        };

        let pubkey_hex = config
            .pubkey_hex
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("config.json missing pubkey_hex"))?;

        // Load secrets (env → file → keychain)
        let mnemonic = config::load_mnemonic(pubkey_hex)
            .context(format!("Failed to load mnemonic for agent '{}'", agent_id))?;
        let db_key = config::load_db_key(pubkey_hex)
            .unwrap_or_else(|_| "keychat-cli-default-key".to_string());

        let identity = libkeychat::Identity::from_mnemonic_str(&mnemonic)?;
        let npub = identity.pubkey_hex();

        let app_state = Arc::new(
            AppState::new(
                identity,
                config.clone(),
                &self.relay_urls,
                &agent_dir,
                &db_key,
            )
            .await?,
        );

        // Start background listener
        let listener_state = app_state.clone();
        let event_tx = self.event_tx.clone();
        let aid = agent_id.to_string();
        let anpub = npub.clone();
        tokio::spawn(async move {
            // Create a per-agent broadcast channel for chat::start_listener
            let (agent_tx, mut agent_rx) = broadcast::channel::<IncomingEvent>(256);

            // Forward agent events to the multi-agent event bus
            let aid2 = aid.clone();
            let anpub2 = anpub.clone();
            tokio::spawn(async move {
                loop {
                    match agent_rx.recv().await {
                        Ok(ev) => {
                            let _ = event_tx.send(AgentEvent {
                                agent_id: aid2.clone(),
                                agent_npub: anpub2.clone(),
                                event: ev,
                            });
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
            });

            chat::start_listener(listener_state, agent_tx).await;
        });

        let handle = AgentHandle {
            id: agent_id.to_string(),
            npub: npub.clone(),
            name: config.name.clone(),
            state: app_state,
        };

        self.agents
            .write()
            .await
            .insert(agent_id.to_string(), handle);
        eprintln!("  ✅ Agent '{}' started (npub: {})", agent_id, &npub[..16]);
        Ok(())
    }

    /// Get a reference to an agent's state.
    pub async fn get_agent(&self, agent_id: &str) -> Option<Arc<AppState>> {
        self.agents
            .read()
            .await
            .get(agent_id)
            .map(|h| h.state.clone())
    }

    /// List all running agents.
    pub async fn list_agents(&self) -> Vec<AgentInfo> {
        self.agents
            .read()
            .await
            .values()
            .map(|h| {
                let bech32 = nostr::prelude::PublicKey::from_hex(&h.npub)
                    .map(|pk| pk.to_bech32().unwrap_or_else(|_| h.npub.clone()))
                    .unwrap_or_else(|_| h.npub.clone());
                AgentInfo {
                    id: h.id.clone(),
                    npub_hex: h.npub.clone(),
                    npub: bech32,
                    name: h.name.clone(),
                }
            })
            .collect()
    }

    /// Watch for new agent directories and auto-start them.
    pub async fn watch_new_agents(self: Arc<Self>) {
        let agents_dir = self.root_dir.join("agents");
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            let Ok(entries) = std::fs::read_dir(&agents_dir) else {
                continue;
            };
            for entry in entries.filter_map(|e| e.ok()) {
                if !entry.path().is_dir() {
                    continue;
                }
                let agent_id = entry.file_name().to_string_lossy().to_string();

                // Skip if already running
                if self.agents.read().await.contains_key(&agent_id) {
                    continue;
                }

                // New directory detected — try to start
                if entry.path().join("config.json").exists() {
                    eprintln!("  🔍 Detected new agent: {}", agent_id);
                    if let Err(e) = self.start_agent(&agent_id).await {
                        eprintln!("  ⚠️  Failed to start new agent '{}': {}", agent_id, e);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub npub_hex: String,
    pub npub: String,
    pub name: String,
}
