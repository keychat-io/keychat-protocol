use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command as ShellCommand;
use std::sync::Arc;

use clap::Parser;
use libkeychat::client::{ClientConfig, KeychatClient};
use libkeychat::nicks::NickStore;
use libkeychat::stamp::{NoopStampProvider, RelayStampFee, StampConfig, StampProvider};
use libkeychat::tui::{run, App, GroupRoom};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

type DynResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.keychat.io",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
];

const KEYCHAIN_SERVICE: &str = "io.keychat.tui";
const KEYCHAIN_ACCOUNT: &str = "mnemonic";

fn keychain_store(mnemonic: &str) -> DynResult<()> {
    // Try update-or-add with -U (no prompt if item exists)
    let output = ShellCommand::new("security")
        .args([
            "add-generic-password",
            "-s", KEYCHAIN_SERVICE,
            "-a", KEYCHAIN_ACCOUNT,
            "-w", mnemonic,
            "-U",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Failed to store in Keychain: {}",
            String::from_utf8_lossy(&output.stderr)
        ).into());
    }
    Ok(())
}

fn keychain_load() -> Option<String> {
    let output = ShellCommand::new("security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let mnemonic = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !mnemonic.is_empty() {
            Some(mnemonic)
        } else {
            None
        }
    } else {
        None
    }
}

/// Keychat TUI - split-pane terminal chat
#[derive(Parser)]
#[command(name = "keychat-tui", version, about)]
struct Cli {
    /// Path to the SQLite database
    #[arg(long, default_value = "keychat-tui.db")]
    db: String,

    /// Display name
    #[arg(long, default_value = "keychat-tui")]
    name: String,

    /// Relay URLs (comma-separated or repeated)
    #[arg(long)]
    relay: Vec<String>,

    /// BIP-39 mnemonic (overrides Keychain)
    #[arg(long)]
    mnemonic: Option<String>,

    /// Media server URL
    #[arg(long)]
    media_server: Option<String>,

    /// Stamp provider implementation (currently supports: noop)
    #[arg(long, default_value = "noop")]
    stamp_provider: String,

    /// Fixed stamp amount for all relays
    #[arg(long)]
    stamp_amount: Option<u64>,

    /// Cashu mint URL for fixed stamp config
    #[arg(long)]
    stamp_mint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StampFileConfig {
    relay_fees: BTreeMap<String, RelayStampFee>,
}

impl Cli {
    fn relays(&self) -> Vec<String> {
        if self.relay.is_empty() {
            DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            self.relay
                .iter()
                .flat_map(|r| r.split(',').map(|s| s.trim().to_string()))
                .collect()
        }
    }

    fn resolve_mnemonic(&self) -> Option<String> {
        if self.mnemonic.is_some() {
            return self.mnemonic.clone();
        }
        keychain_load()
    }

    fn config(&self) -> ClientConfig {
        ClientConfig {
            db_path: self.db.clone(),
            display_name: self.name.clone(),
            relays: self.relays(),
            mnemonic: self.resolve_mnemonic(),
            media_server: self.media_server.clone(),
        }
    }

    fn nick_store(&self) -> NickStore {
        NickStore::load(&self.db)
    }

    fn stamp_config_path(&self) -> PathBuf {
        let db = Path::new(&self.db);
        match db.parent() {
            Some(parent) => parent.join("keychat.stamps.json"),
            None => PathBuf::from("keychat.stamps.json"),
        }
    }

    fn groups_path(&self) -> PathBuf {
        let db = Path::new(&self.db);
        match db.parent() {
            Some(parent) => parent.join("keychat-tui.groups.json"),
            None => PathBuf::from("keychat-tui.groups.json"),
        }
    }

    fn mls_db_path(&self) -> PathBuf {
        let db = Path::new(&self.db);
        match db.parent() {
            Some(parent) => parent.join("keychat-tui.mls.sqlite"),
            None => PathBuf::from("keychat-tui.mls.sqlite"),
        }
    }
}

#[tokio::main]
async fn main() -> DynResult<()> {
    let cli = Cli::parse();

    // Auto-init: generate identity if none exists
    if cli.resolve_mnemonic().is_none() {
        eprintln!("🔑 No identity found. Generating a new one...");
        let client = KeychatClient::init(cli.config()).await?;
        if let Some(phrase) = client.mnemonic() {
            keychain_store(phrase)?;
            eprintln!("✅ Identity created: {}", client.npub().unwrap_or_default());
            eprintln!("🔐 Mnemonic stored in macOS Keychain (io.keychat.tui).");
            eprintln!("   Run 'security find-generic-password -s io.keychat.tui -a mnemonic -w' to export.\n");
        }
    }

    let mut client = init_client(&cli).await?;
    client
        .init_mls(cli.mls_db_path().to_string_lossy().as_ref())
        .await?;
    client.start_listening().await?;

    let nicks = cli.nick_store();
    let peers = client.peers();
    let groups = load_groups(&cli.groups_path())?;
    let self_npub = client.npub().unwrap_or_default();
    let self_pubkey_hex = client.pubkey_hex();
    let relay_count = cli.relays().len();
    let mut app = App::new(
        nicks,
        cli.name.clone(),
        self_npub,
        self_pubkey_hex,
        relay_count,
        peers,
        groups,
    );
    app.groups_path = Some(cli.groups_path());

    let client = Arc::new(Mutex::new(client));
    let app = run(app, client).await?;
    save_groups(&cli.groups_path(), &app.groups_snapshot())?;

    Ok(())
}

fn load_groups(path: &Path) -> DynResult<Vec<GroupRoom>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)?;
    let groups = serde_json::from_str::<Vec<GroupRoom>>(&raw)?;
    Ok(groups)
}

fn save_groups(path: &Path, groups: &[GroupRoom]) -> DynResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(groups)?;
    std::fs::write(path, json)?;
    Ok(())
}

fn validate_stamp_flags(cli: &Cli) -> DynResult<()> {
    match (cli.stamp_amount, cli.stamp_mint.as_deref()) {
        (Some(_), Some(_)) | (None, None) => {}
        (Some(_), None) => {
            return Err("`--stamp-amount` requires `--stamp-mint`".into());
        }
        (None, Some(_)) => {
            return Err("`--stamp-mint` requires `--stamp-amount`".into());
        }
    }

    match cli.stamp_provider.as_str() {
        "noop" => Ok(()),
        other => Err(format!("unsupported --stamp-provider '{}'", other).into()),
    }
}

fn stamp_provider_from_name(name: &str) -> DynResult<Box<dyn StampProvider>> {
    match name {
        "noop" => Ok(Box::new(NoopStampProvider)),
        other => Err(format!("unsupported --stamp-provider '{}'", other).into()),
    }
}

fn stamp_config_from_file(file_cfg: &StampFileConfig) -> StampConfig {
    let mut cfg = StampConfig::new();
    for (relay, fee) in &file_cfg.relay_fees {
        cfg.insert(relay.clone(), fee.clone());
    }
    cfg
}

fn manual_stamp_file_config(cli: &Cli) -> Option<StampFileConfig> {
    let (Some(amount), Some(mint)) = (cli.stamp_amount, cli.stamp_mint.as_deref()) else {
        return None;
    };

    let mut relay_fees = BTreeMap::new();
    for relay in cli.relays() {
        relay_fees.insert(
            relay,
            RelayStampFee {
                amount,
                unit: "sat".to_owned(),
                mints: vec![mint.to_owned()],
            },
        );
    }
    Some(StampFileConfig { relay_fees })
}

fn load_stamp_file_config(cli: &Cli) -> DynResult<Option<StampFileConfig>> {
    let path = cli.stamp_config_path();
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    let cfg = serde_json::from_str::<StampFileConfig>(&data)?;
    Ok(Some(cfg))
}

fn effective_stamp_file_config(cli: &Cli) -> DynResult<Option<StampFileConfig>> {
    if let Some(manual) = manual_stamp_file_config(cli) {
        return Ok(Some(manual));
    }
    load_stamp_file_config(cli)
}

async fn init_client(cli: &Cli) -> DynResult<KeychatClient> {
    validate_stamp_flags(cli)?;
    let mut client = KeychatClient::init(cli.config()).await?;
    client.set_stamp_provider(stamp_provider_from_name(&cli.stamp_provider)?)?;

    if let Some(file_cfg) = effective_stamp_file_config(cli)? {
        client.set_stamp_config(Some(stamp_config_from_file(&file_cfg)));
    }

    Ok(client)
}
