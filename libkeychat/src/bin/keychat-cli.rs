//! keychat — CLI client for the Keychat protocol.
//!
//! A scriptable, headless Keychat client built on libkeychat.
//!
//! Usage:
//!   keychat init                          # Generate identity, store in Keychain
//!   keychat init --mnemonic "word1 ..."   # Restore identity from mnemonic
//!   keychat info                          # Show npub and hex pubkey
//!   keychat add <npub|hex> [message]      # Send friend request
//!   keychat send <name|npub> <message>    # Send a message
//!   keychat send-file <name|npub> <path>  # Send a file
//!   keychat chat [name|npub|index]        # Interactive chat (send + receive)
//!   keychat listen                        # Listen for messages (all peers)
//!   keychat nick <npub|hex> <nickname>    # Set a nickname for a peer
//!   keychat peers                         # List known peers with nicknames
//!   keychat export-mnemonic               # Export mnemonic from Keychain

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command as ShellCommand;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use libkeychat::client::{ClientConfig, InboundEvent, KeychatClient};
use libkeychat::stamp::{fetch_relay_stamp_info, NoopStampProvider, RelayStampFee, StampConfig, StampProvider};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.keychat.io",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
];

const KEYCHAIN_SERVICE: &str = "io.keychat.cli";
const KEYCHAIN_ACCOUNT: &str = "mnemonic";

// ── Nickname store ──

/// Simple nickname store: hex_pubkey → nickname, persisted as JSON next to the DB.
struct NickStore {
    path: PathBuf,
    nicks: HashMap<String, String>,
}

impl NickStore {
    fn load(db_path: &str) -> Self {
        let path = Path::new(db_path).with_extension("nicks.json");
        let nicks = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path, nicks }
    }

    fn save(&self) -> DynResult<()> {
        let json = serde_json::to_string_pretty(&self.nicks)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    fn set(&mut self, hex: &str, nick: &str) {
        self.nicks.insert(hex.to_owned(), nick.to_owned());
    }

    fn get(&self, hex: &str) -> Option<&str> {
        self.nicks.get(hex).map(|s| s.as_str())
    }

    /// Resolve a nickname to hex pubkey. Returns None if not found.
    fn resolve(&self, name: &str) -> Option<String> {
        // Exact match
        for (hex, nick) in &self.nicks {
            if nick.eq_ignore_ascii_case(name) {
                return Some(hex.clone());
            }
        }
        None
    }

    /// Get display name: nickname if set, otherwise truncated hex.
    fn display(&self, hex: &str) -> String {
        if let Some(nick) = self.get(hex) {
            nick.to_owned()
        } else {
            truncate(hex, 12).to_owned()
        }
    }
}

// ── Keychain helpers (macOS) ──

fn keychain_store(mnemonic: &str) -> DynResult<()> {
    let _ = ShellCommand::new("security")
        .args(["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT])
        .output();

    let output = ShellCommand::new("security")
        .args([
            "add-generic-password",
            "-s", KEYCHAIN_SERVICE,
            "-a", KEYCHAIN_ACCOUNT,
            "-w", mnemonic,
            "-T", "",
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
        .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"])
        .output()
        .ok()?;

    if output.status.success() {
        let mnemonic = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !mnemonic.is_empty() { Some(mnemonic) } else { None }
    } else {
        None
    }
}

#[allow(dead_code)]
fn keychain_delete() -> DynResult<()> {
    let output = ShellCommand::new("security")
        .args(["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT])
        .output()?;
    if !output.status.success() {
        return Err("No mnemonic found in Keychain".into());
    }
    Ok(())
}

/// Keychat CLI — E2E encrypted messaging on Nostr
#[derive(Parser)]
#[command(name = "keychat-cli", version, about)]
struct Cli {
    /// Path to the SQLite database
    #[arg(long, default_value = "keychat-cli.db", global = true)]
    db: String,

    /// Display name
    #[arg(long, default_value = "keychat-cli", global = true)]
    name: String,

    /// Relay URLs (comma-separated or repeated)
    #[arg(long, global = true)]
    relay: Vec<String>,

    /// BIP-39 mnemonic (overrides Keychain)
    #[arg(long, global = true)]
    mnemonic: Option<String>,

    /// Media server URL
    #[arg(long, global = true)]
    media_server: Option<String>,

    /// Stamp provider implementation (currently supports: noop)
    #[arg(long, global = true, default_value = "noop")]
    stamp_provider: String,

    /// Fixed stamp amount for all relays
    #[arg(long, global = true)]
    stamp_amount: Option<u64>,

    /// Cashu mint URL for fixed stamp config
    #[arg(long, global = true)]
    stamp_mint: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new identity (or restore from mnemonic). Stores in Keychain.
    Init,

    /// Show identity info (npub, hex pubkey)
    Info,

    /// Send a friend request (hello)
    Add {
        /// Recipient npub or hex pubkey
        recipient: String,
        /// Hello message
        #[arg(default_value = "Hello from keychat-cli!")]
        message: String,
    },

    /// Send a message to a peer (accepts nickname, npub, or hex)
    Send {
        /// Recipient nickname, npub, or hex pubkey
        recipient: String,
        /// Message text (reads from stdin if "-")
        message: String,
    },

    /// Send a file to a peer
    SendFile {
        /// Recipient nickname, npub, or hex pubkey
        recipient: String,
        /// File path
        path: PathBuf,
    },

    /// Interactive chat with a peer (send + receive in one window)
    Chat {
        /// Peer nickname, npub, hex, or index number. Omit to pick interactively.
        peer: Option<String>,
    },

    /// Listen for incoming messages (long-running)
    Listen {
        /// Output format: "human" or "json"
        #[arg(long, default_value = "human")]
        format: String,

        /// Run callback script on each message
        #[arg(long)]
        on_message: Option<String>,

        /// Auto-accept friend requests
        #[arg(long, default_value_t = true)]
        auto_accept: bool,
    },

    /// Set a nickname for a peer
    Nick {
        /// Peer npub or hex pubkey
        peer: String,
        /// Nickname to set
        nickname: String,
    },

    /// List known peers with nicknames
    Peers,

    /// Export mnemonic from Keychain (for backup)
    ExportMnemonic,

    /// Manage relay stamp fees and config
    Stamp {
        #[command(subcommand)]
        command: StampCommand,
    },
}

#[derive(Subcommand)]
enum StampCommand {
    /// Fetch and display stamp fees from configured relays
    Info,
    /// Show current effective stamp configuration
    Config,
    /// Auto-discover stamp fees and optionally save to file
    Fetch {
        /// Save discovered fees to keychat.stamps.json next to the DB
        #[arg(long)]
        save: bool,
    },
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
}

#[tokio::main]
async fn main() -> DynResult<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Init => cmd_init(&cli).await,
        Command::Info => cmd_info(&cli).await,
        Command::Add { recipient, message } => cmd_add(&cli, recipient, message).await,
        Command::Send { recipient, message } => cmd_send(&cli, recipient, message).await,
        Command::SendFile { recipient, path } => cmd_send_file(&cli, recipient, path).await,
        Command::Chat { peer } => cmd_chat(&cli, peer.as_deref()).await,
        Command::Listen {
            format,
            on_message,
            auto_accept,
        } => cmd_listen(&cli, format, on_message.as_deref(), *auto_accept).await,
        Command::Nick { peer, nickname } => cmd_nick(&cli, peer, nickname).await,
        Command::Peers => cmd_peers(&cli).await,
        Command::ExportMnemonic => cmd_export_mnemonic().await,
        Command::Stamp { command } => cmd_stamp(&cli, command).await,
    }
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

fn effective_stamp_file_config(cli: &Cli) -> DynResult<Option<(StampFileConfig, String)>> {
    if let Some(manual) = manual_stamp_file_config(cli) {
        return Ok(Some((manual, "manual-flags".to_owned())));
    }
    if let Some(file) = load_stamp_file_config(cli)? {
        let source = format!("file: {}", cli.stamp_config_path().display());
        return Ok(Some((file, source)));
    }
    Ok(None)
}

async fn init_client(cli: &Cli) -> DynResult<KeychatClient> {
    validate_stamp_flags(cli)?;
    let mut client = KeychatClient::init(cli.config()).await?;
    client.set_stamp_provider(stamp_provider_from_name(&cli.stamp_provider)?)?;

    if let Some((file_cfg, _)) = effective_stamp_file_config(cli)? {
        client.set_stamp_config(Some(stamp_config_from_file(&file_cfg)));
        if cli.stamp_provider == "noop" {
            eprintln!("⚠️  Stamp config is active, but --stamp-provider=noop cannot create tokens.");
        }
    }

    Ok(client)
}

async fn cmd_init(cli: &Cli) -> DynResult<()> {
    validate_stamp_flags(cli)?;
    if cli.mnemonic.is_none() {
        if let Some(existing) = keychain_load() {
            let config = ClientConfig {
                db_path: cli.db.clone(),
                display_name: cli.name.clone(),
                relays: cli.relays(),
                mnemonic: Some(existing),
                media_server: cli.media_server.clone(),
            };
            let client = KeychatClient::init(config).await?;
            println!("✅ Identity restored from Keychain");
            println!("npub: {}", client.npub()?);
            println!("hex:  {}", client.pubkey_hex());
            return Ok(());
        }
    }

    let client = KeychatClient::init(cli.config()).await?;

    if let Some(phrase) = client.mnemonic() {
        keychain_store(phrase)?;
        println!("✅ Identity initialized (mnemonic stored in Keychain)");
        println!("npub: {}", client.npub()?);
        println!("hex:  {}", client.pubkey_hex());
        eprintln!("\n🔐 Mnemonic saved to macOS Keychain. Use 'keychat export-mnemonic' to back it up.");
    } else {
        println!("✅ Identity initialized");
        println!("npub: {}", client.npub()?);
        println!("hex:  {}", client.pubkey_hex());
    }
    Ok(())
}

async fn cmd_info(cli: &Cli) -> DynResult<()> {
    require_identity(cli)?;
    let client = init_client(cli).await?;

    println!("npub: {}", client.npub()?);
    println!("hex:  {}", client.pubkey_hex());
    println!("name: {}", cli.name);
    println!("db:   {}", cli.db);
    println!("relays: {}", cli.relays().join(", "));
    println!("peers: {}", client.peers().len());
    Ok(())
}

async fn cmd_add(cli: &Cli, recipient: &str, message: &str) -> DynResult<()> {
    require_identity(cli)?;
    let mut client = init_client(cli).await?;

    eprintln!("📤 Sending friend request to {}...", truncate(recipient, 20));
    client.add_friend(recipient, message).await?;
    println!("✅ Friend request sent");
    Ok(())
}

async fn cmd_send(cli: &Cli, recipient: &str, message: &str) -> DynResult<()> {
    require_identity(cli)?;

    let text = if message == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf.trim().to_owned()
    } else {
        message.to_owned()
    };

    let nicks = cli.nick_store();
    let mut client = init_client(cli).await?;
    let peer_hex = resolve_peer_or_nick(&client, &nicks, recipient)?;

    client.send(&peer_hex, &text).await?;
    eprintln!("✅ Sent to {}", nicks.display(&peer_hex));
    Ok(())
}

async fn cmd_send_file(cli: &Cli, recipient: &str, path: &PathBuf) -> DynResult<()> {
    require_identity(cli)?;

    let file_bytes = std::fs::read(path)?;
    let filename = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "file".to_owned());
    let suffix = path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_else(|| "bin".to_owned());
    let media_type = guess_media_type(&suffix);

    let nicks = cli.nick_store();
    let mut client = init_client(cli).await?;
    let peer_hex = resolve_peer_or_nick(&client, &nicks, recipient)?;

    eprintln!("📎 Uploading {}...", filename);
    client.send_media(&peer_hex, &file_bytes, &suffix, &filename, media_type).await?;
    eprintln!("✅ File sent to {}", nicks.display(&peer_hex));
    Ok(())
}

async fn cmd_nick(cli: &Cli, peer: &str, nickname: &str) -> DynResult<()> {
    let hex = if peer.starts_with("npub1") {
        libkeychat::identity::decode_npub(peer)?
    } else {
        peer.to_owned()
    };

    let mut nicks = cli.nick_store();
    nicks.set(&hex, nickname);
    nicks.save()?;

    println!("✅ {} → {}", nickname, truncate(&hex, 16));
    Ok(())
}

async fn cmd_chat(cli: &Cli, peer: Option<&str>) -> DynResult<()> {
    require_identity(cli)?;

    let nicks = cli.nick_store();
    let mut client = init_client(cli).await?;
    let peer_hex = select_peer(&client, &nicks, peer)?;
    let peer_display = nicks.display(&peer_hex);

    eprintln!("💬 Chat with {}", peer_display);
    eprintln!("   Type a message and press Enter to send. Ctrl+C to quit.\n");

    client.start_listening().await?;

    let nicks = Arc::new(Mutex::new(nicks));
    let client = Arc::new(Mutex::new(client));
    let peer_hex_clone = peer_hex.clone();

    // Spawn receiver task
    let client_recv = Arc::clone(&client);
    let nicks_recv = Arc::clone(&nicks);
    let recv_handle = tokio::spawn(async move {
        loop {
            let event = {
                let mut c = client_recv.lock().await;
                c.next_event().await
            };
            match event {
                Some(InboundEvent::DirectMessage { sender, plaintext, .. }) => {
                    let ns = nicks_recv.lock().await;
                    let display = ns.display(&sender);
                    drop(ns);
                    eprint!("\r\x1b[2K");
                    println!("← [{}] {}", display, plaintext);
                    eprint!("> ");
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
                Some(InboundEvent::FriendRequest { sender_name, sender, message }) => {
                    // Auto-save nickname from display name
                    {
                        let mut ns = nicks_recv.lock().await;
                        if ns.get(&sender).is_none() && !sender_name.is_empty() {
                            ns.set(&sender, &sender_name);
                            let _ = ns.save();
                        }
                    }
                    eprint!("\r\x1b[2K");
                    println!("🤝 {} wants to add you: {}", sender_name, message);
                    eprint!("> ");
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
                Some(InboundEvent::GroupEvent { from_peer, event }) => {
                    let ns = nicks_recv.lock().await;
                    let display = ns.display(&from_peer);
                    drop(ns);
                    eprint!("\r\x1b[2K");
                    println!("👥 [{}] {:?}", display, event);
                    eprint!("> ");
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
                None => break,
            }
        }
    });

    // Read stdin for sending
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    use tokio::io::AsyncBufReadExt;
    let mut lines = stdin.lines();

    eprint!("> ");
    let _ = std::io::Write::flush(&mut std::io::stderr());

    while let Ok(Some(line)) = lines.next_line().await {
        let text = line.trim().to_owned();
        if text.is_empty() {
            eprint!("> ");
            let _ = std::io::Write::flush(&mut std::io::stderr());
            continue;
        }

        if text == "/quit" || text == "/exit" {
            break;
        }

        let mut c = client.lock().await;
        match c.send(&peer_hex_clone, &text).await {
            Ok(()) => println!("→ {}", text),
            Err(e) => eprintln!("❌ Send failed: {}", e),
        }
        eprint!("> ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }

    recv_handle.abort();
    eprintln!("\n👋 Chat ended.");
    Ok(())
}

async fn cmd_listen(
    cli: &Cli,
    format: &str,
    on_message: Option<&str>,
    _auto_accept: bool,
) -> DynResult<()> {
    require_identity(cli)?;

    let mut nicks = cli.nick_store();
    let mut client = init_client(cli).await?;
    let is_json = format == "json";

    eprintln!("👂 Listening as {} ({})", cli.name, client.npub()?);
    eprintln!("   Press Ctrl+C to stop\n");

    client.start_listening().await?;

    while let Some(event) = client.next_event().await {
        match &event {
            InboundEvent::FriendRequest { sender, sender_name, message } => {
                // Auto-save nickname from display name
                if nicks.get(sender).is_none() && !sender_name.is_empty() {
                    nicks.set(sender, sender_name);
                    let _ = nicks.save();
                }

                if is_json {
                    println!("{}", serde_json::json!({
                        "type": "friend_request",
                        "sender": sender,
                        "sender_name": sender_name,
                        "message": message,
                    }));
                } else {
                    println!("🤝 {} wants to add you: {}", sender_name, message);
                }
            }
            InboundEvent::DirectMessage { sender, plaintext, is_prekey } => {
                if is_json {
                    println!("{}", serde_json::json!({
                        "type": "message",
                        "sender": sender,
                        "sender_name": nicks.get(sender),
                        "text": plaintext,
                        "is_prekey": is_prekey,
                    }));
                } else {
                    let tag = if *is_prekey { " [new]" } else { "" };
                    println!("[{}]{} {}", nicks.display(sender), tag, plaintext);
                }

                if let Some(script) = on_message {
                    let _ = ShellCommand::new("sh")
                        .arg("-c")
                        .arg(script)
                        .env("KEYCHAT_SENDER", sender)
                        .env("KEYCHAT_SENDER_NAME", nicks.get(sender).unwrap_or(""))
                        .env("KEYCHAT_MESSAGE", plaintext)
                        .spawn();
                }
            }
            InboundEvent::GroupEvent { from_peer, event } => {
                if is_json {
                    println!("{}", serde_json::json!({
                        "type": "group_event",
                        "from_peer": from_peer,
                        "event": format!("{:?}", event),
                    }));
                } else {
                    println!("👥 [{}] {:?}", nicks.display(from_peer), event);
                }
            }
        }
    }

    eprintln!("\n🔌 Disconnected.");
    Ok(())
}

async fn cmd_peers(cli: &Cli) -> DynResult<()> {
    require_identity(cli)?;

    let nicks = cli.nick_store();
    let client = init_client(cli).await?;
    let peers = client.peers();

    if peers.is_empty() {
        println!("No peers yet. Use 'keychat add <npub>' to add a friend.");
    } else {
        for (i, peer) in peers.iter().enumerate() {
            let nick = nicks.get(peer);
            if let Some(name) = nick {
                println!("  {} ) {} ({})", i + 1, name, truncate(peer, 16));
            } else {
                println!("  {} ) {}", i + 1, peer);
            }
        }
        eprintln!("\nTip: use 'keychat nick <npub> <name>' to set nicknames.");
    }
    Ok(())
}

async fn cmd_export_mnemonic() -> DynResult<()> {
    match keychain_load() {
        Some(mnemonic) => {
            println!("{}", mnemonic);
            eprintln!("\n⚠️  Keep this safe. Anyone with these words can control your identity.");
        }
        None => return Err("No mnemonic found in Keychain. Run 'keychat init' first.".into()),
    }
    Ok(())
}

async fn cmd_stamp(cli: &Cli, command: &StampCommand) -> DynResult<()> {
    validate_stamp_flags(cli)?;
    match command {
        StampCommand::Info => cmd_stamp_info(cli).await,
        StampCommand::Config => cmd_stamp_config(cli).await,
        StampCommand::Fetch { save } => cmd_stamp_fetch(cli, *save).await,
    }
}

async fn discover_stamp_fees(relays: &[String]) -> Vec<(String, Result<Option<RelayStampFee>, String>)> {
    let tasks = relays.iter().cloned().map(|relay| async move {
        let result = fetch_relay_stamp_info(&relay).await.map_err(|e| e.to_string());
        (relay, result)
    });
    futures::future::join_all(tasks).await
}

fn print_stamp_results(results: &[(String, Result<Option<RelayStampFee>, String>)]) {
    for (relay, result) in results {
        match result {
            Ok(Some(fee)) => {
                println!(
                    "{}: {} {} | mints: {}",
                    relay,
                    fee.amount,
                    fee.unit,
                    if fee.mints.is_empty() {
                        "<none>".to_owned()
                    } else {
                        fee.mints.join(", ")
                    }
                );
            }
            Ok(None) => println!("{}: no stamp fee advertised", relay),
            Err(err) => println!("{}: error: {}", relay, err),
        }
    }
}

async fn cmd_stamp_info(cli: &Cli) -> DynResult<()> {
    let relays = cli.relays();
    println!("Stamp fee info for {} relay(s):", relays.len());
    let results = discover_stamp_fees(&relays).await;
    print_stamp_results(&results);
    Ok(())
}

async fn cmd_stamp_config(cli: &Cli) -> DynResult<()> {
    println!("stamp_provider: {}", cli.stamp_provider);
    println!("stamp_file: {}", cli.stamp_config_path().display());

    let Some((cfg, source)) = effective_stamp_file_config(cli)? else {
        println!("effective_config: none");
        return Ok(());
    };

    println!("effective_config: {}", source);
    if cfg.relay_fees.is_empty() {
        println!("relay_fees: <empty>");
        return Ok(());
    }

    for (relay, fee) in cfg.relay_fees {
        println!(
            "{}: {} {} | mints: {}",
            relay,
            fee.amount,
            fee.unit,
            if fee.mints.is_empty() {
                "<none>".to_owned()
            } else {
                fee.mints.join(", ")
            }
        );
    }
    Ok(())
}

async fn cmd_stamp_fetch(cli: &Cli, save: bool) -> DynResult<()> {
    let relays = cli.relays();
    let results = discover_stamp_fees(&relays).await;
    print_stamp_results(&results);

    if !save {
        return Ok(());
    }

    let mut relay_fees = BTreeMap::new();
    for (relay, result) in results {
        if let Ok(Some(fee)) = result {
            relay_fees.insert(relay, fee);
        }
    }

    let file_cfg = StampFileConfig { relay_fees };
    let path = cli.stamp_config_path();
    let json = serde_json::to_string_pretty(&file_cfg)?;
    std::fs::write(&path, json)?;
    println!("Saved stamp config to {}", path.display());
    Ok(())
}

// ── Helpers ──

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max { &s[..max] } else { s }
}

fn require_identity(cli: &Cli) -> DynResult<()> {
    if cli.resolve_mnemonic().is_none() {
        eprintln!("🔑 No identity found. Generating a new one...");
        // Use a temporary runtime-less init to generate and store mnemonic
        let rt = tokio::runtime::Handle::current();
        let config = cli.config();
        let client = rt.block_on(KeychatClient::init(config))?;
        if let Some(phrase) = client.mnemonic() {
            keychain_store(phrase)?;
            eprintln!("✅ Identity created: {}", client.npub().unwrap_or_default());
            eprintln!("🔐 Mnemonic stored in macOS Keychain.\n");
        }
    }
    Ok(())
}

/// Resolve input as nickname, npub, or hex pubkey.
fn resolve_peer_or_nick(client: &KeychatClient, nicks: &NickStore, input: &str) -> DynResult<String> {
    // Try nickname first
    if let Some(hex) = nicks.resolve(input) {
        if client.has_session(&hex) {
            return Ok(hex);
        }
    }

    // Then npub/hex
    resolve_peer(client, input)
}

/// Select a peer interactively or by nickname/index/npub.
fn select_peer(client: &KeychatClient, nicks: &NickStore, input: Option<&str>) -> DynResult<String> {
    let peers = client.peers();

    if peers.is_empty() {
        return Err("No peers yet. Use 'keychat add <npub>' to add a friend first.".into());
    }

    if let Some(val) = input {
        // Try nickname
        if let Some(hex) = nicks.resolve(val) {
            if client.has_session(&hex) {
                return Ok(hex);
            }
        }

        // Try as 1-based index
        if let Ok(idx) = val.parse::<usize>() {
            if idx >= 1 && idx <= peers.len() {
                return Ok(peers[idx - 1].clone());
            } else {
                return Err(format!("Invalid index {}. You have {} peer(s).", idx, peers.len()).into());
            }
        }

        // npub/hex
        return resolve_peer(client, val);
    }

    // No input — auto-select or interactive
    if peers.len() == 1 {
        return Ok(peers[0].clone());
    }

    eprintln!("Select a peer:");
    for (i, peer) in peers.iter().enumerate() {
        let label = nicks.get(peer).map(|n| format!("{} ({})", n, truncate(peer, 12)))
            .unwrap_or_else(|| peer.clone());
        eprintln!("  {} ) {}", i + 1, label);
    }
    eprint!("\n> ");
    let _ = std::io::Write::flush(&mut std::io::stderr());

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let choice = line.trim();

    // Try nickname
    if let Some(hex) = nicks.resolve(choice) {
        if client.has_session(&hex) {
            return Ok(hex);
        }
    }

    if let Ok(idx) = choice.parse::<usize>() {
        if idx >= 1 && idx <= peers.len() {
            return Ok(peers[idx - 1].clone());
        }
    }

    Err(format!("Invalid selection: {}", choice).into())
}

fn resolve_peer(client: &KeychatClient, input: &str) -> DynResult<String> {
    let hex = if input.starts_with("npub1") {
        libkeychat::identity::decode_npub(input)?
    } else {
        input.to_owned()
    };

    if !client.has_session(&hex) {
        return Err(format!(
            "No session with {}. Send a friend request first: keychat add {}",
            truncate(&hex, 16), input
        ).into());
    }
    Ok(hex)
}

fn guess_media_type(suffix: &str) -> &'static str {
    match suffix.to_lowercase().as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" => "image",
        "mp4" | "mov" | "avi" | "webm" => "video",
        "mp3" | "m4a" | "ogg" | "wav" | "aac" => "voiceNote",
        _ => "file",
    }
}
