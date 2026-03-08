//! Echo Bot — a minimal Keychat bot that echoes back every message.
//!
//! Usage:
//!   cargo run --example echo_bot
//!   cargo run --example echo_bot -- --name "My Bot" --db bot.db
//!   cargo run --example echo_bot -- --mnemonic "word1 word2 ... word12"
//!
//! The bot:
//! 1. Creates (or restores) a Keychat identity
//! 2. Connects to default relays
//! 3. Prints its npub for others to add
//! 4. Accepts friend requests automatically
//! 5. Echoes back every direct message

use std::env;

use libkeychat::client::{ClientConfig, InboundEvent, KeychatClient};

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.keychat.io",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
];

fn parse_args() -> (String, String, Option<String>) {
    let args: Vec<String> = env::args().collect();
    let mut name = "Echo Bot".to_string();
    let mut db_path = "echo-bot.db".to_string();
    let mut mnemonic = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--name" if i + 1 < args.len() => {
                name = args[i + 1].clone();
                i += 2;
            }
            "--db" if i + 1 < args.len() => {
                db_path = args[i + 1].clone();
                i += 2;
            }
            "--mnemonic" if i + 1 < args.len() => {
                mnemonic = Some(args[i + 1].clone());
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!("Usage: echo_bot [--name NAME] [--db PATH] [--mnemonic PHRASE]");
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                i += 1;
            }
        }
    }

    (name, db_path, mnemonic)
}

#[tokio::main]
async fn main() -> DynResult<()> {
    let (name, db_path, mnemonic) = parse_args();

    let config = ClientConfig {
        db_path,
        display_name: name.clone(),
        relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
        mnemonic,
        media_server: None,
    };

    println!("🤖 {} starting...", name);
    let mut client = KeychatClient::init(config).await?;

    println!("📍 npub: {}", client.npub()?);
    println!("📍 hex:  {}", client.pubkey_hex());
    if let Some(phrase) = client.mnemonic() {
        println!("🔑 mnemonic: {}", phrase);
    }

    let existing_peers = client.peers();
    if !existing_peers.is_empty() {
        println!("\n📋 Restored {} peer session(s):", existing_peers.len());
        for peer in &existing_peers {
            println!("   • {}", peer);
        }
    }

    println!("\n👂 Listening for messages...\n");
    client.start_listening().await?;

    while let Some(event) = client.next_event().await {
        match event {
            InboundEvent::FriendRequest {
                sender,
                sender_name,
                message,
            } => {
                println!(
                    "✅ Friend request from {} ({}): {}",
                    sender_name,
                    &sender[..12],
                    message
                );
                // Session is auto-established and auto-saved
            }
            InboundEvent::DirectMessage {
                sender,
                plaintext,
                is_prekey,
            } => {
                let prekey_tag = if is_prekey { " [prekey]" } else { "" };
                println!("📨 [{}]{}: {}", &sender[..12], prekey_tag, plaintext);

                let reply = format!("Echo: {}", plaintext);
                match client.send(&sender, &reply).await {
                    Ok(()) => println!("📤 → {}", reply),
                    Err(e) => eprintln!("❌ Send error: {}", e),
                }
            }
            InboundEvent::GroupEvent { from_peer, event } => {
                println!("👥 Group event from {}: {:?}", &from_peer[..12], event);
            }
        }
    }

    println!("\n🔌 All relays disconnected. Goodbye!");
    Ok(())
}
