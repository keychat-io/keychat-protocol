//! Client API interop test — verifies KeychatClient can exchange messages
//! with a real Keychat peer through Nostr relays.
//!
//! Usage:
//!   cargo run --example client_interop_test -- --peer <npub_or_hex>
//!   cargo run --example client_interop_test -- --peer <npub> --mnemonic "..."
//!
//! Workflow:
//! 1. Init client (generate or restore identity)
//! 2. Send hello to peer
//! 3. Listen for friend request acceptance and messages
//! 4. If a DM arrives, echo it back and report success

use std::env;
use std::time::Duration;

use libkeychat::client::{ClientConfig, InboundEvent, KeychatClient};

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.keychat.io",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
];

#[tokio::main]
async fn main() -> DynResult<()> {
    let args: Vec<String> = env::args().collect();
    let mut peer = None;
    let mut mnemonic = None;
    let mut db_path = "/tmp/client_interop_test.db".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--peer" if i + 1 < args.len() => {
                peer = Some(args[i + 1].clone());
                i += 2;
            }
            "--mnemonic" if i + 1 < args.len() => {
                mnemonic = Some(args[i + 1].clone());
                i += 2;
            }
            "--db" if i + 1 < args.len() => {
                db_path = args[i + 1].clone();
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!("Usage: client_interop_test --peer <npub_or_hex> [--mnemonic PHRASE] [--db PATH]");
                std::process::exit(0);
            }
            _ => {
                i += 1;
            }
        }
    }

    let peer = peer.ok_or("--peer is required")?;

    let config = ClientConfig {
        db_path,
        display_name: "libkeychat-interop".into(),
        relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
        mnemonic,
        media_server: None,
    };

    println!("=== Client API Interop Test ===\n");

    let mut client = KeychatClient::init(config).await?;
    println!("[init] npub: {}", client.npub()?);
    println!("[init] hex:  {}", client.pubkey_hex());
    if let Some(phrase) = client.mnemonic() {
        println!("[init] mnemonic: {}", phrase);
    }

    // Start listening before sending hello
    client.start_listening().await?;
    println!("[listen] Subscribed to identity addresses");

    // Check if we already have a session
    let peer_hex = if peer.starts_with("npub1") {
        libkeychat::identity::decode_npub(&peer)?
    } else {
        peer.clone()
    };

    if client.has_session(&peer_hex) {
        println!("[session] Existing session found, sending test message...");
        client
            .send(&peer_hex, "Hello from KeychatClient! (interop test)")
            .await?;
        println!("[send] Test message sent");
    } else {
        println!(
            "[hello] Sending friend request to {}...",
            &peer[..20.min(peer.len())]
        );
        client
            .add_friend(&peer, "Hello from KeychatClient interop test!")
            .await?;
        println!("[hello] Friend request sent, waiting for response...");
    }

    // Debug: show what addresses we're listening on
    let addrs = client.receiving_addresses();
    println!("[debug] Receiving addresses ({}):", addrs.len());
    for addr in &addrs {
        println!("   📡 {}", addr);
    }
    let subs = client.subscriptions();
    println!("[debug] Active subscriptions ({}):", subs.len());
    for (id, desc) in subs {
        println!("   🔑 {} → {}", id, desc);
    }

    // Listen for events with a timeout
    let timeout = Duration::from_secs(120);
    let start = std::time::Instant::now();
    let mut messages_received = 0;

    loop {
        if start.elapsed() > timeout {
            println!("\n[timeout] No more events after {}s", timeout.as_secs());
            break;
        }

        let event = tokio::time::timeout(Duration::from_secs(30), client.next_event()).await;

        match event {
            Ok(Some(InboundEvent::FriendRequest {
                sender,
                sender_name,
                message,
            })) => {
                println!(
                    "[friend] ✅ Accepted by {} ({}): {}",
                    sender_name,
                    &sender[..12],
                    message
                );
            }
            Ok(Some(InboundEvent::DirectMessage {
                sender,
                plaintext,
                is_prekey,
            })) => {
                messages_received += 1;
                let pk = if is_prekey { " [prekey]" } else { "" };
                println!("[dm] 📨 From {}{}: {}", &sender[..12], pk, plaintext);

                // Echo back
                let reply = format!("Echo #{}: {}", messages_received, plaintext);
                match client.send(&sender, &reply).await {
                    Ok(()) => println!("[send] 📤 {}", reply),
                    Err(e) => eprintln!("[send] ❌ {}", e),
                }

                if messages_received >= 3 {
                    println!(
                        "\n[done] ✅ Received {} messages, interop test PASSED!",
                        messages_received
                    );
                    break;
                }
            }
            Ok(Some(InboundEvent::GroupEvent { from_peer, event })) => {
                println!("[group] 👥 From {}: {:?}", &from_peer[..12], event);
            }
            Ok(None) => {
                println!("[disconnect] All relays disconnected");
                break;
            }
            Err(_) => {
                println!(
                    "[wait] Still waiting... ({}s elapsed)",
                    start.elapsed().as_secs()
                );
            }
        }
    }

    println!("\n=== Test Complete ===");
    if messages_received > 0 {
        println!("Result: PASS ({} messages exchanged)", messages_received);
    } else {
        println!("Result: PARTIAL (hello sent, but no DM received within timeout)");
        println!("This is expected if the peer hasn't responded yet.");
    }

    Ok(())
}
