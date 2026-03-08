//! Small group interop test with the Keychat OpenClaw agent.
//!
//! Flow:
//! 1. Init client, send hello to agent (establish Signal session)
//! 2. Wait for agent to accept friend request
//! 3. Create a small group
//! 4. Send group invite to agent via Signal DM
//! 5. Wait for agent to join and send group hello
//! 6. Send a group message to agent
//! 7. Wait for agent's reply in the group
//!
//! Usage:
//!   cargo run --example group_interop_test -- --peer <agent_npub> [--db <path>] [--mnemonic "<words>"]

use libkeychat::client::types::{ClientConfig, InboundEvent};
use libkeychat::client::KeychatClient;
use libkeychat::identity;

use std::time::Duration;

/// Safe string truncation that respects char boundaries.
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.keychat.io",
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://nos.lol",
    "wss://nostr.mom",
];

fn parse_args() -> (String, String, Option<String>) {
    let args: Vec<String> = std::env::args().collect();
    let mut peer = String::new();
    let mut db = String::from("/tmp/group_interop_test.db");
    let mut mnemonic: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--peer" => {
                peer = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--db" => {
                db = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--mnemonic" => {
                mnemonic = args.get(i + 1).cloned();
                i += 2;
            }
            _ => i += 1,
        }
    }

    if peer.is_empty() {
        eprintln!("Usage: group_interop_test --peer <npub> [--db <path>] [--mnemonic \"<words>\"]");
        std::process::exit(1);
    }

    (peer, db, mnemonic)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (peer_npub, db_path, mnemonic) = parse_args();

    println!("=== Small Group Interop Test ===\n");

    // Resolve peer
    let peer_hex = if peer_npub.starts_with("npub") {
        identity::decode_npub(&peer_npub)?
    } else {
        peer_npub.clone()
    };

    // Generate or restore identity
    let mnemonic = mnemonic.unwrap_or_else(|| {
        let m = identity::generate_mnemonic(12).unwrap();
        let s = m.to_string();
        println!("[init] Generated new mnemonic: {s}");
        s
    });

    let config = ClientConfig {
        mnemonic: Some(mnemonic.clone()),
        db_path: db_path.clone(),
        display_name: "libkeychat-group-test".to_string(),
        relays: DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
        media_server: None,
    };

    let mut client = KeychatClient::init(config).await?;
    let my_pubkey = client.keypair().public_key_hex();
    let my_npub = client.npub()?;

    println!("[init] npub: {my_npub}");
    println!("[init] hex:  {my_pubkey}");
    println!("[init] mnemonic: {mnemonic}");

    // Start listening
    client.start_listening().await?;
    println!("[listen] Subscribed to identity addresses");

    // Step 1: Send hello to agent
    println!(
        "[hello] Sending friend request to {}...",
        &peer_npub[..24.min(peer_npub.len())]
    );
    client.add_friend(&peer_hex, "Group interop test").await?;
    println!("[hello] Friend request sent, waiting for agent to accept...\n");

    // Step 2: Wait for agent's reply (friend accept)
    let mut got_dm = false;
    let timeout = tokio::time::Instant::now() + Duration::from_secs(60);

    while tokio::time::Instant::now() < timeout {
        match tokio::time::timeout(Duration::from_secs(5), client.next_event()).await {
            Ok(Some(InboundEvent::DirectMessage {
                sender, plaintext, ..
            })) => {
                println!(
                    "[dm] 📨 From {}... : {}",
                    truncate(&sender, 12),
                    truncate(&plaintext, 80)
                );
                got_dm = true;
                break;
            }
            Ok(Some(InboundEvent::FriendRequest { sender, .. })) => {
                println!("[friend] Friend request from {}...", truncate(&sender, 12));
            }
            Ok(Some(InboundEvent::GroupEvent { .. })) => {
                println!("[group] Unexpected group event before creating group");
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    if !got_dm {
        println!("\n❌ Timed out waiting for agent's friend accept reply.");
        println!("   Make sure the agent auto-accepts friend requests.");
        return Ok(());
    }

    // Drain remaining DMs (profile, etc.)
    tokio::time::sleep(Duration::from_secs(3)).await;
    loop {
        match tokio::time::timeout(Duration::from_secs(2), client.next_event()).await {
            Ok(Some(InboundEvent::DirectMessage {
                sender, plaintext, ..
            })) => {
                println!(
                    "[dm] 📨 From {}... : {}",
                    truncate(&sender, 12),
                    truncate(&plaintext, 60)
                );
            }
            _ => break,
        }
    }

    // Step 3: Create small group
    println!("\n[group] Creating small group...");
    let group_result = client.create_group("Test Interop Group")?;
    let group_pubkey = group_result.profile.pubkey.clone();
    println!(
        "[group] Created group: {} ({}...)",
        group_result.profile.name,
        &group_pubkey[..16]
    );

    // Add agent as member to the profile
    let mut profile = group_result.profile;
    profile.add_member(&peer_hex, "Agent", false);
    println!(
        "[group] Added agent as member ({} members total)",
        profile.users.len()
    );

    // Step 4: Send group invite to agent
    println!("[group] Sending group invite to agent...");
    client
        .send_group_invite(&peer_hex, &profile, "Join my test group!")
        .await?;
    println!("[group] Invite sent!\n");

    // Step 5: Wait for agent's group activity
    println!("[wait] Waiting for agent's group messages...");
    let mut group_messages: Vec<String> = Vec::new();
    let group_timeout = tokio::time::Instant::now() + Duration::from_secs(60);

    while tokio::time::Instant::now() < group_timeout {
        match tokio::time::timeout(Duration::from_secs(5), client.next_event()).await {
            Ok(Some(InboundEvent::DirectMessage {
                sender, plaintext, ..
            })) => {
                // Group messages arrive as DMs (fan-out encryption)
                if plaintext.contains("\"c\":\"group\"") || plaintext.contains("\"c\": \"group\"") {
                    println!(
                        "[group-dm] 📨 Group payload from {}...",
                        truncate(&sender, 12)
                    );
                    match libkeychat::group::parse_group_message(&plaintext, &sender, &group_pubkey)
                    {
                        Ok(event) => {
                            println!("[group] ✅ Parsed: {:?}", event);
                            group_messages.push(format!("{:?}", event));
                        }
                        Err(e) => {
                            println!("[group] ⚠️  Parse failed: {e}");
                            println!("[group]    Raw: {}", truncate(&plaintext, 120));
                            group_messages.push(plaintext.clone());
                        }
                    }
                } else {
                    println!(
                        "[dm] 📨 From {}... : {}",
                        truncate(&sender, 12),
                        truncate(&plaintext, 80)
                    );
                    // Could be agent's join notification or other response
                    group_messages.push(plaintext.clone());
                }

                if group_messages.len() >= 2 {
                    break;
                }
            }
            Ok(Some(InboundEvent::GroupEvent { from_peer, event })) => {
                println!(
                    "[group] ✅ GroupEvent from {}...: {:?}",
                    truncate(&from_peer, 12),
                    event
                );
                group_messages.push(format!("{:?}", event));
                if group_messages.len() >= 2 {
                    break;
                }
            }
            Ok(Some(InboundEvent::FriendRequest { sender, .. })) => {
                println!("[friend] Friend request from {}...", truncate(&sender, 12));
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    // Step 6: Send a group message
    if !group_messages.is_empty() {
        println!("\n[group] Sending group message to agent...");
        client
            .send_group_message(
                &group_pubkey,
                &[peer_hex.as_str()],
                "Hello from libkeychat group!",
            )
            .await?;
        println!("[group] Group message sent!");

        // Wait for reply
        let reply_timeout = tokio::time::Instant::now() + Duration::from_secs(30);
        while tokio::time::Instant::now() < reply_timeout {
            match tokio::time::timeout(Duration::from_secs(5), client.next_event()).await {
                Ok(Some(InboundEvent::DirectMessage { plaintext, .. })) => {
                    println!("[group-reply] 📨 {}", truncate(&plaintext, 120));
                    group_messages.push(plaintext);
                    break;
                }
                Ok(Some(InboundEvent::GroupEvent { event, .. })) => {
                    println!("[group-reply] ✅ {:?}", event);
                    group_messages.push(format!("{:?}", event));
                    break;
                }
                _ => continue,
            }
        }
    }

    // Summary
    println!("\n=== Test Complete ===");
    if group_messages.is_empty() {
        println!("Result: FAIL (no group messages received)");
        println!("  Possible causes:");
        println!("  - Agent may not handle group invites (type=11, c='group')");
        println!("  - Check agent logs for group invite parsing");
    } else {
        println!(
            "Result: PASS ({} group messages exchanged)",
            group_messages.len()
        );
    }

    Ok(())
}
