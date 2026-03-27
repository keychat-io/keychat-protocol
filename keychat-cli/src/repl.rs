//! Interactive REPL for keychat-cli.
//!
//! Uses `rustyline` for readline with history, `colored` for terminal output,
//! and spawns a background task to print incoming events/messages.

use std::sync::Arc;

use chrono::Utc;
use colored::Colorize;
use keychat_uniffi::{
    ClientEvent, DataChange, GroupMemberInput, KeychatClient, MessageKind, RoomStatus, RoomType,
};
use tokio::sync::broadcast;

// ─── Constants ──────────────────────────────────────────────────

const HISTORY_FILE: &str = "repl_history.txt";
const DEFAULT_HISTORY_COUNT: i32 = 20;

// ─── Public entry point ─────────────────────────────────────────

pub async fn run(
    client: Arc<KeychatClient>,
    event_tx: broadcast::Sender<ClientEvent>,
    data_tx: broadcast::Sender<DataChange>,
) -> anyhow::Result<()> {
    print_banner();

    // Mutable REPL state
    let mut active_room_id: Option<String> = None;

    // Spawn background event printer
    let event_rx = event_tx.subscribe();
    let data_rx = data_tx.subscribe();
    spawn_event_printer(event_rx, data_rx);

    // Set up rustyline
    let mut rl = rustyline::DefaultEditor::new()?;
    let hist_path = dirs::home_dir()
        .map(|p| p.join(".keychat").join(HISTORY_FILE))
        .unwrap_or_else(|| HISTORY_FILE.into());
    let _ = rl.load_history(&hist_path);

    // Shared startup: restore identity → sessions → connect → event loop
    let relay_urls = keychat_uniffi::default_relays();
    if let Some((pubkey, session_count)) = crate::commands::init_and_connect(&client, relay_urls).await {
        print_sys(&format!("Identity loaded: {}", short_key(&pubkey).cyan()));
        if session_count > 0 {
            print_sys(&format!("Restored {} session(s)", session_count));
        }
        print_sys("Connecting to relays...");
    } else {
        print_sys("No identity found. Use /create or /import <mnemonic> to get started.");
    }

    print_help();

    loop {
        let prompt = build_prompt(&active_room_id);

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);

                match dispatch(Arc::clone(&client), &line, &mut active_room_id).await {
                    Ok(should_quit) => {
                        if should_quit {
                            break;
                        }
                    }
                    Err(e) => print_err(&format!("{e}")),
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                print_sys("Ctrl-C — use /quit to exit");
            }
            Err(rustyline::error::ReadlineError::Eof) => break,
            Err(e) => {
                print_err(&format!("readline: {e}"));
                break;
            }
        }
    }

    let _ = rl.save_history(&hist_path);
    let _ = client.disconnect().await;
    print_sys("Goodbye!");
    Ok(())
}

// ─── Command dispatch ───────────────────────────────────────────

/// Returns Ok(true) to quit, Ok(false) to continue.
async fn dispatch(
    client: Arc<KeychatClient>,
    line: &str,
    active_room_id: &mut Option<String>,
) -> anyhow::Result<bool> {
    // Non-command text → send as message if in a chat
    if !line.starts_with('/') {
        return send_chat_message(&client, active_room_id, line).await;
    }

    let mut parts = line.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let args = parts.next().unwrap_or("").trim();

    match cmd {
        // ── Identity ──
        "/create" => cmd_create(Arc::clone(&client), args).await?,
        "/import" => cmd_import(Arc::clone(&client), args).await?,
        "/whoami" => cmd_whoami(&client).await?,
        "/backup" => cmd_backup(&client).await?,
        "/delete-identity" => cmd_delete_identity(&client, active_room_id).await?,

        // ── Connection ──
        "/connect" => cmd_connect(Arc::clone(&client), args).await?,
        "/disconnect" => cmd_disconnect(&client).await?,
        "/relays" => cmd_relays(&client).await?,
        "/add-relay" => cmd_add_relay(&client, args).await?,
        "/remove-relay" => cmd_remove_relay(&client, args).await?,
        "/reconnect" => cmd_reconnect(&client).await?,
        "/status" => cmd_status(&client).await?,

        // ── Friends ──
        "/add" => cmd_add_friend(&client, args).await?,
        "/accept" => cmd_accept(&client, args).await?,
        "/reject" => cmd_reject(&client, args).await?,
        "/contacts" => cmd_contacts(&client).await?,

        // ── Messaging ──
        "/chat" => cmd_chat(&client, args, active_room_id).await?,
        "/rooms" => cmd_rooms(&client).await?,
        "/read" => cmd_read(&client, active_room_id).await?,
        "/history" => cmd_history(&client, args, active_room_id).await?,

        // ── Signal Groups ──
        "/sg-create" => cmd_sg_create(&client, args).await?,
        "/sg-chat" => cmd_sg_chat(args, active_room_id)?,
        "/sg-leave" => cmd_sg_leave(&client, args).await?,
        "/sg-dissolve" => cmd_sg_dissolve(&client, args).await?,
        "/sg-rename" => cmd_sg_rename(&client, args).await?,
        "/sg-kick" => cmd_sg_kick(&client, args).await?,

        // ── Utility ──
        "/retry" => cmd_retry(&client).await?,
        "/debug" => cmd_debug(&client).await?,
        "/help" => print_help(),
        "/quit" | "/exit" => return Ok(true),

        _ => print_err(&format!("Unknown command: {cmd}. Type /help for available commands.")),
    }

    Ok(false)
}

// ─── Identity commands ──────────────────────────────────────────

async fn cmd_create(client: Arc<KeychatClient>, name: &str) -> anyhow::Result<()> {
    let display_name = if name.is_empty() { "CLI User" } else { name };
    let (pubkey_hex, npub, mnemonic) = crate::commands::create_identity(&client, display_name).await?;
    print_ok(&format!("Identity created: {} ({})", display_name.green(), short_key(&pubkey_hex).cyan()));
    println!("  {} {}", "npub:".dimmed(), npub.cyan());
    print_sys(&format!("Mnemonic (save this!): {}", mnemonic.yellow()));

    // Auto-connect to relays (same as TUI)
    let relay_urls = keychat_uniffi::default_relays();
    print_sys(&format!("Connecting to {} relay(s)...", relay_urls.len()));
    let client_bg = Arc::clone(&client);
    tokio::spawn(async move {
        if let Err(e) = client_bg.connect(relay_urls).await {
            tracing::warn!("Auto-connect failed: {e}");
            return;
        }
        if let Err(e) = client_bg.start_event_loop().await {
            tracing::error!("event loop error: {e}");
        }
    });

    Ok(())
}

async fn cmd_import(client: Arc<KeychatClient>, args: &str) -> anyhow::Result<()> {
    if args.is_empty() {
        print_err("Usage: /import <mnemonic words>");
        return Ok(());
    }
    let pubkey = crate::commands::import_identity(&client, args).await?;
    print_ok(&format!("Identity imported: {}", pubkey.cyan()));

    // Auto-connect to relays (same as TUI)
    let relay_urls = keychat_uniffi::default_relays();
    print_sys(&format!("Connecting to {} relay(s)...", relay_urls.len()));
    let client_bg = Arc::clone(&client);
    tokio::spawn(async move {
        if let Err(e) = client_bg.connect(relay_urls).await {
            tracing::warn!("Auto-connect failed: {e}");
            return;
        }
        if let Err(e) = client_bg.start_event_loop().await {
            tracing::error!("event loop error: {e}");
        }
    });

    Ok(())
}

async fn cmd_whoami(client: &KeychatClient) -> anyhow::Result<()> {
    let pubkey = client.get_pubkey_hex().await?;
    let npub = keychat_uniffi::npub_from_hex(pubkey.clone()).unwrap_or_default();
    println!("  {} {}", "Pubkey:".dimmed(), pubkey.cyan());
    println!("  {} {}", "npub:  ".dimmed(), npub.cyan());
    Ok(())
}

async fn cmd_backup(client: &KeychatClient) -> anyhow::Result<()> {
    // The mnemonic is only available at create time via CreateIdentityResult.
    // After that, it's not stored in the client. Inform the user.
    print_sys(
        "Mnemonic backup is only shown at identity creation time (/create).\n  \
         If you saved it then, use that backup. The client does not store the mnemonic after creation.",
    );
    // Still show identity info
    match client.get_pubkey_hex().await {
        Ok(pk) => println!("  {} {}", "Current identity:".dimmed(), short_key(&pk).cyan()),
        Err(_) => print_err("No identity loaded"),
    }
    Ok(())
}

async fn cmd_delete_identity(
    client: &KeychatClient,
    active_room_id: &mut Option<String>,
) -> anyhow::Result<()> {
    print_sys("This will delete your identity and ALL data. Type 'yes' to confirm:");
    let mut rl = rustyline::DefaultEditor::new()?;
    match rl.readline("  Confirm> ") {
        Ok(input) if input.trim() == "yes" => {
            client.remove_identity().await?;
            crate::commands::delete_mnemonic(client).await;
            *active_room_id = None;
            print_ok("Identity and all data deleted.");
        }
        _ => print_sys("Cancelled."),
    }
    Ok(())
}

// ─── Connection commands ────────────────────────────────────────

async fn cmd_connect(client: Arc<KeychatClient>, args: &str) -> anyhow::Result<()> {
    let relay_urls: Vec<String> = if args.is_empty() {
        keychat_uniffi::default_relays()
    } else {
        args.split_whitespace().map(|s| s.to_string()).collect()
    };

    print_sys(&format!("Connecting to {} relay(s)...", relay_urls.len()));
    client.connect(relay_urls).await?;
    print_ok("Connected to relays");

    // Auto-start event loop in background so REPL prompt returns
    let client_el = Arc::clone(&client);
    tokio::spawn(async move {
        if let Err(e) = client_el.start_event_loop().await {
            eprintln!("{}", format!("  ✗ event loop error: {e}").red());
        }
    });
    print_sys("Event loop started — incoming messages will appear automatically.");
    Ok(())
}

async fn cmd_disconnect(client: &KeychatClient) -> anyhow::Result<()> {
    client.disconnect().await?;
    print_ok("Disconnected from all relays");
    Ok(())
}

async fn cmd_relays(client: &KeychatClient) -> anyhow::Result<()> {
    let statuses = client.get_relay_statuses().await?;
    if statuses.is_empty() {
        print_sys("No relays configured");
        return Ok(());
    }
    println!("  {}", "Relay Status:".bold());
    for rs in &statuses {
        let status_colored = match rs.status.as_str() {
            "Connected" => rs.status.green(),
            "Connecting" => rs.status.yellow(),
            _ => rs.status.red(),
        };
        println!("    {} {}", status_colored, rs.url.dimmed());
    }
    Ok(())
}

async fn cmd_add_relay(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    if args.is_empty() {
        print_err("Usage: /add-relay <url>");
        return Ok(());
    }
    client.add_relay(args.to_string()).await?;
    print_ok(&format!("Relay added: {args}"));
    Ok(())
}

async fn cmd_remove_relay(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    if args.is_empty() {
        print_err("Usage: /remove-relay <url>");
        return Ok(());
    }
    client.remove_relay(args.to_string()).await?;
    print_ok(&format!("Relay removed: {args}"));
    Ok(())
}

async fn cmd_reconnect(client: &KeychatClient) -> anyhow::Result<()> {
    client.reconnect_relays().await?;
    print_ok("Reconnecting to all relays...");
    Ok(())
}

async fn cmd_status(client: &KeychatClient) -> anyhow::Result<()> {
    println!("  {}", "─── Status ───".bold());

    // Identity
    match client.get_pubkey_hex().await {
        Ok(pk) => println!("  {} {}", "Identity:".dimmed(), short_key(&pk).cyan()),
        Err(_) => println!("  {} {}", "Identity:".dimmed(), "None".red()),
    }

    // Relays
    let statuses = client.get_relay_statuses().await.unwrap_or_default();
    let connected = statuses.iter().filter(|s| s.status == "Connected").count();
    println!(
        "  {} {}/{}",
        "Relays:  ".dimmed(),
        connected.to_string().green(),
        statuses.len()
    );
    for rs in &statuses {
        let status_colored = match rs.status.as_str() {
            "Connected" => rs.status.green(),
            "Connecting" => rs.status.yellow(),
            _ => rs.status.red(),
        };
        println!("    {} {}", status_colored, rs.url.dimmed());
    }

    // Debug state
    match client.debug_state_summary().await {
        Ok(summary) => println!("  {} {}", "State:   ".dimmed(), summary),
        Err(e) => println!("  {} {}", "State:   ".dimmed(), format!("error: {e}").red()),
    }

    Ok(())
}

// ─── Friend commands ────────────────────────────────────────────

async fn cmd_add_friend(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
    if parts.is_empty() || parts[0].is_empty() {
        print_err("Usage: /add <pubkey_hex_or_npub> [my_name]");
        return Ok(());
    }

    let peer_pubkey = keychat_uniffi::normalize_to_hex(parts[0].to_string())
        .map_err(|e| anyhow::anyhow!("invalid pubkey: {e}"))?;
    let my_name = if parts.len() > 1 {
        parts[1].to_string()
    } else {
        "CLI User".to_string()
    };

    print_sys(&format!(
        "Sending friend request to {}...",
        short_key(&peer_pubkey).cyan()
    ));
    let pending = client
        .send_friend_request(peer_pubkey, my_name, "cli-device".to_string())
        .await?;
    print_ok(&format!(
        "Friend request sent. Request ID: {}",
        short_key(&pending.request_id).yellow()
    ));
    Ok(())
}

async fn cmd_accept(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
    if parts.is_empty() || parts[0].is_empty() {
        print_err("Usage: /accept <request_id> [my_name]");
        return Ok(());
    }

    let request_id = parts[0].to_string();
    let my_name = if parts.len() > 1 {
        parts[1].to_string()
    } else {
        "CLI User".to_string()
    };

    let contact = client
        .accept_friend_request(request_id, my_name)
        .await?;
    print_ok(&format!(
        "Friend request accepted. Contact: {} ({})",
        contact.display_name.green(),
        short_key(&contact.nostr_pubkey_hex).cyan()
    ));
    Ok(())
}

async fn cmd_reject(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    if args.is_empty() {
        print_err("Usage: /reject <request_id>");
        return Ok(());
    }
    client
        .reject_friend_request(args.to_string(), None)
        .await?;
    print_ok("Friend request rejected");
    Ok(())
}

async fn cmd_contacts(client: &KeychatClient) -> anyhow::Result<()> {
    let pubkey = client.get_pubkey_hex().await?;
    let contacts = client.get_contacts(pubkey).await?;
    if contacts.is_empty() {
        print_sys("No contacts yet. Use /add <pubkey> to send a friend request.");
        return Ok(());
    }
    println!("  {}", "Contacts:".bold());
    for c in &contacts {
        let name = c
            .petname
            .as_deref()
            .or(c.name.as_deref())
            .unwrap_or("(unnamed)");
        println!(
            "    {} {}",
            name.green(),
            short_key(&c.pubkey).dimmed()
        );
    }
    Ok(())
}

// ─── Messaging commands ─────────────────────────────────────────

async fn cmd_chat(
    client: &KeychatClient,
    args: &str,
    active_room_id: &mut Option<String>,
) -> anyhow::Result<()> {
    if args.is_empty() {
        if let Some(ref room_id) = active_room_id {
            print_sys(&format!("Active chat: {}", short_key(room_id).cyan()));
        } else {
            print_err("Usage: /chat <number|name|room_id|pubkey>");
        }
        return Ok(());
    }

    let query = args.trim();
    let pubkey = client.get_pubkey_hex().await?;
    let rooms = client.get_rooms(pubkey).await?;

    // Helper to select a room
    let select = |room: &keychat_uniffi::RoomInfo, active: &mut Option<String>| {
        *active = Some(room.id.clone());
        let fallback = short_key(&room.to_main_pubkey);
        let name = room.name.as_deref().unwrap_or(&fallback);
        print_ok(&format!("Chat selected: {}", name.cyan()));
    };

    // 1. Try as index number (1-based, matches /rooms output)
    if let Ok(idx) = query.parse::<usize>() {
        if idx >= 1 && idx <= rooms.len() {
            select(&rooms[idx - 1], active_room_id);
            return Ok(());
        }
        print_err(&format!("Room index {idx} out of range (1-{})", rooms.len()));
        return Ok(());
    }

    // 2. Try exact room_id match
    if let Some(room) = rooms.iter().find(|r| r.id == query) {
        select(room, active_room_id);
        return Ok(());
    }

    // 3. Try room_id prefix match
    let prefix_matches: Vec<_> = rooms.iter().filter(|r| r.id.starts_with(query)).collect();
    if prefix_matches.len() == 1 {
        select(prefix_matches[0], active_room_id);
        return Ok(());
    } else if prefix_matches.len() > 1 {
        print_err(&format!("Ambiguous ID prefix '{}' matches {} rooms — use more characters", query, prefix_matches.len()));
        return Ok(());
    }

    // 4. Try name match (case-insensitive)
    let query_lower = query.to_lowercase();
    let name_matches: Vec<_> = rooms.iter().filter(|r| {
        r.name.as_deref().map(|n| n.to_lowercase() == query_lower).unwrap_or(false)
    }).collect();
    if name_matches.len() == 1 {
        select(name_matches[0], active_room_id);
        return Ok(());
    } else if name_matches.len() > 1 {
        print_err(&format!("Ambiguous name '{}' matches {} rooms — use room index or ID", query, name_matches.len()));
        return Ok(());
    }

    // 5. Try name substring match (case-insensitive)
    let substr_matches: Vec<_> = rooms.iter().filter(|r| {
        r.name.as_deref().map(|n| n.to_lowercase().contains(&query_lower)).unwrap_or(false)
    }).collect();
    if substr_matches.len() == 1 {
        select(substr_matches[0], active_room_id);
        return Ok(());
    } else if substr_matches.len() > 1 {
        print_err(&format!("Ambiguous name '{}' matches {} rooms — use room index or ID", query, substr_matches.len()));
        return Ok(());
    }

    // 6. Try as contact pubkey (hex or npub)
    let normalized = keychat_uniffi::normalize_to_hex(query.to_string()).unwrap_or(query.to_string());
    if let Some(room) = rooms.iter().find(|r| r.to_main_pubkey == normalized) {
        select(room, active_room_id);
        return Ok(());
    }

    print_err(&format!("No room found matching '{}'", query));
    Ok(())
}

async fn cmd_rooms(client: &KeychatClient) -> anyhow::Result<()> {
    let pubkey = client.get_pubkey_hex().await?;
    let rooms = client.get_rooms(pubkey).await?;
    if rooms.is_empty() {
        print_sys("No rooms yet.");
        return Ok(());
    }
    println!("  {}", "Rooms:".bold());
    for (i, r) in rooms.iter().enumerate() {
        let idx = format!("{:>2}", i + 1).cyan();
        let fallback = short_key(&r.to_main_pubkey);
        let name = r.name.as_deref().unwrap_or(&fallback);
        let room_type = match r.room_type {
            RoomType::Dm => "DM",
            RoomType::SignalGroup => "SG",
            RoomType::MlsGroup => "MLS",
        };
        let status = match r.status {
            RoomStatus::Enabled => "●".green(),
            RoomStatus::Requesting => "◐".yellow(),
            RoomStatus::Approving => "◑".yellow(),
            RoomStatus::Rejected => "○".red(),
        };
        let unread = if r.unread_count > 0 {
            format!(" ({})", r.unread_count).red().to_string()
        } else {
            String::new()
        };
        let last_msg = r
            .last_message_content
            .as_deref()
            .map(|s| {
                let truncated = if s.chars().count() > 40 {
                    format!("{}...", s.chars().take(40).collect::<String>())
                } else {
                    s.to_string()
                };
                format!(" — {}", truncated).dimmed().to_string()
            })
            .unwrap_or_default();
        println!(
            "  {idx}. {status} [{room_type}] {name}{unread}{last_msg}",
        );
        println!(
            "      {} {}  {} {}",
            "ID:".dimmed(),
            r.id.dimmed(),
            "Peer:".dimmed(),
            short_key(&r.to_main_pubkey).dimmed(),
        );
    }
    println!();
    print_sys("Use /chat <number> or /chat <name> to select a room");
    Ok(())
}

async fn cmd_read(
    client: &KeychatClient,
    active_room_id: &Option<String>,
) -> anyhow::Result<()> {
    let room_id = match active_room_id {
        Some(id) => id.clone(),
        None => {
            print_err("No active chat. Use /chat <room_id> first.");
            return Ok(());
        }
    };
    client.mark_room_read(room_id).await?;
    print_ok("Room marked as read");
    Ok(())
}

async fn cmd_history(
    client: &KeychatClient,
    args: &str,
    active_room_id: &Option<String>,
) -> anyhow::Result<()> {
    let room_id = match active_room_id {
        Some(id) => id.clone(),
        None => {
            print_err("No active chat. Use /chat <room_id> first.");
            return Ok(());
        }
    };

    let count: i32 = args.parse().unwrap_or(DEFAULT_HISTORY_COUNT);
    let messages = client.get_messages(room_id, count, 0).await?;

    if messages.is_empty() {
        print_sys("No messages in this chat.");
        return Ok(());
    }

    println!("  {}", format!("─── Last {} messages ───", messages.len()).bold());
    for msg in &messages {
        let time = format_timestamp(msg.created_at);
        let sender = if msg.is_me_send {
            "You".green().to_string()
        } else {
            short_key(&msg.sender_pubkey).cyan().to_string()
        };
        let status_icon = match msg.status {
            keychat_uniffi::MessageStatus::Sending => "⏳",
            keychat_uniffi::MessageStatus::Success => "✓",
            keychat_uniffi::MessageStatus::Failed => "✗",
        };
        println!(
            "  {} {} {} {}",
            time.dimmed(),
            sender,
            status_icon.dimmed(),
            msg.content
        );
    }
    Ok(())
}

async fn send_chat_message(
    client: &KeychatClient,
    active_room_id: &Option<String>,
    text: &str,
) -> anyhow::Result<bool> {
    let room_id = match active_room_id {
        Some(id) => id.clone(),
        None => {
            print_err("No active chat. Use /chat <room_id> first, or use / commands.");
            return Ok(false);
        }
    };

    match crate::commands::send_message(client, &room_id, text).await? {
        crate::commands::SendResult::Dm { event_id, relay_count } => {
            print_sys(&format!(
                "Sent [{}] → {} relay(s)",
                short_key(&event_id).dimmed(),
                relay_count
            ));
        }
        crate::commands::SendResult::Group { event_count } => {
            print_sys(&format!("Sent to group ({event_count} event(s))"));
        }
        crate::commands::SendResult::MlsNotSupported => {
            print_err("MLS groups are not yet supported in this CLI.");
        }
    }
    Ok(false)
}

// ─── Signal Group commands ──────────────────────────────────────

async fn cmd_sg_create(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        print_err("Usage: /sg-create <name> <member1_pubkey> [member2_pubkey...]");
        return Ok(());
    }
    let name = parts[0].to_string();
    let members: Vec<GroupMemberInput> = parts[1..]
        .iter()
        .map(|pk| {
            let normalized =
                keychat_uniffi::normalize_to_hex(pk.to_string()).unwrap_or_else(|_| pk.to_string());
            GroupMemberInput {
                nostr_pubkey: normalized.clone(),
                name: short_key(&normalized),
            }
        })
        .collect();

    print_sys(&format!(
        "Creating signal group '{}' with {} member(s)...",
        name,
        members.len()
    ));
    let info = client.create_signal_group(name, members).await?;
    print_ok(&format!(
        "Group created: {} (id: {}, {} members)",
        info.name.green(),
        short_key(&info.group_id).cyan(),
        info.member_count
    ));
    Ok(())
}

fn cmd_sg_chat(args: &str, active_room_id: &mut Option<String>) -> anyhow::Result<()> {
    if args.is_empty() {
        print_err("Usage: /sg-chat <group_id>");
        return Ok(());
    }
    *active_room_id = Some(args.trim().to_string());
    print_ok(&format!(
        "Group chat selected: {}",
        short_key(args.trim()).cyan()
    ));
    Ok(())
}

async fn cmd_sg_leave(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    if args.is_empty() {
        print_err("Usage: /sg-leave <group_id>");
        return Ok(());
    }
    client.leave_signal_group(args.trim().to_string()).await?;
    print_ok("Left signal group");
    Ok(())
}

async fn cmd_sg_dissolve(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    if args.is_empty() {
        print_err("Usage: /sg-dissolve <group_id>");
        return Ok(());
    }
    client
        .dissolve_signal_group(args.trim().to_string())
        .await?;
    print_ok("Signal group dissolved");
    Ok(())
}

async fn cmd_sg_rename(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
    if parts.len() < 2 {
        print_err("Usage: /sg-rename <group_id> <new_name>");
        return Ok(());
    }
    client
        .rename_signal_group(parts[0].to_string(), parts[1].to_string())
        .await?;
    print_ok(&format!("Group renamed to: {}", parts[1].green()));
    Ok(())
}

async fn cmd_sg_kick(client: &KeychatClient, args: &str) -> anyhow::Result<()> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() < 2 {
        print_err("Usage: /sg-kick <group_id> <member_pubkey>");
        return Ok(());
    }
    let member_pk =
        keychat_uniffi::normalize_to_hex(parts[1].to_string()).unwrap_or_else(|_| parts[1].to_string());
    client
        .remove_group_member(parts[0].to_string(), member_pk)
        .await?;
    print_ok("Member removed from group");
    Ok(())
}

// ─── Utility commands ───────────────────────────────────────────

async fn cmd_retry(client: &KeychatClient) -> anyhow::Result<()> {
    let count = client.retry_failed_messages().await?;
    if count > 0 {
        print_ok(&format!("Retrying {} failed message(s)", count));
    } else {
        print_sys("No failed messages to retry");
    }
    Ok(())
}

async fn cmd_debug(client: &KeychatClient) -> anyhow::Result<()> {
    let summary = client.debug_state_summary().await?;
    println!("  {}", "Debug State:".bold());
    println!("  {summary}");
    Ok(())
}

// ─── Background event printer ───────────────────────────────────

fn spawn_event_printer(
    mut event_rx: broadcast::Receiver<ClientEvent>,
    mut data_rx: broadcast::Receiver<DataChange>,
) {
    // Event printer
    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => print_event(&event),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!(
                        "  {} {}",
                        "[warn]".yellow(),
                        format!("Event printer lagged, missed {n} events").dimmed()
                    );
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Data change printer (less verbose, only notable changes)
    tokio::spawn(async move {
        loop {
            match data_rx.recv().await {
                Ok(change) => print_data_change(&change),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

fn print_event(event: &ClientEvent) {
    match event {
        ClientEvent::MessageReceived {
            sender_pubkey,
            kind,
            content,
            group_id,
            ..
        } => {
            let kind_str = match kind {
                MessageKind::Text => "",
                MessageKind::Files => "[file] ",
                MessageKind::FriendRequest => "[friend-request] ",
                MessageKind::FriendApprove => "[friend-approved] ",
                MessageKind::FriendReject => "[friend-rejected] ",
                MessageKind::SignalGroupInvite => "[group-invite] ",
                MessageKind::SignalGroupDissolve => "[group-dissolved] ",
                MessageKind::SignalGroupMemberRemoved => "[member-removed] ",
                MessageKind::SignalGroupSelfLeave => "[member-left] ",
                MessageKind::SignalGroupNameChanged => "[group-renamed] ",
                _ => "[msg] ",
            };
            let group_prefix = group_id
                .as_ref()
                .map(|gid| format!("[{}] ", short_key(gid).magenta()))
                .unwrap_or_default();
            let body = content.as_deref().unwrap_or("");
            eprintln!(
                "\r  {} {}{}{}{} {}",
                format_now().dimmed(),
                group_prefix,
                short_key(sender_pubkey).cyan(),
                ": ".dimmed(),
                kind_str.yellow(),
                body
            );
        }
        ClientEvent::FriendRequestReceived {
            request_id,
            sender_pubkey,
            sender_name,
            message,
            ..
        } => {
            eprintln!(
                "\r  {} {} from {} ({}) {}",
                format_now().dimmed(),
                "Friend request".yellow().bold(),
                sender_name.green(),
                short_key(sender_pubkey).cyan(),
                message.as_deref().unwrap_or("")
            );
            eprintln!(
                "  {} /accept {} [your_name]",
                "To accept:".dimmed(),
                request_id
            );
        }
        ClientEvent::FriendRequestAccepted {
            peer_pubkey,
            peer_name,
        } => {
            eprintln!(
                "\r  {} {} {} ({})",
                format_now().dimmed(),
                "Friend request accepted by".green(),
                peer_name.green(),
                short_key(peer_pubkey).cyan()
            );
        }
        ClientEvent::FriendRequestRejected { peer_pubkey } => {
            eprintln!(
                "\r  {} {} {}",
                format_now().dimmed(),
                "Friend request rejected by".red(),
                short_key(peer_pubkey).cyan()
            );
        }
        ClientEvent::GroupInviteReceived {
            room_id,
            group_name,
            inviter_pubkey,
            ..
        } => {
            eprintln!(
                "\r  {} {} '{}' from {}",
                format_now().dimmed(),
                "Group invite received:".yellow().bold(),
                group_name.green(),
                short_key(inviter_pubkey).cyan()
            );
            eprintln!(
                "  {} /sg-chat {}",
                "To join chat:".dimmed(),
                room_id
            );
        }
        ClientEvent::GroupDissolved { room_id } => {
            eprintln!(
                "\r  {} {} {}",
                format_now().dimmed(),
                "Group dissolved:".red(),
                short_key(room_id).cyan()
            );
        }
        ClientEvent::GroupMemberChanged {
            room_id,
            kind,
            member_pubkey,
            new_value,
        } => {
            let detail = match kind {
                keychat_uniffi::GroupChangeKind::MemberRemoved => {
                    format!(
                        "Member removed: {}",
                        member_pubkey.as_deref().unwrap_or("?")
                    )
                }
                keychat_uniffi::GroupChangeKind::SelfLeave => "A member left the group".to_string(),
                keychat_uniffi::GroupChangeKind::NameChanged => {
                    format!(
                        "Group renamed to: {}",
                        new_value.as_deref().unwrap_or("?")
                    )
                }
            };
            eprintln!(
                "\r  {} {} [{}]",
                format_now().dimmed(),
                detail.yellow(),
                short_key(room_id).dimmed()
            );
        }
        ClientEvent::RelayOk {
            event_id,
            relay_url,
            success,
            message,
        } => {
            if !success {
                eprintln!(
                    "\r  {} {} {} — {}",
                    format_now().dimmed(),
                    "Relay NACK".red(),
                    short_key(event_id).dimmed(),
                    format!("{relay_url}: {message}").dimmed()
                );
            }
        }
        ClientEvent::EventLoopError { description } => {
            eprintln!(
                "\r  {} {}",
                "[event-loop error]".red(),
                description
            );
        }
    }
}

fn print_data_change(change: &DataChange) {
    match change {
        DataChange::ConnectionStatusChanged { status, message } => {
            let status_str = format!("{:?}", status);
            let colored = match status {
                keychat_uniffi::ConnectionStatus::Connected => status_str.green(),
                keychat_uniffi::ConnectionStatus::Connecting
                | keychat_uniffi::ConnectionStatus::Reconnecting => status_str.yellow(),
                _ => status_str.red(),
            };
            let msg = message.as_deref().unwrap_or("");
            eprintln!("\r  {} {} {}", "Connection:".dimmed(), colored, msg.dimmed());
        }
        // Other data changes are too noisy for the REPL; suppress them.
        _ => {}
    }
}

// ─── UI helpers ─────────────────────────────────────────────────

fn build_prompt(active_room_id: &Option<String>) -> String {
    match active_room_id {
        Some(room_id) => format!("{} {} ", short_key(room_id).cyan(), ">".bold()),
        None => format!("{} ", "keychat>".bold()),
    }
}

fn print_banner() {
    println!();
    println!(
        "  {}",
        "Keychat CLI — E2E encrypted messaging over Nostr".bold()
    );
    println!(
        "  {}",
        "Type /help for commands, /quit to exit".dimmed()
    );
    println!();
}

fn print_help() {
    println!("  {}", "─── Commands ───".bold());
    println!();
    println!("  {}", "Identity:".bold());
    println!("    {}  Create new identity", "/create".green());
    println!("    {}  Import from mnemonic", "/import <mnemonic>".green());
    println!("    {}   Show current pubkey", "/whoami".green());
    println!("    {}   Show backup info", "/backup".green());
    println!("    {}  Remove identity (with confirmation)", "/delete-identity".green());
    println!();
    println!("  {}", "Connection:".bold());
    println!(
        "    {}  Connect to relays (default if none given)",
        "/connect [relay_url...]".green()
    );
    println!("    {}  Disconnect from all relays", "/disconnect".green());
    println!("    {}   List relay statuses", "/relays".green());
    println!("    {}  Add a relay", "/add-relay <url>".green());
    println!("    {}  Remove a relay", "/remove-relay <url>".green());
    println!("    {}  Reconnect all relays", "/reconnect".green());
    println!("    {}   Show connection + identity status", "/status".green());
    println!();
    println!("  {}", "Friends:".bold());
    println!(
        "    {}  Send friend request",
        "/add <pubkey> [my_name]".green()
    );
    println!(
        "    {}  Accept request",
        "/accept <request_id> [my_name]".green()
    );
    println!("    {}  Reject request", "/reject <request_id>".green());
    println!("    {}  List contacts", "/contacts".green());
    println!();
    println!("  {}", "Messaging:".bold());
    println!(
        "    {}  Select active chat",
        "/chat <room_id_or_pubkey>".green()
    );
    println!("    {}    List all rooms", "/rooms".green());
    println!("    {}     Mark current room as read", "/read".green());
    println!(
        "    {}  Show message history",
        "/history [count]".green()
    );
    println!(
        "    {}",
        "    (type text without / to send a message)".dimmed()
    );
    println!();
    println!("  {}", "Signal Groups:".bold());
    println!(
        "    {}  Create group",
        "/sg-create <name> <pubkey...>".green()
    );
    println!("    {}  Select group chat", "/sg-chat <group_id>".green());
    println!("    {}  Leave group", "/sg-leave <group_id>".green());
    println!(
        "    {}  Dissolve group (admin)",
        "/sg-dissolve <group_id>".green()
    );
    println!(
        "    {}  Rename group",
        "/sg-rename <group_id> <name>".green()
    );
    println!(
        "    {}  Remove member",
        "/sg-kick <group_id> <pubkey>".green()
    );
    println!();
    println!("  {}", "Utility:".bold());
    println!("    {}    Retry failed messages", "/retry".green());
    println!("    {}    Show debug state", "/debug".green());
    println!("    {}     Show this help", "/help".green());
    println!("    {} Exit", "/quit".green());
    println!();
}

fn print_sys(msg: &str) {
    println!("  {} {msg}", ">>".blue());
}

fn print_ok(msg: &str) {
    println!("  {} {msg}", "OK".green().bold());
}

fn print_err(msg: &str) {
    eprintln!("  {} {msg}", "ERROR".red().bold());
}

use crate::commands::{short_key, format_timestamp};

fn format_now() -> String {
    Utc::now().format("%H:%M:%S").to_string()
}
