use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::{mpsc, Mutex};

use crate::client::{InboundEvent, KeychatClient};
use crate::group::types::{GroupEvent, GroupProfile, GroupTypeWire};
use crate::media;
use crate::mls::transport;
use crate::mls::types::{CommitTypeResult, ProcessedMlsMessage};
use crate::nostr::nip44;
use crate::transport::relay::RelayFilter;

use super::app::{App, AppMode, ChatMessage, ChatMessageKind, PeerPickerAction, Room};
use super::ui;

type DynResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Resize(u16, u16),
    Inbound(InboundEvent),
    MlsMessage { group_id: String, bytes: Vec<u8> },
    MlsWelcome { sender: String, welcome_bytes: Vec<u8> },
    Tick,
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> DynResult<Self> {
        enable_raw_mode()?;
        execute!(std::io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

pub async fn run(mut app: App, client: Arc<Mutex<KeychatClient>>) -> DynResult<App> {
    let _guard = TerminalGuard::enter()?;

    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let (tx, mut rx) = mpsc::channel::<AppEvent>(256);

    let key_tx = tx.clone();
    std::thread::spawn(move || loop {
        match event::poll(Duration::from_millis(100)) {
            Ok(true) => match event::read() {
                Ok(CEvent::Key(key)) => {
                    if key_tx.blocking_send(AppEvent::Key(key)).is_err() {
                        break;
                    }
                }
                Ok(CEvent::Resize(w, h)) => {
                    if key_tx.blocking_send(AppEvent::Resize(w, h)).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            },
            Ok(false) => {}
            Err(_) => break,
        }
    });

    let tick_tx = tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            if tick_tx.send(AppEvent::Tick).await.is_err() {
                break;
            }
        }
    });

    let inbound_tx = tx.clone();
    let inbound_client = Arc::clone(&client);
    tokio::spawn(async move {
        loop {
            // Short lock + timeout so other tasks can acquire the lock
            let next = {
                let mut c = inbound_client.lock().await;
                tokio::time::timeout(Duration::from_millis(100), c.next_event()).await
            };

            match next {
                Ok(Some(event)) => {
                    if inbound_tx.send(AppEvent::Inbound(event)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break, // stream ended
                Err(_) => {
                    // Timeout — release lock, yield to other tasks
                    tokio::task::yield_now().await;
                }
            }
        }
    });

    spawn_mls_welcome_listener(&client, &tx).await?;
    restore_mls_subscriptions(&app, &client, &tx).await;

    loop {
        terminal.draw(|f| ui::render(f, &app))?;

        let Some(event) = rx.recv().await else {
            break;
        };

        match event {
            AppEvent::Key(key) => handle_key(&mut app, key, &client, &tx).await?,
            AppEvent::Inbound(event) => handle_inbound(&mut app, event).await,
            AppEvent::MlsMessage { group_id, bytes } => {
                handle_mls_message(&mut app, &client, &group_id, &bytes).await
            }
            AppEvent::MlsWelcome {
                sender,
                welcome_bytes,
            } => handle_mls_welcome(&mut app, &client, &tx, &sender, &welcome_bytes).await,
            AppEvent::Resize(_, _) | AppEvent::Tick => {}
        }

        if app.should_quit {
            break;
        }
    }

    terminal.show_cursor()?;
    Ok(app)
}

async fn handle_key(
    app: &mut App,
    key: KeyEvent,
    client: &Arc<Mutex<KeychatClient>>,
    event_tx: &mpsc::Sender<AppEvent>,
) -> DynResult<()> {
    let is_ctrl_q = key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'));
    let is_ctrl_c = key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'));
    if is_ctrl_q || is_ctrl_c {
        app.should_quit = true;
        return Ok(());
    }

    let is_switch = matches!(key.code, KeyCode::Tab)
        || (key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('l') | KeyCode::Char('L')));

    if key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y'))
    {
        app.copy_npub_to_clipboard();
        return Ok(());
    }

    if is_switch {
        app.switch_mode();
        return Ok(());
    }

    match app.mode {
        AppMode::RoomSelect => match key.code {
            KeyCode::Up => app.select_prev(),
            KeyCode::Down => app.select_next(),
            KeyCode::Enter => app.open_selected_room(),
            KeyCode::Char('a') | KeyCode::Char('A') => app.enter_add_friend(),
            KeyCode::Char('d') | KeyCode::Char('D') => {
                if !app.rooms.is_empty() {
                    app.mode = AppMode::ConfirmDelete;
                }
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => app.copy_npub_to_clipboard(),
            _ => {}
        },
        AppMode::ConfirmDelete => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.delete_selected_room(),
            _ => {
                app.status_message = None;
                app.mode = AppMode::RoomSelect;
            }
        },
        AppMode::AddFriend => match key.code {
            KeyCode::Esc => {
                app.mode = AppMode::RoomSelect;
            }
            KeyCode::Backspace => app.add_friend_backspace(),
            KeyCode::Char(ch) => {
                if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) {
                    app.add_friend_insert_char(ch);
                }
            }
            KeyCode::Enter => {
                let npub = app.take_add_friend_input();
                let trimmed = npub.trim().to_owned();
                if !trimmed.is_empty() {
                    let mut c = client.lock().await;
                    match c.add_friend(&trimmed, "Hello from keychat-tui!").await {
                        Ok(()) => {
                            app.status_message = Some(format!(
                                "✅ Friend request sent to {}",
                                &trimmed[..trimmed.len().min(20)]
                            ));
                            app.ensure_direct_room(&resolve_npub(&trimmed));
                            app.mode = AppMode::Normal;
                        }
                        Err(e) => {
                            app.status_message = Some(format!("❌ {}", e));
                        }
                    }
                }
            }
            _ => {}
        },
        AppMode::Normal => match key.code {
            KeyCode::Left => app.move_cursor_left(),
            KeyCode::Right => app.move_cursor_right(),
            KeyCode::Backspace => app.backspace(),
            KeyCode::Up
                if key.modifiers.contains(KeyModifiers::SHIFT)
                    || key.modifiers.contains(KeyModifiers::ALT) =>
            {
                app.scroll_up();
            }
            KeyCode::Down
                if key.modifiers.contains(KeyModifiers::SHIFT)
                    || key.modifiers.contains(KeyModifiers::ALT) =>
            {
                app.scroll_down();
            }
            KeyCode::PageUp => app.scroll_up(),
            KeyCode::PageDown => app.scroll_down(),
            KeyCode::Enter => {
                let text = app.take_input();
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    return Ok(());
                }

                if handle_command(app, client, event_tx, trimmed).await? {
                    return Ok(());
                }

                let Some(selected_room) = app.rooms.get(app.selected_room).cloned() else {
                    return Ok(());
                };

                match selected_room {
                    Room::Direct(room) => {
                        let send_result = {
                            let mut c = client.lock().await;
                            c.send(&room.peer_hex, trimmed).await
                        };
                        if let Err(e) = send_result {
                            app.status_message = Some(format!("❌ Send failed: {}", e));
                            return Ok(());
                        }

                        app.add_direct_message(
                            &room.peer_hex,
                            ChatMessage {
                                sender: "You".to_owned(),
                                text: trimmed.to_owned(),
                                timestamp: now_hhmm(),
                                is_self: true,
                                kind: ChatMessageKind::User,
                            },
                            false,
                        );
                    }
                    Room::Group(room) => {
                        if room.is_mls {
                            let group_id = room
                                .group_id
                                .clone()
                                .unwrap_or_else(|| room.group_pubkey.clone());
                            let mut listen_key = room.listen_key.clone().unwrap_or_default();
                            if listen_key.is_empty() {
                                let fetched = {
                                    let c = client.lock().await;
                                    match c.mls_listen_key(&group_id).await {
                                        Ok(k) => k,
                                        Err(e) => {
                                            drop(c);
                                            app.status_message = Some(format!("❌ MLS listen key failed: {}", e));
                                            return Ok(());
                                        }
                                    }
                                };
                                listen_key = fetched;
                                app.set_group_listen_key(&group_id, &listen_key);
                            }
                            let (ciphertext, export_secret, relays) = {
                                let c = client.lock().await;
                                let ct = match c.mls_encrypt(&group_id, trimmed).await {
                                    Ok(ct) => ct,
                                    Err(e) => {
                                        drop(c);
                                        app.status_message = Some(format!("❌ Encrypt failed: {}", e));
                                        return Ok(());
                                    }
                                };
                                let es = match c.mls_export_secret_keypair(&group_id).await {
                                    Ok(es) => es,
                                    Err(e) => {
                                        drop(c);
                                        app.status_message = Some(format!("❌ Export secret failed: {}", e));
                                        return Ok(());
                                    }
                                };
                                let relays = c.relays();
                                (ct, es, relays)
                            };
                            let Some(relay) = relays.first() else {
                                app.status_message = Some("❌ No relay connected".to_owned());
                                return Ok(());
                            };
                            if let Err(e) = transport::send_group_message(
                                relay,
                                &export_secret,
                                &listen_key,
                                &ciphertext,
                            )
                            .await
                            {
                                app.status_message = Some(format!("❌ Send failed: {}", e));
                                return Ok(());
                            }
                        } else {
                            let recipients: Vec<String> = room
                                .members
                                .iter()
                                .filter(|m| *m != &app.self_pubkey_hex)
                                .cloned()
                                .collect();
                            let recipient_refs: Vec<&str> =
                                recipients.iter().map(String::as_str).collect();

                            let send_result = {
                                let mut c = client.lock().await;
                                c.send_group_message(&room.group_pubkey, &recipient_refs, trimmed)
                                    .await
                            };
                            if let Err(e) = send_result {
                                app.status_message = Some(format!("❌ Send failed: {}", e));
                                return Ok(());
                            }
                        }

                        let room_id = room
                            .group_id
                            .clone()
                            .unwrap_or_else(|| room.group_pubkey.clone());
                        app.add_group_message(
                            &room_id,
                            &room.name,
                            ChatMessage {
                                sender: "You".to_owned(),
                                text: trimmed.to_owned(),
                                timestamp: now_hhmm(),
                                is_self: true,
                                kind: ChatMessageKind::User,
                            },
                            false,
                        );
                    }
                }
            }
            KeyCode::Char(ch) => {
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                {
                    app.insert_char(ch);
                }
            }
            _ => {}
        },
        AppMode::PeerPicker => match key.code {
            KeyCode::Esc => {
                app.peer_picker = None;
                app.mode = AppMode::Normal;
            }
            KeyCode::Up => {
                if let Some(ref mut picker) = app.peer_picker {
                    if picker.selected > 0 {
                        picker.selected -= 1;
                    }
                }
            }
            KeyCode::Down => {
                if let Some(ref mut picker) = app.peer_picker {
                    if picker.selected + 1 < picker.peers.len() {
                        picker.selected += 1;
                    }
                }
            }
            KeyCode::Enter => {
                let picker = app.peer_picker.take();
                app.mode = AppMode::Normal;
                if let Some(picker) = picker {
                    if let Some((peer_hex, _name)) = picker.peers.get(picker.selected) {
                        let peer_hex = peer_hex.clone();
                        match picker.action {
                            PeerPickerAction::Invite => {
                                execute_invite(app, client, &peer_hex).await?;
                            }
                            PeerPickerAction::LgInvite => {
                                execute_lg_invite(app, client, event_tx, &peer_hex).await?;
                            }
                        }
                    }
                }
            }
            _ => {}
        },
    }

    Ok(())
}

async fn handle_command(
    app: &mut App,
    client: &Arc<Mutex<KeychatClient>>,
    event_tx: &mpsc::Sender<AppEvent>,
    trimmed: &str,
) -> DynResult<bool> {
    if trimmed.starts_with("/file ") || trimmed.starts_with("/f ") {
        let Some(peer_hex) = app.selected_room_peer().map(str::to_owned) else {
            app.status_message = Some("❌ /file is only supported in 1:1 rooms".to_owned());
            return Ok(true);
        };

        let path_str = trimmed.splitn(2, ' ').nth(1).unwrap_or("").trim();
        let path = expand_tilde(path_str);

        if !path.exists() {
            app.status_message = Some(format!("❌ File not found: {}", path.display()));
            return Ok(true);
        }

        let file_bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                app.status_message = Some(format!("❌ Read error: {}", e));
                return Ok(true);
            }
        };

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let suffix = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let media_type = guess_media_type(&suffix);

        let mut c = client.lock().await;
        match c
            .send_media(&peer_hex, &file_bytes, &suffix, &filename, media_type)
            .await
        {
            Ok(()) => {
                app.add_direct_message(
                    &peer_hex,
                    ChatMessage {
                        sender: "You".to_owned(),
                        text: format!("📎 [{}] {}", media_type, filename),
                        timestamp: now_hhmm(),
                        is_self: true,
                        kind: ChatMessageKind::User,
                    },
                    false,
                );
            }
            Err(e) => {
                app.status_message = Some(format!("❌ Send failed: {}", e));
            }
        }
        return Ok(true);
    }

    // /add — must check specific sub-commands BEFORE generic /add <npub>
    // /add small group and /add large group are handled further down
    if trimmed.starts_with("/add ")
        && !trimmed.starts_with("/add small group ")
        && !trimmed.starts_with("/add sg ")
        && !trimmed.starts_with("/add large group ")
        && !trimmed.starts_with("/add lg ")
    {
        let target = trimmed.splitn(2, ' ').nth(1).unwrap_or("").trim();
        if target.is_empty() {
            app.status_message = Some("❌ Usage: /add <npub>".to_owned());
            return Ok(true);
        }
        let mut c = client.lock().await;
        match c.add_friend(target, "Hello from keychat-tui!").await {
            Ok(()) => {
                let peer_hex = resolve_npub(target);
                app.ensure_direct_room(&peer_hex);
                app.status_message = Some(format!("✅ Friend request sent to {}", &target[..target.len().min(20)]));
            }
            Err(e) => {
                app.status_message = Some(format!("❌ {}", e));
            }
        }
        return Ok(true);
    }

    if trimmed == "/help" || trimmed == "/h" {
        let help_lines = vec![
            "── General ──",
            "/add <npub>            Add friend (DM)",
            "/add small group <name>  Create small group (/add sg)",
            "/add large group <name>  Create large group (/add lg)",
            "/nick <npub> <name>    Set nickname for a contact",
            "/peers                 List all peers",
            "/npub                  Copy your npub to clipboard",
            "/help                  Show this help",
            "",
            "── In DM ──",
            "/file <path>           Send file/image (/f)",
            "/del                   Delete this contact",
            "",
            "── In Small Group ──",
            "/invite <npub>         Invite member to group",
            "/members               List group members",
            "/rename <name>         Rename group",
            "/kick <npub>           Remove member",
            "/leave                 Leave group",
            "",
            "── In Large Group ──",
            "/lg-invite <npub>      Invite member",
            "/lg-members            List members",
            "/lg-leave              Leave group",
            "",
            "── Navigation ──",
            "Tab / ↑↓               Switch rooms",
            "PgUp / PgDn            Scroll messages",
            "Ctrl+Q                 Quit",
        ];
        if app.selected_room_key().is_some() {
            for line in help_lines {
                app.add_system_message_to_current(line.to_owned());
            }
        } else {
            // No room selected — show condensed help in status bar
            app.status_message = Some(help_lines.join("  "));
        }
        return Ok(true);
    }

    if trimmed.starts_with("/add large group ") || trimmed.starts_with("/add lg ") {
        let name = if trimmed.starts_with("/add large group ") {
            trimmed.strip_prefix("/add large group ").unwrap_or("").trim()
        } else {
            trimmed.strip_prefix("/add lg ").unwrap_or("").trim()
        };
        if name.is_empty() {
            app.status_message = Some("❌ Usage: /add large group <name>".to_owned());
            return Ok(true);
        }

        let (group_id, listen_key, key_package, keypair, relays) = {
            let c = client.lock().await;
            let group_id = match c.create_mls_group(name).await {
                Ok(id) => id,
                Err(e) => {
                    drop(c);
                    app.status_message = Some(format!("❌ Create MLS group failed: {}", e));
                    return Ok(true);
                }
            };
            let listen_key = match c.mls_listen_key(&group_id).await {
                Ok(k) => k,
                Err(e) => {
                    drop(c);
                    app.status_message = Some(format!("❌ MLS listen key failed: {}", e));
                    return Ok(true);
                }
            };
            let key_package = match c.create_key_package().await {
                Ok(kp) => kp,
                Err(e) => {
                    drop(c);
                    app.status_message = Some(format!("❌ Create key package failed: {}", e));
                    return Ok(true);
                }
            };
            let keypair = c.keypair().clone();
            let relays = c.relays();
            (group_id, listen_key, key_package.key_package, keypair, relays)
        };

        let Some(relay) = relays.first() else {
            app.status_message = Some("❌ No relay connected".to_owned());
            return Ok(true);
        };
        if let Err(e) = transport::publish_key_package(relay, &keypair, &key_package).await {
            app.status_message = Some(format!("❌ Publish key package failed: {}", e));
            return Ok(true);
        }

        app.ensure_mls_group_room(
            &group_id,
            name,
            &listen_key,
            vec![app.self_pubkey_hex.clone()],
            true,
        );
        app.select_group_room(&group_id);
        if let Err(e) = spawn_mls_subscription(client, event_tx, &group_id, &listen_key).await {
            app.status_message = Some(format!("⚠️ MLS group created but subscription failed: {}", e));
            return Ok(true);
        }
        app.status_message = Some(format!("✅ MLS group created: {}", name));
        return Ok(true);
    }

    if trimmed == "/lg-invite" || trimmed.starts_with("/lg-invite ") {
        let Some(group) = app.selected_room_group().cloned() else {
            app.status_message = Some("❌ /lg-invite works only in an MLS group room".to_owned());
            return Ok(true);
        };
        if !group.is_mls {
            app.status_message = Some("❌ /lg-invite works only in an MLS group room".to_owned());
            return Ok(true);
        }

        let target = trimmed.splitn(2, ' ').nth(1).unwrap_or("").trim();
        if target.is_empty() {
            // No argument: open peer picker
            app.open_peer_picker(super::app::PeerPickerAction::LgInvite);
            return Ok(true);
        }

        let Some(peer_hex) = resolve_peer_input(app, target) else {
            app.status_message = Some(format!("❌ Unknown peer/nick: {}", target));
            return Ok(true);
        };

        execute_lg_invite(app, client, event_tx, &peer_hex).await?;
        return Ok(true);
    }

    if trimmed == "/lg-members" {
        let Some(group) = app.selected_room_group().cloned() else {
            app.status_message = Some("❌ /lg-members works only in an MLS group room".to_owned());
            return Ok(true);
        };
        if !group.is_mls {
            app.status_message = Some("❌ /lg-members works only in an MLS group room".to_owned());
            return Ok(true);
        }

        let mut out = Vec::new();
        for member in &group.members {
            let mut label = app.nicks.display(member);
            if member == &app.self_pubkey_hex {
                label.push_str(" (you)");
            }
            out.push(label);
        }

        let group_id = group.group_id.clone().unwrap_or_else(|| group.group_pubkey.clone());
        app.add_group_message(
            &group_id,
            &group.name,
            system_message(format!("MLS members: {}", out.join(", "))),
            false,
        );
        return Ok(true);
    }

    if trimmed == "/lg-leave" {
        let Some(group) = app.selected_room_group().cloned() else {
            app.status_message = Some("❌ /lg-leave works only in an MLS group room".to_owned());
            return Ok(true);
        };
        if !group.is_mls {
            app.status_message = Some("❌ /lg-leave works only in an MLS group room".to_owned());
            return Ok(true);
        }
        let group_id = group.group_id.clone().unwrap_or_else(|| group.group_pubkey.clone());
        let mut listen_key = group.listen_key.clone().unwrap_or_default();
        if listen_key.is_empty() {
            let fetched = {
                let c = client.lock().await;
                c.mls_listen_key(&group_id).await?
            };
            listen_key = fetched;
            app.set_group_listen_key(&group_id, &listen_key);
        }
        let (export_secret, commit, relays) = {
            let c = client.lock().await;
            let export_secret = c.mls_export_secret_keypair(&group_id).await?;
            let commit = c.mls_leave_group(&group_id).await?;
            let relays = c.relays();
            (export_secret, commit, relays)
        };
        if let Some(relay) = relays.first() {
            let _ = transport::send_group_message(relay, &export_secret, &listen_key, &commit).await;
        }
        app.remove_group_room(&group_id);
        app.status_message = Some("✅ Left MLS group".to_owned());
        return Ok(true);
    }

    if trimmed.starts_with("/add small group ") || trimmed.starts_with("/add sg ") {
        let name = if trimmed.starts_with("/add small group ") {
            trimmed.strip_prefix("/add small group ").unwrap_or("").trim()
        } else {
            trimmed.strip_prefix("/add sg ").unwrap_or("").trim()
        };
        if name.is_empty() {
            app.status_message = Some("❌ Usage: /add small group <name>".to_owned());
            return Ok(true);
        }

        let create = {
            let c = client.lock().await;
            c.create_group(name)
        };

        match create {
            Ok(result) => {
                let (members, is_admin) = parse_profile_members(&result.profile, &app.self_pubkey_hex);
                app.ensure_group_room(
                    &result.profile.pubkey,
                    &result.profile.name,
                    members,
                    is_admin,
                );
                app.select_group_room(&result.profile.pubkey);
                app.status_message = Some(format!(
                    "✅ Group created: {} ({})",
                    result.profile.name,
                    short_hex(&result.profile.pubkey)
                ));
            }
            Err(e) => {
                app.status_message = Some(format!("❌ Create group failed: {}", e));
            }
        }
        return Ok(true);
    }

    if trimmed == "/invite" || trimmed.starts_with("/invite ") {
        let Some(group) = app.selected_room_group().cloned() else {
            app.status_message = Some("❌ /invite works only in a group room".to_owned());
            return Ok(true);
        };
        if group.is_mls {
            app.status_message = Some("❌ Use /lg-invite for MLS groups".to_owned());
            return Ok(true);
        }

        let target = trimmed.splitn(2, ' ').nth(1).unwrap_or("").trim();
        if target.is_empty() {
            // No argument: open peer picker
            app.open_peer_picker(super::app::PeerPickerAction::Invite);
            return Ok(true);
        }

        let Some(peer_hex) = resolve_peer_input(app, target) else {
            app.status_message = Some(format!("❌ Unknown peer/nick: {}", target));
            return Ok(true);
        };

        execute_invite(app, client, &peer_hex).await?;
        return Ok(true);
    }

    if trimmed == "/members" {
        let Some(group) = app.selected_room_group().cloned() else {
            app.status_message = Some("❌ /members works only in a group room".to_owned());
            return Ok(true);
        };
        if group.is_mls {
            app.status_message = Some("❌ Use /lg-members for MLS groups".to_owned());
            return Ok(true);
        }

        let mut out = Vec::new();
        for member in &group.members {
            let mut label = app.nicks.display(member);
            if member == &app.self_pubkey_hex {
                label.push_str(" (you)");
            }
            if group.is_admin && member == &app.self_pubkey_hex {
                label.push_str(" [admin]");
            }
            out.push(label);
        }

        app.add_group_message(
            &group.group_pubkey,
            &group.name,
            system_message(format!("Members: {}", out.join(", "))),
            false,
        );
        return Ok(true);
    }

    if trimmed.starts_with("/rename ") {
        let Some(group) = app.selected_room_group().cloned() else {
            app.status_message = Some("❌ /rename works only in a group room".to_owned());
            return Ok(true);
        };
        if group.is_mls {
            app.status_message = Some("❌ /rename is not supported for MLS groups".to_owned());
            return Ok(true);
        }
        if !group.is_admin {
            app.status_message = Some("❌ Admin only".to_owned());
            return Ok(true);
        }

        let new_name = trimmed.splitn(2, ' ').nth(1).unwrap_or("").trim();
        if new_name.is_empty() {
            app.status_message = Some("❌ Usage: /rename <new_name>".to_owned());
            return Ok(true);
        }

        let recipients: Vec<String> = group
            .members
            .iter()
            .filter(|m| *m != &app.self_pubkey_hex)
            .cloned()
            .collect();
        let recipient_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();

        let mut c = client.lock().await;
        c.rename_group(&group.group_pubkey, new_name, &recipient_refs)
            .await?;

        app.update_group_name(&group.group_pubkey, new_name);
        app.add_group_message(
            &group.group_pubkey,
            new_name,
            system_message(format!("Group renamed to {}", new_name)),
            false,
        );
        return Ok(true);
    }

    if trimmed.starts_with("/kick ") {
        let Some(group) = app.selected_room_group().cloned() else {
            app.status_message = Some("❌ /kick works only in a group room".to_owned());
            return Ok(true);
        };
        if group.is_mls {
            app.status_message = Some("❌ Use /lg-remove (not yet implemented) for MLS groups".to_owned());
            return Ok(true);
        }
        if !group.is_admin {
            app.status_message = Some("❌ Admin only".to_owned());
            return Ok(true);
        }

        let target = trimmed.splitn(2, ' ').nth(1).unwrap_or("").trim();
        if target.is_empty() {
            app.status_message = Some("❌ Usage: /kick <npub_or_nick>".to_owned());
            return Ok(true);
        }

        let Some(member_pubkey) = resolve_peer_input(app, target) else {
            app.status_message = Some(format!("❌ Unknown peer/nick: {}", target));
            return Ok(true);
        };
        if member_pubkey == app.self_pubkey_hex {
            app.status_message = Some("❌ Use /leave to leave your own group".to_owned());
            return Ok(true);
        }
        if !group.members.iter().any(|m| m == &member_pubkey) {
            app.status_message = Some("❌ User is not in this group".to_owned());
            return Ok(true);
        }

        let remaining: Vec<String> = group
            .members
            .iter()
            .filter(|m| *m != &member_pubkey && *m != &app.self_pubkey_hex)
            .cloned()
            .collect();
        let remaining_refs: Vec<&str> = remaining.iter().map(String::as_str).collect();

        let mut c = client.lock().await;
        c.remove_group_member(&group.group_pubkey, &member_pubkey, &remaining_refs)
            .await?;

        app.remove_group_member(&group.group_pubkey, &member_pubkey);
        app.add_group_message(
            &group.group_pubkey,
            &group.name,
            system_message(format!("Removed {}", app.nicks.display(&member_pubkey))),
            false,
        );
        return Ok(true);
    }

    if trimmed == "/leave" {
        let Some(group) = app.selected_room_group().cloned() else {
            app.status_message = Some("❌ /leave works only in a group room".to_owned());
            return Ok(true);
        };
        if group.is_mls {
            app.status_message = Some("❌ Use /lg-leave for MLS groups".to_owned());
            return Ok(true);
        }

        let mut c = client.lock().await;
        if group.is_admin {
            let members: Vec<String> = group
                .members
                .iter()
                .filter(|m| *m != &app.self_pubkey_hex)
                .cloned()
                .collect();
            let member_refs: Vec<&str> = members.iter().map(String::as_str).collect();
            c.dissolve_group(&group.group_pubkey, &member_refs).await?;
            app.remove_group_room(&group.group_pubkey);
            app.status_message = Some("✅ Group dissolved".to_owned());
        } else {
            let remaining: Vec<String> = group
                .members
                .iter()
                .filter(|m| *m != &app.self_pubkey_hex)
                .cloned()
                .collect();
            let remaining_refs: Vec<&str> = remaining.iter().map(String::as_str).collect();
            c.remove_group_member(
                &group.group_pubkey,
                &app.self_pubkey_hex,
                &remaining_refs,
            )
            .await?;
            app.remove_group_room(&group.group_pubkey);
            app.status_message = Some("✅ Left group".to_owned());
        }
        return Ok(true);
    }

    Ok(false)
}

async fn spawn_mls_welcome_listener(
    client: &Arc<Mutex<KeychatClient>>,
    event_tx: &mpsc::Sender<AppEvent>,
) -> DynResult<()> {
    let (relay, keypair, self_pubkey) = {
        let c = client.lock().await;
        let relays = c.relays();
        let Some(relay) = relays.first().cloned() else {
            return Ok(());
        };
        (relay, c.keypair().clone(), c.pubkey_hex())
    };

    let sub_id = format!("mls-welcome-{:016x}", rand::random::<u64>());
    relay.subscribe(sub_id.clone(), RelayFilter::for_welcomes(&self_pubkey))
        .await?;

    let mut events = relay.subscribe_events();
    let tx = event_tx.clone();
    tokio::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event)
                    if event.kind == 444
                        && event
                            .first_tag_value("p")
                            .is_some_and(|value| value == self_pubkey) =>
                {
                    let Ok(plaintext) = nip44::decrypt(&keypair, &event.pubkey, &event.content)
                    else {
                        continue;
                    };
                    let Ok(welcome_bytes) = hex::decode(&plaintext) else {
                        continue;
                    };
                    if tx
                        .send(AppEvent::MlsWelcome {
                            sender: event.pubkey,
                            welcome_bytes,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }

        let _ = relay.unsubscribe(sub_id).await;
    });

    Ok(())
}

async fn restore_mls_subscriptions(
    app: &App,
    client: &Arc<Mutex<KeychatClient>>,
    event_tx: &mpsc::Sender<AppEvent>,
) {
    for room in &app.rooms {
        let Room::Group(group) = room else {
            continue;
        };
        if !group.is_mls {
            continue;
        }
        let group_id = group
            .group_id
            .clone()
            .unwrap_or_else(|| group.group_pubkey.clone());
        let listen_key = if let Some(listen_key) = group.listen_key.clone() {
            listen_key
        } else {
            let maybe_listen_key = {
                let c = client.lock().await;
                c.mls_listen_key(&group_id).await.ok()
            };
            let Some(value) = maybe_listen_key else {
                continue;
            };
            value
        };
        let _ = spawn_mls_subscription(client, event_tx, &group_id, &listen_key).await;
    }
}

async fn handle_mls_welcome(
    app: &mut App,
    client: &Arc<Mutex<KeychatClient>>,
    event_tx: &mpsc::Sender<AppEvent>,
    sender: &str,
    welcome_bytes: &[u8],
) {
    let joined = {
        let c = client.lock().await;
        c.mls_join_group(welcome_bytes).await
    };
    let Ok(group_id) = joined else {
        return;
    };

    let listen_key = {
        let c = client.lock().await;
        c.mls_listen_key(&group_id).await.unwrap_or_default()
    };

    app.ensure_mls_group_room(
        &group_id,
        &format!("MLS {}", short_hex(&group_id)),
        &listen_key,
        vec![app.self_pubkey_hex.clone(), sender.to_owned()],
        false,
    );
    app.select_group_room(&group_id);
    let _ = spawn_mls_subscription(client, event_tx, &group_id, &listen_key).await;

    app.add_group_message(
        &group_id,
        &format!("MLS {}", short_hex(&group_id)),
        system_message(format!("Joined MLS group via welcome from {}", app.nicks.display(sender))),
        true,
    );
    app.status_message = Some("✅ Joined MLS group".to_owned());
}

async fn spawn_mls_subscription(
    client: &Arc<Mutex<KeychatClient>>,
    event_tx: &mpsc::Sender<AppEvent>,
    group_id: &str,
    listen_key: &str,
) -> DynResult<()> {
    let (export_secret, relays) = {
        let c = client.lock().await;
        let export_secret = c.mls_export_secret_keypair(group_id).await?;
        (export_secret, c.relays())
    };
    let Some(relay) = relays.first().cloned() else {
        return Ok(());
    };

    let mut receiver = transport::receive_group_message(&relay, &export_secret, listen_key).await;
    let tx = event_tx.clone();
    let gid = group_id.to_owned();
    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(bytes) => {
                    if tx
                        .send(AppEvent::MlsMessage {
                            group_id: gid.clone(),
                            bytes,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    Ok(())
}

async fn handle_mls_message(
    app: &mut App,
    client: &Arc<Mutex<KeychatClient>>,
    group_id: &str,
    bytes: &[u8],
) {
    let processed = {
        let c = client.lock().await;
        c.mls_process_message(group_id, bytes).await
    };
    let Ok(processed) = processed else {
        return;
    };

    if app.get_group_room(group_id).is_none() {
        let listen_key = {
            let c = client.lock().await;
            c.mls_listen_key(group_id).await.unwrap_or_default()
        };
        app.ensure_mls_group_room(
            group_id,
            &format!("MLS {}", short_hex(group_id)),
            &listen_key,
            vec![app.self_pubkey_hex.clone()],
            false,
        );
    }

    let room_name = app
        .get_group_room(group_id)
        .map(|g| g.name.clone())
        .unwrap_or_else(|| format!("MLS {}", short_hex(group_id)));

    match processed {
        ProcessedMlsMessage::Application {
            plaintext,
            sender_nostr_id,
            ..
        } => {
            app.add_group_member(group_id, &sender_nostr_id);
            app.add_group_message(
                group_id,
                &room_name,
                ChatMessage {
                    sender: app.nicks.display(&sender_nostr_id),
                    text: plaintext,
                    timestamp: now_hhmm(),
                    is_self: sender_nostr_id == app.self_pubkey_hex,
                    kind: ChatMessageKind::User,
                },
                true,
            );
            eprint!("\x07");
        }
        ProcessedMlsMessage::Commit {
            sender,
            commit_type,
            operated_members,
            ..
        } => {
            if commit_type == CommitTypeResult::Remove
                && operated_members
                    .as_ref()
                    .is_some_and(|m| m.iter().any(|x| x == &app.self_pubkey_hex))
            {
                app.remove_group_room(group_id);
                app.status_message = Some(format!(
                    "ℹ️ You were removed from MLS group {} by {}",
                    room_name,
                    app.nicks.display(&sender)
                ));
                return;
            }

            if let Some(members) = operated_members.as_ref() {
                match commit_type {
                    CommitTypeResult::Add => {
                        for member in members {
                            app.add_group_member(group_id, member);
                        }
                    }
                    CommitTypeResult::Remove => {
                        for member in members {
                            app.remove_group_member(group_id, member);
                        }
                    }
                    CommitTypeResult::Update | CommitTypeResult::GroupContextExtensions => {}
                }
            }

            app.add_group_message(
                group_id,
                &room_name,
                system_message(format_mls_commit(&sender, &commit_type, operated_members.as_ref(), app)),
                true,
            );
        }
    }
}

fn format_mls_commit(
    sender: &str,
    commit_type: &CommitTypeResult,
    operated_members: Option<&Vec<String>>,
    app: &App,
) -> String {
    let sender_name = app.nicks.display(sender);
    match commit_type {
        CommitTypeResult::Add => {
            let members = operated_members
                .map(|m| {
                    m.iter()
                        .map(|id| app.nicks.display(id))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "unknown members".to_owned());
            format!("MLS commit by {sender_name}: added {members}")
        }
        CommitTypeResult::Update => format!("MLS commit by {sender_name}: member update"),
        CommitTypeResult::Remove => {
            let members = operated_members
                .map(|m| {
                    m.iter()
                        .map(|id| app.nicks.display(id))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "unknown members".to_owned());
            format!("MLS commit by {sender_name}: removed {members}")
        }
        CommitTypeResult::GroupContextExtensions => {
            format!("MLS commit by {sender_name}: group context updated")
        }
    }
}

async fn handle_inbound(app: &mut App, event: InboundEvent) {
    match event {
        InboundEvent::FriendRequest {
            sender,
            sender_name,
            message,
        } => {
            if app.nicks.get(&sender).is_none() && !sender_name.is_empty() {
                app.nicks.set(&sender, &sender_name);
                let _ = app.nicks.save();
                app.update_room_name(&sender);
            }

            app.add_direct_message(
                &sender,
                ChatMessage {
                    sender: if sender_name.is_empty() {
                        app.nicks.display(&sender)
                    } else {
                        sender_name
                    },
                    text: format!("[Friend request] {}", message),
                    timestamp: now_hhmm(),
                    is_self: false,
                    kind: ChatMessageKind::User,
                },
                true,
            );
        }
        InboundEvent::DirectMessage {
            sender, plaintext, ..
        } => {
            let sender_display = app.nicks.display(&sender);

            let plaintext = extract_message_text(&plaintext);
            let display_text = if let Some(info) = media::parse_media_url(&plaintext) {
                let download_dir =
                    dirs_next::download_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
                let filename = info.source_name.clone().unwrap_or_else(|| {
                    format!("keychat_{}.{}", now_hhmm().replace(':', ""), info.suffix)
                });
                let save_path = download_dir.join(&filename);

                match download_and_decrypt(&info.url, &info.key, &info.iv, &save_path).await {
                    Ok(()) => format!("📎 [{}] Saved: {}", info.kctype, save_path.display()),
                    Err(e) => format!("📎 [{}] Download failed: {} ({})", info.kctype, e, info.url),
                }
            } else {
                plaintext
            };

            app.add_direct_message(
                &sender,
                ChatMessage {
                    sender: sender_display,
                    text: display_text,
                    timestamp: now_hhmm(),
                    is_self: false,
                    kind: ChatMessageKind::User,
                },
                true,
            );
            eprint!("\x07");
        }
        InboundEvent::GroupEvent {
            from_peer: _from_peer,
            event,
        } => match event {
            GroupEvent::Invite { profile, inviter } => {
                let inviter_display = app.nicks.display(&inviter);
                let (members, is_admin) = parse_profile_members(&profile, &app.self_pubkey_hex);

                app.ensure_group_room(&profile.pubkey, &profile.name, members, is_admin);
                app.add_group_message(
                    &profile.pubkey,
                    &profile.name,
                    system_message(format!(
                        "Joined group '{}' via invite from {}",
                        profile.name, inviter_display
                    )),
                    true,
                );
                app.status_message = Some(format!("✅ Joined group: {}", profile.name));
            }
            GroupEvent::Message {
                sender,
                content,
                group_pubkey,
            } => {
                let room_name = app
                    .get_group_room(&group_pubkey)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("Group {}", short_hex(&group_pubkey)));

                app.add_group_member(&group_pubkey, &sender);
                app.add_group_message(
                    &group_pubkey,
                    &room_name,
                    ChatMessage {
                        sender: app.nicks.display(&sender),
                        text: content,
                        timestamp: now_hhmm(),
                        is_self: sender == app.self_pubkey_hex,
                        kind: ChatMessageKind::User,
                    },
                    true,
                );
                eprint!("\x07");
            }
            GroupEvent::MemberRemoved {
                member_pubkey,
                by,
                group_pubkey,
            } => {
                let room_name = app
                    .get_group_room(&group_pubkey)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("Group {}", short_hex(&group_pubkey)));

                if member_pubkey == app.self_pubkey_hex {
                    app.remove_group_room(&group_pubkey);
                    app.status_message = Some(format!(
                        "ℹ️ You were removed from group {} by {}",
                        room_name,
                        app.nicks.display(&by)
                    ));
                } else {
                    let removed_display = app.nicks.display(&member_pubkey);
                    let by_display = app.nicks.display(&by);
                    app.remove_group_member(&group_pubkey, &member_pubkey);
                    app.add_group_message(
                        &group_pubkey,
                        &room_name,
                        system_message(format!("{} was removed by {}", removed_display, by_display)),
                        true,
                    );
                }
            }
            GroupEvent::Dissolved { by, group_pubkey } => {
                let room_name = app
                    .get_group_room(&group_pubkey)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("Group {}", short_hex(&group_pubkey)));
                let by_display = app.nicks.display(&by);

                app.set_group_members(&group_pubkey, Vec::new());
                app.set_group_admin(&group_pubkey, false);
                app.add_group_message(
                    &group_pubkey,
                    &room_name,
                    system_message(format!("Group dissolved by {}", by_display)),
                    true,
                );
            }
            GroupEvent::RoomNameChanged {
                new_name,
                by,
                group_pubkey,
            } => {
                let by_display = app.nicks.display(&by);
                app.update_group_name(&group_pubkey, &new_name);
                app.add_group_message(
                    &group_pubkey,
                    &new_name,
                    system_message(format!("Group renamed to '{}' by {}", new_name, by_display)),
                    true,
                );
            }
            GroupEvent::NicknameChanged {
                new_name,
                by,
                group_pubkey,
            } => {
                app.nicks.set(&by, &new_name);
                let _ = app.nicks.save();
                app.update_room_name(&by);

                let room_name = app
                    .get_group_room(&group_pubkey)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("Group {}", short_hex(&group_pubkey)));
                app.add_group_message(
                    &group_pubkey,
                    &room_name,
                    system_message(format!("{} changed nickname to {}", short_hex(&by), new_name)),
                    true,
                );
            }
        },
    }
}

async fn download_and_decrypt(
    url: &str,
    key: &str,
    iv: &str,
    save_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = reqwest::get(url).await?;
    let ciphertext = response.bytes().await?;
    let plaintext = media::decrypt_file(&ciphertext, key, iv)?;

    if let Some(parent) = save_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(save_path, plaintext)?;
    Ok(())
}

fn expand_tilde(path: &str) -> std::path::PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs_next::home_dir() {
            return home.join(&path[2..]);
        }
    }
    std::path::PathBuf::from(path)
}

fn guess_media_type(suffix: &str) -> &'static str {
    match suffix {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "bmp" | "svg" => "image",
        "mp4" | "mov" | "avi" | "mkv" | "webm" => "video",
        "mp3" | "m4a" | "ogg" | "wav" | "aac" | "opus" => "voiceNote",
        _ => "file",
    }
}

/// Try to extract human-readable text from KeychatMessage JSON
fn extract_message_text(raw: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        // Try "msg" field first (KeychatMessage: {"type":100,"c":"signal","msg":"..."})
        // Then "message" field (hello reply: {"nostrId":"...","message":"{\"type\":100,...}"})
        let text_field = v.get("msg").and_then(|m| m.as_str())
            .or_else(|| v.get("message").and_then(|m| m.as_str()));
        if let Some(msg) = text_field {
            // msg might itself be a nested KeychatMessage JSON
            if let Ok(inner) = serde_json::from_str::<serde_json::Value>(msg) {
                if let Some(inner_msg) = inner.get("msg").and_then(|m| m.as_str()) {
                    return inner_msg.to_owned();
                }
            }
            return msg.to_owned();
        }
    }
    raw.to_owned()
}

fn resolve_npub(input: &str) -> String {
    if input.starts_with("npub1") {
        crate::identity::decode_npub(input).unwrap_or_else(|_| input.to_owned())
    } else {
        input.to_owned()
    }
}

fn resolve_peer_input(app: &App, input: &str) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    if let Some(hex) = app.nicks.resolve(input) {
        return Some(hex);
    }
    Some(resolve_npub(input))
}

fn system_message(text: String) -> ChatMessage {
    ChatMessage {
        sender: "system".to_owned(),
        text,
        timestamp: now_hhmm(),
        is_self: false,
        kind: ChatMessageKind::System,
    }
}

fn parse_profile_members(profile: &GroupProfile, self_pubkey: &str) -> (Vec<String>, bool) {
    let mut members = Vec::new();
    let mut is_admin = false;

    for user in &profile.users {
        let Some(obj) = user.as_object() else {
            continue;
        };

        let Some(pubkey) = obj
            .get("idPubkey")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("pubkey").and_then(|v| v.as_str()))
        else {
            continue;
        };

        if !members.iter().any(|m| m == pubkey) {
            members.push(pubkey.to_owned());
        }

        let member_is_admin = obj
            .get("isAdmin")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if pubkey == self_pubkey {
            is_admin = member_is_admin;
        }
    }

    if !members.iter().any(|m| m == self_pubkey) {
        members.push(self_pubkey.to_owned());
    }

    (members, is_admin)
}

fn build_group_profile(app: &App, group: &super::app::GroupRoom) -> GroupProfile {
    let mut users = Vec::new();
    for member in &group.members {
        users.push(serde_json::json!({
            "idPubkey": member,
            "name": app.nicks.display(member),
            "isAdmin": member == &app.self_pubkey_hex && group.is_admin,
        }));
    }

    GroupProfile {
        pubkey: group.group_pubkey.clone(),
        name: group.name.clone(),
        users,
        group_type: GroupTypeWire::SendAll,
        updated_at: now_unix_ms(),
        group_relay: None,
        small_group_id: Some(group.group_pubkey.clone()),
    }
}

fn now_unix_ms() -> i64 {
    let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    dur.as_millis() as i64
}

fn short_hex(value: &str) -> String {
    value.chars().take(12).collect()
}

fn now_hhmm() -> String {
    let output = std::process::Command::new("date").args(["+%H:%M"]).output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        _ => "--:--".to_owned(),
    }
}

/// Execute small group invite for a resolved peer_hex.
async fn execute_invite(
    app: &mut App,
    client: &Arc<Mutex<KeychatClient>>,
    peer_hex: &str,
) -> DynResult<()> {
    let Some(group) = app.selected_room_group().cloned() else {
        app.status_message = Some("❌ No group selected".to_owned());
        return Ok(());
    };
    if group.members.iter().any(|m| m == peer_hex) {
        app.status_message = Some("ℹ️ Member already in group".to_owned());
        return Ok(());
    }
    let profile = build_group_profile(app, &group);
    let mut c = client.lock().await;
    match c
        .send_group_invite(peer_hex, &profile, "Join my group")
        .await
    {
        Ok(()) => {
            drop(c);
            app.add_group_member(&group.group_pubkey, peer_hex);
            app.add_group_message(
                &group.group_pubkey,
                &group.name,
                system_message(format!("Invited {}", app.nicks.display(peer_hex))),
                false,
            );
        }
        Err(e) => {
            let msg = format!("{}", e);
            if msg.contains("missing peer") || msg.contains("Missing") {
                app.status_message = Some(format!(
                    "❌ No Signal session with {}. Add as friend first (/add)",
                    app.nicks.display(peer_hex)
                ));
            } else {
                app.status_message = Some(format!("❌ Invite failed: {}", e));
            }
        }
    }
    Ok(())
}

/// Execute MLS large group invite for a resolved peer_hex.
async fn execute_lg_invite(
    app: &mut App,
    client: &Arc<Mutex<KeychatClient>>,
    event_tx: &mpsc::Sender<AppEvent>,
    peer_hex: &str,
) -> DynResult<()> {
    let _ = event_tx; // may be needed later
    let Some(group) = app.selected_room_group().cloned() else {
        app.status_message = Some("❌ No MLS group selected".to_owned());
        return Ok(());
    };
    if group.members.iter().any(|m| m == peer_hex) {
        app.status_message = Some("ℹ️ Member already in MLS group".to_owned());
        return Ok(());
    }
    let group_id = group.group_id.clone().unwrap_or_else(|| group.group_pubkey.clone());
    let mut listen_key = group.listen_key.clone().unwrap_or_default();
    if listen_key.is_empty() {
        let fetched = {
            let c = client.lock().await;
            match c.mls_listen_key(&group_id).await {
                Ok(k) => k,
                Err(e) => {
                    drop(c);
                    app.status_message = Some(format!("❌ MLS listen key failed: {}", e));
                    return Ok(());
                }
            }
        };
        listen_key = fetched;
        app.set_group_listen_key(&group_id, &listen_key);
    }
    let (keypair, relays) = {
        let c = client.lock().await;
        (c.keypair().clone(), c.relays())
    };
    let Some(relay) = relays.first() else {
        app.status_message = Some("❌ No relay connected".to_owned());
        return Ok(());
    };
    let key_package_hex = match transport::fetch_key_package(relay, peer_hex).await {
        Ok(kp) => kp,
        Err(e) => {
            app.status_message = Some(format!("❌ Fetch key package failed: {}", e));
            return Ok(());
        }
    };
    let (add_result, export_secret) = {
        let c = client.lock().await;
        let add_result = match c.mls_add_member(&group_id, &key_package_hex).await {
            Ok(r) => r,
            Err(e) => {
                drop(c);
                app.status_message = Some(format!("❌ MLS add member failed: {}", e));
                return Ok(());
            }
        };
        let export_secret = match c.mls_export_secret_keypair(&group_id).await {
            Ok(s) => s,
            Err(e) => {
                drop(c);
                app.status_message = Some(format!("❌ MLS export secret failed: {}", e));
                return Ok(());
            }
        };
        (add_result, export_secret)
    };
    if let Err(e) = transport::send_group_message(relay, &export_secret, &listen_key, &add_result.commit_message).await {
        app.status_message = Some(format!("❌ Send commit failed: {}", e));
        return Ok(());
    }
    if let Err(e) = transport::send_welcome(relay, &keypair, peer_hex, &add_result.welcome).await {
        app.status_message = Some(format!("❌ Send welcome failed: {}", e));
        return Ok(());
    }
    app.add_group_member(&group_id, peer_hex);
    app.add_group_message(
        &group_id,
        &group.name,
        system_message(format!("Invited {}", app.nicks.display(peer_hex))),
        false,
    );
    Ok(())
}
