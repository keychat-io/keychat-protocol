//! Terminal UI for keychat-cli using ratatui.
//!
//! Layout:
//! ┌─ Rooms ──────────┬─ Messages ─────────────────────────┐
//! │ ● Alice          │ 10:00 Alice: Hello                  │
//! │ ● Bob            │ 10:01 You: Hi there                 │
//! │ ◐ Group A        │                                     │
//! │                   ├─────────────────────────────────────┤
//! │                   │ > type message here_                │
//! └───────────────────┴─────────────────────────────────────┘
//!  [Connected 2/3] [Identity: a1b2c3...] [Tab: switch panel]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, cursor};
use keychat_uniffi::{
    ClientEvent, DataChange, GroupMemberInput, KeychatClient, MessageKind, MessageStatus,
    RoomStatus, RoomType,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::Terminal;
use tokio::sync::broadcast;

// ─── Types ──────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct RoomEntry {
    id: String,
    name: String,
    room_type: RoomType,
    status: RoomStatus,
    unread_count: u32,
    last_message: Option<String>,
    to_main_pubkey: String,
}

#[derive(Clone, Debug)]
struct MessageEntry {
    sender: String,
    content: String,
    is_me: bool,
    status: MessageStatus,
    timestamp: u64,
}

#[derive(PartialEq, Clone, Copy)]
enum Panel {
    Rooms,
    Messages,
    Input,
}

struct App {
    client: Arc<KeychatClient>,
    data_dir: PathBuf,
    rooms: Vec<RoomEntry>,
    room_state: ListState,
    messages: Vec<MessageEntry>,
    input: String,
    cursor_pos: usize,
    active_panel: Panel,
    notification: Option<(String, std::time::Instant)>,
    identity_hex: Option<String>,
    owner_pubkey: Option<String>,
    connected_relays: usize,
    total_relays: usize,
    should_quit: bool,
    messages_scroll: usize,
    event_loop_started: bool,
    command_output: Vec<(String, Color)>,
    show_help: bool,
}

impl App {
    fn new(client: Arc<KeychatClient>, data_dir: PathBuf) -> Self {
        let mut room_state = ListState::default();
        room_state.select(Some(0));
        let owner_pubkey = load_owner(&data_dir);
        Self {
            client,
            data_dir,
            rooms: Vec::new(),
            room_state,
            messages: Vec::new(),
            input: String::new(),
            cursor_pos: 0,
            active_panel: Panel::Input,
            notification: None,
            identity_hex: None,
            owner_pubkey,
            connected_relays: 0,
            total_relays: 0,
            should_quit: false,
            messages_scroll: 0,
            event_loop_started: false,
            command_output: Vec::new(),
            show_help: false,
        }
    }

    fn selected_room_id(&self) -> Option<String> {
        self.room_state
            .selected()
            .and_then(|i| self.rooms.get(i))
            .map(|r| r.id.clone())
    }

    fn selected_room_name(&self) -> Option<String> {
        self.room_state
            .selected()
            .and_then(|i| self.rooms.get(i))
            .map(|r| r.name.clone())
    }

    fn notify(&mut self, msg: String) {
        self.notification = Some((msg, std::time::Instant::now()));
    }

    fn push_output(&mut self, msg: String, color: Color) {
        self.command_output.push((msg, color));
        // Keep last 100 lines
        if self.command_output.len() > 100 {
            self.command_output.drain(..self.command_output.len() - 100);
        }
    }
}

// ─── Public entry point ─────────────────────────────────────

pub async fn run(
    client: Arc<KeychatClient>,
    event_tx: broadcast::Sender<ClientEvent>,
    data_tx: broadcast::Sender<DataChange>,
    data_dir: String,
) -> anyhow::Result<()> {
    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(Arc::clone(&client), PathBuf::from(&data_dir));

    // Load identity if exists
    if let Ok(pubkey) = client.get_pubkey_hex().await {
        app.identity_hex = Some(pubkey);
        // Restore sessions
        match client.restore_sessions().await {
            Ok(n) if n > 0 => app.push_output(format!("Restored {n} session(s)"), Color::Cyan),
            _ => {}
        }
    }

    // Load initial rooms
    refresh_rooms(&mut app).await;
    refresh_relay_status(&mut app).await;

    // Subscribe to events
    let mut event_rx = event_tx.subscribe();
    let mut data_rx = data_tx.subscribe();

    // Main loop
    loop {
        // Draw
        terminal.draw(|f| draw_ui(f, &mut app))?;

        // Poll for events with a timeout to allow async message updates
        let timeout = Duration::from_millis(50);

        // Check crossterm events
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                handle_key_event(&mut app, key).await;
            }
        }

        // Check broadcast events (non-blocking)
        while let Ok(ev) = event_rx.try_recv() {
            handle_client_event(&mut app, &ev).await;
        }
        while let Ok(dc) = data_rx.try_recv() {
            handle_data_change(&mut app, &dc).await;
        }

        // Clear old notifications
        if let Some((_, ts)) = &app.notification {
            if ts.elapsed() > Duration::from_secs(5) {
                app.notification = None;
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Cleanup
    terminal::disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        cursor::Show
    )?;
    let _ = client.disconnect().await;

    Ok(())
}

// ─── Drawing ────────────────────────────────────────────────

fn draw_ui(f: &mut ratatui::Frame, app: &mut App) {
    let size = f.area();

    // Main layout: status bar at bottom
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(size);

    // Content area: rooms panel | messages+input
    let content = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(28), Constraint::Min(30)])
        .split(outer[0]);

    // Right side: messages + input
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(3)])
        .split(content[1]);

    draw_rooms(f, app, content[0]);
    draw_messages(f, app, right[0]);
    draw_input(f, app, right[1]);
    draw_status_bar(f, app, outer[1]);

    // Help overlay
    if app.show_help {
        draw_help_overlay(f, size);
    }
}

fn draw_rooms(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let highlight_style = if app.active_panel == Panel::Rooms {
        Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
    } else {
        Style::default().bg(Color::DarkGray)
    };

    let items: Vec<ListItem> = app
        .rooms
        .iter()
        .map(|room| {
            let status_icon = match room.status {
                RoomStatus::Enabled => "●",
                RoomStatus::Requesting => "◐",
                RoomStatus::Approving => "◑",
                RoomStatus::Rejected => "○",
            };
            let status_color = match room.status {
                RoomStatus::Enabled => Color::Green,
                RoomStatus::Requesting | RoomStatus::Approving => Color::Yellow,
                RoomStatus::Rejected => Color::Red,
            };
            let type_tag = match room.room_type {
                RoomType::Dm => "",
                RoomType::SignalGroup => "[SG]",
                RoomType::MlsGroup => "[MLS]",
            };

            let unread = if room.unread_count > 0 {
                format!(" ({})", room.unread_count)
            } else {
                String::new()
            };

            let name_display = if room.name.chars().count() > 18 {
                format!("{}…", room.name.chars().take(17).collect::<String>())
            } else {
                room.name.clone()
            };

            let line = Line::from(vec![
                Span::styled(format!("{status_icon} "), Style::default().fg(status_color)),
                Span::styled(type_tag.to_string(), Style::default().fg(Color::DarkGray)),
                if !type_tag.is_empty() {
                    Span::raw(" ")
                } else {
                    Span::raw("")
                },
                Span::styled(name_display, Style::default().fg(Color::White)),
                Span::styled(unread, Style::default().fg(Color::Red)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let border_style = if app.active_panel == Panel::Rooms {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let rooms_block = Block::default()
        .title(" Rooms ")
        .borders(Borders::ALL)
        .border_style(border_style);

    let rooms_list = List::new(items)
        .block(rooms_block)
        .highlight_style(highlight_style)
        .highlight_symbol("▸ ");

    f.render_stateful_widget(rooms_list, area, &mut app.room_state);
}

fn draw_messages(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let border_style = if app.active_panel == Panel::Messages {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let title = match app.selected_room_name() {
        Some(name) => format!(" {} ", name),
        None => " Messages ".to_string(),
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);

    if app.messages.is_empty() && app.command_output.is_empty() {
        // Show welcome or command output
        let welcome = if app.identity_hex.is_none() {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Welcome to Keychat CLI",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  No identity found. Type a command:",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  /create       — Create new identity",
                    Style::default().fg(Color::Green),
                )),
                Line::from(Span::styled(
                    "  /import <m>   — Import from mnemonic",
                    Style::default().fg(Color::Green),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  Press F1 or /help for all commands",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        } else if app.rooms.is_empty() {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  No conversations yet",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  /connect      — Connect to relays",
                    Style::default().fg(Color::Green),
                )),
                Line::from(Span::styled(
                    "  /add <pubkey> — Send friend request",
                    Style::default().fg(Color::Green),
                )),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  Select a room from the left panel",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  Use ↑↓ to navigate, Enter to select",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        };
        let p = Paragraph::new(welcome).block(block);
        f.render_widget(p, area);
        return;
    }

    // Build message lines
    let mut lines: Vec<Line> = Vec::new();

    // Show command output first if any and no messages
    if app.messages.is_empty() {
        for (msg, color) in &app.command_output {
            lines.push(Line::from(Span::styled(
                format!("  {msg}"),
                Style::default().fg(*color),
            )));
        }
    } else {
        for msg in &app.messages {
            let time = format_timestamp(msg.timestamp);
            let status_icon = match msg.status {
                MessageStatus::Sending => "⏳",
                MessageStatus::Success => "✓",
                MessageStatus::Failed => "✗",
            };
            let status_color = match msg.status {
                MessageStatus::Sending => Color::Yellow,
                MessageStatus::Success => Color::Green,
                MessageStatus::Failed => Color::Red,
            };

            if msg.is_me {
                lines.push(Line::from(vec![
                    Span::styled(format!("  {time} "), Style::default().fg(Color::DarkGray)),
                    Span::styled("You", Style::default().fg(Color::Green)),
                    Span::styled(
                        format!(" {status_icon} "),
                        Style::default().fg(status_color),
                    ),
                    Span::raw(&msg.content),
                ]));
            } else {
                let sender_display = short_key(&msg.sender);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {time} "), Style::default().fg(Color::DarkGray)),
                    Span::styled(sender_display, Style::default().fg(Color::Cyan)),
                    Span::raw(": "),
                    Span::raw(&msg.content),
                ]));
            }
        }
    }

    // Auto-scroll to bottom
    let inner_height = area.height.saturating_sub(2) as usize;
    let scroll = if lines.len() > inner_height {
        (lines.len() - inner_height) as u16
    } else {
        0
    };

    let messages_widget = Paragraph::new(lines).block(block).scroll((scroll, 0));
    f.render_widget(messages_widget, area);
}

fn draw_input(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let border_style = if app.active_panel == Panel::Input {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let input_title = if app.input.starts_with('/') {
        " Command "
    } else if app.selected_room_id().is_some() {
        " Message "
    } else {
        " Input (/ for commands) "
    };

    let block = Block::default()
        .title(input_title)
        .borders(Borders::ALL)
        .border_style(border_style);

    let input_text = Paragraph::new(Line::from(vec![
        Span::styled("> ", Style::default().fg(Color::Cyan)),
        Span::raw(&app.input),
    ]))
    .block(block);

    f.render_widget(input_text, area);

    // Show cursor
    if app.active_panel == Panel::Input {
        f.set_cursor_position((
            area.x + 3 + app.cursor_pos as u16,
            area.y + 1,
        ));
    }
}

fn draw_status_bar(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let identity = match &app.identity_hex {
        Some(hex) => format!("ID:{}", short_key(hex)),
        None => "No identity".to_string(),
    };

    let relay_status = format!("Relays:{}/{}", app.connected_relays, app.total_relays);
    let relay_color = if app.connected_relays > 0 {
        Color::Green
    } else if app.total_relays > 0 {
        Color::Yellow
    } else {
        Color::DarkGray
    };

    let notification_span = if let Some((msg, _)) = &app.notification {
        Span::styled(format!(" │ {msg}"), Style::default().fg(Color::Yellow))
    } else {
        Span::raw("")
    };

    let bar = Line::from(vec![
        Span::styled(" ", Style::default().bg(Color::DarkGray)),
        Span::styled(
            &identity,
            Style::default().fg(Color::Cyan).bg(Color::DarkGray),
        ),
        Span::styled(" │ ", Style::default().fg(Color::Gray).bg(Color::DarkGray)),
        Span::styled(
            &relay_status,
            Style::default().fg(relay_color).bg(Color::DarkGray),
        ),
        Span::styled(" │ ", Style::default().fg(Color::Gray).bg(Color::DarkGray)),
        Span::styled(
            "Tab:switch  F1:help  Ctrl-C:quit",
            Style::default()
                .fg(Color::DarkGray)
                .bg(Color::DarkGray),
        ),
        Span::styled(
            notification_span.content.to_string(),
            Style::default().fg(Color::Yellow).bg(Color::DarkGray),
        ),
        // Fill rest with bg
        Span::styled(
            " ".repeat(area.width as usize),
            Style::default().bg(Color::DarkGray),
        ),
    ]);

    let bar_widget = Paragraph::new(bar);
    f.render_widget(bar_widget, area);
}

fn draw_help_overlay(f: &mut ratatui::Frame, area: Rect) {
    // Center the help popup
    let popup_width = 60u16.min(area.width.saturating_sub(4));
    let popup_height = 35u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let help_lines = vec![
        Line::from(Span::styled(
            " Keychat CLI Commands",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(" Navigation", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  Tab        Switch between panels", Style::default().fg(Color::White))),
        Line::from(Span::styled("  ↑/↓        Navigate rooms / scroll messages", Style::default().fg(Color::White))),
        Line::from(Span::styled("  Enter      Select room / send message", Style::default().fg(Color::White))),
        Line::from(Span::styled("  Esc        Back to input / close help", Style::default().fg(Color::White))),
        Line::from(Span::styled("  Ctrl-C     Quit", Style::default().fg(Color::White))),
        Line::from(""),
        Line::from(Span::styled(" Identity", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  /create             Create new identity", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /import <mnemonic>  Import identity", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /whoami             Show pubkey", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /delete-identity    Remove identity", Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled(" Connection", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  /connect [url...]   Connect to relays", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /disconnect         Disconnect all", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /relays             Show relay status", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /add-relay <url>    Add a relay", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /reconnect          Reconnect all", Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled(" Friends & Messaging", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  /add <pubkey> [name]  Send friend request", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /accept <id> [name]   Accept request", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /contacts             List contacts", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /history [count]      Message history", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /retry                Retry failed msgs", Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled(" Signal Groups", Style::default().add_modifier(Modifier::BOLD))),
        Line::from(Span::styled("  /sg-create <name> <pk...>  Create group", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /sg-leave <id>             Leave group", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /sg-rename <id> <name>     Rename group", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /sg-kick <id> <pk>         Remove member", Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled(" Press Esc or F1 to close", Style::default().fg(Color::DarkGray))),
    ];

    let help_widget = Paragraph::new(help_lines)
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(help_widget, popup_area);
}

// ─── Key event handling ─────────────────────────────────────

async fn handle_key_event(app: &mut App, key: KeyEvent) {
    // Global shortcuts
    match key.code {
        KeyCode::F(1) => {
            app.show_help = !app.show_help;
            return;
        }
        _ => {}
    }

    if app.show_help {
        if matches!(key.code, KeyCode::Esc | KeyCode::F(1)) {
            app.show_help = false;
        }
        return;
    }

    match key.code {
        KeyCode::Tab => {
            app.active_panel = match app.active_panel {
                Panel::Rooms => Panel::Input,
                Panel::Input => Panel::Messages,
                Panel::Messages => Panel::Rooms,
            };
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }
        _ => match app.active_panel {
            Panel::Rooms => handle_rooms_key(app, key).await,
            Panel::Messages => handle_messages_key(app, key),
            Panel::Input => handle_input_key(app, key).await,
        },
    }
}

async fn handle_rooms_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up => {
            let i = app.room_state.selected().unwrap_or(0);
            if i > 0 {
                app.room_state.select(Some(i - 1));
            }
        }
        KeyCode::Down => {
            let i = app.room_state.selected().unwrap_or(0);
            if i + 1 < app.rooms.len() {
                app.room_state.select(Some(i + 1));
            }
        }
        KeyCode::Enter => {
            // Select room and load messages
            if let Some(room_id) = app.selected_room_id() {
                load_messages(app, &room_id).await;
                app.active_panel = Panel::Input;
                // Mark as read
                let _ = app.client.mark_room_read(room_id).await;
                refresh_rooms(app).await;
            }
        }
        KeyCode::Esc => {
            app.active_panel = Panel::Input;
        }
        _ => {}
    }
}

fn handle_messages_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up => {
            app.messages_scroll = app.messages_scroll.saturating_add(1);
        }
        KeyCode::Down => {
            app.messages_scroll = app.messages_scroll.saturating_sub(1);
        }
        KeyCode::Esc => {
            app.active_panel = Panel::Input;
        }
        _ => {}
    }
}

async fn handle_input_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            if !app.input.is_empty() {
                let input = app.input.clone();
                app.input.clear();
                app.cursor_pos = 0;
                process_input(app, &input).await;
            }
        }
        KeyCode::Char(c) => {
            app.input.insert(app.cursor_pos, c);
            app.cursor_pos += 1;
        }
        KeyCode::Backspace => {
            if app.cursor_pos > 0 {
                app.cursor_pos -= 1;
                app.input.remove(app.cursor_pos);
            }
        }
        KeyCode::Delete => {
            if app.cursor_pos < app.input.len() {
                app.input.remove(app.cursor_pos);
            }
        }
        KeyCode::Left => {
            app.cursor_pos = app.cursor_pos.saturating_sub(1);
        }
        KeyCode::Right => {
            if app.cursor_pos < app.input.len() {
                app.cursor_pos += 1;
            }
        }
        KeyCode::Home => {
            app.cursor_pos = 0;
        }
        KeyCode::End => {
            app.cursor_pos = app.input.len();
        }
        KeyCode::Up => {
            // Switch to rooms panel
            app.active_panel = Panel::Rooms;
        }
        KeyCode::Esc => {
            app.active_panel = Panel::Rooms;
        }
        _ => {}
    }
}

// ─── Command processing ─────────────────────────────────────

async fn process_input(app: &mut App, input: &str) {
    if input.starts_with('/') {
        process_command(app, input).await;
    } else {
        // Send message to active room
        send_message(app, input).await;
    }
}

async fn send_message(app: &mut App, text: &str) {
    let room_id = match app.selected_room_id() {
        Some(id) => id,
        None => {
            app.notify("No room selected. Use ↑/Enter to select a room.".into());
            return;
        }
    };

    // Check room type for routing
    if let Ok(Some(room)) = app.client.get_room(room_id.clone()).await {
        match room.room_type {
            RoomType::SignalGroup => {
                match app
                    .client
                    .send_group_text(room_id.clone(), text.to_string())
                    .await
                {
                    Ok(result) => {
                        app.push_output(
                            format!("Sent to group ({} event(s))", result.event_ids.len()),
                            Color::Green,
                        );
                    }
                    Err(e) => app.notify(format!("Send failed: {e}")),
                }
            }
            RoomType::MlsGroup => {
                app.notify("MLS groups not yet supported".into());
                return;
            }
            RoomType::Dm => {
                match app
                    .client
                    .send_text(room_id.clone(), text.to_string(), None, None, None)
                    .await
                {
                    Ok(_) => {}
                    Err(e) => app.notify(format!("Send failed: {e}")),
                }
            }
        }
    } else {
        // Try DM by default
        match app
            .client
            .send_text(room_id.clone(), text.to_string(), None, None, None)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                app.notify(format!("Send failed: {e}"));
                return;
            }
        }
    }

    // Reload messages
    load_messages(app, &room_id).await;
    refresh_rooms(app).await;
}

async fn process_command(app: &mut App, input: &str) {
    let mut parts = input.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let args = parts.next().unwrap_or("").trim();

    match cmd {
        "/create" => {
            match app.client.create_identity().await {
                Ok(result) => {
                    app.identity_hex = Some(result.pubkey_hex.clone());
                    let npub = keychat_uniffi::npub_from_hex(result.pubkey_hex.clone())
                        .unwrap_or_default();

                    app.push_output("Identity created!".into(), Color::Green);
                    app.push_output(String::new(), Color::White);
                    app.push_output(format!("Pubkey: {}", result.pubkey_hex), Color::Cyan);
                    app.push_output(format!("npub:   {npub}"), Color::Cyan);
                    app.push_output(String::new(), Color::White);

                    // Show QR code of npub for easy scanning
                    let qr_lines = render_qr_lines(&npub);
                    for line in &qr_lines {
                        app.push_output(line.clone(), Color::White);
                    }
                    app.push_output(String::new(), Color::White);
                    app.push_output(
                        "Mnemonic (SAVE THIS!):".into(),
                        Color::Yellow,
                    );
                    app.push_output(result.mnemonic, Color::Yellow);
                    app.push_output(String::new(), Color::White);
                    app.push_output(
                        "First friend request will be auto-approved as owner.".into(),
                        Color::DarkGray,
                    );
                    app.notify("Identity created! Use /connect to join relays.".into());
                }
                Err(e) => app.notify(format!("Create failed: {e}")),
            }
        }
        "/import" => {
            if args.is_empty() {
                app.notify("Usage: /import <mnemonic words>".into());
                return;
            }
            match app.client.import_identity(args.to_string()).await {
                Ok(pubkey) => {
                    app.identity_hex = Some(pubkey.clone());
                    app.push_output(
                        format!("Identity imported: {}", short_key(&pubkey)),
                        Color::Green,
                    );
                    let _ = app.client.restore_sessions().await;
                    refresh_rooms(app).await;
                }
                Err(e) => app.notify(format!("Import failed: {e}")),
            }
        }
        "/whoami" => {
            if let Some(ref pk) = app.identity_hex {
                let npub = keychat_uniffi::npub_from_hex(pk.clone()).unwrap_or_default();
                app.push_output(format!("Pubkey: {pk}"), Color::Cyan);
                app.push_output(format!("npub:   {npub}"), Color::Cyan);
                app.push_output(String::new(), Color::White);
                let qr_lines = render_qr_lines(&npub);
                for line in &qr_lines {
                    app.push_output(line.clone(), Color::White);
                }
                if let Some(owner) = app.owner_pubkey.clone() {
                    app.push_output(String::new(), Color::White);
                    app.push_output(format!("Owner: {}", short_key(&owner)), Color::Green);
                } else {
                    app.push_output(String::new(), Color::White);
                    app.push_output(
                        "No owner set — first friend request will be auto-approved.".into(),
                        Color::DarkGray,
                    );
                }
            } else {
                app.notify("No identity".into());
            }
        }
        "/delete-identity" => {
            app.push_output(
                "Type /confirm-delete to confirm identity deletion".into(),
                Color::Yellow,
            );
        }
        "/confirm-delete" => {
            match app.client.remove_identity().await {
                Ok(_) => {
                    app.identity_hex = None;
                    app.rooms.clear();
                    app.messages.clear();
                    app.notify("Identity deleted".into());
                }
                Err(e) => app.notify(format!("Delete failed: {e}")),
            }
        }
        "/connect" => {
            let relay_urls: Vec<String> = if args.is_empty() {
                keychat_uniffi::default_relays()
            } else {
                args.split_whitespace().map(|s| s.to_string()).collect()
            };
            app.push_output(
                format!("Connecting to {} relay(s)...", relay_urls.len()),
                Color::Cyan,
            );
            match app.client.connect(relay_urls).await {
                Ok(_) => {
                    app.push_output("Connected".into(), Color::Green);
                    refresh_relay_status(app).await;
                    // Start event loop if not started
                    if !app.event_loop_started {
                        let client_el = Arc::clone(&app.client);
                        tokio::spawn(async move {
                            if let Err(e) = client_el.start_event_loop().await {
                                tracing::error!("event loop error: {e}");
                            }
                        });
                        app.event_loop_started = true;
                    }
                }
                Err(e) => app.notify(format!("Connect failed: {e}")),
            }
        }
        "/disconnect" => {
            let _ = app.client.disconnect().await;
            app.connected_relays = 0;
            app.push_output("Disconnected".into(), Color::Yellow);
        }
        "/relays" => {
            match app.client.get_relay_statuses().await {
                Ok(statuses) => {
                    if statuses.is_empty() {
                        app.push_output("No relays configured".into(), Color::DarkGray);
                    } else {
                        for rs in &statuses {
                            let color = match rs.status.as_str() {
                                "Connected" => Color::Green,
                                "Connecting" => Color::Yellow,
                                _ => Color::Red,
                            };
                            app.push_output(format!("{} {}", rs.status, rs.url), color);
                        }
                    }
                }
                Err(e) => app.notify(format!("Error: {e}")),
            }
        }
        "/add-relay" => {
            if args.is_empty() {
                app.notify("Usage: /add-relay <url>".into());
                return;
            }
            match app.client.add_relay(args.to_string()).await {
                Ok(_) => {
                    app.push_output(format!("Relay added: {args}"), Color::Green);
                    refresh_relay_status(app).await;
                }
                Err(e) => app.notify(format!("Error: {e}")),
            }
        }
        "/remove-relay" => {
            if args.is_empty() {
                app.notify("Usage: /remove-relay <url>".into());
                return;
            }
            match app.client.remove_relay(args.to_string()).await {
                Ok(_) => {
                    app.push_output(format!("Relay removed: {args}"), Color::Green);
                    refresh_relay_status(app).await;
                }
                Err(e) => app.notify(format!("Error: {e}")),
            }
        }
        "/reconnect" => {
            let _ = app.client.reconnect_relays().await;
            app.push_output("Reconnecting...".into(), Color::Yellow);
        }
        "/status" => {
            refresh_relay_status(app).await;
            if let Some(ref pk) = app.identity_hex {
                app.push_output(format!("Identity: {}", short_key(pk)), Color::Cyan);
            } else {
                app.push_output("Identity: None".into(), Color::Red);
            }
            app.push_output(
                format!("Relays: {}/{}", app.connected_relays, app.total_relays),
                if app.connected_relays > 0 {
                    Color::Green
                } else {
                    Color::Red
                },
            );
            match app.client.debug_state_summary().await {
                Ok(s) => app.push_output(format!("State: {s}"), Color::White),
                Err(e) => app.push_output(format!("State error: {e}"), Color::Red),
            }
        }
        "/add" => {
            let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
            if parts.is_empty() || parts[0].is_empty() {
                app.notify("Usage: /add <pubkey> [my_name]".into());
                return;
            }
            let peer = match keychat_uniffi::normalize_to_hex(parts[0].to_string()) {
                Ok(p) => p,
                Err(e) => {
                    app.notify(format!("Invalid pubkey: {e}"));
                    return;
                }
            };
            let name = if parts.len() > 1 {
                parts[1].to_string()
            } else {
                "CLI User".to_string()
            };
            match app
                .client
                .send_friend_request(peer.clone(), name, "cli-device".to_string())
                .await
            {
                Ok(pending) => {
                    app.push_output(
                        format!(
                            "Friend request sent to {}. ID: {}",
                            short_key(&peer),
                            short_key(&pending.request_id)
                        ),
                        Color::Green,
                    );
                    refresh_rooms(app).await;
                }
                Err(e) => app.notify(format!("Send failed: {e}")),
            }
        }
        "/accept" => {
            let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
            if parts.is_empty() || parts[0].is_empty() {
                app.notify("Usage: /accept <request_id> [my_name]".into());
                return;
            }
            let name = if parts.len() > 1 {
                parts[1].to_string()
            } else {
                "CLI User".to_string()
            };
            match app
                .client
                .accept_friend_request(parts[0].to_string(), name)
                .await
            {
                Ok(contact) => {
                    app.push_output(
                        format!("Accepted: {}", contact.display_name),
                        Color::Green,
                    );
                    refresh_rooms(app).await;
                }
                Err(e) => app.notify(format!("Accept failed: {e}")),
            }
        }
        "/reject" => {
            if args.is_empty() {
                app.notify("Usage: /reject <request_id>".into());
                return;
            }
            match app
                .client
                .reject_friend_request(args.to_string(), None)
                .await
            {
                Ok(_) => app.push_output("Friend request rejected".into(), Color::Yellow),
                Err(e) => app.notify(format!("Reject failed: {e}")),
            }
        }
        "/contacts" => {
            if let Some(ref pk) = app.identity_hex {
                match app.client.get_contacts(pk.clone()).await {
                    Ok(contacts) => {
                        if contacts.is_empty() {
                            app.push_output("No contacts yet".into(), Color::DarkGray);
                        } else {
                            for c in &contacts {
                                let name = c
                                    .petname
                                    .as_deref()
                                    .or(c.name.as_deref())
                                    .unwrap_or("(unnamed)");
                                app.push_output(
                                    format!("{name}  {}", short_key(&c.pubkey)),
                                    Color::White,
                                );
                            }
                        }
                    }
                    Err(e) => app.notify(format!("Error: {e}")),
                }
            }
        }
        "/history" => {
            let room_id = match app.selected_room_id() {
                Some(id) => id,
                None => {
                    app.notify("Select a room first".into());
                    return;
                }
            };
            let count: i32 = args.parse().unwrap_or(20);
            load_messages_with_count(app, &room_id, count).await;
        }
        "/retry" => {
            match app.client.retry_failed_messages().await {
                Ok(count) if count > 0 => {
                    app.push_output(format!("Retrying {count} message(s)"), Color::Green);
                }
                Ok(_) => app.push_output("No failed messages".into(), Color::DarkGray),
                Err(e) => app.notify(format!("Retry failed: {e}")),
            }
        }
        "/sg-create" => {
            let parts: Vec<&str> = args.split_whitespace().collect();
            if parts.len() < 2 {
                app.notify("Usage: /sg-create <name> <pubkey...>".into());
                return;
            }
            let name = parts[0].to_string();
            let members: Vec<GroupMemberInput> = parts[1..]
                .iter()
                .map(|pk| {
                    let normalized = keychat_uniffi::normalize_to_hex(pk.to_string())
                        .unwrap_or_else(|_| pk.to_string());
                    GroupMemberInput {
                        nostr_pubkey: normalized.clone(),
                        name: short_key(&normalized),
                    }
                })
                .collect();
            match app.client.create_signal_group(name, members).await {
                Ok(info) => {
                    app.push_output(
                        format!(
                            "Group created: {} ({} members)",
                            info.name, info.member_count
                        ),
                        Color::Green,
                    );
                    refresh_rooms(app).await;
                }
                Err(e) => app.notify(format!("Create failed: {e}")),
            }
        }
        "/sg-leave" => {
            if args.is_empty() {
                app.notify("Usage: /sg-leave <group_id>".into());
                return;
            }
            match app
                .client
                .leave_signal_group(args.trim().to_string())
                .await
            {
                Ok(_) => {
                    app.push_output("Left group".into(), Color::Yellow);
                    refresh_rooms(app).await;
                }
                Err(e) => app.notify(format!("Leave failed: {e}")),
            }
        }
        "/sg-dissolve" => {
            if args.is_empty() {
                app.notify("Usage: /sg-dissolve <group_id>".into());
                return;
            }
            match app
                .client
                .dissolve_signal_group(args.trim().to_string())
                .await
            {
                Ok(_) => {
                    app.push_output("Group dissolved".into(), Color::Red);
                    refresh_rooms(app).await;
                }
                Err(e) => app.notify(format!("Dissolve failed: {e}")),
            }
        }
        "/sg-rename" => {
            let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
            if parts.len() < 2 {
                app.notify("Usage: /sg-rename <group_id> <new_name>".into());
                return;
            }
            match app
                .client
                .rename_signal_group(parts[0].to_string(), parts[1].to_string())
                .await
            {
                Ok(_) => {
                    app.push_output(format!("Renamed to: {}", parts[1]), Color::Green);
                    refresh_rooms(app).await;
                }
                Err(e) => app.notify(format!("Rename failed: {e}")),
            }
        }
        "/sg-kick" => {
            let parts: Vec<&str> = args.split_whitespace().collect();
            if parts.len() < 2 {
                app.notify("Usage: /sg-kick <group_id> <pubkey>".into());
                return;
            }
            let member_pk = keychat_uniffi::normalize_to_hex(parts[1].to_string())
                .unwrap_or_else(|_| parts[1].to_string());
            match app
                .client
                .remove_group_member(parts[0].to_string(), member_pk)
                .await
            {
                Ok(_) => app.push_output("Member removed".into(), Color::Yellow),
                Err(e) => app.notify(format!("Kick failed: {e}")),
            }
        }
        "/debug" => {
            match app.client.debug_state_summary().await {
                Ok(s) => app.push_output(s, Color::White),
                Err(e) => app.notify(format!("Error: {e}")),
            }
        }
        "/help" => {
            app.show_help = true;
        }
        "/quit" | "/exit" => {
            app.should_quit = true;
        }
        "/read" => {
            if let Some(room_id) = app.selected_room_id() {
                let _ = app.client.mark_room_read(room_id).await;
                app.push_output("Marked as read".into(), Color::Green);
                refresh_rooms(app).await;
            }
        }
        _ => {
            app.notify(format!("Unknown command: {cmd}. Press F1 for help."));
        }
    }
}

// ─── Event handlers ─────────────────────────────────────────

async fn handle_client_event(app: &mut App, event: &ClientEvent) {
    match event {
        ClientEvent::MessageReceived {
            sender_pubkey,
            content,
            room_id,
            ..
        } => {
            // Refresh rooms to show new message
            refresh_rooms(app).await;
            // If viewing this room, reload messages
            if app.selected_room_id().as_deref() == Some(room_id.as_str()) {
                load_messages(app, room_id).await;
            }
            let sender = short_key(sender_pubkey);
            let body = content.as_deref().unwrap_or("");
            let preview = if body.chars().count() > 30 {
                format!("{}…", body.chars().take(30).collect::<String>())
            } else {
                body.to_string()
            };
            app.notify(format!("{sender}: {preview}"));
        }
        ClientEvent::FriendRequestReceived {
            request_id,
            sender_pubkey,
            sender_name,
            ..
        } => {
            // Auto-approve first friend request as owner
            if app.owner_pubkey.is_none() {
                app.push_output(
                    format!("Auto-approving {sender_name} as owner..."),
                    Color::Green,
                );
                match app
                    .client
                    .accept_friend_request(request_id.clone(), "CLI User".to_string())
                    .await
                {
                    Ok(contact) => {
                        save_owner(&app.data_dir, sender_pubkey);
                        app.owner_pubkey = Some(sender_pubkey.clone());
                        app.push_output(
                            format!(
                                "Owner set: {} ({})",
                                contact.display_name,
                                short_key(sender_pubkey)
                            ),
                            Color::Green,
                        );
                        app.notify(format!("{} approved as owner", contact.display_name));
                    }
                    Err(e) => {
                        app.push_output(format!("Auto-approve failed: {e}"), Color::Red);
                    }
                }
            } else {
                app.push_output(
                    format!(
                        "Friend request from {sender_name}. /accept {request_id}"
                    ),
                    Color::Yellow,
                );
                app.notify(format!("Friend request from {sender_name}"));
            }
            refresh_rooms(app).await;
        }
        ClientEvent::FriendRequestAccepted { peer_name, .. } => {
            app.push_output(
                format!("Friend accepted by {peer_name}"),
                Color::Green,
            );
            app.notify(format!("{peer_name} accepted your request"));
            refresh_rooms(app).await;
        }
        ClientEvent::FriendRequestRejected { peer_pubkey } => {
            app.notify(format!("Request rejected by {}", short_key(peer_pubkey)));
        }
        ClientEvent::GroupInviteReceived {
            group_name,
            inviter_pubkey,
            ..
        } => {
            app.push_output(
                format!(
                    "Group invite: '{}' from {}",
                    group_name,
                    short_key(inviter_pubkey)
                ),
                Color::Yellow,
            );
            app.notify(format!("Invited to group: {group_name}"));
            refresh_rooms(app).await;
        }
        ClientEvent::GroupDissolved { room_id } => {
            app.notify(format!("Group dissolved: {}", short_key(room_id)));
            refresh_rooms(app).await;
        }
        ClientEvent::GroupMemberChanged { kind, new_value, .. } => {
            let msg = match kind {
                keychat_uniffi::GroupChangeKind::NameChanged => {
                    format!("Group renamed to: {}", new_value.as_deref().unwrap_or("?"))
                }
                keychat_uniffi::GroupChangeKind::MemberRemoved => "Member removed".to_string(),
                keychat_uniffi::GroupChangeKind::SelfLeave => "A member left".to_string(),
            };
            app.notify(msg);
            refresh_rooms(app).await;
        }
        ClientEvent::RelayOk {
            success, message, relay_url, ..
        } => {
            if !*success {
                app.push_output(
                    format!("Relay NACK: {relay_url} — {message}"),
                    Color::Red,
                );
            }
        }
        ClientEvent::EventLoopError { description } => {
            app.push_output(format!("Event loop error: {description}"), Color::Red);
        }
    }
}

async fn handle_data_change(app: &mut App, change: &DataChange) {
    match change {
        DataChange::ConnectionStatusChanged { status, .. } => {
            refresh_relay_status(app).await;
            let status_str = format!("{:?}", status);
            app.notify(format!("Connection: {status_str}"));
        }
        DataChange::RoomListChanged => {
            refresh_rooms(app).await;
        }
        DataChange::MessageAdded { room_id, .. } | DataChange::MessageUpdated { room_id, .. } => {
            if app.selected_room_id().as_deref() == Some(room_id.as_str()) {
                load_messages(app, room_id).await;
            }
        }
        DataChange::RoomUpdated { .. } | DataChange::RoomDeleted { .. } => {
            refresh_rooms(app).await;
        }
        DataChange::ContactUpdated { .. }
        | DataChange::ContactListChanged
        | DataChange::IdentityListChanged => {}
    }
}

// ─── Data loading ───────────────────────────────────────────

async fn refresh_rooms(app: &mut App) {
    let pubkey = match &app.identity_hex {
        Some(pk) => pk.clone(),
        None => return,
    };
    if let Ok(rooms) = app.client.get_rooms(pubkey).await {
        let selected_id = app.selected_room_id();
        app.rooms = rooms
            .into_iter()
            .map(|r| {
                let name = r
                    .name
                    .unwrap_or_else(|| short_key(&r.to_main_pubkey));
                RoomEntry {
                    id: r.id,
                    name,
                    room_type: r.room_type,
                    status: r.status,
                    unread_count: r.unread_count as u32,
                    last_message: r.last_message_content,
                    to_main_pubkey: r.to_main_pubkey,
                }
            })
            .collect();

        // Restore selection
        if let Some(ref sid) = selected_id {
            if let Some(idx) = app.rooms.iter().position(|r| r.id == *sid) {
                app.room_state.select(Some(idx));
            }
        }
        if app.rooms.is_empty() {
            app.room_state.select(None);
        } else if app.room_state.selected().is_none() {
            app.room_state.select(Some(0));
        }
    }
}

async fn refresh_relay_status(app: &mut App) {
    if let Ok(statuses) = app.client.get_relay_statuses().await {
        app.total_relays = statuses.len();
        app.connected_relays = statuses.iter().filter(|s| s.status == "Connected").count();
    }
}

async fn load_messages(app: &mut App, room_id: &str) {
    load_messages_with_count(app, room_id, 50).await;
}

async fn load_messages_with_count(app: &mut App, room_id: &str, count: i32) {
    match app.client.get_messages(room_id.to_string(), count, 0).await {
        Ok(msgs) => {
            app.messages = msgs
                .into_iter()
                .map(|m| MessageEntry {
                    sender: m.sender_pubkey,
                    content: m.content,
                    is_me: m.is_me_send,
                    status: m.status,
                    timestamp: m.created_at,
                })
                .collect();
            app.command_output.clear();
            app.messages_scroll = 0;
        }
        Err(e) => {
            app.notify(format!("Load messages failed: {e}"));
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────

fn short_key(key: &str) -> String {
    if key.len() > 16 {
        format!("{}…", &key[..16])
    } else {
        key.to_string()
    }
}

fn format_timestamp(ts: u64) -> String {
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| dt.format("%H:%M").to_string())
        .unwrap_or_else(|| ts.to_string())
}

// ─── Owner management ───────────────────────────────────────

const OWNER_FILE: &str = "owner.txt";

fn load_owner(data_dir: &PathBuf) -> Option<String> {
    let path = data_dir.join(OWNER_FILE);
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_owner(data_dir: &PathBuf, pubkey: &str) {
    let path = data_dir.join(OWNER_FILE);
    if let Err(e) = std::fs::write(&path, pubkey) {
        tracing::warn!("Failed to save owner file: {e}");
    }
}

// ─── QR code rendering ─────────────────────────────────────

fn render_qr_lines(data: &str) -> Vec<String> {
    use qrcode::QrCode;

    let code = match QrCode::new(data.as_bytes()) {
        Ok(c) => c,
        Err(_) => return vec!["(QR generation failed)".to_string()],
    };

    let matrix = code.to_colors();
    let width = code.width();

    // Use Unicode half-block characters: each character encodes 2 vertical pixels
    // ▀ = top filled, ▄ = bottom filled, █ = both filled, ' ' = neither
    let mut lines = Vec::new();
    let rows: Vec<&[qrcode::Color]> = matrix.chunks(width).collect();

    for pair in rows.chunks(2) {
        let top = pair[0];
        let bottom = if pair.len() > 1 { Some(pair[1]) } else { None };
        let mut line = String::with_capacity(width + 4);
        line.push_str("  ");
        for x in 0..width {
            let t = top[x] == qrcode::Color::Dark;
            let b = bottom.map_or(false, |row| row[x] == qrcode::Color::Dark);
            line.push(match (t, b) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        lines.push(line);
    }
    lines
}
