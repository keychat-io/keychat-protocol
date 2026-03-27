//! Terminal UI for keychat-cli using ratatui.
//!
//! Layout:
//! ┌─ Contacts ───────┬─ Messages ─────────────────────────┐
//! │ ▾ Alice          │                    10:01            │
//! │   └ 📎 Files     │               Hi there  ✓  [You]   │
//! │   └ 🤖 Bot       │                                     │
//! │ ● Bob            │  [Alice]  Hello!                    │
//! │ ─ Groups ─       │           How are you?              │
//! │ ● Team Chat      │                                     │
//! │                   ├─────────────────────────────────────┤
//! │                   │ > type message here_                │
//! └───────────────────┴─────────────────────────────────────┘
//!  ID:a1b2 │ Relays:2/3 │ Tab/j/k │ F1:help │ Ctrl-C:quit

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{cursor, execute};
use keychat_uniffi::{
    ClientEvent, DataChange, GroupMemberInput, KeychatClient, MessageStatus,
    RoomStatus, RoomType,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;
use tokio::sync::broadcast;
use unicode_width::UnicodeWidthStr;

// ─── Types ──────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct RoomEntry {
    id: String,
    name: String,
    room_type: RoomType,
    status: RoomStatus,
    unread_count: u32,
    last_message: Option<String>,
    last_message_at: Option<u64>,
    to_main_pubkey: String,
    parent_room_id: Option<String>,
}

#[derive(Clone, Debug)]
struct MessageEntry {
    sender: String,
    sender_name: Option<String>,
    content: String,
    is_me: bool,
    status: MessageStatus,
    timestamp: u64,
    reply_to_content: Option<String>,
}

/// Flat display row for the room list (may be a section header or a room)
#[derive(Clone, Debug)]
struct DisplayRow {
    kind: DisplayRowKind,
}

#[derive(Clone, Debug)]
enum DisplayRowKind {
    SectionHeader(String),
    Room {
        room_id: String,
        depth: u8,
        icon: String,
        icon_color: Color,
        type_tag: String,
        name: String,
        unread: u32,
        preview: Option<String>,
    },
}

#[derive(PartialEq, Clone, Copy)]
enum Panel {
    Rooms,
    Messages,
    Input,
}

// ─── Theme ──────────────────────────────────────────────────

#[derive(Clone)]
struct Theme {
    accent: Color,
    muted: Color,
    success: Color,
    warning: Color,
    error: Color,
    self_msg: Color,
    other_msg: Color,
    border_active: Color,
    border_inactive: Color,
    bar_bg: Color,
}

impl Theme {
    fn dark() -> Self {
        Self {
            accent: Color::Cyan,
            muted: Color::DarkGray,
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            self_msg: Color::Green,
            other_msg: Color::Cyan,
            border_active: Color::Cyan,
            border_inactive: Color::DarkGray,
            bar_bg: Color::DarkGray,
        }
    }

    fn light() -> Self {
        Self {
            accent: Color::Blue,
            muted: Color::Gray,
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            self_msg: Color::Blue,
            other_msg: Color::Magenta,
            border_active: Color::Blue,
            border_inactive: Color::Gray,
            bar_bg: Color::Gray,
        }
    }
}

// ─── App State ──────────────────────────────────────────────

struct App {
    client: Arc<KeychatClient>,
    data_dir: PathBuf,
    // Room data
    rooms: Vec<RoomEntry>,
    display_rows: Vec<DisplayRow>,
    room_state: ListState,
    // Messages
    messages: Vec<MessageEntry>,
    messages_scroll: usize,
    // Input
    input: String,
    cursor_pos: usize,
    input_history: Vec<String>,
    history_index: Option<usize>,
    history_draft: String,
    // UI state
    active_panel: Panel,
    notification: Option<(String, std::time::Instant)>,
    command_output: Vec<(String, Color)>,
    show_help: bool,
    show_whoami: bool,
    // Identity/connection
    identity_hex: Option<String>,
    identity_name: Option<String>,
    owner_pubkey: Option<String>,
    connected_relays: usize,
    total_relays: usize,
    // Control
    should_quit: bool,
    event_loop_started: bool,
    theme: Theme,
    // Contact name cache: pubkey -> display name
    contact_names: std::collections::HashMap<String, String>,
}

impl App {
    fn new(client: Arc<KeychatClient>, data_dir: PathBuf) -> Self {
        let mut room_state = ListState::default();
        room_state.select(Some(0));
        Self {
            client,
            data_dir,
            rooms: Vec::new(),
            display_rows: Vec::new(),
            room_state,
            messages: Vec::new(),
            messages_scroll: 0,
            input: String::new(),
            cursor_pos: 0,
            input_history: Vec::new(),
            history_index: None,
            history_draft: String::new(),
            active_panel: Panel::Input,
            notification: None,
            command_output: Vec::new(),
            show_help: false,
            show_whoami: false,
            identity_hex: None,
            identity_name: None,
            owner_pubkey: None,
            connected_relays: 0,
            total_relays: 0,
            should_quit: false,
            event_loop_started: false,
            theme: Theme::dark(),
            contact_names: std::collections::HashMap::new(),
        }
    }

    fn selected_room_id(&self) -> Option<String> {
        self.room_state
            .selected()
            .and_then(|i| self.display_rows.get(i))
            .and_then(|row| match &row.kind {
                DisplayRowKind::Room { room_id, .. } => Some(room_id.clone()),
                DisplayRowKind::SectionHeader(_) => None,
            })
    }

    fn selected_room_name(&self) -> Option<String> {
        self.room_state
            .selected()
            .and_then(|i| self.display_rows.get(i))
            .and_then(|row| match &row.kind {
                DisplayRowKind::Room { name, .. } => Some(name.clone()),
                DisplayRowKind::SectionHeader(_) => None,
            })
    }

    fn notify(&mut self, msg: String) {
        // Terminal bell
        eprint!("\x07");
        self.notification = Some((msg, std::time::Instant::now()));
    }

    fn push_output(&mut self, msg: String, color: Color) {
        self.command_output.push((msg, color));
        if self.command_output.len() > 100 {
            self.command_output.drain(..self.command_output.len() - 100);
        }
    }

    fn push_history(&mut self, input: String) {
        if !input.is_empty() {
            // Avoid consecutive duplicates
            if self.input_history.last() != Some(&input) {
                self.input_history.push(input);
            }
        }
        self.history_index = None;
        self.history_draft.clear();
    }

    fn history_up(&mut self) {
        if self.input_history.is_empty() {
            return;
        }
        match self.history_index {
            None => {
                self.history_draft = self.input.clone();
                let idx = self.input_history.len() - 1;
                self.history_index = Some(idx);
                self.input = self.input_history[idx].clone();
            }
            Some(idx) if idx > 0 => {
                let idx = idx - 1;
                self.history_index = Some(idx);
                self.input = self.input_history[idx].clone();
            }
            _ => {}
        }
        self.cursor_pos = self.input.len();
    }

    fn history_down(&mut self) {
        match self.history_index {
            Some(idx) => {
                if idx + 1 < self.input_history.len() {
                    let idx = idx + 1;
                    self.history_index = Some(idx);
                    self.input = self.input_history[idx].clone();
                } else {
                    self.history_index = None;
                    self.input = self.history_draft.clone();
                }
            }
            None => {}
        }
        self.cursor_pos = self.input.len();
    }

    fn contact_name(&self, pubkey: &str) -> String {
        self.contact_names
            .get(pubkey)
            .cloned()
            .unwrap_or_else(|| short_key(pubkey))
    }
}

// ─── Public entry point ─────────────────────────────────────

pub async fn run(
    client: Arc<KeychatClient>,
    event_tx: broadcast::Sender<ClientEvent>,
    data_tx: broadcast::Sender<DataChange>,
    data_dir: String,
) -> anyhow::Result<()> {
    terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(Arc::clone(&client), PathBuf::from(&data_dir));

    // Load settings from DB
    app.owner_pubkey = load_owner(&client).await;
    app.theme = load_theme_setting(&client).await;

    // Shared startup: restore identity → sessions → connect → event loop
    let relay_urls = keychat_uniffi::default_relays();
    if let Some((pubkey, session_count)) = crate::commands::init_and_connect(&client, relay_urls).await {
        app.identity_hex = Some(pubkey.clone());
        // Load identity display name from app storage
        if let Ok(identities) = client.get_identities().await {
            if let Some(id) = identities.iter().find(|i| i.nostr_pubkey_hex == pubkey) {
                app.identity_name = Some(id.name.clone());
            }
        }
        if session_count > 0 {
            app.push_output(format!("Restored {session_count} session(s)"), Color::Cyan);
        }
        app.event_loop_started = true;
        app.push_output("Connecting to relays...".into(), Color::Cyan);
    } else {
        tracing::info!("No identity found, waiting for /create");
    }

    refresh_rooms(&mut app).await;
    refresh_relay_status(&mut app).await;
    refresh_contacts(&mut app).await;

    let mut event_rx = event_tx.subscribe();
    let mut data_rx = data_tx.subscribe();
    let mut last_relay_check = std::time::Instant::now();

    loop {
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if crossterm::event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                handle_key_event(&mut app, key).await;
            }
        }

        while let Ok(ev) = event_rx.try_recv() {
            handle_client_event(&mut app, &ev).await;
        }
        while let Ok(dc) = data_rx.try_recv() {
            handle_data_change(&mut app, &dc).await;
        }

        // Refresh relay status every 3s (catches background connect completion)
        if last_relay_check.elapsed() > Duration::from_secs(3) {
            refresh_relay_status(&mut app).await;
            last_relay_check = std::time::Instant::now();
        }

        // Clear old notifications (5s)
        if let Some((_, ts)) = &app.notification {
            if ts.elapsed() > Duration::from_secs(5) {
                app.notification = None;
            }
        }

        if app.should_quit {
            break;
        }
    }

    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, cursor::Show)?;
    let _ = client.disconnect().await;
    Ok(())
}

// ─── Drawing ────────────────────────────────────────────────

fn draw_ui(f: &mut ratatui::Frame, app: &mut App) {
    let size = f.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(size);

    // Hide room panel when: no identity, no rooms, or window too narrow
    let show_rooms = app.identity_hex.is_some() && !app.rooms.is_empty() && size.width >= 60;

    // Dynamic input height: 3 lines base + 1 per extra newline, capped at 8
    let line_count = app.input.chars().filter(|c| *c == '\n').count() + 1;
    let input_height = (line_count as u16 + 2).min(8).max(3); // +2 for border

    if show_rooms {
        let content = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Min(30)])
            .split(outer[0]);

        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(input_height)])
            .split(content[1]);

        draw_rooms(f, app, content[0]);
        draw_messages(f, app, right[0]);
        draw_input(f, app, right[1]);
    } else {
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(input_height)])
            .split(outer[0]);

        draw_messages(f, app, right[0]);
        draw_input(f, app, right[1]);
    }

    draw_status_bar(f, app, outer[1]);

    if app.show_help {
        draw_help_overlay(f, size);
    }
    if app.show_whoami {
        draw_whoami_overlay(f, app, size);
    }
}

fn draw_rooms(f: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let t = &app.theme;
    let highlight_style = Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);

    let items: Vec<ListItem> = app
        .display_rows
        .iter()
        .map(|row| match &row.kind {
            DisplayRowKind::SectionHeader(label) => {
                let line = Line::from(vec![
                    Span::styled("─ ", Style::default().fg(t.muted)),
                    Span::styled(
                        label.as_str(),
                        Style::default()
                            .fg(t.muted)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" ─", Style::default().fg(t.muted)),
                ]);
                ListItem::new(line)
            }
            DisplayRowKind::Room {
                depth,
                icon,
                icon_color,
                type_tag,
                name,
                unread,
                preview,
                ..
            } => {
                let indent = if *depth > 0 { " └" } else { "" };
                let name_display = if name.chars().count() > (20 - indent.len()) {
                    format!(
                        "{}…",
                        name.chars()
                            .take(19 - indent.len())
                            .collect::<String>()
                    )
                } else {
                    name.clone()
                };

                let unread_span = if *unread > 0 {
                    Span::styled(format!(" ({unread})"), Style::default().fg(t.error))
                } else {
                    Span::raw("")
                };

                let mut spans = vec![
                    Span::styled(indent.to_string(), Style::default().fg(t.muted)),
                    Span::styled(format!("{icon} "), Style::default().fg(*icon_color)),
                ];
                if !type_tag.is_empty() {
                    spans.push(Span::styled(
                        format!("{type_tag} "),
                        Style::default().fg(t.muted),
                    ));
                }
                spans.push(Span::styled(
                    name_display,
                    Style::default().fg(Color::White),
                ));
                spans.push(unread_span);

                let mut lines = vec![Line::from(spans)];

                // Preview line for top-level rooms
                if *depth == 0 {
                    if let Some(prev) = preview {
                        let trunc = if prev.chars().count() > 24 {
                            format!("{}…", prev.chars().take(23).collect::<String>())
                        } else {
                            prev.clone()
                        };
                        lines.push(Line::from(Span::styled(
                            format!("  {trunc}"),
                            Style::default().fg(t.muted),
                        )));
                    }
                }

                ListItem::new(lines)
            }
        })
        .collect();

    let border_style = if app.active_panel == Panel::Rooms {
        Style::default().fg(t.border_active)
    } else {
        Style::default().fg(t.border_inactive)
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
    let t = &app.theme;
    let border_style = if app.active_panel == Panel::Messages {
        Style::default().fg(t.border_active)
    } else {
        Style::default().fg(t.border_inactive)
    };

    let title = match app.selected_room_name() {
        Some(name) => format!(" {} ", name),
        None => " Messages ".to_string(),
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);

    let inner_width = area.width.saturating_sub(2) as usize;

    if app.messages.is_empty() && app.command_output.is_empty() {
        let welcome = draw_welcome(app);
        let p = Paragraph::new(welcome).block(block);
        f.render_widget(p, area);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();

    if app.messages.is_empty() {
        // Show command output
        for (msg, color) in &app.command_output {
            lines.push(Line::from(Span::styled(
                format!("  {msg}"),
                Style::default().fg(*color),
            )));
        }
    } else {
        // Render chat messages with bubble layout
        let mut last_date: Option<String> = None;
        let mut last_sender: Option<(bool, String)> = None; // (is_me, pubkey)

        for msg in &app.messages {
            // Date separator
            let date_str = format_date(msg.timestamp);
            if last_date.as_ref() != Some(&date_str) {
                if last_date.is_some() {
                    lines.push(Line::from(""));
                }
                let pad = inner_width.saturating_sub(date_str.len() + 4) / 2;
                lines.push(Line::from(Span::styled(
                    format!(
                        "{:─<pad$} {date_str} {:─<rpad$}",
                        "",
                        "",
                        pad = pad,
                        rpad = inner_width.saturating_sub(pad + date_str.len() + 2)
                    ),
                    Style::default().fg(t.muted),
                )));
                last_date = Some(date_str);
                last_sender = None;
            }

            let time = format_time(msg.timestamp);
            let same_sender = last_sender
                .as_ref()
                .map_or(false, |(is_me, pk)| *is_me == msg.is_me && *pk == msg.sender);

            if msg.is_me {
                // Right-aligned: content + status + [You]
                let status_icon = match msg.status {
                    MessageStatus::Sending => "⏳",
                    MessageStatus::Success => "✓",
                    MessageStatus::Failed => "✗",
                };
                let status_color = match msg.status {
                    MessageStatus::Sending => t.warning,
                    MessageStatus::Success => t.success,
                    MessageStatus::Failed => t.error,
                };

                if !same_sender {
                    // Time + sender label (right-aligned)
                    let label = format!("{time}  You");
                    let rpad = inner_width.saturating_sub(label.len());
                    lines.push(Line::from(vec![
                        Span::styled(
                            " ".repeat(rpad),
                            Style::default(),
                        ),
                        Span::styled(time.clone(), Style::default().fg(t.muted)),
                        Span::styled("  You", Style::default().fg(t.self_msg).add_modifier(Modifier::BOLD)),
                    ]));
                }

                // Reply quote (right-aligned)
                if let Some(ref reply_content) = msg.reply_to_content {
                    let truncated: String = reply_content.chars().take(30).collect();
                    let quote = format!("↩ {truncated}");
                    let rpad = inner_width.saturating_sub(quote.len() + 2);
                    lines.push(Line::from(vec![
                        Span::raw(" ".repeat(rpad.max(2))),
                        Span::styled(quote, Style::default().fg(t.muted).add_modifier(Modifier::ITALIC)),
                    ]));
                }

                let msg_with_status = format!("{} {status_icon}", msg.content);
                let rpad = inner_width.saturating_sub(msg_with_status.len() + 2);
                lines.push(Line::from(vec![
                    Span::raw(" ".repeat(rpad.max(2))),
                    Span::raw(&msg.content),
                    Span::styled(format!(" {status_icon}"), Style::default().fg(status_color)),
                ]));
            } else {
                // Left-aligned: [Sender] content
                if !same_sender {
                    let fallback = app.contact_name(&msg.sender);
                    let sender_name = msg
                        .sender_name
                        .as_deref()
                        .unwrap_or(&fallback);
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("  {sender_name}"),
                            Style::default()
                                .fg(t.other_msg)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(format!("  {time}"), Style::default().fg(t.muted)),
                    ]));
                }

                // Reply quote (left-aligned)
                if let Some(ref reply_content) = msg.reply_to_content {
                    let truncated: String = reply_content.chars().take(30).collect();
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled(format!("↩ {truncated}"), Style::default().fg(t.muted).add_modifier(Modifier::ITALIC)),
                    ]));
                }

                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::raw(&msg.content),
                ]));
            }

            last_sender = Some((msg.is_me, msg.sender.clone()));
        }
    }

    // Auto-scroll to bottom
    let inner_height = area.height.saturating_sub(2) as usize;
    let scroll = if lines.len() > inner_height {
        let base = lines.len() - inner_height;
        base.saturating_sub(app.messages_scroll)
    } else {
        0
    };

    let messages_widget = Paragraph::new(lines).block(block).scroll((scroll as u16, 0));
    f.render_widget(messages_widget, area);
}

fn draw_welcome(app: &App) -> Vec<Line<'static>> {
    let t = &app.theme;
    if app.identity_hex.is_none() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Welcome to Keychat CLI",
                Style::default()
                    .fg(t.accent)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  /create <name> — Create new identity with display name",
                Style::default().fg(t.success),
            )),
            Line::from(Span::styled(
                "  /import <m>   — Import from mnemonic",
                Style::default().fg(t.success),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Press F1 or /help for all commands",
                Style::default().fg(t.muted),
            )),
        ]
    } else if app.rooms.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No conversations yet",
                Style::default().fg(t.muted),
            )),
            Line::from(Span::styled(
                "  /connect      — Connect to relays",
                Style::default().fg(t.success),
            )),
            Line::from(Span::styled(
                "  /add <pubkey> — Send friend request",
                Style::default().fg(t.success),
            )),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Select a room with ↑↓ or j/k, Enter to open",
                Style::default().fg(t.muted),
            )),
        ]
    }
}

fn draw_input(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let border_style = if app.active_panel == Panel::Input {
        Style::default().fg(t.border_active)
    } else {
        Style::default().fg(t.border_inactive)
    };

    let title = if app.input.starts_with('/') {
        " Command "
    } else if app.selected_room_id().is_some() {
        " Message (Alt+Enter: newline) "
    } else {
        " Input (/ for commands) "
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);

    // Build multi-line display: prepend "> " to first line
    let input_lines: Vec<Line> = app
        .input
        .split('\n')
        .enumerate()
        .map(|(i, line)| {
            if i == 0 {
                Line::from(vec![
                    Span::styled("> ", Style::default().fg(t.accent)),
                    Span::raw(line),
                ])
            } else {
                Line::from(vec![
                    Span::styled("  ", Style::default().fg(t.accent)),
                    Span::raw(line),
                ])
            }
        })
        .collect();

    let input_text = Paragraph::new(input_lines).block(block);
    f.render_widget(input_text, area);

    if app.active_panel == Panel::Input {
        // Find cursor row and column within the multi-line input
        let before_cursor = &app.input[..app.cursor_pos];
        let cursor_row = before_cursor.chars().filter(|c| *c == '\n').count() as u16;
        let last_line_start = before_cursor.rfind('\n').map(|p| p + 1).unwrap_or(0);
        let cursor_col = before_cursor[last_line_start..].width() as u16;
        f.set_cursor_position((area.x + 3 + cursor_col, area.y + 1 + cursor_row));
    }
}

fn draw_status_bar(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let identity = match &app.identity_hex {
        Some(hex) => format!("ID:{}", short_key(hex)),
        None => "No identity".to_string(),
    };

    let relay_status = format!("Relays:{}/{}", app.connected_relays, app.total_relays);
    let relay_color = if app.connected_relays > 0 {
        t.success
    } else if app.total_relays > 0 {
        t.warning
    } else {
        t.muted
    };

    let sep = Span::styled(" │ ", Style::default().fg(Color::Gray).bg(t.bar_bg));

    // When notification is active, show it instead of help shortcuts to maximize space
    let mut spans = vec![
        Span::styled(" ", Style::default().bg(t.bar_bg)),
        Span::styled(&identity, Style::default().fg(t.accent).bg(t.bar_bg)),
        sep.clone(),
        Span::styled(&relay_status, Style::default().fg(relay_color).bg(t.bar_bg)),
        sep,
    ];

    if let Some((msg, _)) = &app.notification {
        spans.push(Span::styled(msg.as_str(), Style::default().fg(t.warning).bg(t.bar_bg)));
    } else {
        spans.push(Span::styled(
            "Tab/j/k  F1:help  ^C:quit",
            Style::default().fg(t.muted).bg(t.bar_bg),
        ));
    }

    // Fill remaining width with background color
    spans.push(Span::styled(
        " ".repeat(area.width as usize),
        Style::default().bg(t.bar_bg),
    ));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_help_overlay(f: &mut ratatui::Frame, area: Rect) {
    let pw = 62u16.min(area.width.saturating_sub(4));
    let ph = 38u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(pw)) / 2;
    let y = (area.height.saturating_sub(ph)) / 2;
    let popup = Rect::new(x, y, pw, ph);

    f.render_widget(Clear, popup);

    let lines = vec![
        Line::from(Span::styled(
            " Keychat CLI",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Navigation",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  Tab          Switch panels (Rooms→Input→Messages)"),
        Line::from("  j/k or ↑/↓   Navigate rooms / scroll messages"),
        Line::from("  Enter        Select room / send message"),
        Line::from("  Esc          Back to input / close help"),
        Line::from("  ↑/↓ in input Browse input history"),
        Line::from("  Ctrl-C       Quit"),
        Line::from(""),
        Line::from(Span::styled(
            " Identity",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled("  /create  /import  /whoami  /delete-identity", Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled(
            " Connection",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled("  /connect  /disconnect  /relays  /add-relay  /reconnect  /status", Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled(
            " Friends & Messaging",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled("  /add <pk> [greeting]  /accept <id>  /reject <id>  /contacts", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /history [n]       /retry         /read", Style::default().fg(Color::Green))),
        Line::from("  (type text without / to send a message)"),
        Line::from(""),
        Line::from(Span::styled(
            " Signal Groups",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled("  /sg-create <name> <pk...>  /sg-leave  /sg-dissolve", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /sg-rename <id> <name>     /sg-kick <id> <pk>", Style::default().fg(Color::Green))),
        Line::from(""),
        Line::from(Span::styled(
            " Settings",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled("  /theme dark|light  — Switch theme", Style::default().fg(Color::Green))),
        Line::from(Span::styled("  /reset             — Delete all data and start fresh", Style::default().fg(Color::Red))),
        Line::from(""),
        Line::from(Span::styled(
            " Tips",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  Alt+Enter    Insert newline (multi-line message)"),
        Line::from(""),
        Line::from(Span::styled(
            " Press Esc or F1 to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let w = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(w, popup);
}

fn draw_whoami_overlay(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let pw = 62u16.min(area.width.saturating_sub(4));
    let ph = 28u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(pw)) / 2;
    let y = (area.height.saturating_sub(ph)) / 2;
    let popup = Rect::new(x, y, pw, ph);

    f.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(Span::styled(
            " Identity",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    if let Some(ref pk) = app.identity_hex {
        let npub = keychat_uniffi::npub_from_hex(pk.clone()).unwrap_or_default();
        if let Some(ref name) = app.identity_name {
            lines.push(Line::from(vec![
                Span::styled("  Name:   ", Style::default().fg(Color::DarkGray)),
                Span::styled(name.as_str(), Style::default().fg(Color::Green)),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("  Pubkey: ", Style::default().fg(Color::DarkGray)),
            Span::styled(pk.as_str(), Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  npub:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(npub.clone(), Style::default().fg(Color::Cyan)),
        ]));
        if let Some(ref owner) = app.owner_pubkey {
            lines.push(Line::from(vec![
                Span::styled("  Owner:  ", Style::default().fg(Color::DarkGray)),
                Span::styled(owner.as_str(), Style::default().fg(Color::Green)),
            ]));
        }
        lines.push(Line::from(""));
        for qr_line in render_qr_lines(&npub) {
            lines.push(Line::from(format!("  {qr_line}")));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  No identity. Use /create or /import.",
            Style::default().fg(Color::Yellow),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Press Esc to close",
        Style::default().fg(Color::DarkGray),
    )));

    let w = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Who Am I ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(w, popup);
}

// ─── Key event handling ─────────────────────────────────────

async fn handle_key_event(app: &mut App, key: KeyEvent) {
    // Global shortcuts
    if key.code == KeyCode::F(1) {
        app.show_help = !app.show_help;
        return;
    }

    if app.show_help {
        if matches!(key.code, KeyCode::Esc | KeyCode::F(1)) {
            app.show_help = false;
        }
        return;
    }

    if app.show_whoami {
        if matches!(key.code, KeyCode::Esc) {
            app.show_whoami = false;
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
        KeyCode::Up | KeyCode::Char('k') => room_select_prev(app),
        KeyCode::Down | KeyCode::Char('j') => room_select_next(app),
        KeyCode::Enter | KeyCode::Char('l') => {
            if let Some(room_id) = app.selected_room_id() {
                load_messages(app, &room_id).await;
                app.active_panel = Panel::Input;
                let _ = app.client.mark_room_read(room_id).await;
                refresh_rooms(app).await;
            }
        }
        KeyCode::Esc | KeyCode::Char('h') => {
            app.active_panel = Panel::Input;
        }
        _ => {}
    }
}

fn room_select_prev(app: &mut App) {
    let current = app.room_state.selected().unwrap_or(0);
    // Skip section headers
    let mut target = current;
    loop {
        if target == 0 {
            break;
        }
        target -= 1;
        if matches!(
            app.display_rows.get(target),
            Some(DisplayRow {
                kind: DisplayRowKind::Room { .. },
                ..
            })
        ) {
            break;
        }
    }
    if matches!(
        app.display_rows.get(target),
        Some(DisplayRow {
            kind: DisplayRowKind::Room { .. },
            ..
        })
    ) {
        app.room_state.select(Some(target));
    }
}

fn room_select_next(app: &mut App) {
    let current = app.room_state.selected().unwrap_or(0);
    let len = app.display_rows.len();
    let mut target = current;
    loop {
        target += 1;
        if target >= len {
            target = current;
            break;
        }
        if matches!(
            app.display_rows.get(target),
            Some(DisplayRow {
                kind: DisplayRowKind::Room { .. },
                ..
            })
        ) {
            break;
        }
    }
    app.room_state.select(Some(target));
}

fn handle_messages_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            app.messages_scroll = app.messages_scroll.saturating_add(3);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.messages_scroll = app.messages_scroll.saturating_sub(3);
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
            // Alt+Enter or Shift+Enter inserts a newline for multi-line input
            if key.modifiers.contains(KeyModifiers::ALT)
                || key.modifiers.contains(KeyModifiers::SHIFT)
            {
                app.input.insert(app.cursor_pos, '\n');
                app.cursor_pos += 1;
            } else if !app.input.is_empty() {
                let input = app.input.clone();
                app.input.clear();
                app.cursor_pos = 0;
                app.push_history(input.clone());
                process_input(app, &input).await;
            }
        }
        KeyCode::Char(c) => {
            // Tab completion for commands
            if c == '\t' || (key.code == KeyCode::Char('i') && key.modifiers.contains(KeyModifiers::CONTROL)) {
                try_tab_complete(app);
                return;
            }
            app.input.insert(app.cursor_pos, c);
            app.cursor_pos += c.len_utf8();
        }
        KeyCode::BackTab | KeyCode::Tab => {
            try_tab_complete(app);
        }
        KeyCode::Backspace => {
            if app.cursor_pos > 0 {
                // Find previous char boundary
                let prev = app.input[..app.cursor_pos]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.input.remove(prev);
                app.cursor_pos = prev;
            }
        }
        KeyCode::Delete => {
            if app.cursor_pos < app.input.len() {
                app.input.remove(app.cursor_pos);
            }
        }
        KeyCode::Left => {
            if app.cursor_pos > 0 {
                app.cursor_pos = app.input[..app.cursor_pos]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.cursor_pos < app.input.len() {
                let ch = app.input[app.cursor_pos..].chars().next().unwrap();
                app.cursor_pos += ch.len_utf8();
            }
        }
        KeyCode::Home => app.cursor_pos = 0,
        KeyCode::End => app.cursor_pos = app.input.len(),
        KeyCode::Up => app.history_up(),
        KeyCode::Down => app.history_down(),
        KeyCode::Esc => app.active_panel = Panel::Rooms,
        _ => {}
    }
}

// ─── Tab completion ─────────────────────────────────────────

const COMMANDS: &[&str] = &[
    "/create",
    "/import",
    "/whoami",
    "/delete-identity",
    "/confirm-delete",
    "/connect",
    "/disconnect",
    "/relays",
    "/add-relay",
    "/remove-relay",
    "/reconnect",
    "/status",
    "/add",
    "/accept",
    "/reject",
    "/contacts",
    "/history",
    "/retry",
    "/read",
    "/sg-create",
    "/sg-leave",
    "/sg-dissolve",
    "/sg-rename",
    "/sg-kick",
    "/debug",
    "/reset",
    "/confirm-reset",
    "/help",
    "/quit",
    "/exit",
    "/theme",
];

fn try_tab_complete(app: &mut App) {
    if !app.input.starts_with('/') {
        return;
    }
    let prefix = &app.input;
    let matches: Vec<&&str> = COMMANDS
        .iter()
        .filter(|cmd| cmd.starts_with(prefix))
        .collect();
    match matches.len() {
        0 => {}
        1 => {
            app.input = format!("{} ", matches[0]);
            app.cursor_pos = app.input.len();
        }
        _ => {
            // Find common prefix
            let first = matches[0];
            let common_len = matches.iter().fold(first.len(), |acc, cmd| {
                first
                    .chars()
                    .zip(cmd.chars())
                    .take_while(|(a, b)| a == b)
                    .count()
                    .min(acc)
            });
            if common_len > app.input.len() {
                app.input = first[..common_len].to_string();
                app.cursor_pos = app.input.len();
            }
            // Show options in notification
            let opts: Vec<&str> = matches.iter().map(|s| **s).collect();
            app.notification = Some((opts.join("  "), std::time::Instant::now()));
        }
    }
}

// ─── Command processing ─────────────────────────────────────

async fn process_input(app: &mut App, input: &str) {
    if input.starts_with('/') {
        process_command(app, input).await;
    } else {
        send_message(app, input).await;
    }
}

/// Extract group_id (to_main_pubkey) from the currently selected room, if it's a group.
async fn resolve_selected_group_id(app: &App) -> Option<String> {
    let room_id = app.selected_room_id()?;
    let room = app.client.get_room(room_id).await.ok()??;
    if matches!(room.room_type, RoomType::SignalGroup) {
        Some(room.to_main_pubkey)
    } else {
        None
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
    tracing::info!("Sending message to room={}, len={}", &room_id[..16.min(room_id.len())], text.len());

    match crate::commands::send_message(&app.client, &room_id, text).await {
        Ok(crate::commands::SendResult::Dm { .. }) => {}
        Ok(crate::commands::SendResult::Group { event_count }) => {
            app.push_output(format!("Sent to group ({event_count} event(s))"), Color::Green);
        }
        Ok(crate::commands::SendResult::MlsNotSupported) => {
            app.notify("MLS groups not yet supported".into());
            return;
        }
        Err(e) => {
            app.notify(format!("Send failed: {e}"));
            return;
        }
    }

    load_messages(app, &room_id).await;
    refresh_rooms(app).await;
}

async fn process_command(app: &mut App, input: &str) {
    let mut parts = input.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let args = parts.next().unwrap_or("").trim();

    match cmd {
        "/create" => {
            if args.is_empty() {
                app.notify("Usage: /create <name>  (set your display name)".into());
                return;
            }
            let display_name = args.to_string();
            match crate::commands::create_identity(&app.client, &display_name).await {
                Ok((pubkey_hex, npub, mnemonic)) => {
                    app.identity_hex = Some(pubkey_hex.clone());
                    app.identity_name = Some(display_name.clone());

                    app.push_output(format!("Identity created! Name: {display_name}"), Color::Green);
                    app.push_output(String::new(), Color::White);
                    app.push_output("Pubkey (hex):".into(), Color::DarkGray);
                    app.push_output(pubkey_hex, Color::Cyan);
                    app.push_output(String::new(), Color::White);
                    app.push_output("npub:".into(), Color::DarkGray);
                    app.push_output(npub.clone(), Color::Cyan);
                    app.push_output(String::new(), Color::White);

                    for line in render_qr_lines(&npub) {
                        app.push_output(line, Color::White);
                    }
                    app.push_output(String::new(), Color::White);
                    app.push_output("Mnemonic (SAVE THIS!):".into(), Color::Yellow);
                    let words: Vec<&str> = mnemonic.split_whitespace().collect();
                    for chunk in words.chunks(4) {
                        app.push_output(chunk.join(" "), Color::Yellow);
                    }
                    app.push_output(String::new(), Color::White);
                    app.push_output(
                        "First friend request will be auto-approved as owner.".into(),
                        app.theme.muted,
                    );

                    // Auto-connect to relays in background (don't block UI)
                    if !app.event_loop_started {
                        app.event_loop_started = true;
                        let client_bg = Arc::clone(&app.client);
                        tokio::spawn(async move {
                            let relay_urls = keychat_uniffi::default_relays();
                            tracing::info!("Background connecting to {} relay(s)", relay_urls.len());
                            if let Err(e) = client_bg.connect(relay_urls).await {
                                tracing::warn!("Auto-connect failed: {e}");
                                return;
                            }
                            if let Err(e) = client_bg.start_event_loop().await {
                                tracing::error!("event loop error: {e}");
                            }
                        });
                    }
                    app.notify("Identity created! Connecting to relays...".into());
                }
                Err(e) => app.notify(format!("Create failed: {e}")),
            }
        }
        "/import" => {
            if args.is_empty() {
                app.notify("Usage: /import <mnemonic words>".into());
                return;
            }
            match crate::commands::import_identity(&app.client, args).await {
                Ok(pubkey) => {
                    app.identity_hex = Some(pubkey.clone());
                    // Restore identity name from app storage
                    if let Ok(identities) = app.client.get_identities().await {
                        if let Some(id) = identities.iter().find(|i| i.nostr_pubkey_hex == pubkey) {
                            app.identity_name = Some(id.name.clone());
                        }
                    }
                    app.push_output(format!("Identity imported: {}", short_key(&pubkey)), Color::Green);
                    refresh_rooms(app).await;
                    refresh_contacts(app).await;
                }
                Err(e) => app.notify(format!("Import failed: {e}")),
            }
        }
        "/whoami" => {
            app.show_whoami = true;
        }
        "/delete-identity" => {
            app.push_output(
                "Type /confirm-delete to confirm identity deletion".into(),
                Color::Yellow,
            );
        }
        "/confirm-delete" => match app.client.remove_identity().await {
            Ok(_) => {
                delete_mnemonic(&app.client).await;
                app.identity_hex = None;
                app.identity_name = None;
                app.owner_pubkey = None;
                app.rooms.clear();
                app.display_rows.clear();
                app.messages.clear();
                app.notify("Identity deleted".into());
            }
            Err(e) => app.notify(format!("Delete failed: {e}")),
        },
        "/reset" => {
            app.push_output(
                "⚠ This will DELETE ALL DATA (identity, messages, contacts, sessions).".into(),
                Color::Red,
            );
            app.push_output(
                "Type /confirm-reset to confirm.".into(),
                Color::Yellow,
            );
        }
        "/confirm-reset" => {
            let data_dir = app.data_dir.clone();
            // Disconnect first
            let _ = app.client.disconnect().await;
            // Delete the entire data directory
            match std::fs::remove_dir_all(&data_dir) {
                Ok(_) => {
                    app.push_output("All data deleted.".into(), Color::Green);
                    app.push_output(
                        "Restart keychat to begin fresh.".into(),
                        Color::Cyan,
                    );
                    app.identity_hex = None;
                    app.identity_name = None;
                    app.owner_pubkey = None;
                    app.rooms.clear();
                    app.display_rows.clear();
                    app.messages.clear();
                    app.contact_names.clear();
                    app.connected_relays = 0;
                    app.total_relays = 0;
                    app.event_loop_started = false;
                    app.should_quit = true;
                }
                Err(e) => app.notify(format!("Reset failed: {e}")),
            }
        }
        "/connect" => {
            let relay_urls: Vec<String> = if args.is_empty() {
                keychat_uniffi::default_relays()
            } else {
                args.split_whitespace().map(|s| s.to_string()).collect()
            };
            app.push_output(format!("Connecting to {} relay(s)...", relay_urls.len()), Color::Cyan);
            match app.client.connect(relay_urls).await {
                Ok(_) => {
                    app.push_output("Connected".into(), Color::Green);
                    refresh_relay_status(app).await;
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
        "/relays" => match app.client.get_relay_statuses().await {
            Ok(statuses) => {
                if statuses.is_empty() {
                    app.push_output("No relays configured".into(), app.theme.muted);
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
        },
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
            let relay_color = if app.connected_relays > 0 { Color::Green } else { Color::Red };
            app.push_output(
                format!("Relays: {}/{}", app.connected_relays, app.total_relays),
                relay_color,
            );
            match app.client.debug_state_summary().await {
                Ok(s) => app.push_output(format!("State: {s}"), Color::White),
                Err(e) => app.push_output(format!("State error: {e}"), Color::Red),
            }
        }
        "/add" => {
            let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
            if parts.is_empty() || parts[0].is_empty() {
                app.notify("Usage: /add <pubkey> [greeting]".into());
                return;
            }
            let peer = match keychat_uniffi::normalize_to_hex(parts[0].to_string()) {
                Ok(p) => p,
                Err(e) => {
                    app.notify(format!("Invalid pubkey: {e}"));
                    return;
                }
            };
            // Use identity display name; greeting is optional second arg
            let name = app.identity_name.clone().unwrap_or_else(|| "CLI User".to_string());
            let greeting = if parts.len() > 1 { parts[1] } else { "" };
            if !greeting.is_empty() {
                app.push_output(format!("Greeting: {greeting}"), app.theme.muted);
            }
            tracing::info!("Sending friend request to {}", short_key(&peer));
            match app
                .client
                .send_friend_request(peer.clone(), name, "cli-device".to_string())
                .await
            {
                Ok(pending) => {
                    tracing::info!("Friend request sent, id={}", &pending.request_id);
                    app.push_output(
                        format!("Request sent to {}. ID: {}", short_key(&peer), short_key(&pending.request_id)),
                        Color::Green,
                    );
                    refresh_rooms(app).await;
                }
                Err(e) => {
                    tracing::error!("Friend request send failed: {e}");
                    app.notify(format!("Send failed: {e}"));
                }
            }
        }
        "/accept" => {
            let parts: Vec<&str> = args.splitn(2, char::is_whitespace).collect();
            if parts.is_empty() || parts[0].is_empty() {
                app.notify("Usage: /accept <request_id> [my_name]".into());
                return;
            }
            let name = if parts.len() > 1 { parts[1].to_string() } else { "CLI User".to_string() };
            tracing::info!("Accepting friend request: {}", parts[0]);
            match app.client.accept_friend_request(parts[0].to_string(), name).await {
                Ok(contact) => {
                    tracing::info!("Friend request accepted: {}", contact.display_name);
                    app.push_output(format!("Accepted: {}", contact.display_name), Color::Green);
                    refresh_rooms(app).await;
                    refresh_contacts(app).await;
                }
                Err(e) => {
                    tracing::error!("Accept friend request failed: {e}");
                    app.notify(format!("Accept failed: {e}"));
                }
            }
        }
        "/reject" => {
            if args.is_empty() {
                app.notify("Usage: /reject <request_id>".into());
                return;
            }
            match app.client.reject_friend_request(args.to_string(), None).await {
                Ok(_) => app.push_output("Friend request rejected".into(), Color::Yellow),
                Err(e) => app.notify(format!("Reject failed: {e}")),
            }
        }
        "/contacts" => {
            if let Some(ref pk) = app.identity_hex {
                match app.client.get_contacts(pk.clone()).await {
                    Ok(contacts) => {
                        if contacts.is_empty() {
                            app.push_output("No contacts yet".into(), app.theme.muted);
                        } else {
                            for c in &contacts {
                                let name = c.petname.as_deref().or(c.name.as_deref()).unwrap_or("(unnamed)");
                                app.push_output(format!("{name}  {}", short_key(&c.pubkey)), Color::White);
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
            let count: i32 = args.parse().unwrap_or(50);
            load_messages_with_count(app, &room_id, count).await;
        }
        "/retry" => match app.client.retry_failed_messages().await {
            Ok(count) if count > 0 => app.push_output(format!("Retrying {count} message(s)"), Color::Green),
            Ok(_) => app.push_output("No failed messages".into(), app.theme.muted),
            Err(e) => app.notify(format!("Retry failed: {e}")),
        },
        "/read" => {
            if let Some(room_id) = app.selected_room_id() {
                let _ = app.client.mark_room_read(room_id).await;
                app.push_output("Marked as read".into(), Color::Green);
                refresh_rooms(app).await;
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
                    let n = keychat_uniffi::normalize_to_hex(pk.to_string())
                        .unwrap_or_else(|_| pk.to_string());
                    GroupMemberInput { nostr_pubkey: n.clone(), name: short_key(&n) }
                })
                .collect();
            match app.client.create_signal_group(name, members).await {
                Ok(info) => {
                    app.push_output(
                        format!("Group created: {} ({} members)", info.name, info.member_count),
                        Color::Green,
                    );
                    refresh_rooms(app).await;
                }
                Err(e) => app.notify(format!("Create failed: {e}")),
            }
        }
        "/sg-leave" => {
            let gid = resolve_selected_group_id(app).await;
            match gid {
                None => app.notify("Select a group room first".into()),
                Some(gid) => match app.client.leave_signal_group(gid).await {
                    Ok(_) => { app.push_output("Left group".into(), Color::Yellow); refresh_rooms(app).await; }
                    Err(e) => app.notify(format!("Leave failed: {e}")),
                },
            }
        }
        "/sg-dissolve" => {
            let gid = resolve_selected_group_id(app).await;
            match gid {
                None => app.notify("Select a group room first".into()),
                Some(gid) => match app.client.dissolve_signal_group(gid).await {
                    Ok(_) => { app.push_output("Group dissolved".into(), Color::Red); refresh_rooms(app).await; }
                    Err(e) => app.notify(format!("Dissolve failed: {e}")),
                },
            }
        }
        "/sg-rename" => {
            if args.is_empty() { app.notify("Usage: /sg-rename <new_name>".into()); return; }
            let gid = resolve_selected_group_id(app).await;
            match gid {
                None => app.notify("Select a group room first".into()),
                Some(gid) => match app.client.rename_signal_group(gid, args.to_string()).await {
                    Ok(_) => { app.push_output(format!("Renamed to: {args}"), Color::Green); refresh_rooms(app).await; }
                    Err(e) => app.notify(format!("Rename failed: {e}")),
                },
            }
        }
        "/sg-kick" => {
            if args.is_empty() { app.notify("Usage: /sg-kick <pubkey>".into()); return; }
            let gid = resolve_selected_group_id(app).await;
            let pk = keychat_uniffi::normalize_to_hex(args.trim().to_string()).unwrap_or_else(|_| args.trim().to_string());
            match gid {
                None => app.notify("Select a group room first".into()),
                Some(gid) => match app.client.remove_group_member(gid, pk).await {
                    Ok(_) => app.push_output("Member removed".into(), Color::Yellow),
                    Err(e) => app.notify(format!("Kick failed: {e}")),
                },
            }
        }
        "/debug" => match app.client.debug_state_summary().await {
            Ok(s) => app.push_output(s, Color::White),
            Err(e) => app.notify(format!("Error: {e}")),
        },
        "/theme" => {
            let new_theme = match args {
                "light" => { save_theme_setting(&app.client, "light").await; Theme::light() }
                "dark" | "" => { save_theme_setting(&app.client, "dark").await; Theme::dark() }
                _ => { app.notify("Usage: /theme dark|light".into()); return; }
            };
            app.theme = new_theme;
            app.push_output(format!("Theme set to: {}", if args.is_empty() { "dark" } else { args }), Color::Green);
        }
        "/help" => app.show_help = true,
        "/quit" | "/exit" => app.should_quit = true,
        _ => app.notify(format!("Unknown command: {cmd}. Press F1 for help.")),
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
            tracing::info!("Message received: room={}, sender={}, len={}", &room_id[..16.min(room_id.len())], &sender_pubkey[..16.min(sender_pubkey.len())], content.as_deref().map_or(0, |c| c.len()));
            refresh_rooms(app).await;
            if app.selected_room_id().as_deref() == Some(room_id.as_str()) {
                load_messages(app, room_id).await;
            }
            let sender = app.contact_name(sender_pubkey);
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
            tracing::info!("Friend request received: name={sender_name}, pubkey={}, request_id={request_id}", &sender_pubkey[..16.min(sender_pubkey.len())]);
            let is_owner = app.owner_pubkey.as_deref() == Some(sender_pubkey.as_str());
            let should_auto_approve = app.owner_pubkey.is_none() || is_owner;
            if should_auto_approve {
                let reason = if is_owner { "owner request" } else { "first friend → owner" };
                tracing::info!("Auto-approving ({reason}): {sender_name}");
                app.push_output(format!("Auto-approving {sender_name}..."), Color::Green);

                // Get display name for accept response
                let my_name = if let Ok(ids) = app.client.get_identities().await {
                    ids.first().map(|i| i.name.clone()).filter(|n| !n.is_empty())
                        .unwrap_or_else(|| "CLI User".to_string())
                } else {
                    "CLI User".to_string()
                };

                // Retry up to 3 times — relay may still be connecting
                let mut accepted = false;
                for attempt in 0..3 {
                    match app.client.accept_friend_request(request_id.clone(), my_name.clone()).await {
                        Ok(contact) => {
                            if app.owner_pubkey.is_none() {
                                save_owner(&app.client, sender_pubkey).await;
                                app.owner_pubkey = Some(sender_pubkey.clone());
                                tracing::info!("Owner set: {} ({})", contact.display_name, &sender_pubkey[..16.min(sender_pubkey.len())]);
                                app.push_output(
                                    format!("Owner set: {} ({})", contact.display_name, short_key(sender_pubkey)),
                                    Color::Green,
                                );
                            } else {
                                tracing::info!("Approved owner request: {}", contact.display_name);
                                app.push_output(
                                    format!("Approved: {} (owner)", contact.display_name),
                                    Color::Green,
                                );
                            }
                            app.notify(format!("{} approved", contact.display_name));
                            refresh_contacts(app).await;
                            // Refresh rooms and auto-select the new conversation
                            refresh_rooms(app).await;
                            if let Some(identity) = &app.identity_hex {
                                let new_room_id = format!("{}:{}", sender_pubkey, identity);
                                if let Some(pos) = app.display_rows.iter().position(|r| {
                                    matches!(&r.kind, DisplayRowKind::Room { room_id, .. } if room_id == &new_room_id)
                                }) {
                                    app.room_state.select(Some(pos));
                                    load_messages(app, &new_room_id).await;
                                    app.active_panel = Panel::Input;
                                }
                            }
                            accepted = true;
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("Auto-approve attempt {} failed: {e}", attempt + 1);
                            if attempt < 2 {
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            }
                        }
                    }
                }
                if !accepted {
                    app.push_output(
                        format!("Auto-approve failed. Manual: /accept {request_id}"),
                        Color::Red,
                    );
                }
            } else {
                tracing::info!("Owner exists, queuing for manual approval");
                app.push_output(
                    format!("Friend request from {sender_name}. /accept {request_id}"),
                    Color::Yellow,
                );
                app.notify(format!("Friend request from {sender_name}"));
            }
            refresh_rooms(app).await;
        }
        ClientEvent::FriendRequestAccepted { peer_name, .. } => {
            tracing::info!("Friend request accepted by {peer_name}");
            app.push_output(format!("Friend accepted by {peer_name}"), Color::Green);
            app.notify(format!("{peer_name} accepted your request"));
            refresh_rooms(app).await;
            refresh_contacts(app).await;
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
                format!("Group invite: '{}' from {}", group_name, short_key(inviter_pubkey)),
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
            success,
            message,
            relay_url,
            ..
        } => {
            if !*success {
                app.push_output(format!("Relay NACK: {relay_url} — {message}"), Color::Red);
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
            app.notify(format!("Connection: {:?}", status));
        }
        DataChange::RoomListChanged
        | DataChange::RoomUpdated { .. }
        | DataChange::RoomDeleted { .. } => {
            refresh_rooms(app).await;
        }
        DataChange::MessageAdded { room_id, .. } | DataChange::MessageUpdated { room_id, .. } => {
            if app.selected_room_id().as_deref() == Some(room_id.as_str()) {
                load_messages(app, room_id).await;
            }
        }
        DataChange::ContactUpdated { .. } | DataChange::ContactListChanged => {
            refresh_contacts(app).await;
        }
        DataChange::IdentityListChanged => {}
    }
}

// ─── Data loading ───────────────────────────────────────────

async fn refresh_rooms(app: &mut App) {
    let pubkey = match &app.identity_hex {
        Some(pk) => pk.clone(),
        None => return,
    };
    let rooms = match app.client.get_rooms(pubkey).await {
        Ok(r) => r,
        Err(_) => return,
    };

    let selected_id = app.selected_room_id();

    app.rooms = rooms
        .into_iter()
        .map(|r| {
            let name = r.name.unwrap_or_else(|| short_key(&r.to_main_pubkey));
            RoomEntry {
                id: r.id,
                name,
                room_type: r.room_type,
                status: r.status,
                unread_count: r.unread_count as u32,
                last_message: r.last_message_content,
                last_message_at: r.last_message_at,
                to_main_pubkey: r.to_main_pubkey,
                parent_room_id: r.parent_room_id,
            }
        })
        .collect();

    // Build grouped display
    build_display_rows(app);

    // Restore selection
    if let Some(ref sid) = selected_id {
        if let Some(idx) = app.display_rows.iter().position(|row| {
            matches!(&row.kind, DisplayRowKind::Room { room_id, .. } if room_id == sid)
        }) {
            app.room_state.select(Some(idx));
            return;
        }
    }
    // Default: select first room
    if let Some(idx) = app.display_rows.iter().position(|r| matches!(r.kind, DisplayRowKind::Room { .. })) {
        app.room_state.select(Some(idx));
    } else {
        app.room_state.select(None);
    }
}

fn build_display_rows(app: &mut App) {
    let t = &app.theme;
    let rooms = &app.rooms;

    // Separate: top-level DMs, topics (has parent), signal groups
    let mut top_dms: Vec<&RoomEntry> = Vec::new();
    let mut topics: Vec<&RoomEntry> = Vec::new();
    let mut groups: Vec<&RoomEntry> = Vec::new();

    for r in rooms {
        if r.parent_room_id.is_some() {
            topics.push(r);
        } else {
            match r.room_type {
                RoomType::SignalGroup | RoomType::MlsGroup => groups.push(r),
                RoomType::Dm => top_dms.push(r),
            }
        }
    }

    // Group topics by parent, and also group DMs by to_main_pubkey for agent grouping
    let mut children_map: std::collections::HashMap<String, Vec<&RoomEntry>> =
        std::collections::HashMap::new();
    for topic in &topics {
        if let Some(ref parent_id) = topic.parent_room_id {
            children_map
                .entry(parent_id.clone())
                .or_default()
                .push(topic);
        }
    }

    // Group DMs by to_main_pubkey to detect agent sub-chats (same user, multiple rooms)
    let mut pubkey_rooms: std::collections::HashMap<String, Vec<&RoomEntry>> =
        std::collections::HashMap::new();
    for dm in &top_dms {
        pubkey_rooms
            .entry(dm.to_main_pubkey.clone())
            .or_default()
            .push(dm);
    }

    let mut rows: Vec<DisplayRow> = Vec::new();

    // ── Contacts section ──
    if !top_dms.is_empty() {
        rows.push(DisplayRow {
            kind: DisplayRowKind::SectionHeader("Contacts".into()),
        });

        // Sort by last_message_at desc
        let mut sorted_pubkeys: Vec<(&String, &Vec<&RoomEntry>)> = pubkey_rooms.iter().collect();
        sorted_pubkeys.sort_by(|a, b| {
            let a_time = a.1.iter().filter_map(|r| r.last_message_at).max().unwrap_or(0);
            let b_time = b.1.iter().filter_map(|r| r.last_message_at).max().unwrap_or(0);
            b_time.cmp(&a_time)
        });

        for (_pubkey, dm_rooms) in &sorted_pubkeys {
            // Find the "main" room (no parent, most recent)
            let mut sorted = dm_rooms.to_vec();
            sorted.sort_by(|a, b| {
                b.last_message_at
                    .unwrap_or(0)
                    .cmp(&a.last_message_at.unwrap_or(0))
            });

            let main_room = sorted[0];
            let (icon, icon_color) = room_icon(main_room, t);

            rows.push(DisplayRow {
                kind: DisplayRowKind::Room {
                    room_id: main_room.id.clone(),
                    depth: 0,
                    icon: icon.to_string(),
                    icon_color,
                    type_tag: String::new(),
                    name: main_room.name.clone(),
                    unread: main_room.unread_count,
                    preview: main_room.last_message.clone(),
                },
            });

            // Children: topics under this room
            if let Some(children) = children_map.get(&main_room.id) {
                for child in children {
                    let (ci, cc) = room_icon(child, t);
                    rows.push(DisplayRow {
                        kind: DisplayRowKind::Room {
                            room_id: child.id.clone(),
                            depth: 1,
                            icon: ci.to_string(),
                            icon_color: cc,
                            type_tag: String::new(),
                            name: child.name.clone(),
                            unread: child.unread_count,
                            preview: None,
                        },
                    });
                }
            }

            // Additional rooms with same pubkey (agent sub-chats)
            if sorted.len() > 1 {
                for extra in &sorted[1..] {
                    let (ei, ec) = room_icon(extra, t);
                    rows.push(DisplayRow {
                        kind: DisplayRowKind::Room {
                            room_id: extra.id.clone(),
                            depth: 1,
                            icon: ei.to_string(),
                            icon_color: ec,
                            type_tag: String::new(),
                            name: extra.name.clone(),
                            unread: extra.unread_count,
                            preview: None,
                        },
                    });
                }
            }
        }
    }

    // ── Groups section ──
    if !groups.is_empty() {
        rows.push(DisplayRow {
            kind: DisplayRowKind::SectionHeader("Groups".into()),
        });

        let mut sorted_groups = groups.to_vec();
        sorted_groups.sort_by(|a, b| {
            b.last_message_at
                .unwrap_or(0)
                .cmp(&a.last_message_at.unwrap_or(0))
        });

        for g in sorted_groups {
            let (icon, icon_color) = room_icon(g, t);
            let tag = match g.room_type {
                RoomType::SignalGroup => "SG",
                RoomType::MlsGroup => "MLS",
                _ => "",
            };
            rows.push(DisplayRow {
                kind: DisplayRowKind::Room {
                    room_id: g.id.clone(),
                    depth: 0,
                    icon: icon.to_string(),
                    icon_color,
                    type_tag: tag.to_string(),
                    name: g.name.clone(),
                    unread: g.unread_count,
                    preview: g.last_message.clone(),
                },
            });

            // Topics under groups
            if let Some(children) = children_map.get(&g.id) {
                for child in children {
                    let (ci, cc) = room_icon(child, t);
                    rows.push(DisplayRow {
                        kind: DisplayRowKind::Room {
                            room_id: child.id.clone(),
                            depth: 1,
                            icon: ci.to_string(),
                            icon_color: cc,
                            type_tag: String::new(),
                            name: child.name.clone(),
                            unread: child.unread_count,
                            preview: None,
                        },
                    });
                }
            }
        }
    }

    app.display_rows = rows;
}

fn room_icon<'a>(room: &RoomEntry, t: &Theme) -> (&'a str, Color) {
    match room.status {
        RoomStatus::Enabled => ("●", t.success),
        RoomStatus::Requesting => ("◐", t.warning),
        RoomStatus::Approving => ("◑", t.warning),
        RoomStatus::Rejected => ("○", t.error),
    }
}

async fn refresh_relay_status(app: &mut App) {
    if let Ok(statuses) = app.client.get_relay_statuses().await {
        app.total_relays = statuses.len();
        app.connected_relays = statuses.iter().filter(|s| s.status == "Connected").count();
    }
}

async fn refresh_contacts(app: &mut App) {
    let pubkey = match &app.identity_hex {
        Some(pk) => pk.clone(),
        None => return,
    };
    if let Ok(contacts) = app.client.get_contacts(pubkey).await {
        app.contact_names.clear();
        for c in contacts {
            let name = c
                .petname
                .or(c.name)
                .unwrap_or_else(|| short_key(&c.pubkey));
            app.contact_names.insert(c.pubkey, name);
        }
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
                    sender_name: app.contact_names.get(&m.sender_pubkey).cloned(),
                    sender: m.sender_pubkey,
                    content: m.content,
                    is_me: m.is_me_send,
                    status: m.status,
                    timestamp: m.created_at,
                    reply_to_content: m.reply_to_content,
                })
                .collect();
            app.command_output.clear();
            app.messages_scroll = 0;
        }
        Err(e) => app.notify(format!("Load messages failed: {e}")),
    }
}

// ─── Helpers ────────────────────────────────────────────────

use crate::commands::short_key;

fn format_time(ts: u64) -> String {
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| dt.format("%H:%M").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn format_date(ts: u64) -> String {
    let now = Utc::now().date_naive();
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| {
            let d = dt.date_naive();
            if d == now {
                "Today".to_string()
            } else if d == now.pred_opt().unwrap_or(now) {
                "Yesterday".to_string()
            } else {
                d.format("%b %d").to_string()
            }
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

// ─── Settings (DB-backed) ────────────────────────────────────

const SETTING_OWNER: &str = "owner_pubkey";
const SETTING_THEME: &str = "theme";


async fn load_owner(client: &KeychatClient) -> Option<String> {
    client.get_setting(SETTING_OWNER.to_string()).await.ok().flatten()
}

async fn save_owner(client: &KeychatClient, pubkey: &str) {
    if let Err(e) = client.set_setting(SETTING_OWNER.to_string(), pubkey.to_string()).await {
        tracing::warn!("Failed to save owner setting: {e}");
    }
}

async fn load_theme_setting(client: &KeychatClient) -> Theme {
    match client.get_setting(SETTING_THEME.to_string()).await {
        Ok(Some(s)) if s == "light" => Theme::light(),
        _ => Theme::dark(),
    }
}

async fn save_theme_setting(client: &KeychatClient, theme: &str) {
    let _ = client.set_setting(SETTING_THEME.to_string(), theme.to_string()).await;
}

use crate::commands::delete_mnemonic;

// ─── QR code rendering ─────────────────────────────────────

fn render_qr_lines(data: &str) -> Vec<String> {
    use qrcode::{QrCode, EcLevel};

    // Use low ECC for smaller QR (fewer modules)
    let code = match QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L) {
        Ok(c) => c,
        Err(_) => return vec!["(QR generation failed)".to_string()],
    };

    let matrix = code.to_colors();
    let width = code.width();
    let rows: Vec<&[qrcode::Color]> = matrix.chunks(width).collect();
    let mut lines = Vec::new();

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
