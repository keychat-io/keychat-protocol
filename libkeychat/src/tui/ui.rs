use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use ratatui::layout::Rect;
use ratatui::widgets::Clear;

use super::app::{App, AppMode, ChatMessageKind, PeerPickerAction, Room};

pub fn render(frame: &mut Frame<'_>, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(5)])
        .split(frame.area());

    let npub_short = if app.self_npub.len() > 20 {
        format!("{}…", &app.self_npub[..20])
    } else {
        app.self_npub.clone()
    };
    let top_bar = Line::from(vec![
        Span::styled(
            format!(" 🔑 {} ", npub_short),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("| "),
        Span::styled(
            format!("📡 {} relays ", app.relay_count),
            Style::default().fg(Color::Green),
        ),
        Span::raw("| "),
        Span::styled(
            format!("{} rooms", app.rooms.len()),
            Style::default().fg(Color::White),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(top_bar).style(Style::default().bg(Color::DarkGray)),
        outer[0],
    );

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(22), Constraint::Percentage(78)])
        .split(outer[1]);

    render_rooms(frame, app, chunks[0]);
    render_chat(frame, app, chunks[1]);
}

fn render_rooms(frame: &mut Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let room_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if matches!(app.mode, AppMode::AddFriend) {
            vec![Constraint::Min(3), Constraint::Length(3)]
        } else {
            vec![Constraint::Min(3), Constraint::Length(1)]
        })
        .split(area);

    // Categorize rooms
    let mut directs: Vec<(usize, &Room)> = Vec::new();
    let mut small_groups: Vec<(usize, &Room)> = Vec::new();
    let mut mls_groups: Vec<(usize, &Room)> = Vec::new();
    for (i, room) in app.rooms.iter().enumerate() {
        match room {
            Room::Direct(_) => directs.push((i, room)),
            Room::Group(g) if g.is_mls => mls_groups.push((i, room)),
            Room::Group(_) => small_groups.push((i, room)),
        }
    }

    let mut room_items: Vec<ListItem<'_>> = Vec::new();
    // visual_index -> real room index mapping
    let mut index_map: Vec<Option<usize>> = Vec::new();

    // -- Contacts section --
    if !directs.is_empty() {
        room_items.push(ListItem::new(Line::from(Span::styled(
            "── DM ──",
            Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
        ))));
        index_map.push(None); // section header, not selectable

        for (real_idx, room) in &directs {
            let mut spans = vec![Span::raw(format!("  {}", room.title()))];
            if room.unread() > 0 {
                spans.push(Span::styled(
                    format!(" [{}]", room.unread()),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ));
            }
            room_items.push(ListItem::new(Line::from(spans)));
            index_map.push(Some(*real_idx));
        }
    }

    // -- Small Groups section --
    if !small_groups.is_empty() {
        room_items.push(ListItem::new(Line::from(Span::styled(
            "── Small Group ──",
            Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
        ))));
        index_map.push(None);

        for (real_idx, room) in &small_groups {
            let member_count = if let Room::Group(g) = room { g.members.len() } else { 0 };
            let mut spans = vec![Span::raw(format!("  {} ({})", room.title(), member_count))];
            if room.unread() > 0 {
                spans.push(Span::styled(
                    format!(" [{}]", room.unread()),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ));
            }
            room_items.push(ListItem::new(Line::from(spans)));
            index_map.push(Some(*real_idx));
        }
    }

    // -- MLS Groups section --
    if !mls_groups.is_empty() {
        room_items.push(ListItem::new(Line::from(Span::styled(
            "── Large Group ──",
            Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
        ))));
        index_map.push(None);

        for (real_idx, room) in &mls_groups {
            let member_count = if let Room::Group(g) = room { g.members.len() } else { 0 };
            let mut spans = vec![Span::raw(format!("  {} ({})", room.title(), member_count))];
            if room.unread() > 0 {
                spans.push(Span::styled(
                    format!(" [{}]", room.unread()),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ));
            }
            room_items.push(ListItem::new(Line::from(spans)));
            index_map.push(Some(*real_idx));
        }
    }

    // No "+ Add Friend" button — use /add command instead

    // Find the visual index for the currently selected room
    let visual_selected = index_map
        .iter()
        .position(|idx| *idx == Some(app.selected_room))
        .unwrap_or(0);

    let title = if matches!(app.mode, AppMode::RoomSelect) {
        "Rooms [a: add]"
    } else {
        "Rooms"
    };

    let list = List::new(room_items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("●");

    let mut state = ratatui::widgets::ListState::default();
    if app.room_count() > 0 {
        state.select(Some(visual_selected));
    }
    frame.render_stateful_widget(list, room_chunks[0], &mut state);

    if matches!(app.mode, AppMode::AddFriend) {
        let input = Paragraph::new(format!("> {}", app.add_friend_input))
            .block(Block::default().borders(Borders::ALL).title("npub or hex"))
            .style(Style::default().fg(Color::Yellow));
        frame.render_widget(input, room_chunks[1]);

        let cursor_x = room_chunks[1].x + 3 + app.add_friend_cursor as u16;
        let cursor_y = room_chunks[1].y + 1;
        frame.set_cursor_position((cursor_x, cursor_y));
    } else if let Some(status) = &app.status_message {
        let color = if status.starts_with('✅') || status.starts_with('ℹ') {
            Color::Green
        } else {
            Color::Red
        };
        frame.render_widget(
            Paragraph::new(status.as_str()).style(Style::default().fg(color)),
            room_chunks[1],
        );
    }
}

fn render_chat(frame: &mut Frame<'_>, app: &App, area: ratatui::layout::Rect) {
    let chat_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    let title = format!("Chat: {}", app.current_room_name());
    let messages_block = Block::default().title(title).borders(Borders::ALL);

    let message_lines: Vec<Line<'_>> = app
        .messages_for_selected()
        .iter()
        .map(|msg| {
            let header_color = match msg.kind {
                ChatMessageKind::System => Color::Yellow,
                ChatMessageKind::User if msg.is_self => Color::Green,
                ChatMessageKind::User => Color::Cyan,
            };
            let text_style = match msg.kind {
                ChatMessageKind::System => Style::default().fg(Color::LightYellow),
                ChatMessageKind::User => Style::default(),
            };
            Line::from(vec![
                Span::styled(
                    format!("[{}] {}: ", msg.timestamp, msg.sender),
                    Style::default()
                        .fg(header_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(msg.text.clone(), text_style),
            ])
        })
        .collect();

    let visible_height = chat_chunks[0].height.saturating_sub(2) as usize;
    let auto_scroll = message_lines.len().saturating_sub(visible_height);
    let scroll = auto_scroll.saturating_sub(app.scroll_offset) as u16;
    let messages = Paragraph::new(message_lines)
        .block(messages_block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    frame.render_widget(messages, chat_chunks[0]);

    let input = Paragraph::new(format!("> {}", app.input))
        .block(Block::default().borders(Borders::ALL).title("Input"));
    frame.render_widget(input, chat_chunks[1]);

    let status = match app.mode {
        AppMode::RoomSelect => {
            "↑↓ navigate  Enter open  a add friend  d delete  y copy npub  Tab chat  Ctrl+Q quit"
        }
        AppMode::AddFriend => "Paste npub → Enter to send  Esc cancel  Ctrl+Q quit",
        AppMode::ConfirmDelete => {
            "Delete this contact? y confirm  any key cancel"
        }
        AppMode::PeerPicker => "↑↓ select  Enter invite  Esc cancel",
        AppMode::Normal => {
            match app.rooms.get(app.selected_room) {
                Some(Room::Direct(_)) => {
                    "Enter send  /add <npub>  /file <path>  Tab rooms  PgUp/Dn scroll  /help  Ctrl+Q quit"
                }
                Some(Room::Group(g)) if g.is_mls => {
                    "Enter send  /lg-invite /lg-members /lg-leave  Tab rooms  /help  Ctrl+Q quit"
                }
                Some(Room::Group(_)) => {
                    "Enter send  /invite /members /rename /kick /leave  Tab rooms  /help  Ctrl+Q quit"
                }
                None => {
                    "/add <npub>  /add small group <name>  /add large group <name>  /help  Ctrl+Q quit"
                }
            }
        }
    };
    frame.render_widget(
        Paragraph::new(status).style(Style::default().fg(Color::White).bg(Color::DarkGray)),
        chat_chunks[2],
    );

    if matches!(app.mode, AppMode::Normal) {
        let cursor_x = chat_chunks[1].x + 3 + app.input_cursor as u16;
        let cursor_y = chat_chunks[1].y + 1;
        frame.set_cursor_position((cursor_x, cursor_y));
    }

    // Peer picker overlay
    if let (AppMode::PeerPicker, Some(picker)) = (&app.mode, &app.peer_picker) {
        let area = frame.area();
        let title = match picker.action {
            PeerPickerAction::Invite => " Select friend to invite (↑↓ Enter, Esc cancel) ",
            PeerPickerAction::LgInvite => " Select friend to invite (↑↓ Enter, Esc cancel) ",
        };
        let height = (picker.peers.len() as u16 + 2).min(area.height.saturating_sub(4));
        let width = 50u16.min(area.width.saturating_sub(4));
        let x = (area.width.saturating_sub(width)) / 2;
        let y = (area.height.saturating_sub(height)) / 2;
        let popup_area = Rect::new(x, y, width, height);

        frame.render_widget(Clear, popup_area);

        let items: Vec<ListItem> = picker
            .peers
            .iter()
            .enumerate()
            .map(|(i, (_hex, name))| {
                let style = if i == picker.selected {
                    Style::default().fg(Color::Black).bg(Color::White)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Line::from(Span::styled(format!("  {}  ", name), style)))
            })
            .collect();

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .style(Style::default().bg(Color::DarkGray)),
        );
        frame.render_widget(list, popup_area);
    }
}
