use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::nicks::NickStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    Normal,
    RoomSelect,
    AddFriend,
    ConfirmDelete,
    PeerPicker,
}

/// What action to perform after selecting a peer in the picker.
#[derive(Debug, Clone)]
pub enum PeerPickerAction {
    Invite,
    LgInvite,
}

/// State for the peer picker overlay.
#[derive(Debug, Clone)]
pub struct PeerPickerState {
    pub action: PeerPickerAction,
    pub peers: Vec<(String, String)>, // (hex, display_name)
    pub selected: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRoom {
    pub group_pubkey: String,
    #[serde(default)]
    pub group_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub listen_key: Option<String>,
    #[serde(default)]
    pub is_mls: bool,
    pub members: Vec<String>,
    pub is_admin: bool,
    pub unread: usize,
    pub last_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DirectRoom {
    pub peer_hex: String,
    pub display_name: String,
    pub unread: usize,
    pub last_message: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Room {
    Direct(DirectRoom),
    Group(GroupRoom),
}

impl Room {
    pub fn key(&self) -> String {
        match self {
            Room::Direct(room) => format!("dm:{}", room.peer_hex),
            Room::Group(room) => format!("grp:{}", room.storage_id()),
        }
    }

    pub fn title(&self) -> String {
        match self {
            Room::Direct(room) => room.display_name.clone(),
            Room::Group(room) => room.name.clone(),
        }
    }

    pub fn unread(&self) -> usize {
        match self {
            Room::Direct(room) => room.unread,
            Room::Group(room) => room.unread,
        }
    }

    pub fn set_unread(&mut self, unread: usize) {
        match self {
            Room::Direct(room) => room.unread = unread,
            Room::Group(room) => room.unread = unread,
        }
    }

    pub fn bump_unread(&mut self) {
        match self {
            Room::Direct(room) => room.unread += 1,
            Room::Group(room) => room.unread += 1,
        }
    }

    pub fn set_last_message(&mut self, text: String) {
        match self {
            Room::Direct(room) => room.last_message = Some(text),
            Room::Group(room) => room.last_message = Some(text),
        }
    }

    pub fn is_direct_peer(&self, peer_hex: &str) -> bool {
        matches!(self, Room::Direct(room) if room.peer_hex == peer_hex)
    }

    pub fn is_group_pubkey(&self, group_pubkey: &str) -> bool {
        matches!(self, Room::Group(room) if room.group_pubkey == group_pubkey)
    }

    pub fn is_group_id(&self, group_id: &str) -> bool {
        matches!(self, Room::Group(room) if room.matches_id(group_id))
    }
}

impl GroupRoom {
    pub fn storage_id(&self) -> &str {
        if self.is_mls {
            self.group_id
                .as_deref()
                .unwrap_or(self.group_pubkey.as_str())
        } else {
            self.group_pubkey.as_str()
        }
    }

    pub fn matches_id(&self, id: &str) -> bool {
        self.group_pubkey == id || self.group_id.as_deref() == Some(id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatMessageKind {
    User,
    System,
}

#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub sender: String,
    pub text: String,
    pub timestamp: String,
    pub is_self: bool,
    pub kind: ChatMessageKind,
}

pub struct App {
    pub rooms: Vec<Room>,
    pub selected_room: usize,
    pub messages: HashMap<String, Vec<ChatMessage>>,
    pub input: String,
    pub input_cursor: usize,
    pub should_quit: bool,
    pub nicks: NickStore,
    pub mode: AppMode,
    pub self_name: String,
    pub self_npub: String,
    pub self_pubkey_hex: String,
    pub add_friend_input: String,
    pub add_friend_cursor: usize,
    pub status_message: Option<String>,
    pub scroll_offset: usize,
    pub relay_count: usize,
    pub groups_path: Option<std::path::PathBuf>,
    pub peer_picker: Option<PeerPickerState>,
}

impl App {
    pub fn new(
        nicks: NickStore,
        self_name: String,
        self_npub: String,
        self_pubkey_hex: String,
        relay_count: usize,
        peers: Vec<String>,
        groups: Vec<GroupRoom>,
    ) -> Self {
        let mut app = Self {
            rooms: Vec::new(),
            selected_room: 0,
            messages: HashMap::new(),
            input: String::new(),
            input_cursor: 0,
            should_quit: false,
            nicks,
            mode: AppMode::Normal,
            self_name,
            self_npub,
            self_pubkey_hex,
            add_friend_input: String::new(),
            add_friend_cursor: 0,
            status_message: None,
            scroll_offset: 0,
            relay_count,
            groups_path: None,
            peer_picker: None,
        };

        for peer in peers {
            app.ensure_direct_room(&peer);
        }

        for group in groups {
            app.ensure_group_room(
                &group.group_pubkey,
                &group.name,
                group.members,
                group.is_admin,
            );
        }

        // No special mode for empty rooms — status bar shows /add command

        app
    }

    pub fn switch_mode(&mut self) {
        self.mode = match self.mode {
            AppMode::Normal => AppMode::RoomSelect,
            AppMode::RoomSelect => AppMode::Normal,
            AppMode::AddFriend => AppMode::Normal,
            AppMode::ConfirmDelete => AppMode::RoomSelect,
            AppMode::PeerPicker => AppMode::Normal,
        };
    }

    pub fn copy_npub_to_clipboard(&mut self) {
        let _ = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    let _ = stdin.write_all(self.self_npub.as_bytes());
                }
                child.wait()
            });
        self.status_message = Some("📋 npub copied to clipboard".to_owned());
    }

    pub fn delete_selected_room(&mut self) {
        if self.rooms.is_empty() {
            return;
        }

        let idx = self.selected_room;
        let room = self.rooms.remove(idx);
        match room {
            Room::Direct(room) => {
                self.messages.remove(&format!("dm:{}", room.peer_hex));
                self.nicks.remove(&room.peer_hex);
                let _ = self.nicks.save();
                self.status_message = Some("🗑 Contact removed".to_owned());
            }
            Room::Group(room) => {
                self.messages.remove(&format!("grp:{}", room.storage_id()));
                self.status_message = Some("🗑 Group removed".to_owned());
            }
        }

        if self.selected_room >= self.rooms.len() && !self.rooms.is_empty() {
            self.selected_room = self.rooms.len() - 1;
        }
        self.mode = AppMode::RoomSelect;
    }

    pub fn enter_add_friend(&mut self) {
        self.add_friend_input.clear();
        self.add_friend_cursor = 0;
        self.status_message = None;
        self.mode = AppMode::AddFriend;
    }

    pub fn add_friend_insert_char(&mut self, ch: char) {
        let byte_idx = char_to_byte_idx(&self.add_friend_input, self.add_friend_cursor);
        self.add_friend_input.insert(byte_idx, ch);
        self.add_friend_cursor += 1;
    }

    pub fn add_friend_backspace(&mut self) {
        if self.add_friend_cursor == 0 {
            return;
        }
        let byte_idx = char_to_byte_idx(&self.add_friend_input, self.add_friend_cursor);
        let prev_idx = char_to_byte_idx(&self.add_friend_input, self.add_friend_cursor - 1);
        self.add_friend_input.replace_range(prev_idx..byte_idx, "");
        self.add_friend_cursor -= 1;
    }

    pub fn take_add_friend_input(&mut self) -> String {
        self.add_friend_cursor = 0;
        std::mem::take(&mut self.add_friend_input)
    }

    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    pub fn selected_room_key(&self) -> Option<String> {
        self.rooms.get(self.selected_room).map(Room::key)
    }

    pub fn selected_room_peer(&self) -> Option<&str> {
        match self.rooms.get(self.selected_room) {
            Some(Room::Direct(room)) => Some(room.peer_hex.as_str()),
            _ => None,
        }
    }

    pub fn selected_room_group(&self) -> Option<&GroupRoom> {
        match self.rooms.get(self.selected_room) {
            Some(Room::Group(room)) => Some(room),
            _ => None,
        }
    }

    pub fn select_group_room(&mut self, group_pubkey: &str) {
        if let Some(idx) = self.rooms.iter().position(|r| r.is_group_id(group_pubkey)) {
            self.selected_room = idx;
        }
    }

    pub fn current_room_name(&self) -> String {
        self.rooms
            .get(self.selected_room)
            .map(Room::title)
            .unwrap_or_else(|| "No room".to_owned())
    }

    pub fn ensure_direct_room(&mut self, peer_hex: &str) {
        if self.rooms.iter().any(|r| r.is_direct_peer(peer_hex)) {
            return;
        }

        self.rooms.push(Room::Direct(DirectRoom {
            peer_hex: peer_hex.to_owned(),
            display_name: self.nicks.display(peer_hex),
            unread: 0,
            last_message: None,
        }));

        if self.rooms.len() == 1 {
            self.selected_room = 0;
        }
    }

    pub fn ensure_group_room(
        &mut self,
        group_pubkey: &str,
        name: &str,
        members: Vec<String>,
        is_admin: bool,
    ) {
        if let Some(Room::Group(room)) = self.rooms.iter_mut().find(|r| r.is_group_id(group_pubkey))
        {
            room.name = name.to_owned();
            room.members = members;
            room.is_admin = is_admin;
            room.is_mls = false;
            room.group_id = None;
            room.listen_key = None;
            return;
        }

        self.rooms.push(Room::Group(GroupRoom {
            group_pubkey: group_pubkey.to_owned(),
            group_id: None,
            name: name.to_owned(),
            listen_key: None,
            is_mls: false,
            members,
            is_admin,
            unread: 0,
            last_message: None,
        }));

        if self.rooms.len() == 1 {
            self.selected_room = 0;
        }
        self.save_groups_now();
    }

    pub fn ensure_mls_group_room(
        &mut self,
        group_id: &str,
        name: &str,
        listen_key: &str,
        members: Vec<String>,
        is_admin: bool,
    ) {
        if let Some(Room::Group(room)) = self.rooms.iter_mut().find(|r| r.is_group_id(group_id)) {
            room.group_pubkey = group_id.to_owned();
            room.group_id = Some(group_id.to_owned());
            room.name = name.to_owned();
            room.listen_key = Some(listen_key.to_owned());
            room.members = members;
            room.is_admin = is_admin;
            room.is_mls = true;
            return;
        }

        self.rooms.push(Room::Group(GroupRoom {
            group_pubkey: group_id.to_owned(),
            group_id: Some(group_id.to_owned()),
            name: name.to_owned(),
            listen_key: Some(listen_key.to_owned()),
            is_mls: true,
            members,
            is_admin,
            unread: 0,
            last_message: None,
        }));

        if self.rooms.len() == 1 {
            self.selected_room = 0;
        }
        self.save_groups_now();
    }

    pub fn remove_group_room(&mut self, group_pubkey: &str) -> bool {
        let Some(idx) = self.rooms.iter().position(|r| r.is_group_id(group_pubkey)) else {
            return false;
        };

        let removed = self.rooms.remove(idx);
        if let Room::Group(room) = removed {
            self.messages.remove(&format!("grp:{}", room.storage_id()));
        }

        if self.selected_room >= self.rooms.len() && !self.rooms.is_empty() {
            self.selected_room = self.rooms.len() - 1;
        }
        self.save_groups_now();
        true
    }

    pub fn update_room_name(&mut self, peer_hex: &str) {
        if let Some(Room::Direct(room)) = self
            .rooms
            .iter_mut()
            .find(|r| r.is_direct_peer(peer_hex))
        {
            room.display_name = self.nicks.display(peer_hex);
        }
    }

    pub fn update_group_name(&mut self, group_pubkey: &str, new_name: &str) {
        if let Some(Room::Group(room)) = self.rooms.iter_mut().find(|r| r.is_group_id(group_pubkey))
        {
            room.name = new_name.to_owned();
        }
    }

    pub fn add_group_member(&mut self, group_pubkey: &str, member_pubkey: &str) {
        if let Some(Room::Group(room)) = self.rooms.iter_mut().find(|r| r.is_group_id(group_pubkey))
        {
            if !room.members.iter().any(|m| m == member_pubkey) {
                room.members.push(member_pubkey.to_owned());
            }
        }
        self.save_groups_now();
    }

    pub fn remove_group_member(&mut self, group_pubkey: &str, member_pubkey: &str) {
        if let Some(Room::Group(room)) = self.rooms.iter_mut().find(|r| r.is_group_id(group_pubkey))
        {
            room.members.retain(|m| m != member_pubkey);
        }
        self.save_groups_now();
    }

    pub fn set_group_members(&mut self, group_pubkey: &str, members: Vec<String>) {
        if let Some(Room::Group(room)) = self.rooms.iter_mut().find(|r| r.is_group_id(group_pubkey))
        {
            room.members = members;
        }
    }

    pub fn set_group_admin(&mut self, group_pubkey: &str, is_admin: bool) {
        if let Some(Room::Group(room)) = self.rooms.iter_mut().find(|r| r.is_group_id(group_pubkey))
        {
            room.is_admin = is_admin;
        }
    }

    pub fn set_group_listen_key(&mut self, group_pubkey: &str, listen_key: &str) {
        if let Some(Room::Group(room)) = self.rooms.iter_mut().find(|r| r.is_group_id(group_pubkey))
        {
            room.listen_key = Some(listen_key.to_owned());
        }
    }

    pub fn get_group_room(&self, group_pubkey: &str) -> Option<&GroupRoom> {
        match self.rooms.iter().find(|r| r.is_group_id(group_pubkey)) {
            Some(Room::Group(room)) => Some(room),
            _ => None,
        }
    }

    /// Open peer picker for a given action, excluding members already in the current group.
    pub fn open_peer_picker(&mut self, action: PeerPickerAction) {
        let exclude: Vec<String> = if let Some(Room::Group(group)) = self.rooms.get(self.selected_room) {
            group.members.clone()
        } else {
            vec![]
        };

        let peers: Vec<(String, String)> = self
            .rooms
            .iter()
            .filter_map(|r| match r {
                Room::Direct(d) => {
                    if exclude.contains(&d.peer_hex) {
                        None
                    } else {
                        Some((d.peer_hex.clone(), self.nicks.display(&d.peer_hex)))
                    }
                }
                _ => None,
            })
            .collect();

        if peers.is_empty() {
            self.status_message = Some("❌ No friends available to invite".to_owned());
            return;
        }

        self.peer_picker = Some(PeerPickerState {
            action,
            peers,
            selected: 0,
        });
        self.mode = AppMode::PeerPicker;
    }

    /// Persist groups to disk immediately (crash-safe)
    pub fn save_groups_now(&self) {
        if let Some(path) = &self.groups_path {
            let groups = self.groups_snapshot();
            let json = serde_json::to_string_pretty(&groups).unwrap_or_default();
            let _ = std::fs::write(path, json);
        }
    }

    pub fn groups_snapshot(&self) -> Vec<GroupRoom> {
        self.rooms
            .iter()
            .filter_map(|r| match r {
                Room::Group(group) => Some(group.clone()),
                Room::Direct(_) => None,
            })
            .collect()
    }

    pub fn select_next(&mut self) {
        if self.rooms.is_empty() {
            return;
        }
        self.selected_room = (self.selected_room + 1) % self.rooms.len();
    }

    pub fn select_prev(&mut self) {
        if self.rooms.is_empty() {
            return;
        }
        self.selected_room = if self.selected_room == 0 {
            self.rooms.len() - 1
        } else {
            self.selected_room - 1
        };
    }

    pub fn open_selected_room(&mut self) {
        if let Some(room) = self.rooms.get_mut(self.selected_room) {
            room.set_unread(0);
        }
        self.scroll_offset = 0;
        self.mode = AppMode::Normal;
    }

    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_add(3);
    }

    pub fn scroll_down(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(3);
    }

    pub fn messages_for_selected(&self) -> &[ChatMessage] {
        if let Some(key) = self.selected_room_key() {
            self.messages.get(&key).map(Vec::as_slice).unwrap_or(&[])
        } else {
            &[]
        }
    }

    pub fn add_message(&mut self, room_key: &str, message: ChatMessage, bump_unread: bool) {
        let is_current_room = self
            .selected_room_key()
            .map(|key| key == room_key)
            .unwrap_or(false);

        if let Some(room) = self.rooms.iter_mut().find(|r| r.key() == room_key) {
            room.set_last_message(message.text.clone());

            if bump_unread && !is_current_room {
                room.bump_unread();
            }
        }

        self.messages
            .entry(room_key.to_owned())
            .or_default()
            .push(message);

        if is_current_room {
            self.scroll_offset = 0;
        }
    }

    pub fn add_direct_message(&mut self, peer_hex: &str, message: ChatMessage, bump_unread: bool) {
        self.ensure_direct_room(peer_hex);
        self.add_message(&format!("dm:{}", peer_hex), message, bump_unread);
    }

    pub fn add_system_message_to_current(&mut self, text: String) {
        if let Some(key) = self.selected_room_key() {
            self.add_message(
                &key,
                ChatMessage {
                    sender: String::new(),
                    text,
                    timestamp: String::new(),
                    is_self: false,
                    kind: ChatMessageKind::System,
                },
                false,
            );
        }
    }

    pub fn add_group_message(
        &mut self,
        group_pubkey: &str,
        fallback_name: &str,
        message: ChatMessage,
        bump_unread: bool,
    ) {
        if self.get_group_room(group_pubkey).is_none() {
            self.ensure_group_room(
                group_pubkey,
                fallback_name,
                vec![self.self_pubkey_hex.clone()],
                false,
            );
        }
        let key = self
            .get_group_room(group_pubkey)
            .map(|room| format!("grp:{}", room.storage_id()))
            .unwrap_or_else(|| format!("grp:{group_pubkey}"));
        self.add_message(&key, message, bump_unread);
    }

    pub fn insert_char(&mut self, ch: char) {
        let byte_idx = char_to_byte_idx(&self.input, self.input_cursor);
        self.input.insert(byte_idx, ch);
        self.input_cursor += 1;
    }

    pub fn backspace(&mut self) {
        if self.input_cursor == 0 {
            return;
        }

        let byte_idx = char_to_byte_idx(&self.input, self.input_cursor);
        let prev_idx = char_to_byte_idx(&self.input, self.input_cursor - 1);
        self.input.replace_range(prev_idx..byte_idx, "");
        self.input_cursor -= 1;
    }

    pub fn move_cursor_left(&mut self) {
        if self.input_cursor > 0 {
            self.input_cursor -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        let len = self.input.chars().count();
        if self.input_cursor < len {
            self.input_cursor += 1;
        }
    }

    pub fn take_input(&mut self) -> String {
        self.input_cursor = 0;
        std::mem::take(&mut self.input)
    }
}

fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(idx, _)| idx)
        .unwrap_or(s.len())
}
