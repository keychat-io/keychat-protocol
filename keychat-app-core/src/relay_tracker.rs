//! Relay send tracker — dynamic, incremental relay status updates.
//!
//! Data model:  Message → Event(s) → Relay(s)
//!   - 1:1 message: 1 event → N relays
//!   - Group message: M events (one per member) → N relays each
//!
//! Flow:
//!   1. On send, `track` / `track_group` → returns initial JSON (all relays "pending")
//!   2. Each relay OK → `handle_relay_ok` → returns updated JSON for immediate DB write
//!   3. Timeout → `check_timeouts` → marks remaining "pending" as "timeout"
//!   4. Re-broadcast → call `track` again with same msgid to reset/add event

use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Returned on every status change so the caller can write to DB immediately.
pub struct RelayStatusUpdate {
    pub msgid: String,
    pub room_id: String,
    /// Full relay_status_json for the message (all events, all relays).
    pub relay_status_json: String,
    /// True when every relay in every event has responded (no more "pending").
    pub all_resolved: bool,
    /// True if at least one relay in each event accepted the message.
    pub has_success: bool,
}

#[derive(Clone)]
struct RelayState {
    status: String, // "pending", "success", "failed", "timeout"
    error: Option<String>,
}

struct TrackedEvent {
    msgid: String,
    room_id: String,
    member: Option<String>,
    /// relay_url → state (O(1) lookup by URL)
    relays: HashMap<String, RelayState>,
    /// Insertion order for deterministic JSON output
    relay_order: Vec<String>,
    started_at: Instant,
}

pub struct RelaySendTracker {
    /// event_id → tracked event
    events: HashMap<String, TrackedEvent>,
    /// msgid → [event_ids] (ordering preserved for JSON output)
    msgid_events: HashMap<String, Vec<String>>,
}

impl RelaySendTracker {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
            msgid_events: HashMap::new(),
        }
    }

    /// Track a 1:1 send. Returns initial relay_status_json (all relays "pending").
    pub fn track(
        &mut self,
        event_id: String,
        msgid: String,
        room_id: String,
        relay_urls: Vec<String>,
    ) -> String {
        let relays: HashMap<String, RelayState> = relay_urls
            .iter()
            .map(|url| {
                (
                    url.clone(),
                    RelayState {
                        status: "pending".into(),
                        error: None,
                    },
                )
            })
            .collect();

        self.events.insert(
            event_id.clone(),
            TrackedEvent {
                msgid: msgid.clone(),
                room_id: room_id.clone(),
                member: None,
                relays,
                relay_order: relay_urls,
                started_at: Instant::now(),
            },
        );
        self.msgid_events
            .entry(msgid.clone())
            .or_default()
            .push(event_id);

        self.build_json(&msgid)
    }

    /// Track a group send (multiple events sharing one msgid).
    /// Returns initial relay_status_json.
    pub fn track_group(
        &mut self,
        msgid: String,
        room_id: String,
        members: Vec<(String, String)>, // (event_id, member_name)
        relay_urls: Vec<String>,
    ) -> String {
        for (event_id, member_name) in &members {
            let relays: HashMap<String, RelayState> = relay_urls
                .iter()
                .map(|url| {
                    (
                        url.clone(),
                        RelayState {
                            status: "pending".into(),
                            error: None,
                        },
                    )
                })
                .collect();
            self.events.insert(
                event_id.clone(),
                TrackedEvent {
                    msgid: msgid.clone(),
                    room_id: room_id.clone(),
                    member: Some(member_name.clone()),
                    relays,
                    relay_order: relay_urls.clone(),
                    started_at: Instant::now(),
                },
            );
        }

        let event_ids: Vec<String> = members.into_iter().map(|(eid, _)| eid).collect();
        self.msgid_events.insert(msgid.clone(), event_ids);

        self.build_json(&msgid)
    }

    /// Handle a relay OK response. Returns updated JSON if this event is tracked.
    pub fn handle_relay_ok(
        &mut self,
        event_id: &str,
        relay_url: &str,
        success: bool,
        message: &str,
    ) -> Option<RelayStatusUpdate> {
        let entry = self.events.get_mut(event_id)?;
        let msgid = entry.msgid.clone();

        // O(1) lookup by relay URL
        if let Some(relay) = entry.relays.get_mut(relay_url) {
            if success {
                relay.status = "success".into();
                relay.error = None;
            } else {
                relay.status = "failed".into();
                relay.error = Some(message.to_string());
            }
        }

        Some(self.build_update(&msgid))
    }

    /// Mark remaining "pending" relays as "timeout" for entries older than timeout_secs.
    /// Returns updates for affected messages.
    pub fn check_timeouts(&mut self, timeout_secs: u64) -> Vec<RelayStatusUpdate> {
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let mut affected_msgids = HashSet::new();

        for entry in self.events.values_mut() {
            if entry.started_at.elapsed() >= timeout {
                for relay in entry.relays.values_mut() {
                    if relay.status == "pending" {
                        relay.status = "timeout".into();
                    }
                }
                affected_msgids.insert(entry.msgid.clone());
            }
        }

        affected_msgids
            .into_iter()
            .map(|msgid| self.build_update(&msgid))
            .collect()
    }

    /// Clean up fully resolved messages from memory.
    /// Call periodically to prevent unbounded growth.
    pub fn cleanup_resolved(&mut self) {
        let resolved_msgids: Vec<String> = self
            .msgid_events
            .iter()
            .filter(|(_, eids)| {
                eids.iter().all(|eid| {
                    self.events
                        .get(eid)
                        .map_or(true, |e| e.relays.values().all(|r| r.status != "pending"))
                })
            })
            .map(|(msgid, _)| msgid.clone())
            .collect();

        for msgid in resolved_msgids {
            if let Some(eids) = self.msgid_events.remove(&msgid) {
                for eid in eids {
                    self.events.remove(&eid);
                }
            }
        }
    }

    // ── Internal ──

    fn build_update(&self, msgid: &str) -> RelayStatusUpdate {
        let json = self.build_json(msgid);

        // Check resolution status across all events for this message
        let eids = self.msgid_events.get(msgid);
        let (all_resolved, has_success) = eids
            .map(|eids| {
                let mut all_resolved = true;
                let mut all_events_have_success = true;
                for eid in eids {
                    if let Some(entry) = self.events.get(eid) {
                        let event_has_success =
                            entry.relays.values().any(|r| r.status == "success");
                        let event_resolved = entry.relays.values().all(|r| r.status != "pending");
                        if !event_resolved {
                            all_resolved = false;
                        }
                        if !event_has_success {
                            all_events_have_success = false;
                        }
                    }
                }
                (all_resolved, all_events_have_success)
            })
            .unwrap_or((true, false));

        let room_id = eids
            .and_then(|eids| eids.first())
            .and_then(|eid| self.events.get(eid))
            .map(|e| e.room_id.clone())
            .unwrap_or_default();

        RelayStatusUpdate {
            msgid: msgid.to_string(),
            room_id,
            relay_status_json: json,
            all_resolved,
            has_success,
        }
    }

    fn build_json(&self, msgid: &str) -> String {
        let Some(eids) = self.msgid_events.get(msgid) else {
            return "[]".to_string();
        };

        let mut events_json: Vec<serde_json::Value> = Vec::new();
        for eid in eids {
            let Some(entry) = self.events.get(eid) else {
                continue;
            };

            // Use relay_order for deterministic JSON output
            let relays: Vec<serde_json::Value> = entry
                .relay_order
                .iter()
                .filter_map(|url| {
                    let r = entry.relays.get(url)?;
                    let mut obj = serde_json::json!({
                        "url": url,
                        "status": r.status,
                    });
                    if let Some(ref err) = r.error {
                        obj["error"] = serde_json::Value::String(err.clone());
                    }
                    Some(obj)
                })
                .collect();

            let mut event_obj = serde_json::json!({
                "event_id": eid,
                "relays": relays,
            });
            if let Some(ref member) = entry.member {
                event_obj["member"] = serde_json::Value::String(member.clone());
            }
            events_json.push(event_obj);
        }

        serde_json::to_string(&events_json).unwrap_or_else(|_| "[]".to_string())
    }
}
