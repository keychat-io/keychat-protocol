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

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(n: u32) -> String {
        format!("wss://relay{n}.example.com")
    }

    // ── track + build_json ──────────────────────────────────────────

    #[test]
    fn track_produces_all_pending() {
        let mut t = RelaySendTracker::new();
        let json = t.track(
            "evt1".into(),
            "msg1".into(),
            "room1".into(),
            vec![relay(1), relay(2)],
        );
        let v: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(v.len(), 1);
        let relays = v[0]["relays"].as_array().unwrap();
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0]["status"], "pending");
        assert_eq!(relays[1]["status"], "pending");
        assert_eq!(relays[0]["url"], relay(1));
        assert_eq!(relays[1]["url"], relay(2));
    }

    #[test]
    fn track_preserves_relay_order() {
        let mut t = RelaySendTracker::new();
        let urls = vec![relay(3), relay(1), relay(2)];
        let json = t.track("e".into(), "m".into(), "r".into(), urls.clone());
        let v: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        let out_urls: Vec<String> = v[0]["relays"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["url"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(out_urls, urls);
    }

    // ── handle_relay_ok ─────────────────────────────────────────────

    #[test]
    fn relay_ok_success_updates_status() {
        let mut t = RelaySendTracker::new();
        t.track("evt1".into(), "msg1".into(), "room1".into(), vec![relay(1)]);

        let u = t.handle_relay_ok("evt1", &relay(1), true, "").unwrap();
        assert_eq!(u.msgid, "msg1");
        assert_eq!(u.room_id, "room1");
        assert!(u.all_resolved);
        assert!(u.has_success);

        let v: Vec<serde_json::Value> = serde_json::from_str(&u.relay_status_json).unwrap();
        assert_eq!(v[0]["relays"][0]["status"], "success");
    }

    #[test]
    fn relay_ok_failure_updates_status_and_error() {
        let mut t = RelaySendTracker::new();
        t.track("evt1".into(), "msg1".into(), "room1".into(), vec![relay(1)]);

        let u = t
            .handle_relay_ok("evt1", &relay(1), false, "rate-limited")
            .unwrap();
        assert!(u.all_resolved);
        assert!(!u.has_success);

        let v: Vec<serde_json::Value> = serde_json::from_str(&u.relay_status_json).unwrap();
        assert_eq!(v[0]["relays"][0]["status"], "failed");
        assert_eq!(v[0]["relays"][0]["error"], "rate-limited");
    }

    #[test]
    fn partial_resolution_not_all_resolved() {
        let mut t = RelaySendTracker::new();
        t.track(
            "evt1".into(),
            "msg1".into(),
            "room1".into(),
            vec![relay(1), relay(2)],
        );

        let u = t.handle_relay_ok("evt1", &relay(1), true, "").unwrap();
        assert!(!u.all_resolved, "one relay still pending");
        assert!(u.has_success);

        let u2 = t.handle_relay_ok("evt1", &relay(2), true, "").unwrap();
        assert!(u2.all_resolved);
        assert!(u2.has_success);
    }

    #[test]
    fn unknown_event_returns_none() {
        let mut t = RelaySendTracker::new();
        assert!(t.handle_relay_ok("unknown", &relay(1), true, "").is_none());
    }

    #[test]
    fn unknown_relay_url_is_ignored() {
        let mut t = RelaySendTracker::new();
        t.track("evt1".into(), "msg1".into(), "room1".into(), vec![relay(1)]);

        let u = t.handle_relay_ok("evt1", &relay(99), true, "").unwrap();
        // The unknown relay is silently ignored; relay(1) still pending
        assert!(!u.all_resolved);
    }

    // ── mixed success/failure ───────────────────────────────────────

    #[test]
    fn mixed_success_and_failure() {
        let mut t = RelaySendTracker::new();
        t.track(
            "evt1".into(),
            "msg1".into(),
            "room1".into(),
            vec![relay(1), relay(2), relay(3)],
        );

        t.handle_relay_ok("evt1", &relay(1), true, "");
        t.handle_relay_ok("evt1", &relay(2), false, "blocked");
        let u = t.handle_relay_ok("evt1", &relay(3), false, "err").unwrap();

        assert!(u.all_resolved);
        assert!(u.has_success, "at least one relay succeeded");

        let v: Vec<serde_json::Value> = serde_json::from_str(&u.relay_status_json).unwrap();
        let statuses: Vec<&str> = v[0]["relays"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["status"].as_str().unwrap())
            .collect();
        assert_eq!(statuses, vec!["success", "failed", "failed"]);
    }

    #[test]
    fn all_relays_fail() {
        let mut t = RelaySendTracker::new();
        t.track(
            "evt1".into(),
            "msg1".into(),
            "room1".into(),
            vec![relay(1), relay(2)],
        );

        t.handle_relay_ok("evt1", &relay(1), false, "err1");
        let u = t.handle_relay_ok("evt1", &relay(2), false, "err2").unwrap();

        assert!(u.all_resolved);
        assert!(!u.has_success);
    }

    // ── check_timeouts ──────────────────────────────────────────────

    #[test]
    fn timeout_marks_pending_relays() {
        let mut t = RelaySendTracker::new();
        t.track(
            "evt1".into(),
            "msg1".into(),
            "room1".into(),
            vec![relay(1), relay(2)],
        );

        // Respond to relay(1) only
        t.handle_relay_ok("evt1", &relay(1), true, "");

        // Force entry to look old
        t.events.get_mut("evt1").unwrap().started_at =
            std::time::Instant::now() - std::time::Duration::from_secs(10);

        let updates = t.check_timeouts(5);
        assert_eq!(updates.len(), 1);
        let u = &updates[0];
        assert!(u.all_resolved);
        assert!(u.has_success, "relay(1) succeeded before timeout");

        let v: Vec<serde_json::Value> = serde_json::from_str(&u.relay_status_json).unwrap();
        let statuses: Vec<&str> = v[0]["relays"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["status"].as_str().unwrap())
            .collect();
        assert_eq!(statuses, vec!["success", "timeout"]);
    }

    #[test]
    fn timeout_does_not_affect_fresh_entries() {
        let mut t = RelaySendTracker::new();
        t.track("evt1".into(), "msg1".into(), "room1".into(), vec![relay(1)]);

        // Entry is fresh — timeout(5) should not affect it
        let updates = t.check_timeouts(5);
        assert!(updates.is_empty());
    }

    #[test]
    fn timeout_all_pending_means_no_success() {
        let mut t = RelaySendTracker::new();
        t.track("evt1".into(), "msg1".into(), "room1".into(), vec![relay(1)]);
        t.events.get_mut("evt1").unwrap().started_at =
            std::time::Instant::now() - std::time::Duration::from_secs(10);

        let updates = t.check_timeouts(5);
        assert_eq!(updates.len(), 1);
        assert!(!updates[0].has_success);
        assert!(updates[0].all_resolved);
    }

    // ── track_group ─────────────────────────────────────────────────

    #[test]
    fn track_group_creates_multiple_events() {
        let mut t = RelaySendTracker::new();
        let json = t.track_group(
            "gmsg1".into(),
            "group-room".into(),
            vec![
                ("evt-bob".into(), "Bob".into()),
                ("evt-tom".into(), "Tom".into()),
            ],
            vec![relay(1)],
        );

        let v: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(v.len(), 2, "two events for two members");
        assert_eq!(v[0]["member"], "Bob");
        assert_eq!(v[0]["event_id"], "evt-bob");
        assert_eq!(v[1]["member"], "Tom");
        assert_eq!(v[1]["event_id"], "evt-tom");
    }

    #[test]
    fn group_resolution_requires_all_events() {
        let mut t = RelaySendTracker::new();
        t.track_group(
            "gmsg1".into(),
            "group-room".into(),
            vec![
                ("evt-bob".into(), "Bob".into()),
                ("evt-tom".into(), "Tom".into()),
            ],
            vec![relay(1)],
        );

        // Only Bob's event resolved
        let u = t.handle_relay_ok("evt-bob", &relay(1), true, "").unwrap();
        assert!(!u.all_resolved, "Tom's event still pending");

        // Now Tom's event
        let u2 = t.handle_relay_ok("evt-tom", &relay(1), true, "").unwrap();
        assert!(u2.all_resolved);
        assert!(u2.has_success);
    }

    #[test]
    fn group_has_success_requires_all_events_have_at_least_one_success() {
        let mut t = RelaySendTracker::new();
        t.track_group(
            "gmsg1".into(),
            "group-room".into(),
            vec![
                ("evt-bob".into(), "Bob".into()),
                ("evt-tom".into(), "Tom".into()),
            ],
            vec![relay(1)],
        );

        // Bob succeeds, Tom fails
        t.handle_relay_ok("evt-bob", &relay(1), true, "");
        let u = t
            .handle_relay_ok("evt-tom", &relay(1), false, "err")
            .unwrap();
        assert!(u.all_resolved);
        assert!(!u.has_success, "Tom's event has no success relay");
    }

    #[test]
    fn group_timeout_applies_per_event() {
        let mut t = RelaySendTracker::new();
        t.track_group(
            "gmsg1".into(),
            "group-room".into(),
            vec![
                ("evt-bob".into(), "Bob".into()),
                ("evt-tom".into(), "Tom".into()),
            ],
            vec![relay(1), relay(2)],
        );

        // Bob: relay(1) succeeds, relay(2) pending
        t.handle_relay_ok("evt-bob", &relay(1), true, "");
        // Tom: both pending

        // Age all entries
        let past = std::time::Instant::now() - std::time::Duration::from_secs(10);
        for entry in t.events.values_mut() {
            entry.started_at = past;
        }

        let updates = t.check_timeouts(5);
        assert_eq!(updates.len(), 1); // one msgid
        let u = &updates[0];
        assert!(u.all_resolved);
        // Bob has success (relay1=success, relay2=timeout), Tom has no success (both timeout)
        assert!(!u.has_success, "Tom's event has 0 success relays");
    }

    // ── cleanup_resolved ────────────────────────────────────────────

    #[test]
    fn cleanup_removes_fully_resolved() {
        let mut t = RelaySendTracker::new();
        t.track("evt1".into(), "msg1".into(), "room1".into(), vec![relay(1)]);
        t.track("evt2".into(), "msg2".into(), "room2".into(), vec![relay(1)]);

        // Resolve msg1 only
        t.handle_relay_ok("evt1", &relay(1), true, "");

        t.cleanup_resolved();

        assert!(
            t.events.get("evt1").is_none(),
            "resolved event should be removed"
        );
        assert!(
            t.msgid_events.get("msg1").is_none(),
            "resolved msgid should be removed"
        );
        assert!(
            t.events.get("evt2").is_some(),
            "unresolved event should remain"
        );
        assert!(
            t.msgid_events.get("msg2").is_some(),
            "unresolved msgid should remain"
        );
    }

    #[test]
    fn cleanup_keeps_partially_resolved_group() {
        let mut t = RelaySendTracker::new();
        t.track_group(
            "gmsg1".into(),
            "room".into(),
            vec![("evt-a".into(), "A".into()), ("evt-b".into(), "B".into())],
            vec![relay(1)],
        );

        // Only evt-a resolved
        t.handle_relay_ok("evt-a", &relay(1), true, "");

        t.cleanup_resolved();

        // Both events should still be present (group not fully resolved)
        assert!(t.events.get("evt-a").is_some());
        assert!(t.events.get("evt-b").is_some());
        assert!(t.msgid_events.get("gmsg1").is_some());

        // Now resolve evt-b
        t.handle_relay_ok("evt-b", &relay(1), true, "");
        t.cleanup_resolved();

        assert!(t.events.is_empty());
        assert!(t.msgid_events.is_empty());
    }

    #[test]
    fn cleanup_on_empty_tracker_is_noop() {
        let mut t = RelaySendTracker::new();
        t.cleanup_resolved(); // should not panic
        assert!(t.events.is_empty());
    }

    // ── re-track (re-broadcast) ─────────────────────────────────────

    #[test]
    fn retrack_same_msgid_adds_event() {
        let mut t = RelaySendTracker::new();
        t.track("evt1".into(), "msg1".into(), "room1".into(), vec![relay(1)]);
        t.track("evt2".into(), "msg1".into(), "room1".into(), vec![relay(1)]);

        let eids = t.msgid_events.get("msg1").unwrap();
        assert_eq!(eids.len(), 2);
        assert_eq!(eids, &["evt1", "evt2"]);
    }

    // ── edge: zero relays ───────────────────────────────────────────

    #[test]
    fn track_with_zero_relays() {
        let mut t = RelaySendTracker::new();
        let json = t.track("evt1".into(), "msg1".into(), "room1".into(), vec![]);

        let v: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(v[0]["relays"].as_array().unwrap().len(), 0);

        // Already resolved (no relays to wait for)
        let u = t.build_update("msg1");
        assert!(u.all_resolved);
        // No success either (vacuously true per current logic — depends on impl)
    }

    #[test]
    fn track_group_with_zero_members() {
        let mut t = RelaySendTracker::new();
        let json = t.track_group("gmsg1".into(), "room".into(), vec![], vec![relay(1)]);
        let v: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(v.is_empty());
    }
}
