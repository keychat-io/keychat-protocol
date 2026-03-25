//! Relay send tracker: matches relay OK responses to pending outgoing messages.
//!
//! After a message is published to relays, this tracker records which relays are
//! expected to respond. As relay OK responses arrive, they are matched to the pending
//! entry. Once all relays respond or a timeout occurs, the entry is finalized with
//! a success/failure status and per-relay JSON report.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// A finalized relay tracking entry, ready for DB persistence.
pub struct FinalizedEntry {
    pub event_id: String,
    pub msgid: String,
    pub room_id: String,
    pub relay_status_json: String,
    pub success: bool,
}

struct PendingEntry {
    msgid: String,
    room_id: String,
    expected_relays: HashSet<String>,
    success_relays: HashSet<String>,
    failed_relays: HashMap<String, String>,
    started_at: Instant,
}

pub struct RelaySendTracker {
    pending: HashMap<String, PendingEntry>,
}

impl RelaySendTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
        }
    }

    /// Register a sent event for relay tracking.
    pub fn track(
        &mut self,
        event_id: String,
        msgid: String,
        room_id: String,
        expected_relays: Vec<String>,
    ) {
        self.pending.insert(
            event_id,
            PendingEntry {
                msgid,
                room_id,
                expected_relays: expected_relays.into_iter().collect(),
                success_relays: HashSet::new(),
                failed_relays: HashMap::new(),
                started_at: Instant::now(),
            },
        );
    }

    /// Record a relay OK response. Returns `Some(FinalizedEntry)` if all relays have responded.
    pub fn handle_relay_ok(
        &mut self,
        event_id: &str,
        relay_url: &str,
        success: bool,
        message: &str,
    ) -> Option<FinalizedEntry> {
        let entry = self.pending.get_mut(event_id)?;

        if success {
            entry.success_relays.insert(relay_url.to_string());
        } else {
            entry
                .failed_relays
                .insert(relay_url.to_string(), message.to_string());
        }

        let responded = entry.success_relays.len() + entry.failed_relays.len();
        if responded >= entry.expected_relays.len() {
            return self.finalize(event_id);
        }

        None
    }

    /// Finalize all entries that have exceeded the timeout. Returns finalized entries.
    pub fn check_timeouts(&mut self, timeout_secs: u64) -> Vec<FinalizedEntry> {
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let timed_out: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, e)| e.started_at.elapsed() >= timeout)
            .map(|(eid, _)| eid.clone())
            .collect();

        timed_out
            .into_iter()
            .filter_map(|eid| self.finalize(&eid))
            .collect()
    }

    fn finalize(&mut self, event_id: &str) -> Option<FinalizedEntry> {
        let entry = self.pending.remove(event_id)?;
        let success = !entry.success_relays.is_empty();

        // Build per-relay status JSON array
        let mut relays = Vec::new();
        for url in &entry.success_relays {
            relays.push(serde_json::json!({"url": url, "status": "ok"}));
        }
        for (url, err) in &entry.failed_relays {
            relays.push(serde_json::json!({"url": url, "status": "failed", "error": err}));
        }
        // Mark unresponsive relays as timed out
        for url in &entry.expected_relays {
            if !entry.success_relays.contains(url) && !entry.failed_relays.contains_key(url) {
                relays.push(serde_json::json!({"url": url, "status": "timeout"}));
            }
        }

        let relay_status_json = serde_json::to_string(&relays).unwrap_or_default();

        Some(FinalizedEntry {
            event_id: event_id.to_string(),
            msgid: entry.msgid,
            room_id: entry.room_id,
            relay_status_json,
            success,
        })
    }
}
