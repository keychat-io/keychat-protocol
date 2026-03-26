//! Signal Group (sendAll) UniFFI bindings.
//!
//! Wraps libkeychat::group functions for Swift consumption.
//! Groups use per-member 1:1 Signal encryption — each message
//! is encrypted individually for every member.

use libkeychat::{
    create_signal_group, receive_group_invite, send_group_dissolve, send_group_invite,
    send_group_member_removed, send_group_message, send_group_name_changed, send_group_self_leave,
    GroupManager, KCMessage, SignalGroup,
};
use libkeychat::{DeviceId, ProtocolAddress};

use crate::client::KeychatClient;
use crate::error::KeychatUniError;
use crate::types::*;

impl KeychatClient {
    /// Helper: send a list of (member_id, Event) tuples to relay (I-7).
    pub(crate) async fn broadcast_group_events(
        &self,
        events: Vec<(String, nostr::Event)>,
    ) -> Result<Vec<String>, KeychatUniError> {
        let inner = self.inner.read().await;
        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        let nostr_client = transport.client();
        let mut event_ids = Vec::new();
        for (_member_id, event) in events {
            let eid = event.id.to_hex();
            if let Err(e) = nostr_client.send_event(event).await {
                tracing::warn!("broadcast_group_events: send failed: {e}");
            }
            event_ids.push(eid);
        }
        Ok(event_ids)
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl KeychatClient {
    /// Create a new Signal group.
    ///
    /// `members` is a list of (peer_nostr_pubkey, name) tuples.
    /// Each peer must already have an established 1:1 Signal session.
    /// Returns the group_id and sends invites to all members.
    pub async fn create_signal_group(
        &self,
        name: String,
        members: Vec<GroupMemberInput>,
    ) -> Result<SignalGroupInfo, KeychatUniError> {
        // I-15: Collect all data under read lock, then drop before async work
        let (my_nostr_pubkey, my_signal_id, other_members, member_sessions) = {
            let inner = self.inner.read().await;

            let identity = inner
                .identity
                .as_ref()
                .ok_or(KeychatUniError::NotInitialized {
                    msg: "no identity set".into(),
                })?;
            let my_nostr_pubkey = identity.pubkey_hex();

            let my_signal_id = if let Some(session_mutex) = inner.sessions.values().next() {
                let session = session_mutex.lock().await;
                session.signal.identity_public_key_hex()
            } else {
                tracing::warn!(
                    "create_signal_group: no sessions available, using nostr pubkey as signal_id"
                );
                my_nostr_pubkey.clone()
            };

            let mut other_members = Vec::new();
            let mut member_sessions = Vec::new();
            for member in &members {
                let signal_id = inner
                    .peer_nostr_to_signal
                    .get(&member.nostr_pubkey)
                    .ok_or(KeychatUniError::PeerNotFound {
                        peer_id: member.nostr_pubkey.clone(),
                    })?
                    .clone();
                let session_arc = inner
                    .sessions
                    .get(&signal_id)
                    .ok_or(KeychatUniError::PeerNotFound {
                        peer_id: signal_id.clone(),
                    })?
                    .clone();
                other_members.push((
                    signal_id.clone(),
                    member.nostr_pubkey.clone(),
                    member.name.clone(),
                ));
                member_sessions.push((signal_id, session_arc));
            }

            (
                my_nostr_pubkey,
                my_signal_id,
                other_members,
                member_sessions,
            )
        }; // read lock dropped

        let group =
            create_signal_group(&name, &my_signal_id, &my_nostr_pubkey, "Me", other_members);

        let group_id = group.group_id.clone();
        let group_name = group.name.clone();
        let member_count = group.members.len() as u32;

        tracing::info!(
            "created signal group: id={}, name={}, members={}",
            &group_id[..16.min(group_id.len())],
            name,
            member_count
        );

        // Send invite to each member (no read lock held)
        let mut all_events = Vec::new();
        for (signal_id, session_arc) in &member_sessions {
            let mut session = session_arc.lock().await;
            let addr = session.addresses.clone();
            let event = send_group_invite(&mut session.signal, &group, signal_id, &addr).await?;
            tracing::info!(
                "sent group invite to {}",
                &signal_id[..16.min(signal_id.len())]
            );
            all_events.push((signal_id.clone(), event));
        }
        let _ = self.broadcast_group_events(all_events).await;

        // Store group in manager + persist
        let mut inner = self.inner.write().await;
        let gid = group.group_id.clone();
        inner.group_manager.add_group(group);
        if let Ok(store) = inner.storage.clone().lock() {
            let _ = inner.group_manager.save_group(&gid, &store);
        }

        Ok(SignalGroupInfo {
            group_id,
            name: group_name,
            member_count,
        })
    }

    /// Send a text message to a Signal group.
    /// The message is encrypted and sent individually to each member.
    pub async fn send_group_text(
        &self,
        group_id: String,
        text: String,
    ) -> Result<GroupSentMessage, KeychatUniError> {
        let inner = self.inner.read().await;

        let group = inner
            .group_manager
            .get_group(&group_id)
            .ok_or(KeychatUniError::PeerNotFound {
                peer_id: group_id.clone(),
            })?
            .clone();

        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        let nostr_client = transport.client().clone();

        let mut msg = KCMessage::text(&text);
        msg.group_id = Some(group_id.clone());

        let mut event_ids = Vec::new();

        // Send to each member individually
        for member in group.other_members() {
            let session_mutex = match inner.sessions.get(&member.signal_id).or_else(|| {
                inner
                    .peer_nostr_to_signal
                    .get(&member.nostr_pubkey)
                    .and_then(|sid| inner.sessions.get(sid))
            }) {
                Some(s) => s.clone(),
                None => {
                    tracing::warn!(
                        "no session for group member {}",
                        &member.signal_id[..16.min(member.signal_id.len())]
                    );
                    continue;
                }
            };

            let events = {
                let mut session = session_mutex.lock().await;
                let addr = session.addresses.clone();
                send_group_message(&mut session.signal, &group, &msg, &addr).await?
            };

            for (_member_id, event) in events {
                let eid = event.id.to_hex();
                nostr_client
                    .send_event(event)
                    .await
                    .map_err(|e| KeychatUniError::Transport { msg: e.to_string() })?;
                event_ids.push(eid);
            }
        }

        tracing::info!(
            "sent group text to {} members, group={}",
            event_ids.len(),
            &group_id[..16.min(group_id.len())]
        );

        Ok(GroupSentMessage {
            group_id,
            event_ids,
        })
    }

    /// Leave a Signal group. Notifies all members.
    pub async fn leave_signal_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;

        let group = inner
            .group_manager
            .get_group(&group_id)
            .ok_or(KeychatUniError::PeerNotFound {
                peer_id: group_id.clone(),
            })?
            .clone();

        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        let nostr_client = transport.client().clone();

        let mut all_events = Vec::new();
        for member in group.other_members() {
            if let Some(sm) = inner.sessions.get(&member.signal_id).or_else(|| {
                inner
                    .peer_nostr_to_signal
                    .get(&member.nostr_pubkey)
                    .and_then(|sid| inner.sessions.get(sid))
            }) {
                let mut session = sm.lock().await;
                let addr = session.addresses.clone();
                let evts = send_group_self_leave(&mut session.signal, &group, &addr).await?;
                all_events.extend(evts);
            }
        }
        drop(inner);
        let _ = self.broadcast_group_events(all_events).await;

        // Remove group from manager + storage
        let mut inner = self.inner.write().await;
        if let Ok(store) = inner.storage.clone().lock() {
            let _ = inner
                .group_manager
                .remove_group_persistent(&group_id, &store);
        } else {
            inner.group_manager.remove_group(&group_id);
        }

        tracing::info!("left signal group {}", &group_id[..16.min(group_id.len())]);
        Ok(())
    }

    /// Dissolve a Signal group (admin only). Notifies all members.
    pub async fn dissolve_signal_group(&self, group_id: String) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;

        let group = inner
            .group_manager
            .get_group(&group_id)
            .ok_or(KeychatUniError::PeerNotFound {
                peer_id: group_id.clone(),
            })?
            .clone();

        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        let nostr_client = transport.client().clone();

        let mut all_events = Vec::new();
        for member in group.other_members() {
            if let Some(sm) = inner.sessions.get(&member.signal_id).or_else(|| {
                inner
                    .peer_nostr_to_signal
                    .get(&member.nostr_pubkey)
                    .and_then(|sid| inner.sessions.get(sid))
            }) {
                let mut session = sm.lock().await;
                let addr = session.addresses.clone();
                let evts = send_group_dissolve(&mut session.signal, &group, &addr).await?;
                all_events.extend(evts);
            }
        }
        drop(inner);
        let _ = self.broadcast_group_events(all_events).await;

        let mut inner = self.inner.write().await;
        if let Ok(store) = inner.storage.clone().lock() {
            let _ = inner
                .group_manager
                .remove_group_persistent(&group_id, &store);
        } else {
            inner.group_manager.remove_group(&group_id);
        }

        tracing::info!(
            "dissolved signal group {}",
            &group_id[..16.min(group_id.len())]
        );
        Ok(())
    }

    /// Remove a member from a Signal group (admin only).
    pub async fn remove_group_member(
        &self,
        group_id: String,
        member_nostr_pubkey: String,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;

        let group = inner
            .group_manager
            .get_group(&group_id)
            .ok_or(KeychatUniError::PeerNotFound {
                peer_id: group_id.clone(),
            })?
            .clone();

        let removed_signal_id = inner
            .peer_nostr_to_signal
            .get(&member_nostr_pubkey)
            .ok_or(KeychatUniError::PeerNotFound {
                peer_id: member_nostr_pubkey.clone(),
            })?
            .clone();

        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        let nostr_client = transport.client().clone();

        let mut all_events = Vec::new();
        for member in group.other_members() {
            if let Some(sm) = inner.sessions.get(&member.signal_id).or_else(|| {
                inner
                    .peer_nostr_to_signal
                    .get(&member.nostr_pubkey)
                    .and_then(|sid| inner.sessions.get(sid))
            }) {
                let mut session = sm.lock().await;
                let addr = session.addresses.clone();
                let evts = send_group_member_removed(
                    &mut session.signal,
                    &group,
                    &removed_signal_id,
                    &addr,
                )
                .await?;
                all_events.extend(evts);
            }
        }
        drop(inner);
        let _ = self.broadcast_group_events(all_events).await;

        // Update group state + persist
        let mut inner = self.inner.write().await;
        if let Some(g) = inner.group_manager.get_group_mut(&group_id) {
            g.remove_member(&removed_signal_id);
        }
        if let Ok(store) = inner.storage.clone().lock() {
            let _ = inner.group_manager.save_group(&group_id, &store);
        }

        tracing::info!(
            "removed member {} from group {}",
            &member_nostr_pubkey[..16.min(member_nostr_pubkey.len())],
            &group_id[..16.min(group_id.len())]
        );
        Ok(())
    }

    /// Rename a Signal group (admin only).
    pub async fn rename_signal_group(
        &self,
        group_id: String,
        new_name: String,
    ) -> Result<(), KeychatUniError> {
        let inner = self.inner.read().await;

        let group = inner
            .group_manager
            .get_group(&group_id)
            .ok_or(KeychatUniError::PeerNotFound {
                peer_id: group_id.clone(),
            })?
            .clone();

        let transport = inner
            .transport
            .as_ref()
            .ok_or(KeychatUniError::Transport {
                msg: "Not connected to any relay. Please check your network.".into(),
            })?;
        let nostr_client = transport.client().clone();

        let mut all_events = Vec::new();
        for member in group.other_members() {
            if let Some(sm) = inner.sessions.get(&member.signal_id).or_else(|| {
                inner
                    .peer_nostr_to_signal
                    .get(&member.nostr_pubkey)
                    .and_then(|sid| inner.sessions.get(sid))
            }) {
                let mut session = sm.lock().await;
                let addr = session.addresses.clone();
                let evts =
                    send_group_name_changed(&mut session.signal, &group, &new_name, &addr).await?;
                all_events.extend(evts);
            }
        }
        drop(inner);
        let _ = self.broadcast_group_events(all_events).await;

        let mut inner = self.inner.write().await;
        if let Some(g) = inner.group_manager.get_group_mut(&group_id) {
            g.name = new_name.clone();
        }

        tracing::info!(
            "renamed group {} to {}",
            &group_id[..16.min(group_id.len())],
            new_name
        );
        Ok(())
    }
}
