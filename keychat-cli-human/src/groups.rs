//! Signal Group + MLS Group commands.

use anyhow::Result;
use libkeychat::group::*;
use libkeychat::{send_group_message, AddressManager, KCMessage};
use libkeychat::{DeviceId, ProtocolAddress};
use nostr::prelude::*;
use tls_codec::Serialize as TlsSerialize;

use crate::state::{AppState, ChatTarget};
use crate::ui;

// ─── Signal Group ───────────────────────────────────────────────────────────

pub async fn sg_create(state: &AppState, name: &str) -> Result<()> {
    let my_sig_id = {
        // Get our signal ID from any peer session, or generate one
        let peers = state.peers.read().await;
        if let Some((_, peer)) = peers.iter().next() {
            // Use the signal identity from our perspective
            peer.signal.identity_public_key_hex()
        } else {
            anyhow::bail!("Add at least one friend first (need Signal identity)");
        }
    };

    let group = create_signal_group(
        name,
        &my_sig_id,
        &state.npub(),
        &state.name,
        vec![], // empty, add members with /sg-invite
    );

    let gid = group.group_id.clone();
    let mut groups = state.signal_groups.write().await;
    groups.add_group(group);
    let _ = groups.save_group(&gid, &state.db());

    ui::sys(&format!(
        "📱 Signal group created: \"{}\" ({}...)",
        name,
        &gid[..16]
    ));
    ui::sys(&format!(
        "  Use /sg-invite {} <npub> to add members",
        &gid[..16]
    ));
    Ok(())
}

pub async fn sg_invite(state: &AppState, gid_prefix: &str, peer_npub: &str) -> Result<()> {
    let peers = state.peers.read().await;
    let peer = peers
        .get(peer_npub)
        .ok_or_else(|| anyhow::anyhow!("Peer not found. Add as friend first."))?;

    let mut groups = state.signal_groups.write().await;
    let group = find_group_by_prefix(&groups, gid_prefix)?;
    let gid = group.group_id.clone();

    // Add member to group
    let group = groups.get_group_mut(&gid).unwrap();
    group.members.insert(
        peer.signal_id.clone(),
        GroupMember {
            signal_id: peer.signal_id.clone(),
            nostr_pubkey: peer.nostr_pubkey.clone(),
            name: peer.name.clone(),
            is_admin: false,
        },
    );
    let _ = groups.save_group(&gid, &state.db());
    drop(groups);
    drop(peers);

    // Send invite
    let groups = state.signal_groups.read().await;
    let group = groups.get_group(&gid).unwrap();

    let mut peers_w = state.peers.write().await;
    let peer = peers_w.get_mut(peer_npub).unwrap();
    let addr = ProtocolAddress::new(peer.signal_id.clone(), DeviceId::new(1).unwrap());
    let mut addr_mgr = AddressManager::new();
    let recv = Keys::generate();
    addr_mgr.add_peer(&peer.signal_id, Some(recv.public_key().to_hex()), None);

    let event =
        libkeychat::send_group_invite(&mut peer.signal, group, &peer.signal_id, &addr_mgr).await?;
    state.client.send_event(event).await?;

    ui::sys(&format!(
        "✅ Invited {} to group \"{}\"",
        peer.name, group.name
    ));
    Ok(())
}

pub async fn sg_send(state: &AppState, text: &str) -> Result<()> {
    let active = state.active_chat.read().await;
    let gid = match active.as_ref() {
        Some(ChatTarget::SignalGroup(g)) => g.clone(),
        _ => anyhow::bail!("Active chat is not a Signal group"),
    };
    drop(active);

    let groups = state.signal_groups.read().await;
    let group = groups
        .get_group(&gid)
        .ok_or_else(|| anyhow::anyhow!("Group not found"))?;

    let mut msg = KCMessage::text(text);
    msg.group_id = Some(gid.clone());

    // Build address manager for all members
    let mut addr_mgr = AddressManager::new();
    let peers = state.peers.read().await;
    for member in group.other_members() {
        let recv = Keys::generate();
        addr_mgr.add_peer(&member.signal_id, Some(recv.public_key().to_hex()), None);
    }
    drop(peers);

    // Need mutable access to each peer's signal participant
    let mut peers_w = state.peers.write().await;
    // Find which peer has our signal identity
    let my_sig_id = group.my_signal_id.clone();

    // Get any peer's signal participant for encryption (they share our identity)
    let first_peer = peers_w
        .values_mut()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No peers available"))?;

    let results = send_group_message(&mut first_peer.signal, group, &msg, &addr_mgr).await?;

    for (_, event) in &results {
        state.client.send_event(event.clone()).await?;
    }

    ui::sys(&format!(
        "📨 Group message sent to {} members",
        results.len()
    ));
    Ok(())
}

pub async fn sg_list(state: &AppState) -> Result<()> {
    let groups = state.signal_groups.read().await;
    if groups.group_count() == 0 {
        ui::sys("No Signal groups. Use /sg-create <name>");
    } else {
        println!();
        // Iterate through groups (GroupManager doesn't expose iter, so we track IDs)
        ui::sys(&format!("{} Signal group(s)", groups.group_count()));
        println!();
    }
    Ok(())
}

pub async fn sg_leave(state: &AppState, gid_prefix: &str) -> Result<()> {
    let mut groups = state.signal_groups.write().await;
    let group = find_group_by_prefix(&groups, gid_prefix)?;
    let gid = group.group_id.clone();
    let name = group.name.clone();

    // Send leave notification
    let mut peers = state.peers.write().await;
    if let Some(peer) = peers.values_mut().next() {
        let mut addr_mgr = AddressManager::new();
        for member in group.other_members() {
            let recv = Keys::generate();
            addr_mgr.add_peer(&member.signal_id, Some(recv.public_key().to_hex()), None);
        }
        let results = libkeychat::send_group_self_leave(&mut peer.signal, group, &addr_mgr).await?;
        for (_, event) in &results {
            state.client.send_event(event.clone()).await?;
        }
    }
    drop(peers);

    let _ = groups.remove_group_persistent(&gid, &state.db());
    ui::sys(&format!("👋 Left group \"{}\"", name));
    Ok(())
}

pub async fn sg_dissolve(state: &AppState, gid_prefix: &str) -> Result<()> {
    let mut groups = state.signal_groups.write().await;
    let group = find_group_by_prefix(&groups, gid_prefix)?;
    let gid = group.group_id.clone();
    let name = group.name.clone();

    let mut peers = state.peers.write().await;
    if let Some(peer) = peers.values_mut().next() {
        let mut addr_mgr = AddressManager::new();
        for member in group.other_members() {
            let recv = Keys::generate();
            addr_mgr.add_peer(&member.signal_id, Some(recv.public_key().to_hex()), None);
        }
        let results = libkeychat::send_group_dissolve(&mut peer.signal, group, &addr_mgr).await?;
        for (_, event) in &results {
            state.client.send_event(event.clone()).await?;
        }
    }
    drop(peers);

    let _ = groups.remove_group_persistent(&gid, &state.db());
    ui::sys(&format!("💥 Dissolved group \"{}\"", name));
    Ok(())
}

pub async fn sg_rename(state: &AppState, gid_prefix: &str, new_name: &str) -> Result<()> {
    let groups = state.signal_groups.read().await;
    let group = find_group_by_prefix(&groups, gid_prefix)?;
    let gid = group.group_id.clone();

    let mut peers = state.peers.write().await;
    if let Some(peer) = peers.values_mut().next() {
        let mut addr_mgr = AddressManager::new();
        for member in group.other_members() {
            let recv = Keys::generate();
            addr_mgr.add_peer(&member.signal_id, Some(recv.public_key().to_hex()), None);
        }
        let results =
            libkeychat::send_group_name_changed(&mut peer.signal, group, new_name, &addr_mgr)
                .await?;
        for (_, event) in &results {
            state.client.send_event(event.clone()).await?;
        }
    }
    drop(peers);
    drop(groups);

    // Update local + persist
    let mut groups = state.signal_groups.write().await;
    if let Some(g) = groups.get_group_mut(&gid) {
        g.name = new_name.to_string();
    }
    let _ = groups.save_group(&gid, &state.db());
    ui::sys(&format!("✏️ Renamed group to \"{}\"", new_name));
    Ok(())
}

fn find_group_by_prefix<'a>(groups: &'a GroupManager, prefix: &str) -> Result<&'a SignalGroup> {
    // Try exact match first, then prefix
    if let Some(g) = groups.get_group(prefix) {
        return Ok(g);
    }
    // GroupManager doesn't expose iteration, so we can't do prefix search easily
    // For now require exact ID
    anyhow::bail!("Group not found: {}. Use full group ID.", prefix)
}

// ─── MLS Group ──────────────────────────────────────────────────────────────

pub async fn mls_create(state: &AppState, name: &str) -> Result<()> {
    let mut mls = state.mls.lock().unwrap();
    let participant = mls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

    let gid = format!("mls-{}", &hex::encode(&rand::random::<[u8; 8]>()));
    participant.create_group(&gid, name)?;
    let _ = state.db().save_mls_group_id(&gid);

    ui::sys(&format!("🔐 MLS group created: \"{}\" ({})", name, &gid));
    ui::sys(&format!("  Use /mls-add {} <npub> to add members", &gid));
    Ok(())
}

pub async fn mls_add(state: &AppState, gid: &str, peer_npub: &str) -> Result<()> {
    let peers = state.peers.read().await;
    let _peer = peers
        .get(peer_npub)
        .ok_or_else(|| anyhow::anyhow!("Peer not found"))?;

    // In a full implementation, we'd fetch their KeyPackage from a relay
    // For now, this is a placeholder showing the flow
    ui::sys("⚠️ MLS add requires fetching peer's KeyPackage from relay (kind:10443)");
    ui::sys("  In a full deployment, the peer publishes their KeyPackage and we fetch it.");
    Ok(())
}

pub async fn mls_send(state: &AppState, text: &str) -> Result<()> {
    let active = state.active_chat.read().await;
    let gid = match active.as_ref() {
        Some(ChatTarget::MlsGroup(g)) => g.clone(),
        _ => anyhow::bail!("Active chat is not an MLS group"),
    };
    drop(active);

    let mls = state.mls.lock().unwrap();
    let participant = mls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

    let mut msg = KCMessage::text(text);
    msg.group_id = Some(gid.clone());

    let inbox = participant.derive_temp_inbox(&gid)?;
    let event = libkeychat::send_mls_message(participant, &gid, &msg, &inbox)?;
    state.client.send_event(event).await?;

    ui::sent(text);
    Ok(())
}

pub async fn mls_leave(state: &AppState, gid: &str) -> Result<()> {
    let mls = state.mls.lock().unwrap();
    let participant = mls
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("MLS not initialized"))?;

    let leave_bytes = participant.leave_group(gid)?;
    let inbox = participant.derive_temp_inbox(gid)?;
    let event = libkeychat::broadcast_commit(&leave_bytes, &inbox)?;
    state.client.send_event(event).await?;

    let _ = state.db().delete_mls_group_id(gid);
    ui::sys(&format!("👋 Left MLS group {}", &gid));
    Ok(())
}

pub async fn mls_list(state: &AppState) -> Result<()> {
    ui::sys("MLS groups are managed via the MLS participant.");
    ui::sys("Use /mls-create <name> to create, /mls-chat <gid> to switch.");
    Ok(())
}
