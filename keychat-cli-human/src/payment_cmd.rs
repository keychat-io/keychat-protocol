//! Payment commands — Cashu + Lightning.

use anyhow::Result;
use libkeychat::{send_encrypted_message, KCMessage};
use libkeychat::{DeviceId, ProtocolAddress};
use nostr::prelude::*;

use crate::state::{AppState, ChatTarget};
use crate::ui;

pub async fn send_cashu(state: &AppState, token: &str, amount: u64) -> Result<()> {
    libkeychat::payment::validate_cashu_token(token)?;

    let msg = libkeychat::payment::build_cashu_message("unknown", token, amount, Some("sat"), None);
    send_to_active(state, &msg, &format!("💰 Sent {} sats (cashu)", amount)).await
}

pub async fn send_lightning(state: &AppState, invoice: &str, amount: u64) -> Result<()> {
    let msg = libkeychat::payment::build_lightning_message(invoice, amount, None);
    send_to_active(state, &msg, &format!("⚡ Sent invoice: {} sats", amount)).await
}

async fn send_to_active(state: &AppState, msg: &KCMessage, confirm_text: &str) -> Result<()> {
    let active = state.active_chat.read().await;
    let peer_npub = match active.as_ref() {
        Some(ChatTarget::Peer(p)) => p.clone(),
        _ => anyhow::bail!("Payment requires active 1:1 chat"),
    };
    drop(active);

    let mut peers = state.peers.write().await;
    let peer = peers
        .get_mut(&peer_npub)
        .ok_or_else(|| anyhow::anyhow!("Peer not found"))?;

    let addr = ProtocolAddress::new(peer.signal_id.clone(), DeviceId::new(1).unwrap());
    let recv_keys = Keys::generate();
    let event = send_encrypted_message(
        &mut peer.signal,
        &addr,
        msg,
        &recv_keys.public_key().to_hex(),
    )
    .await?;
    state.client.send_event(event).await?;

    ui::sys(confirm_text);
    Ok(())
}
