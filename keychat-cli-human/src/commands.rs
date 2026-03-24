//! Command parser and dispatcher.

use crate::state::{AppState, ChatTarget};
use crate::ui;
use crate::{chat, groups, payment_cmd};

pub async fn handle(state: &AppState, input: &str) -> anyhow::Result<bool> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(false);
    }

    if !input.starts_with('/') {
        // Regular text — route to active chat target
        let active = state.active_chat.read().await.clone();
        match active {
            Some(ChatTarget::Peer(_)) => chat::send_text(state, input).await?,
            Some(ChatTarget::SignalGroup(_)) => groups::sg_send(state, input).await?,
            Some(ChatTarget::MlsGroup(_)) => groups::mls_send(state, input).await?,
            None => ui::err("No active chat. Use /chat, /sg-chat, or /mls-chat first."),
        }
        return Ok(false);
    }

    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let cmd = parts[0];
    let arg = parts.get(1).map(|s| s.trim()).unwrap_or("");

    match cmd {
        "/quit" | "/exit" | "/q" => return Ok(true),
        "/help" | "/h" => ui::help(),
        "/info" | "/id" => ui::identity(&state.npub(), &state.name, &state.relay_urls),

        // ── 1:1 Chat ────────────────────────────────────────────────
        "/add" => {
            if arg.is_empty() {
                ui::err("Usage: /add <npub or hex>");
            } else {
                chat::add_friend(state, arg).await?;
            }
        }

        "/chat" => {
            if arg.is_empty() {
                ui::err("Usage: /chat <name or npub>");
            } else {
                // Resolve: try name match first, then npub/hex
                let resolved = {
                    let peers = state.peers.read().await;
                    if let Some((npub, _)) =
                        peers.iter().find(|(_, p)| p.name.eq_ignore_ascii_case(arg))
                    {
                        Some(npub.clone())
                    } else if arg.starts_with("npub1") {
                        nostr::nips::nip19::FromBech32::from_bech32(arg)
                            .ok()
                            .map(|pk: nostr::PublicKey| pk.to_hex())
                    } else {
                        Some(arg.to_string())
                    }
                };
                let target = resolved.unwrap_or_else(|| arg.to_string());
                *state.active_chat.write().await = Some(ChatTarget::Peer(target.clone()));
                let name = state
                    .peers
                    .read()
                    .await
                    .get(&target)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| format!("{}...", &target[..8.min(target.len())]));
                ui::sys(&format!("💬 Chatting with {}", name));
            }
        }

        "/peers" | "/contacts" | "/ls" => {
            let peers = state.peers.read().await;
            if peers.is_empty() {
                ui::sys("No contacts. Use /add <npub>");
            } else {
                let active = state.active_chat.read().await;
                println!();
                for (npub, peer) in peers.iter() {
                    let marker = match &*active {
                        Some(ChatTarget::Peer(p)) if p == npub => "▸ ",
                        _ => "  ",
                    };
                    println!(
                        "  {}{} — {}...",
                        marker,
                        peer.name,
                        &npub[..16.min(npub.len())]
                    );
                }
                println!();
            }
        }

        "/rename" => {
            let parts: Vec<&str> = arg.splitn(2, ' ').collect();
            if parts.len() < 2 {
                ui::err("Usage: /rename <npub> <new_name>");
            } else {
                let mut peers = state.peers.write().await;
                if let Some(peer) = peers.get_mut(parts[0]) {
                    let old = peer.name.clone();
                    peer.name = parts[1].to_string();
                    state
                        .db()
                        .save_peer_mapping(&peer.nostr_pubkey, &peer.signal_id, parts[1])?;
                    ui::sys(&format!("Renamed {} → {}", old, parts[1]));
                } else {
                    ui::err("Peer not found");
                }
            }
        }

        "/file" => {
            if arg.is_empty() {
                ui::err("Usage: /file <path>");
            } else {
                chat::send_file(state, arg).await?;
            }
        }

        "/voice" => {
            if arg.is_empty() {
                ui::err("Usage: /voice <path>");
            } else {
                chat::send_voice(state, arg).await?;
            }
        }

        // ── Signal Group ────────────────────────────────────────────
        "/sg-create" => {
            if arg.is_empty() {
                ui::err("Usage: /sg-create <name>");
            } else {
                groups::sg_create(state, arg).await?;
            }
        }

        "/sg-invite" => {
            let parts: Vec<&str> = arg.splitn(2, ' ').collect();
            if parts.len() < 2 {
                ui::err("Usage: /sg-invite <group_id> <npub>");
            } else {
                groups::sg_invite(state, parts[0], parts[1]).await?;
            }
        }

        "/sg-chat" => {
            if arg.is_empty() {
                ui::err("Usage: /sg-chat <group_id>");
            } else {
                *state.active_chat.write().await = Some(ChatTarget::SignalGroup(arg.to_string()));
                let name = state
                    .signal_groups
                    .read()
                    .await
                    .get_group(arg)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| arg[..8.min(arg.len())].to_string());
                ui::sys(&format!("📱 Signal group: {}", name));
            }
        }

        "/sg-list" => groups::sg_list(state).await?,
        "/sg-leave" => {
            if arg.is_empty() {
                ui::err("Usage: /sg-leave <group_id>");
            } else {
                groups::sg_leave(state, arg).await?;
            }
        }
        "/sg-dissolve" => {
            if arg.is_empty() {
                ui::err("Usage: /sg-dissolve <group_id>");
            } else {
                groups::sg_dissolve(state, arg).await?;
            }
        }
        "/sg-rename" => {
            let parts: Vec<&str> = arg.splitn(2, ' ').collect();
            if parts.len() < 2 {
                ui::err("Usage: /sg-rename <group_id> <new_name>");
            } else {
                groups::sg_rename(state, parts[0], parts[1]).await?;
            }
        }

        // ── MLS Group ───────────────────────────────────────────────
        "/mls-create" => {
            if arg.is_empty() {
                ui::err("Usage: /mls-create <name>");
            } else {
                groups::mls_create(state, arg).await?;
            }
        }

        "/mls-add" => {
            let parts: Vec<&str> = arg.splitn(2, ' ').collect();
            if parts.len() < 2 {
                ui::err("Usage: /mls-add <group_id> <npub>");
            } else {
                groups::mls_add(state, parts[0], parts[1]).await?;
            }
        }

        "/mls-chat" => {
            if arg.is_empty() {
                ui::err("Usage: /mls-chat <group_id>");
            } else {
                *state.active_chat.write().await = Some(ChatTarget::MlsGroup(arg.to_string()));
                ui::sys(&format!("🔐 MLS group: {}", arg));
            }
        }

        "/mls-list" => groups::mls_list(state).await?,
        "/mls-leave" => {
            if arg.is_empty() {
                ui::err("Usage: /mls-leave <group_id>");
            } else {
                groups::mls_leave(state, arg).await?;
            }
        }

        // ── Payment ─────────────────────────────────────────────────
        "/cashu" => {
            let parts: Vec<&str> = arg.splitn(2, ' ').collect();
            if parts.len() < 2 {
                ui::err("Usage: /cashu <token> <amount>");
            } else {
                let amount: u64 = parts[1]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("amount must be a number"))?;
                payment_cmd::send_cashu(state, parts[0], amount).await?;
            }
        }

        "/invoice" => {
            let parts: Vec<&str> = arg.splitn(2, ' ').collect();
            if parts.len() < 2 {
                ui::err("Usage: /invoice <bolt11> <amount>");
            } else {
                let amount: u64 = parts[1]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("amount must be a number"))?;
                payment_cmd::send_lightning(state, parts[0], amount).await?;
            }
        }

        _ => ui::err(&format!("Unknown: {}. Try /help", cmd)),
    }

    Ok(false)
}
