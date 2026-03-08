use tokio::sync::broadcast;

use crate::error::{KeychatError, Result};
use crate::identity::NostrKeypair;
use crate::nostr::nip44;
use crate::nostr::{generate_ephemeral_sender, now, NostrEvent};
use crate::transport::relay::{RelayConnection, RelayFilter};

pub async fn publish_key_package(
    relay: &RelayConnection,
    nostr_keypair: &NostrKeypair,
    key_package_hex: &str,
) -> Result<()> {
    // Keychat app/bridge publishes KeyPackages without p-tags, just author + content.
    let event = NostrEvent::new_unsigned(
        nostr_keypair.public_key_hex(),
        10443,
        vec![],
        key_package_hex.to_owned(),
        now(),
    )
    .sign(nostr_keypair)?;

    relay.publish(&event).await
}

pub async fn fetch_key_package(relay: &RelayConnection, member_pubkey_hex: &str) -> Result<String> {
    let sub_id = random_sub_id("mls-kp");
    relay
        .subscribe(
            sub_id.clone(),
            RelayFilter::for_key_packages(member_pubkey_hex.to_owned()),
        )
        .await?;

    let mut events = relay.subscribe_events();
    loop {
        match events.recv().await {
            Ok(event) if event.kind == 10443 && event.pubkey == member_pubkey_hex => {
                let _ = relay.unsubscribe(sub_id.clone()).await;
                return Ok(event.content);
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                let _ = relay.unsubscribe(sub_id.clone()).await;
                return Err(KeychatError::Nostr("relay event stream closed".to_owned()));
            }
        }
    }
}

pub async fn send_welcome(
    relay: &RelayConnection,
    sender: &NostrKeypair,
    recipient_pubkey_hex: &str,
    welcome_bytes: &[u8],
) -> Result<()> {
    let plaintext_hex = hex::encode(welcome_bytes);
    let encrypted = nip44::encrypt(sender, recipient_pubkey_hex, &plaintext_hex)?;
    let event = NostrEvent::new_unsigned(
        sender.public_key_hex(),
        444,
        vec![vec!["p".to_owned(), recipient_pubkey_hex.to_owned()]],
        encrypted,
        now(),
    )
    .sign(sender)?;

    relay.publish(&event).await
}

/// Send an MLS group message as a kind:1059 event (matching Keychat app protocol).
///
/// Keychat wraps MLS ciphertext in NIP-44 encryption using the group's export_secret
/// derived keypair. The event is:
/// - kind: 1059
/// - content: NIP-44 encrypted MLS ciphertext (encrypt with export_secret keypair)
/// - p-tag: listen_key (group export_secret derived pubkey)
/// - pubkey: ephemeral random keypair (metadata minimization)
///
/// `export_secret_keypair` is the keypair derived from the group's export_secret.
/// Use `mls::get_export_secret_keypair(nostr_id, group_id)` to obtain it.
pub async fn send_group_message(
    relay: &RelayConnection,
    export_secret_keypair: &NostrKeypair,
    listen_key_hex: &str,
    ciphertext: &[u8],
) -> Result<()> {
    // NIP-44 encrypt ciphertext with the export_secret keypair (self-encrypt)
    let encrypted_content = nip44::encrypt(export_secret_keypair, listen_key_hex, ciphertext)?;

    let ephemeral = generate_ephemeral_sender();
    let event = NostrEvent::new_unsigned(
        ephemeral.public_key_hex(),
        1059,
        vec![vec!["p".to_owned(), listen_key_hex.to_owned()]],
        encrypted_content,
        now(),
    )
    .sign(&ephemeral)?;
    relay.publish(&event).await
}

/// Subscribe to MLS group messages on a relay.
///
/// Returns a broadcast receiver that yields raw MLS ciphertext bytes.
/// Each event's content is NIP-44 decrypted using the export_secret keypair,
/// then forwarded as raw bytes.
pub async fn receive_group_message(
    relay: &RelayConnection,
    export_secret_keypair: &NostrKeypair,
    listen_key_hex: &str,
) -> broadcast::Receiver<Vec<u8>> {
    let (tx, rx) = broadcast::channel(256);
    let relay = relay.clone();
    let es_keypair = export_secret_keypair.clone();
    let listen_key_hex = listen_key_hex.to_owned();
    let sub_id = random_sub_id("mls-group");

    tokio::spawn(async move {
        if relay
            .subscribe(
                sub_id.clone(),
                RelayFilter::for_group_messages(listen_key_hex.clone()),
            )
            .await
            .is_err()
        {
            return;
        }

        let mut events = relay.subscribe_events();
        loop {
            match events.recv().await {
                Ok(event)
                    if event.kind == 1059
                        && event
                            .first_tag_value("p")
                            .is_some_and(|value| value == listen_key_hex) =>
                {
                    // NIP-44 decrypt to raw bytes using export_secret keypair
                    match nip44::decrypt_to_bytes(&es_keypair, &listen_key_hex, &event.content) {
                        Ok(plaintext_bytes) => {
                            let _ = tx.send(plaintext_bytes);
                        }
                        Err(_) => {
                            // NIP-44 decrypt failed — try hex decode as fallback
                            if let Ok(raw) = hex::decode(&event.content) {
                                let _ = tx.send(raw);
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }

        let _ = relay.unsubscribe(sub_id).await;
    });

    rx
}

fn random_sub_id(prefix: &str) -> String {
    format!("{prefix}-{:016x}", rand::random::<u64>())
}
