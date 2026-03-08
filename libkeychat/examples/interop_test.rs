use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use libsignal_protocol::ProtocolAddress;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use libkeychat::identity::{
    generate_mnemonic, nostr_keypair_from_mnemonic, recover_mnemonic, NostrKeypair,
};
use libkeychat::protocol::address::{AddressChange, AddressManager};
use libkeychat::protocol::hello::{create_hello, receive_hello};
use libkeychat::protocol::messaging::receive_message;
use libkeychat::signal::keys::generate_prekey_material;
use libkeychat::signal::{SignalParticipant, SignalParticipantSnapshot};
use libkeychat::transport::relay::RelayFilter;
use libkeychat::transport::RelayPool;

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_RELAYS: [&str; 3] = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
];
const STATE_KEY: &str = "runtime_state";

#[derive(Parser)]
#[command(name = "interop_test")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate,
    Hello {
        recipient: String,
        #[arg(long = "relay")]
        relay: Vec<String>,
    },
    Listen {
        #[arg(long = "relay")]
        relay: Vec<String>,
    },
    MlsPublishKeyPackage {
        #[arg(long = "relay")]
        relay: Vec<String>,
    },
    MlsListen {
        group_id: String,
        listen_key: String,
        #[arg(long = "relay")]
        relay: Vec<String>,
    },
    MlsJoinAndListen {
        welcome_hex: String,
        listen_key: String,
        #[arg(long = "relay")]
        relay: Vec<String>,
    },
    /// Create MLS group, fetch a remote peer's KeyPackage from relay, add them,
    /// send Welcome via Gift Wrap (kind:1059 with inner kind:444), then listen.
    MlsCreateInvite {
        /// npub or hex pubkey of the peer to invite
        peer: String,
        #[arg(long = "relay")]
        relay: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IdentityRecord {
    mnemonic: String,
    npub: String,
    pubkey_hex: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RuntimeState {
    signal: Option<SignalParticipantSnapshot>,
    address_manager: AddressManager,
    peers: BTreeMap<String, PeerState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerState {
    name: String,
    signal_address: String,
}

#[tokio::main]
async fn main() -> DynResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate => generate_identity_command()?,
        Command::Hello { recipient, relay } => hello_command(recipient, relay).await?,
        Command::Listen { relay } => listen_command(relay).await?,
        Command::MlsPublishKeyPackage { relay } => mls_publish_key_package_command(relay).await?,
        Command::MlsListen {
            group_id,
            listen_key,
            relay,
        } => mls_listen_command(group_id, listen_key, relay).await?,
        Command::MlsJoinAndListen {
            welcome_hex,
            listen_key,
            relay,
        } => mls_join_and_listen_command(welcome_hex, listen_key, relay).await?,
        Command::MlsCreateInvite { peer, relay } => mls_create_invite_command(peer, relay).await?,
    }

    Ok(())
}

fn generate_identity_command() -> DynResult<()> {
    let base_dir = app_dir()?;
    fs::create_dir_all(&base_dir)?;

    let mnemonic = generate_mnemonic(12)?;
    let keys = nostr_keypair_from_mnemonic(&mnemonic)?;
    let record = IdentityRecord {
        mnemonic: mnemonic.to_string(),
        npub: keys.npub()?,
        pubkey_hex: keys.public_key_hex(),
    };

    save_identity(&record)?;
    let signal_db = signal_db_path()?;
    if signal_db.exists() {
        fs::remove_file(signal_db)?;
    }

    println!("mnemonic: {}", record.mnemonic);
    println!("npub: {}", record.npub);
    println!("nsec: {}", keys.nsec()?);
    println!("pubkey_hex: {}", record.pubkey_hex);
    Ok(())
}

async fn hello_command(recipient: String, relays: Vec<String>) -> DynResult<()> {
    let (_identity, local_nostr) = load_or_create_identity()?;
    let recipient_hex = decode_pubkey(&recipient)?;
    let mut runtime = load_runtime_state(&signal_db_path()?)?;

    let relay_urls = normalize_relays(relays);
    let relay_refs = relay_urls.iter().map(String::as_str).collect::<Vec<_>>();
    let mut relay_pool = RelayPool::connect(&relay_refs).await?;

    let hello = create_hello(
        &local_nostr,
        &recipient_hex,
        "libkeychat-cli",
        "Hello from libkeychat",
        &recipient_hex,
        &mut runtime.address_manager,
    )?;
    let mut local_signal = hello.signal.clone();

    let mut reply_subscriptions = BTreeMap::new();
    apply_address_changes(
        &relay_pool,
        &mut reply_subscriptions,
        &hello.address_changes,
    )
    .await?;

    relay_pool.publish(&hello.event).await?;
    println!("published hello event {}", hello.event.id);
    println!("onetimekey: {}", hello.qr.onetimekey);
    println!("signal identity: {}", hello.qr.curve25519_pk_hex);
    println!(
        "subscribed addresses: {:?}",
        reply_subscriptions.keys().collect::<Vec<_>>()
    );
    persist_runtime_state(&signal_db_path()?, &mut local_signal, &runtime)?;

    let remote_signal_address = ProtocolAddress::new(recipient_hex.clone(), 1u32.into());
    let reply = tokio::time::timeout(
        Duration::from_secs(60),
        wait_for_kind4_reply(
            &mut relay_pool,
            &local_nostr,
            &mut local_signal,
            &mut runtime,
            &remote_signal_address,
            &reply_subscriptions,
            &recipient_hex,
        ),
    )
    .await??;

    runtime.peers.insert(
        recipient_hex.clone(),
        PeerState {
            name: recipient_hex.clone(),
            signal_address: remote_signal_address.name().to_owned(),
        },
    );
    persist_runtime_state(&signal_db_path()?, &mut local_signal, &runtime)?;

    println!("reply type: {}", reply.r#type);
    println!("reply message: {}", reply.msg);

    // Send a confirmation message back
    let confirm = libkeychat::protocol::message_types::KeychatMessage {
        c: "signal".to_owned(),
        r#type: 100,
        msg: "Hello! libkeychat received your message successfully. 🎉".to_owned(),
        name: None,
    };
    let (confirm_event, confirm_changes) = libkeychat::protocol::messaging::send_signal_message(
        &local_nostr,
        &mut local_signal,
        &remote_signal_address,
        &mut runtime.address_manager,
        &recipient_hex,
        &confirm,
    )?;
    apply_address_changes(&relay_pool, &mut reply_subscriptions, &confirm_changes).await?;
    eprintln!(
        "[debug] confirm event p-tag: {:?}",
        confirm_event.first_tag_value("p")
    );
    eprintln!(
        "[debug] confirm event pubkey: {}",
        &confirm_event.pubkey[..16]
    );
    eprintln!("[debug] confirm event kind: {}", confirm_event.kind);
    eprintln!("[debug] recipient_hex: {}", &recipient_hex);
    relay_pool.publish(&confirm_event).await?;
    println!("sent confirmation reply: {}", confirm_event.id);
    persist_runtime_state(&signal_db_path()?, &mut local_signal, &runtime)?;

    // Keep listening for more messages
    println!("listening for more messages (Ctrl+C to stop)...");
    loop {
        let event = relay_pool
            .next_event()
            .await
            .ok_or_else(|| std::io::Error::other("relay closed"))?;
        if event.kind != 4 {
            continue;
        }
        let Some(address) = event.first_tag_value("p") else {
            continue;
        };
        if !reply_subscriptions.contains_key(address) {
            continue;
        }
        match libkeychat::protocol::messaging::receive_message(
            &local_nostr,
            &mut local_signal,
            &remote_signal_address,
            &mut runtime.address_manager,
            &recipient_hex,
            &event,
        ) {
            Ok(received) => {
                println!(">> {}: {}", received.message.r#type, received.message.msg);
                // Echo back
                let echo = libkeychat::protocol::message_types::KeychatMessage {
                    c: "signal".to_owned(),
                    r#type: 100,
                    msg: format!("Echo: {}", received.message.msg),
                    name: None,
                };
                if let Ok((echo_event, echo_changes)) =
                    libkeychat::protocol::messaging::send_signal_message(
                        &local_nostr,
                        &mut local_signal,
                        &remote_signal_address,
                        &mut runtime.address_manager,
                        &recipient_hex,
                        &echo,
                    )
                {
                    let _ =
                        apply_address_changes(&relay_pool, &mut reply_subscriptions, &echo_changes)
                            .await;
                    let _ = relay_pool.publish(&echo_event).await;
                    println!("<< Echo sent");
                }
                persist_runtime_state(&signal_db_path()?, &mut local_signal, &runtime)?;
            }
            Err(err) => eprintln!("decrypt error: {err}"),
        }
    }
}

async fn listen_command(relays: Vec<String>) -> DynResult<()> {
    let (identity, local_nostr) = load_or_create_identity()?;
    let mut runtime = load_runtime_state(&signal_db_path()?)?;
    let mut local_signal = load_or_create_signal(&runtime)?;

    let relay_urls = normalize_relays(relays);
    let relay_refs = relay_urls.iter().map(String::as_str).collect::<Vec<_>>();
    let mut relay_pool = RelayPool::connect(&relay_refs).await?;
    let mut address_subscriptions = BTreeMap::new();
    let mut seen_events = BTreeSet::new();

    let gift_sub = relay_pool
        .subscribe(
            RelayFilter::new()
                .with_kind(1059)
                .with_p_tag(identity.pubkey_hex.clone()),
        )
        .await?;
    for address in runtime.address_manager.get_all_receiving_addresses() {
        subscribe_kind4_address(&relay_pool, &mut address_subscriptions, address).await?;
    }

    println!("listening on {} (gift sub {})", identity.npub, gift_sub);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                persist_runtime_state(&signal_db_path()?, &mut local_signal, &runtime)?;
                let _ = relay_pool.disconnect().await;
                break;
            }
            maybe_event = relay_pool.next_event() => {
                let Some(event) = maybe_event else {
                    break;
                };
                if !seen_events.insert(event.id.clone()) {
                    continue;
                }

                if event.kind == 1059 && event.first_tag_value("p") == Some(identity.pubkey_hex.as_str()) {
                    match receive_hello(&local_nostr, &mut local_signal, &mut runtime.address_manager, &event) {
                        Ok(outcome) => {
                            println!("hello from {} ({})", outcome.peer.name, outcome.peer.pubkey);
                            runtime.peers.insert(
                                outcome.peer.pubkey.clone(),
                                PeerState {
                                    name: outcome.peer.name.clone(),
                                    signal_address: outcome.remote_signal_address.name().to_owned(),
                                },
                            );
                            eprintln!("[listen] address_changes count: {}", outcome.address_changes.len());
                            apply_address_changes(&relay_pool, &mut address_subscriptions, &outcome.address_changes).await?;
                            eprintln!("[listen] subscribed kind:4 addresses: {:?}", address_subscriptions.keys().collect::<Vec<_>>());
                            relay_pool.publish(&outcome.auto_reply).await?;
                            println!("auto-replied with {}", outcome.auto_reply.id);
                            persist_runtime_state(&signal_db_path()?, &mut local_signal, &runtime)?;
                        }
                        Err(err) => eprintln!("failed to process hello: {err}"),
                    }
                    continue;
                }

                if event.kind != 4 {
                    continue;
                }

                let Some(recipient_address) = event.first_tag_value("p") else {
                    continue;
                };
                let Some(peer_id) = runtime.address_manager.resolve_peer_by_receiving_address(recipient_address) else {
                    eprintln!("ignoring kind:4 for unknown address {recipient_address}");
                    continue;
                };
                let Some(peer) = runtime.peers.get(&peer_id).cloned() else {
                    eprintln!("ignoring kind:4 for unknown peer {peer_id}");
                    continue;
                };

                let remote_signal_address = ProtocolAddress::new(peer.signal_address, 1u32.into());
                match receive_message(
                    &local_nostr,
                    &mut local_signal,
                    &remote_signal_address,
                    &mut runtime.address_manager,
                    &peer_id,
                    &event,
                ) {
                    Ok(received) => {
                        println!("message from {}: {}", peer.name, received.message.msg);
                        apply_address_changes(&relay_pool, &mut address_subscriptions, &received.address_changes).await?;

                        // Echo reply
                        let echo_msg = libkeychat::protocol::message_types::KeychatMessage {
                            c: "signal".to_owned(),
                            r#type: libkeychat::protocol::message_types::TYPE_DM,
                            msg: format!("echo: {}", received.message.msg),
                            name: None,
                        };
                        match libkeychat::protocol::messaging::send_signal_message(
                            &local_nostr,
                            &mut local_signal,
                            &remote_signal_address,
                            &mut runtime.address_manager,
                            &peer_id,
                            &echo_msg,
                        ) {
                            Ok((echo_event, echo_changes)) => {
                                apply_address_changes(&relay_pool, &mut address_subscriptions, &echo_changes).await?;
                                relay_pool.publish(&echo_event).await?;
                                println!("echo replied: {}", echo_event.id);
                            }
                            Err(err) => eprintln!("failed to send echo: {err}"),
                        }

                        persist_runtime_state(&signal_db_path()?, &mut local_signal, &runtime)?;
                    }
                    Err(err) => eprintln!("failed to decrypt message from {}: {err}\n  event content ({} bytes): {:?}", peer.name, event.content.len(), &event.content[..event.content.len().min(100)]),
                }
            }
        }
    }

    Ok(())
}

async fn mls_publish_key_package_command(relays: Vec<String>) -> DynResult<()> {
    let (_identity, keypair) = load_or_create_identity()?;
    let nostr_id = keypair.public_key_hex();
    let db_path = mls_db_path()?;

    // MLS functions use an internal block_on(), so run them on a blocking thread
    // to avoid "Cannot start a runtime from within a runtime" panic.
    let nostr_id_clone = nostr_id.clone();
    let key_package = tokio::task::spawn_blocking(move || {
        let db_path_str = db_path.to_str().ok_or_else(|| {
            libkeychat::error::KeychatError::Mls("mls db path is not valid utf-8".to_owned())
        })?;
        libkeychat::mls::init_mls(db_path_str, &nostr_id_clone)?;
        libkeychat::mls::create_key_package(&nostr_id_clone)
    })
    .await??;
    let relay_urls = normalize_relays(relays);
    let relay_refs = relay_urls.iter().map(String::as_str).collect::<Vec<_>>();
    let relay_pool = RelayPool::connect(&relay_refs).await?;

    let mut any_ok = false;
    let mut last_err = None;
    for relay in relay_pool.relays() {
        match libkeychat::mls::transport::publish_key_package(
            relay,
            &keypair,
            &key_package.key_package,
        )
        .await
        {
            Ok(()) => any_ok = true,
            Err(err) => {
                eprintln!("failed to publish key package to {}: {err}", relay.url());
                last_err = Some(err);
            }
        }
    }

    if !any_ok {
        return Err(last_err
            .map(|err| -> Box<dyn std::error::Error> { Box::new(err) })
            .unwrap_or_else(|| Box::new(std::io::Error::other("failed to publish to relays"))));
    }

    println!("{}", key_package.key_package);
    Ok(())
}

async fn mls_listen_command(
    group_id: String,
    listen_key: String,
    relays: Vec<String>,
) -> DynResult<()> {
    let (_identity, keypair) = load_or_create_identity()?;
    let nostr_id = keypair.public_key_hex();
    let db_path = mls_db_path()?;

    let nid = nostr_id.clone();
    tokio::task::spawn_blocking(move || {
        let db_path_str = db_path.to_str().ok_or_else(|| {
            libkeychat::error::KeychatError::Mls("mls db path is not valid utf-8".to_owned())
        })?;
        libkeychat::mls::init_mls(db_path_str, &nid)
    })
    .await??;

    mls_listen_loop(group_id, listen_key, relays, keypair, nostr_id).await
}

async fn mls_join_and_listen_command(
    welcome_hex: String,
    listen_key: String,
    relays: Vec<String>,
) -> DynResult<()> {
    let (_identity, keypair) = load_or_create_identity()?;
    let nostr_id = keypair.public_key_hex();
    let db_path = mls_db_path()?;

    let nid = nostr_id.clone();
    let wb = hex::decode(welcome_hex)?;
    let group_id = tokio::task::spawn_blocking(move || {
        let db_path_str = db_path.to_str().ok_or_else(|| {
            libkeychat::error::KeychatError::Mls("mls db path is not valid utf-8".to_owned())
        })?;
        libkeychat::mls::init_mls(db_path_str, &nid)?;
        libkeychat::mls::join_group_from_welcome(&nid, &wb)
    })
    .await??;
    println!("joined group_id: {}", group_id);

    mls_listen_loop(group_id, listen_key, relays, keypair, nostr_id).await
}

async fn mls_listen_loop(
    group_id: String,
    mut listen_key: String,
    relays: Vec<String>,
    _keypair: NostrKeypair,
    nostr_id: String,
) -> DynResult<()> {
    let relay_urls = normalize_relays(relays);
    let relay_refs = relay_urls.iter().map(String::as_str).collect::<Vec<_>>();
    let relay_pool = RelayPool::connect(&relay_refs).await?;

    // Get export_secret keypair for NIP-44 layer
    let nid_es = nostr_id.clone();
    let gid_es = group_id.clone();
    let mut es_keypair = tokio::task::spawn_blocking(move || {
        libkeychat::mls::get_export_secret_keypair(&nid_es, &gid_es)
    })
    .await??;

    let (cipher_tx, mut cipher_rx) = mpsc::channel::<Vec<u8>>(256);
    for relay in relay_pool.relays() {
        let mut relay_rx =
            libkeychat::mls::transport::receive_group_message(relay, &es_keypair, &listen_key)
                .await;
        let tx = cipher_tx.clone();
        tokio::spawn(async move {
            loop {
                match relay_rx.recv().await {
                    Ok(ciphertext) => {
                        if tx.send(ciphertext).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
    drop(cipher_tx);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = relay_pool.disconnect().await;
                break;
            }
            maybe_ciphertext = cipher_rx.recv() => {
                let Some(ciphertext) = maybe_ciphertext else {
                    break;
                };

                let nid = nostr_id.clone();
                let gid = group_id.clone();
                let ct = ciphertext.clone();

                // Try decrypt as application message first
                let decrypt_result = tokio::task::spawn_blocking(move || {
                    libkeychat::mls::decrypt_group_message(&nid, &gid, &ct)
                }).await?;

                match decrypt_result {
                    Ok(decrypted) => {
                        println!("[MLS from {}]: {}", decrypted.sender_nostr_id, decrypted.plaintext);

                        // Check if listen key changed after decryption
                        let nid_lk = nostr_id.clone();
                        let gid_lk = group_id.clone();
                        if let Ok(new_lk) = tokio::task::spawn_blocking(move || {
                            libkeychat::mls::get_group_listen_key(&nid_lk, &gid_lk)
                        }).await? {
                            if new_lk != listen_key {
                                println!("[MLS] Listen key rotated: {}... → {}...", &listen_key[..12], &new_lk[..12]);
                                listen_key = new_lk;
                            }
                        }

                        let reply_text = format!("Echo: {}", decrypted.plaintext);
                        let nid2 = nostr_id.clone();
                        let gid2 = group_id.clone();
                        match tokio::task::spawn_blocking(move || {
                            libkeychat::mls::encrypt_group_message(&nid2, &gid2, &reply_text)
                        }).await? {
                            Ok(reply_ciphertext) => {
                                if let Err(err) = send_mls_echo_to_relays(
                                    &relay_pool,
                                    &es_keypair,
                                    &listen_key,
                                    &reply_ciphertext,
                                ).await {
                                    eprintln!("failed to send MLS echo reply: {err}");
                                }
                            }
                            Err(err) => eprintln!("failed to encrypt MLS echo reply: {err}"),
                        }
                    }
                    Err(_) => {
                        // Not an application message — try as commit
                        let nid_c = nostr_id.clone();
                        let gid_c = group_id.clone();
                        let ct_c = ciphertext;
                        match tokio::task::spawn_blocking(move || {
                            libkeychat::mls::process_commit(&nid_c, &gid_c, &ct_c)
                        }).await? {
                            Ok(commit) => {
                                println!("[MLS commit from {}]: {:?}, members: {:?}",
                                    commit.sender, commit.commit_type, commit.operated_members);

                                // Listen key rotates after commit — must re-subscribe
                                let nid_lk = nostr_id.clone();
                                let gid_lk = group_id.clone();
                                if let Ok(new_lk) = tokio::task::spawn_blocking(move || {
                                    libkeychat::mls::get_group_listen_key(&nid_lk, &gid_lk)
                                }).await? {
                                    if new_lk != listen_key {
                                        println!("[MLS] Listen key rotated after commit: {}... → {}...", &listen_key[..12], &new_lk[..12]);
                                        // Re-subscribe on all relays
                                        // Update export_secret keypair after commit
                                        let nid_es2 = nostr_id.clone();
                                        let gid_es2 = group_id.clone();
                                        if let Ok(new_es) = tokio::task::spawn_blocking(move || {
                                            libkeychat::mls::get_export_secret_keypair(&nid_es2, &gid_es2)
                                        }).await? {
                                            es_keypair = new_es;
                                        }
                                        for relay in relay_pool.relays() {
                                            let _ = libkeychat::mls::transport::receive_group_message(
                                                relay, &es_keypair, &new_lk,
                                            ).await;
                                        }
                                        listen_key = new_lk;
                                    }
                                }
                            }
                            Err(err) => eprintln!("failed to process MLS message (neither app nor commit): {err}"),
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

async fn send_mls_echo_to_relays(
    relay_pool: &RelayPool,
    keypair: &NostrKeypair,
    listen_key: &str,
    ciphertext: &[u8],
) -> DynResult<()> {
    let mut any_ok = false;
    let mut last_err = None;
    for relay in relay_pool.relays() {
        match libkeychat::mls::transport::send_group_message(relay, keypair, listen_key, ciphertext)
            .await
        {
            Ok(()) => any_ok = true,
            Err(err) => {
                eprintln!("failed to send MLS group message to {}: {err}", relay.url());
                last_err = Some(err);
            }
        }
    }

    if any_ok {
        return Ok(());
    }

    Err(last_err
        .map(|err| -> Box<dyn std::error::Error> { Box::new(err) })
        .unwrap_or_else(|| Box::new(std::io::Error::other("failed to send to relays"))))
}

async fn mls_create_invite_command(peer: String, relays: Vec<String>) -> DynResult<()> {
    let (_identity, keypair) = load_or_create_identity()?;
    let nostr_id = keypair.public_key_hex();
    let peer_pubkey = decode_pubkey(&peer)?;
    let db_path = mls_db_path()?;

    // Initialize MLS on blocking thread (internal block_on)
    let nid = nostr_id.clone();
    let dbp = db_path.clone();
    tokio::task::spawn_blocking(move || {
        let p = dbp
            .to_str()
            .ok_or_else(|| libkeychat::error::KeychatError::Mls("bad path".into()))?;
        libkeychat::mls::init_mls(p, &nid)
    })
    .await??;

    let relay_urls = normalize_relays(relays);
    let relay_refs = relay_urls.iter().map(String::as_str).collect::<Vec<_>>();
    let relay_pool = RelayPool::connect(&relay_refs).await?;

    // Step 1: Fetch peer's KeyPackage from relay
    println!("[1/5] Fetching KeyPackage for {}...", &peer_pubkey[..12]);
    let peer_kp_hex = {
        let relay = relay_pool
            .relays()
            .first()
            .ok_or_else(|| std::io::Error::other("no relays connected"))?;
        tokio::time::timeout(
            Duration::from_secs(15),
            libkeychat::mls::transport::fetch_key_package(relay, &peer_pubkey),
        )
        .await??
    };
    println!(
        "  KeyPackage fetched: {}...",
        &peer_kp_hex[..40.min(peer_kp_hex.len())]
    );

    // Step 2: Create MLS group
    let nid2 = nostr_id.clone();
    let group_id = tokio::task::spawn_blocking(move || {
        libkeychat::mls::create_mls_group(&nid2, "libkeychat-interop-test")
    })
    .await??;
    println!("[2/5] Created MLS group: {}", &group_id[..16]);

    // Step 3: Add peer to group
    let nid3 = nostr_id.clone();
    let gid3 = group_id.clone();
    let pkp = peer_kp_hex.clone();
    let add_result =
        tokio::task::spawn_blocking(move || libkeychat::mls::add_member(&nid3, &gid3, &pkp))
            .await??;
    println!(
        "[3/5] Added peer to group, commit={} bytes, welcome={} bytes",
        add_result.commit_message.len(),
        add_result.welcome.len()
    );

    // Step 4: Get listen key
    let nid4 = nostr_id.clone();
    let gid4 = group_id.clone();
    let listen_key =
        tokio::task::spawn_blocking(move || libkeychat::mls::get_group_listen_key(&nid4, &gid4))
            .await??;
    println!("[4/6] Listen key: {}", &listen_key[..16]);

    // Step 4.5: Subscribe to listen key BEFORE sending Welcome
    // This prevents the timing race where peer's commit arrives before our subscription.
    let nid_es = nostr_id.clone();
    let gid_es = group_id.clone();
    let es_keypair = tokio::task::spawn_blocking(move || {
        libkeychat::mls::get_export_secret_keypair(&nid_es, &gid_es)
    })
    .await??;

    let (cipher_tx, cipher_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    for relay in relay_pool.relays() {
        let mut relay_rx =
            libkeychat::mls::transport::receive_group_message(relay, &es_keypair, &listen_key)
                .await;
        let tx = cipher_tx.clone();
        tokio::spawn(async move {
            loop {
                match relay_rx.recv().await {
                    Ok(ciphertext) => {
                        if tx.send(ciphertext).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
    drop(cipher_tx);
    println!("[5/6] Subscribed to listen key, ready to receive");

    // Step 6: Send Welcome to peer via Gift Wrap (kind:1059 with inner kind:444)
    // The Keychat app sends Welcome with additionalTags: [[p, groupId]] only.
    // The receiver (channel.ts handleMlsWelcome) takes innerPTags[0] as group_id.
    // Keychat app sends Welcome as base64 (not hex) — must match for interop.
    use base64::Engine;
    let welcome_b64 = base64::engine::general_purpose::STANDARD.encode(&add_result.welcome);
    let gift = libkeychat::nostr::nip59::create_gift_wrap(
        &keypair,
        &peer_pubkey,
        444, // inner kind: Welcome
        welcome_b64,
        vec![vec!["p".to_owned(), group_id.clone()]],
    )?;

    let mut welcome_sent = false;
    for relay in relay_pool.relays() {
        match relay.publish(&gift).await {
            Ok(()) => {
                println!("[6/6] Welcome sent via {} ✓", relay.url());
                welcome_sent = true;
            }
            Err(err) => eprintln!("  Failed to send Welcome to {}: {err}", relay.url()),
        }
    }

    if !welcome_sent {
        return Err("failed to send Welcome to any relay".into());
    }

    println!("\n=== MLS Group Created ===");
    println!("group_id:   {}", group_id);
    println!("listen_key: {}", listen_key);
    println!("peer:       {}", peer_pubkey);
    println!("\nWaiting for peer to join and send messages...");

    // Inline listen loop (subscriptions already created above)
    let mut listen_key = listen_key;
    let mut es_keypair = es_keypair;
    let mut cipher_rx = cipher_rx;
    let mut seen_hashes: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = relay_pool.disconnect().await;
                break;
            }
            maybe_ciphertext = cipher_rx.recv() => {
                let Some(ciphertext) = maybe_ciphertext else { break; };

                // Dedup: skip if we've seen this exact ciphertext before
                use sha2::{Sha256, Digest};
                let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
                if !seen_hashes.insert(hash) {
                    continue; // duplicate from another relay
                }

                let nid = nostr_id.clone();
                let gid = group_id.clone();
                let ct = ciphertext.clone();

                // Unified message processing — handles both application messages and commits
                let result = tokio::task::spawn_blocking(move || {
                    libkeychat::mls::process_mls_message(&nid, &gid, &ct)
                }).await?;

                match result {
                    Ok(libkeychat::mls::ProcessedMlsMessage::Application {
                        plaintext,
                        sender_nostr_id,
                        ..
                    }) => {
                        println!("✅ [MLS from {}]: {}", sender_nostr_id, plaintext);

                        // Echo reply
                        let reply_text = format!("Echo: {}", plaintext);
                        let nid2 = nostr_id.clone();
                        let gid2 = group_id.clone();
                        if let Ok(reply_ct) = tokio::task::spawn_blocking(move || {
                            libkeychat::mls::encrypt_group_message(&nid2, &gid2, &reply_text)
                        }).await? {
                            let _ = send_mls_echo_to_relays(&relay_pool, &es_keypair, &listen_key, &reply_ct).await;
                            println!("✅ Echo reply sent");
                        }
                    }
                    Ok(libkeychat::mls::ProcessedMlsMessage::Commit {
                        sender,
                        commit_type,
                        listen_key: new_listen_key,
                        ..
                    }) => {
                        println!("✅ [MLS commit from {}]: {:?}", sender, commit_type);

                        if new_listen_key != listen_key {
                            println!("🔄 Listen key rotated: {}... → {}...", &listen_key[..12], &new_listen_key[..12]);
                            let nid_es2 = nostr_id.clone();
                            let gid_es2 = group_id.clone();
                            if let Ok(new_es) = tokio::task::spawn_blocking(move || {
                                libkeychat::mls::get_export_secret_keypair(&nid_es2, &gid_es2)
                            }).await? {
                                es_keypair = new_es;
                            }
                            listen_key = new_listen_key;

                            // Re-subscribe on new listen key
                            let (new_tx, new_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                            for relay in relay_pool.relays() {
                                let mut relay_rx =
                                    libkeychat::mls::transport::receive_group_message(relay, &es_keypair, &listen_key).await;
                                let tx = new_tx.clone();
                                tokio::spawn(async move {
                                    loop {
                                        match relay_rx.recv().await {
                                            Ok(ct) => { if tx.send(ct).await.is_err() { break; } }
                                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                        }
                                    }
                                });
                            }
                            drop(new_tx);
                            cipher_rx = new_rx;
                            println!("📡 Re-subscribed on new listen key");

                            // Wait for peer's subscription to settle, then send test message
                            println!("⏳ Waiting 5s for peer subscription to settle...");
                            tokio::time::sleep(Duration::from_secs(5)).await;

                            let nid_msg = nostr_id.clone();
                            let gid_msg = group_id.clone();
                            let msg_text = "Hello from libkeychat! 🦀".to_string();
                            if let Ok(ct) = tokio::task::spawn_blocking(move || {
                                libkeychat::mls::encrypt_group_message(&nid_msg, &gid_msg, &msg_text)
                            }).await? {
                                let _ = send_mls_echo_to_relays(&relay_pool, &es_keypair, &listen_key, &ct).await;
                                println!("📤 Sent test message to peer");
                            }
                        }
                    }
                    Err(err) => {
                        let err_str = err.to_string();
                        if err_str.contains("Cannot decrypt own messages") {
                            continue; // normal MLS behavior
                        }
                        eprintln!("⚠ failed to process MLS message: {err}");
                    }
                }
            }
        }
    }

    Ok(())
}

async fn wait_for_kind4_reply(
    relay_pool: &mut RelayPool,
    local_nostr: &NostrKeypair,
    local_signal: &mut SignalParticipant,
    runtime: &mut RuntimeState,
    remote_signal_address: &ProtocolAddress,
    subscriptions: &BTreeMap<String, String>,
    peer_id: &str,
) -> DynResult<libkeychat::protocol::message_types::KeychatMessage> {
    loop {
        let event = relay_pool
            .next_event()
            .await
            .ok_or_else(|| std::io::Error::other("relay closed"))?;
        if event.kind != 4 {
            continue;
        }
        let Some(address) = event.first_tag_value("p") else {
            eprintln!("[debug] kind:4 event without p-tag, skipping");
            continue;
        };
        eprintln!(
            "[debug] kind:4 event to address: {}, from pubkey: {}, content len: {}",
            address,
            &event.pubkey[..16],
            event.content.len()
        );
        if !subscriptions.contains_key(address) {
            eprintln!("[debug] address not in our subscriptions, skipping");
            continue;
        }
        eprintln!("[debug] matched subscription, attempting decrypt...");

        match receive_message(
            local_nostr,
            local_signal,
            remote_signal_address,
            &mut runtime.address_manager,
            peer_id,
            &event,
        ) {
            Ok(received) => return Ok(received.message),
            Err(err) => {
                eprintln!("failed to decrypt or parse kind:4 reply: {err}");
                continue;
            }
        }
    }
}

async fn apply_address_changes(
    relay_pool: &RelayPool,
    subscriptions: &mut BTreeMap<String, String>,
    changes: &[AddressChange],
) -> DynResult<()> {
    for change in changes {
        eprintln!("[addr] change: {:?}", change);
        match change {
            AddressChange::Subscribe(address) => {
                eprintln!("[addr] subscribing kind:4 p-tag: {}", address);
                subscribe_kind4_address(relay_pool, subscriptions, address.clone()).await?;
            }
            AddressChange::Unsubscribe(address) => {
                eprintln!("[addr] unsubscribing: {}", address);
                if let Some(sub_id) = subscriptions.remove(address) {
                    relay_pool.unsubscribe(&sub_id).await?;
                }
            }
            AddressChange::UpdateSendAddr { .. } => {}
        }
    }
    Ok(())
}

async fn subscribe_kind4_address(
    relay_pool: &RelayPool,
    subscriptions: &mut BTreeMap<String, String>,
    address: String,
) -> DynResult<()> {
    if subscriptions.contains_key(&address) {
        return Ok(());
    }

    let sub_id = relay_pool
        .subscribe(RelayFilter::new().with_kind(4).with_p_tag(address.clone()))
        .await?;
    subscriptions.insert(address, sub_id);
    Ok(())
}

fn load_or_create_identity() -> DynResult<(IdentityRecord, NostrKeypair)> {
    let path = identity_path()?;
    if path.exists() {
        let record: IdentityRecord = serde_json::from_slice(&fs::read(path)?)?;
        let mnemonic = recover_mnemonic(&record.mnemonic)?;
        return Ok((record, nostr_keypair_from_mnemonic(&mnemonic)?));
    }

    let mnemonic = generate_mnemonic(12)?;
    let keys = nostr_keypair_from_mnemonic(&mnemonic)?;
    let record = IdentityRecord {
        mnemonic: mnemonic.to_string(),
        npub: keys.npub()?,
        pubkey_hex: keys.public_key_hex(),
    };
    save_identity(&record)?;
    Ok((record, keys))
}

fn save_identity(record: &IdentityRecord) -> DynResult<()> {
    let path = identity_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(record)?)?;
    Ok(())
}

fn load_or_create_signal(state: &RuntimeState) -> DynResult<SignalParticipant> {
    if let Some(snapshot) = state.signal.clone() {
        return Ok(SignalParticipant::from_snapshot(snapshot)?);
    }

    let prekeys = generate_prekey_material()?;
    let name = hex::encode(prekeys.identity_key_pair.identity_key().serialize());
    Ok(SignalParticipant::from_prekey_material(name, 1, prekeys)?)
}

fn load_runtime_state(path: &Path) -> DynResult<RuntimeState> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = open_state_db(path)?;
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM app_state WHERE key = ?1",
            params![STATE_KEY],
            |row| row.get(0),
        )
        .optional()?;

    match value {
        Some(value) => Ok(serde_json::from_str(&value)?),
        None => Ok(RuntimeState::default()),
    }
}

fn persist_runtime_state(
    path: &Path,
    signal: &mut SignalParticipant,
    runtime: &RuntimeState,
) -> DynResult<()> {
    let mut to_store = runtime.clone();
    to_store.signal = Some(signal.snapshot()?);

    let conn = open_state_db(path)?;
    conn.execute(
        "INSERT INTO app_state (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![STATE_KEY, serde_json::to_string(&to_store)?],
    )?;
    Ok(())
}

fn open_state_db(path: &Path) -> DynResult<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS app_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )?;
    Ok(conn)
}

fn normalize_relays(relays: Vec<String>) -> Vec<String> {
    if relays.is_empty() {
        return DEFAULT_RELAYS
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
    }
    relays
}

fn decode_pubkey(value: &str) -> DynResult<String> {
    if value.starts_with("npub1") {
        return Ok(hex::encode(libkeychat::identity::bech32::decode_npub(
            value,
        )?));
    }
    Ok(value.to_owned())
}

fn app_dir() -> DynResult<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("HOME is not set"))?;
    Ok(home.join(".libkeychat"))
}

fn identity_path() -> DynResult<PathBuf> {
    Ok(app_dir()?.join("identity.json"))
}

fn signal_db_path() -> DynResult<PathBuf> {
    Ok(app_dir()?.join("signal.db"))
}

fn mls_db_path() -> DynResult<PathBuf> {
    Ok(app_dir()?.join("mls.sqlite"))
}
