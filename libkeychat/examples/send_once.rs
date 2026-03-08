//! Send a single message to a peer using an existing session.
//! Usage: cargo run --example send_once -- --peer <hex> --db <path> --mnemonic "<words>" --msg "<text>"

use libkeychat::client::types::ClientConfig;
use libkeychat::client::KeychatClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut peer = String::new();
    let mut db = String::new();
    let mut mnemonic = String::new();
    let mut msg = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--peer" => {
                peer = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--db" => {
                db = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--mnemonic" => {
                mnemonic = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            "--msg" => {
                msg = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            _ => i += 1,
        }
    }

    let config = ClientConfig {
        mnemonic: Some(mnemonic),
        db_path: db,
        display_name: "libkeychat".to_string(),
        relays: vec![
            "wss://relay.keychat.io".into(),
            "wss://relay.damus.io".into(),
            "wss://relay.primal.net".into(),
            "wss://nostr.mom".into(),
        ],
        media_server: None,
    };

    let mut client = KeychatClient::init(config).await?;
    client.start_listening().await?;
    println!("[init] Session restored");

    let payload = format!(
        r#"{{"type":100,"c":"signal","msg":"{}"}}"#,
        msg.replace('"', r#"\""#)
    );
    client.send(&peer, &payload).await?;
    println!("[send] ✅ Sent: {msg}");

    Ok(())
}
