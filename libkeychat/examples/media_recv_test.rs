use libkeychat::client::{ClientConfig, InboundEvent, KeychatClient};
use libkeychat::media::{parse_media_url, decrypt_file};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mnemonic = args.iter().position(|a| a == "--mnemonic")
        .and_then(|i| args.get(i + 1)).cloned();
    let db = args.iter().position(|a| a == "--db")
        .and_then(|i| args.get(i + 1)).cloned()
        .unwrap_or("/tmp/media_recv.db".into());

    let config = ClientConfig {
        db_path: db,
        display_name: "MediaRecv".into(),
        relays: vec![
            "wss://relay.keychat.io".into(),
            "wss://relay.damus.io".into(),
            "wss://relay.primal.net".into(),
            "wss://nos.lol".into(),
        ],
        mnemonic,
        media_server: None,
    };

    let mut client = KeychatClient::init(config).await?;
    println!("[init] npub: {}", client.npub()?);
    println!("[init] mnemonic: {}", client.mnemonic().unwrap_or("(none)"));
    client.start_listening().await?;
    println!("[listen] Waiting for messages (120s)...\n");

    let timeout = tokio::time::Instant::now() + Duration::from_secs(120);
    while tokio::time::Instant::now() < timeout {
        match tokio::time::timeout(Duration::from_secs(5), client.next_event()).await {
            Ok(Some(InboundEvent::DirectMessage { sender, plaintext, .. })) => {
                println!("[dm] From {}...", &sender[..12.min(sender.len())]);

                if let Some(info) = parse_media_url(&plaintext) {
                    println!("[media] ✅ Parsed media URL!");
                    println!("  kctype: {}", info.kctype);
                    println!("  suffix: {}", info.suffix);
                    println!("  size: {}", info.size);
                    println!("  source: {:?}", info.source_name);
                    println!("  url: {}", info.url);

                    println!("[media] Downloading...");
                    let resp = reqwest::get(&info.url).await?;
                    if !resp.status().is_success() {
                        println!("[media] ❌ Download failed: {}", resp.status());
                        continue;
                    }
                    let encrypted = resp.bytes().await?;
                    println!("[media] Downloaded {} bytes", encrypted.len());

                    match decrypt_file(&encrypted, &info.key, &info.iv) {
                        Ok(decrypted) => {
                            let out_path = format!("/tmp/received_media.{}", info.suffix);
                            std::fs::write(&out_path, &decrypted)?;
                            println!("[media] ✅ Decrypted {} bytes → {}", decrypted.len(), out_path);
                            println!("\n=== Media Receive Test: PASS ===");
                            return Ok(());
                        }
                        Err(e) => println!("[media] ❌ Decrypt failed: {}", e),
                    }
                } else {
                    println!("  text: {}", &plaintext[..80.min(plaintext.len())]);
                }
            }
            Ok(Some(InboundEvent::FriendRequest { sender_name, .. })) => {
                println!("[friend] ✅ Request from {sender_name} — session established");
            }
            _ => {}
        }
    }

    println!("\n=== Timeout — no media received ===");
    Ok(())
}
