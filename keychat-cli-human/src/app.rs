//! Application lifecycle.

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

use crate::chat;
use crate::commands;
use crate::config::Config;
use crate::state::AppState;
use crate::ui;

pub async fn run(data_dir: String, relay_urls: Vec<String>, db_key: Option<String>) -> Result<()> {
    let data_path = Path::new(&data_dir);
    std::fs::create_dir_all(data_path)?;

    ui::banner();

    // Load or create identity — mnemonic in OS keychain
    let (identity, config) = match Config::load(data_path)? {
        Some(config) => {
            ui::sys("Identity loaded");
            let pubkey_hex = config.pubkey_hex.as_deref()
                .ok_or_else(|| anyhow::anyhow!("config.json missing pubkey_hex"))?;
            let mnemonic = crate::config::load_mnemonic(pubkey_hex)?;
            let identity = libkeychat::Identity::from_mnemonic_str(&mnemonic)?;
            (identity, config)
        }
        None => {
            println!("  First run — creating identity.\n");
            let name = prompt_input("  Your name: ")?;
            let gen = libkeychat::Identity::generate()?;
            let pubkey_hex = gen.identity.pubkey_hex();

            // Store mnemonic in OS keychain
            crate::config::store_mnemonic(&pubkey_hex, &gen.mnemonic)?;

            // Generate and store DB key in OS keychain
            let generated_db_key = crate::config::generate_db_key();
            crate::config::store_db_key(&pubkey_hex, &generated_db_key)?;

            let config = Config {
                name,
                relays: relay_urls.clone(),
                auto_accept_friends: true,
                owner: None,
                pubkey_hex: Some(pubkey_hex.clone()),
            };
            config.save(data_path)?;

            println!();
            println!("  ✅ Identity created. Mnemonic stored in OS keychain.");
            println!("  💡 Use /backup to view your mnemonic when needed.");
            println!();
            (gen.identity, config)
        }
    };

    // Resolve DB key: CLI arg > keychain > legacy fallback
    let db_key = match db_key {
        Some(k) => k,
        None => crate::config::load_db_key(&identity.pubkey_hex())
            .unwrap_or_else(|_| "keychat-cli-default-key".to_string()),
    };

    let relays = if relay_urls.len() > 1 || relay_urls[0] != "wss://nos.lol" {
        relay_urls  // CLI override
    } else {
        config.relays.clone()
    };

    ui::identity(&identity.pubkey_hex(), &config.name, &relays);

    let state = Arc::new(
        AppState::new(identity, config, &relays, data_path, &db_key).await?
    );

    ui::sys(&format!("Connected to {} relay(s)", relays.len()));
    println!();
    ui::help();

    // Background listener (REPL doesn't use SSE but we need the event_tx for the unified API)
    let (event_tx, _) = tokio::sync::broadcast::channel(256);
    let listener = state.clone();
    let ltx = event_tx.clone();
    tokio::spawn(async move {
        chat::start_listener(listener, ltx).await;
    });

    // REPL
    let mut rl = rustyline::DefaultEditor::new()?;
    let hist = data_path.join("history.txt");
    let _ = rl.load_history(&hist);

    loop {
        let target = state.active_chat.read().await.as_ref().map(|t| t.to_string());
        let prompt = ui::prompt(target.as_deref());

        match rl.readline(&prompt) {
            Ok(line) => {
                let _ = rl.add_history_entry(&line);
                match commands::handle(&state, &line).await {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(e) => ui::err(&format!("{}", e)),
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                ui::sys("Ctrl-C — /quit to exit");
            }
            Err(rustyline::error::ReadlineError::Eof) => break,
            Err(e) => {
                ui::err(&format!("{}", e));
                break;
            }
        }
    }

    let _ = rl.save_history(&hist);
    state.client.disconnect().await?;
    ui::sys("Goodbye!");
    Ok(())
}

fn prompt_input(prompt: &str) -> Result<String> {
    let mut rl = rustyline::DefaultEditor::new()?;
    loop {
        match rl.readline(prompt) {
            Ok(s) if !s.trim().is_empty() => return Ok(s.trim().to_string()),
            Ok(_) => println!("  Cannot be empty."),
            Err(_) => return Ok("Anon".to_string()),
        }
    }
}
