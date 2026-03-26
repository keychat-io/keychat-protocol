use std::sync::Arc;

use clap::{Parser, Subcommand};
use keychat_cli::{commands, daemon, repl};
use keychat_uniffi::KeychatClient;

#[derive(Parser)]
#[command(name = "keychat", about = "Keychat unified CLI")]
struct Cli {
    /// Database directory (default: ~/.keychat)
    #[arg(long, default_value_t = default_data_dir())]
    data_dir: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive REPL mode
    Interactive,
    /// Start HTTP daemon mode
    Daemon {
        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,
        /// Also start interactive REPL alongside the daemon
        #[arg(long)]
        interactive: bool,
    },
}

fn default_data_dir() -> String {
    dirs::home_dir()
        .map(|p| p.join(".keychat").to_string_lossy().to_string())
        .unwrap_or_else(|| ".keychat".to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keychat=info,keychat_uniffi=info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Ensure data directory exists
    std::fs::create_dir_all(&cli.data_dir)?;

    let db_path = format!("{}/protocol.db", cli.data_dir);
    let db_key = commands::get_or_create_db_key(&cli.data_dir)?;

    let client = Arc::new(KeychatClient::new(db_path, db_key)?);

    // Set up event and data listeners
    let (event_tx, _) = tokio::sync::broadcast::channel(256);
    let (data_tx, _) = tokio::sync::broadcast::channel(256);

    let event_listener = commands::CliEventListener::new(event_tx.clone());
    let data_listener = commands::CliDataListener::new(data_tx.clone());
    client.set_event_listener(Box::new(event_listener)).await;
    client.set_data_listener(Box::new(data_listener)).await;

    match cli.command {
        Commands::Interactive => {
            repl::run(client, event_tx, data_tx).await?;
        }
        Commands::Daemon { port, interactive } => {
            if interactive {
                let client2 = Arc::clone(&client);
                let event_tx2 = event_tx.clone();
                let data_tx2 = data_tx.clone();
                let daemon_handle = tokio::spawn(async move {
                    if let Err(e) = daemon::run(client2, event_tx2, data_tx2, port).await {
                        tracing::error!("daemon error: {e}");
                    }
                });
                repl::run(client, event_tx, data_tx).await?;
                daemon_handle.abort();
            } else {
                daemon::run(client, event_tx, data_tx, port).await?;
            }
        }
    }

    Ok(())
}
