mod app;
mod chat;
mod commands;
mod config;
mod groups;
mod media_cmd;
mod payment_cmd;
mod state;
mod ui;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "keychat",
    version,
    about = "Keychat v2 — E2E encrypted messaging over Nostr (human client)"
)]
struct Cli {
    /// Path to config/data directory
    #[arg(long, default_value_t = default_data_dir())]
    data_dir: String,

    /// Nostr relay URL(s), comma-separated
    #[arg(
        long,
        default_value = "wss://relay.keychat.io,wss://relay.damus.io,wss://relay.primal.net,wss://relay.ditto.pub"
    )]
    relay: String,

    /// Database encryption key (in production, use OS keychain)
    #[arg(long)]
    db_key: Option<String>,
}

fn default_data_dir() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("keychat-cli")
        .to_string_lossy()
        .to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let relays: Vec<String> = cli.relay.split(',').map(|s| s.trim().to_string()).collect();
    app::run(cli.data_dir, relays, cli.db_key).await
}
