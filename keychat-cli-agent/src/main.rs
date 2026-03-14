mod chat;
mod config;
mod daemon;
mod groups;
mod media_cmd;
mod multi_agent;
mod multi_daemon;
mod payment_cmd;
mod state;
mod ui;

use clap::Parser;

#[derive(Parser)]
#[command(name = "keychat-agent", version, about = "Keychat v2 — Agent daemon with HTTP API")]
struct Cli {
    /// Path to config/data directory
    #[arg(long, default_value_t = default_data_dir())]
    data_dir: String,

    /// Nostr relay URL(s), comma-separated
    #[arg(long, default_value = "wss://nos.lol")]
    relay: String,

    /// Database encryption key (overrides keychain value)
    #[arg(long)]
    db_key: Option<String>,

    /// HTTP listen address
    #[arg(long, default_value = "127.0.0.1:7700")]
    listen: String,

    /// Auto-accept incoming friend requests (first becomes owner)
    #[arg(long, default_value_t = true)]
    auto_accept: bool,

    /// Agent display name
    #[arg(long)]
    name: Option<String>,

    /// Multi-agent mode: manage multiple agents from one daemon.
    /// Uses <data-dir>/agents/<id>/ for each agent.
    #[arg(long)]
    multi: bool,
}

fn default_data_dir() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("keychat-agent")
        .to_string_lossy()
        .to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let relays: Vec<String> = cli.relay.split(',').map(|s| s.trim().to_string()).collect();

    if cli.multi {
        multi_daemon::run(cli.data_dir, relays, cli.listen).await
    } else {
        daemon::run(cli.data_dir, relays, cli.db_key, cli.listen, cli.auto_accept, cli.name).await
    }
}
