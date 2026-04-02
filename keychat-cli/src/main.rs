use std::sync::Arc;

use clap::{Parser, Subcommand};
use keychat_cli::{agent_daemon, commands, daemon, repl, tui};
use keychat_uniffi::KeychatClient;

#[derive(Parser)]
#[command(
    name = "keychat",
    about = "Keychat — E2E encrypted messaging over Nostr",
    long_about = "Keychat CLI provides four interface modes:\n\n\
        • tui (default)   — Full terminal UI with room list, messages, and input\n\
        • interactive      — Simple REPL with slash commands\n\
        • daemon           — HTTP REST API + SSE event stream\n\
        • agent            — Headless daemon for AI frameworks\n\n\
        Examples:\n\
        \x20 keychat                          Start TUI mode\n\
        \x20 keychat tui                      Start TUI mode (explicit)\n\
        \x20 keychat interactive              Start REPL mode\n\
        \x20 keychat daemon --port 9000       Start HTTP daemon on port 9000\n\
        \x20 keychat daemon --interactive     Daemon + REPL together\n\
        \x20 keychat agent                    Start agent on port 10443\n\
        \x20 keychat agent --name MyBot       Agent with custom name\n\
        \x20 keychat --data-dir /tmp/bob tui  Use custom data directory",
    version
)]
struct Cli {
    /// Database directory (default: ~/.keychat)
    #[arg(long, default_value_t = default_data_dir())]
    data_dir: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Start full terminal UI with room list and message panels (default)
    Tui,
    /// Start simple REPL with slash commands
    Interactive,
    /// Start HTTP daemon mode (REST API + SSE)
    Daemon {
        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,
        /// Also start interactive REPL alongside the daemon
        #[arg(long)]
        interactive: bool,
    },
    /// Start headless agent daemon for AI frameworks
    Agent {
        /// Port to listen on
        #[arg(long, default_value = "10443")]
        port: u16,
        /// Disable auto-accept friend requests
        #[arg(long)]
        no_auto_accept: bool,
        /// Agent display name
        #[arg(long, default_value = "Keychat Agent")]
        name: String,
        /// Relay URLs (comma-separated, overrides defaults)
        #[arg(long)]
        relay: Option<String>,
        /// API authentication token (auto-generated if not provided)
        #[arg(long)]
        api_token: Option<String>,
    },
}

fn default_data_dir() -> String {
    dirs::home_dir()
        .map(|p| p.join(".keychat").to_string_lossy().to_string())
        .unwrap_or_else(|| ".keychat".to_string())
}

/// Initialize logging: write to dated file under {data_dir}/logs/, keep last 7 days.
/// Falls back to stderr if file creation fails.
fn init_logging(data_dir: &str, mode: &str) {
    let default_filter = "keychat=info,keychat_uniffi=info,keychat_cli=info";
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| default_filter.into());

    let logs_dir = format!("{data_dir}/logs");
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        // Fall back to stderr if we can't create the log directory
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
        tracing::warn!("Cannot create log dir {logs_dir}: {e}, logging to stderr");
        return;
    }

    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let log_path = format!("{logs_dir}/keychat-{today}.log");

    // Clean up logs older than 7 days (best-effort)
    let _ = cleanup_old_logs(&logs_dir, 7);

    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&log_path)
    {
        Ok(log_file) => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_writer(std::sync::Mutex::new(log_file))
                .with_ansi(false)
                .init();
            tracing::info!("=== keychat-cli started ({mode} mode) ===");
            tracing::info!("Log: {log_path}");
            tracing::info!("Data: {data_dir}");
        }
        Err(e) => {
            // Fall back to stderr
            tracing_subscriber::fmt().with_env_filter(env_filter).init();
            tracing::warn!("Cannot open log file {log_path}: {e}, logging to stderr");
            tracing::info!("=== keychat-cli started ({mode} mode) ===");
        }
    }
}

/// Clean up log files older than N days from the logs directory.
fn cleanup_old_logs(logs_dir: &str, days: i64) -> anyhow::Result<()> {
    let cutoff = chrono::Local::now() - chrono::Duration::days(days);

    if let Ok(entries) = std::fs::read_dir(logs_dir) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let modified_chrono = chrono::DateTime::<chrono::Local>::from(modified);
                    if modified_chrono < cutoff {
                        if let Ok(filename) = entry.file_name().into_string() {
                            if filename.starts_with("keychat-") && filename.ends_with(".log") {
                                let path = entry.path();
                                if let Err(e) = std::fs::remove_file(&path) {
                                    eprintln!("Failed to delete old log {filename}: {e}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let command = cli.command.clone().unwrap_or(Commands::Tui);

    let mode = match &command {
        Commands::Tui => "tui",
        Commands::Daemon { .. } => "daemon",
        Commands::Agent { .. } => "agent",
        _ => "interactive",
    };
    init_logging(&cli.data_dir, mode);

    // Agent mode manages its own client lifecycle
    if let Commands::Agent {
        port,
        no_auto_accept,
        name,
        relay,
        api_token,
    } = command
    {
        agent_daemon::run(cli.data_dir, port, !no_auto_accept, name, relay, api_token).await?;
        return Ok(());
    }

    // Standard modes: shared client initialization
    // Create subdirectories: db/, files/, logs/
    let db_dir = format!("{}/db", cli.data_dir);
    std::fs::create_dir_all(&db_dir)?;

    let db_path = format!("{}/protocol.db", db_dir);
    let db_key = commands::get_or_create_db_key(&db_dir)?;

    let client = Arc::new(KeychatClient::new(db_path, db_key)?);

    // Set up event and data listeners
    let (event_tx, _) = tokio::sync::broadcast::channel(256);
    let (data_tx, _) = tokio::sync::broadcast::channel(256);

    let event_listener = commands::CliEventListener::new(event_tx.clone());
    let data_listener = commands::CliDataListener::new(data_tx.clone());
    client.set_event_listener(Box::new(event_listener)).await;
    client.set_data_listener(Box::new(data_listener)).await;

    match command {
        Commands::Tui => {
            tui::run(client, event_tx, data_tx, cli.data_dir).await?;
        }
        Commands::Interactive => {
            repl::run(client, event_tx, data_tx, cli.data_dir).await?;
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
                repl::run(client, event_tx, data_tx, cli.data_dir).await?;
                daemon_handle.abort();
            } else {
                daemon::run(client, event_tx, data_tx, port).await?;
            }
        }
        Commands::Agent { .. } => unreachable!(),
    }

    Ok(())
}
