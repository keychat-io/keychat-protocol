//! Terminal UI.

use chrono::Local;
use colored::*;

pub fn banner() {
    println!("{}", "╔═══════════════════════════════════════════╗".cyan());
    println!("{}", "║  Keychat CLI v0.1.0                       ║".cyan());
    println!("{}", "║  E2E encrypted messaging over Nostr       ║".cyan());
    println!("{}", "║  Signal Protocol (PQXDH) + MLS            ║".cyan());
    println!("{}", "╚═══════════════════════════════════════════╝".cyan());
    println!();
}

pub fn identity(npub: &str, name: &str, relays: &[String]) {
    println!("  {} {}", "Name:".dimmed(), name.green());
    println!("  {} {}", "npub:".dimmed(), npub.yellow());
    for r in relays {
        println!("  {} {}", "Relay:".dimmed(), r.blue());
    }
    println!();
}

pub fn help() {
    println!("{}", "── Chat ───────────────────────────────────".bold());
    println!("  {}         Send friend request", "/add <npub>".green());
    println!("  {}        Switch to peer chat", "/chat <npub>".green());
    println!("  {}            List contacts", "/peers".green());
    println!("  {} Rename contact", "/rename <npub> <name>".green());
    println!("  {}      Send a file", "/file <path>".green());
    println!("  {}     Send voice", "/voice <path>".green());
    println!();
    println!("{}", "── Signal Group (small, <50) ───────────────".bold());
    println!("  {}    Create group", "/sg-create <name>".green());
    println!("  {} Invite peer", "/sg-invite <gid> <npub>".green());
    println!("  {}    Switch to group", "/sg-chat <gid>".green());
    println!("  {}     Rename group", "/sg-rename <gid> <name>".green());
    println!("  {}     Leave group", "/sg-leave <gid>".green());
    println!("  {}   Dissolve group", "/sg-dissolve <gid>".green());
    println!("  {}              List groups", "/sg-list".green());
    println!();
    println!("{}", "── MLS Group (large) ──────────────────────".bold());
    println!("  {}   Create MLS group", "/mls-create <name>".green());
    println!("  {}  Add member", "/mls-add <gid> <npub>".green());
    println!("  {}   Switch to MLS group", "/mls-chat <gid>".green());
    println!("  {}    Leave MLS group", "/mls-leave <gid>".green());
    println!("  {}             List MLS groups", "/mls-list".green());
    println!();
    println!("{}", "── Payment ────────────────────────────────".bold());
    println!("  {}  Send cashu", "/cashu <token> <amount>".green());
    println!("  {} Send invoice", "/invoice <bolt11> <amt>".green());
    println!();
    println!("{}", "── Other ──────────────────────────────────".bold());
    println!("  {}              Your identity", "/info".green());
    println!("  {}              This help", "/help".green());
    println!("  {}              Exit", "/quit".green());
    println!();
    println!("  Type text to send to active chat target.");
    println!();
}

pub fn sys(msg: &str) {
    let t = Local::now().format("%H:%M:%S");
    println!("{} {}", format!("[{}]", t).dimmed(), msg.cyan());
}

pub fn sent(text: &str) {
    let t = Local::now().format("%H:%M:%S");
    println!("{} {} {}", format!("[{}]", t).dimmed(), "You:".green().bold(), text);
}

pub fn received(name: &str, text: &str) {
    let t = Local::now().format("%H:%M:%S");
    println!("{} {} {}", format!("[{}]", t).dimmed(), format!("{}:", name).blue().bold(), text);
}

pub fn group_msg(group_name: &str, sender: &str, text: &str) {
    let t = Local::now().format("%H:%M:%S");
    println!("{} {} {} {}",
        format!("[{}]", t).dimmed(),
        format!("[{}]", group_name).magenta(),
        format!("{}:", sender).blue().bold(),
        text);
}

pub fn err(msg: &str) {
    eprintln!("{} {}", "Error:".red().bold(), msg);
}

pub fn prompt(target: Option<&str>) -> String {
    match target {
        Some(t) => format!("{} ", format!("[{}]>", t).green()),
        None => format!("{} ", "[keychat]>".dimmed()),
    }
}
