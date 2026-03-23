mod address;
mod client;
mod error;
mod event_loop;
mod friend_request;
mod messaging;
mod types;

pub use client::KeychatClient;
pub use error::KeychatUniError;
pub use types::*;

uniffi::setup_scaffolding!();
