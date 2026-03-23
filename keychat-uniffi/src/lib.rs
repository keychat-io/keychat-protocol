mod error;
mod types;

pub use error::KeychatUniError;
pub use types::*;

uniffi::setup_scaffolding!();
