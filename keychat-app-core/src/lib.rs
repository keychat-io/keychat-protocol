//! keychat-app-core — shared application layer for all UI clients.
//!
//! Contains app-level persistence (rooms, messages, contacts, settings),
//! relay send tracking, and the `OrchestratorDelegate` implementation
//! that bridges protocol events to app storage and UI notifications.

pub mod app_client;
pub mod app_storage;
pub mod event_loop;
pub mod friend_request;
pub mod group;
pub mod messaging;
pub mod relay_tracker;
pub mod types;

pub use app_client::{
    AppClient, AppClientInner, AppError, AppResult,
    default_device_id, lock_app_storage, lock_app_storage_result,
};
pub use app_storage::AppStorage;
pub use relay_tracker::{RelaySendTracker, RelayStatusUpdate};
pub use types::*;
