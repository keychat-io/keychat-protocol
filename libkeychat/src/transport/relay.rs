use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::error::{KeychatError, Result};
use crate::nostr::NostrEvent;

const INITIAL_BACKOFF_MS: u64 = 250;
const MAX_BACKOFF_MS: u64 = 8_000;
const COMMAND_BUFFER: usize = 256;
const EVENT_BUFFER: usize = 256;

type RelaySocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Clone, Debug)]
pub struct RelayConnection {
    pub(crate) url: String,
    sender: mpsc::Sender<RelayCommand>,
    events: broadcast::Sender<NostrEvent>,
}

#[derive(Debug)]
pub enum RelayCommand {
    Publish {
        event: NostrEvent,
        stamp_token: Option<String>,
        ack: oneshot::Sender<Result<()>>,
    },
    Subscribe {
        id: String,
        filter: RelayFilter,
    },
    Unsubscribe {
        id: String,
    },
    Disconnect,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RelayFilter {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
    #[serde(rename = "#p", skip_serializing_if = "Vec::is_empty")]
    pub p_tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

enum RelayLoopState {
    Reconnect,
    Shutdown,
}

impl RelayConnection {
    pub async fn connect(url: impl Into<String>) -> Result<Self> {
        Self::connect_with_forwarder(url.into(), None).await
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<NostrEvent> {
        self.events.subscribe()
    }

    pub async fn publish(&self, event: &NostrEvent) -> Result<()> {
        self.publish_with_stamp(event, None).await
    }

    pub async fn publish_with_stamp(&self, event: &NostrEvent, stamp: Option<String>) -> Result<()> {
        event.verify()?;
        let (ack_tx, ack_rx) = oneshot::channel();
        self.sender
            .send(RelayCommand::Publish {
                event: event.clone(),
                stamp_token: stamp,
                ack: ack_tx,
            })
            .await
            .map_err(|_| KeychatError::Nostr("relay task stopped".to_owned()))?;
        match tokio::time::timeout(std::time::Duration::from_secs(10), ack_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(KeychatError::Nostr(format!(
                "relay {} publish ack dropped",
                self.url
            ))),
            Err(_) => Err(KeychatError::Nostr(format!(
                "relay {} publish ack timeout (10s)",
                self.url
            ))),
        }
    }

    pub async fn subscribe(&self, id: impl Into<String>, filter: RelayFilter) -> Result<()> {
        self.sender
            .send(RelayCommand::Subscribe {
                id: id.into(),
                filter,
            })
            .await
            .map_err(|_| KeychatError::Nostr("relay task stopped".to_owned()))
    }

    pub async fn unsubscribe(&self, id: impl Into<String>) -> Result<()> {
        self.sender
            .send(RelayCommand::Unsubscribe { id: id.into() })
            .await
            .map_err(|_| KeychatError::Nostr("relay task stopped".to_owned()))
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.sender
            .send(RelayCommand::Disconnect)
            .await
            .map_err(|_| KeychatError::Nostr("relay task stopped".to_owned()))
    }

    pub(crate) async fn connect_with_forwarder(
        url: String,
        forwarder: Option<mpsc::Sender<NostrEvent>>,
    ) -> Result<Self> {
        validate_relay_url(&url)?;

        let (sender, receiver) = mpsc::channel(COMMAND_BUFFER);
        let (events, _) = broadcast::channel(EVENT_BUFFER);

        let task_url = url.clone();
        let task_events = events.clone();
        tokio::spawn(async move {
            relay_task(task_url, receiver, task_events, forwarder).await;
        });

        Ok(Self {
            url,
            sender,
            events,
        })
    }
}

impl RelayFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter for MLS KeyPackages (kind:10443) by author pubkey.
    /// Note: Keychat app/bridge publishes KeyPackages without p-tags,
    /// so we filter by `authors` (event pubkey), not by p-tag.
    pub fn for_key_packages(author_pubkey_hex: impl Into<String>) -> Self {
        Self::new().with_kind(10443).with_author(author_pubkey_hex)
    }

    pub fn for_welcomes(recipient_pubkey_hex: impl Into<String>) -> Self {
        Self::new().with_kind(444).with_p_tag(recipient_pubkey_hex)
    }

    pub fn for_group_messages(listen_key_pubkey_hex: impl Into<String>) -> Self {
        Self::new()
            .with_kind(1059)
            .with_p_tag(listen_key_pubkey_hex)
    }

    pub fn with_kind(mut self, kind: u16) -> Self {
        if !self.kinds.contains(&kind) {
            self.kinds.push(kind);
        }
        self
    }

    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.authors.push(author.into());
        self
    }

    pub fn with_p_tag(mut self, value: impl Into<String>) -> Self {
        self.p_tags.push(value.into());
        self
    }

    /// Set the `since` timestamp (only return events created after this Unix time).
    pub fn with_since(mut self, unix_secs: u64) -> Self {
        self.since = Some(unix_secs);
        self
    }
}

async fn relay_task(
    url: String,
    mut receiver: mpsc::Receiver<RelayCommand>,
    events: broadcast::Sender<NostrEvent>,
    forwarder: Option<mpsc::Sender<NostrEvent>>,
) {
    let mut backoff_ms = INITIAL_BACKOFF_MS;
    let mut subscriptions = BTreeMap::new();

    loop {
        match connect_async(url.as_str()).await {
            Ok((socket, _)) => {
                backoff_ms = INITIAL_BACKOFF_MS;
                match run_connected(
                    socket,
                    &mut receiver,
                    &events,
                    forwarder.clone(),
                    &mut subscriptions,
                )
                .await
                {
                    RelayLoopState::Reconnect => {}
                    RelayLoopState::Shutdown => break,
                }
            }
            Err(_) => {
                if receiver.is_closed() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms.saturating_mul(2)).min(MAX_BACKOFF_MS);
            }
        }
    }
}

async fn run_connected(
    mut socket: RelaySocket,
    receiver: &mut mpsc::Receiver<RelayCommand>,
    events: &broadcast::Sender<NostrEvent>,
    forwarder: Option<mpsc::Sender<NostrEvent>>,
    subscriptions: &mut BTreeMap<String, RelayFilter>,
) -> RelayLoopState {
    let mut pending_acks: BTreeMap<String, oneshot::Sender<Result<()>>> = BTreeMap::new();

    for (id, filter) in subscriptions.iter() {
        if send_subscription(&mut socket, id, filter).await.is_err() {
            fail_pending_acks(&mut pending_acks, "relay send failed");
            return RelayLoopState::Reconnect;
        }
    }

    loop {
        tokio::select! {
            command = receiver.recv() => {
                let Some(command) = command else {
                    fail_pending_acks(&mut pending_acks, "relay task stopped");
                    return RelayLoopState::Shutdown;
                };

                match command {
                    RelayCommand::Publish { event, stamp_token, ack } => {
                        let event_id = event.id.clone();
                        match send_publish(&mut socket, &event, stamp_token.as_deref()).await {
                            Ok(()) => {
                                pending_acks.insert(event_id, ack);
                            }
                            Err(err) => {
                                let _ = ack.send(Err(err));
                                fail_pending_acks(&mut pending_acks, "relay disconnected");
                                return RelayLoopState::Reconnect;
                            }
                        }
                    }
                    RelayCommand::Subscribe { id, filter } => {
                        subscriptions.insert(id.clone(), filter.clone());
                        if send_subscription(&mut socket, &id, &filter).await.is_err() {
                            fail_pending_acks(&mut pending_acks, "relay disconnected");
                            return RelayLoopState::Reconnect;
                        }
                    }
                    RelayCommand::Unsubscribe { id } => {
                        subscriptions.remove(&id);
                        if send_close(&mut socket, &id).await.is_err() {
                            fail_pending_acks(&mut pending_acks, "relay disconnected");
                            return RelayLoopState::Reconnect;
                        }
                    }
                    RelayCommand::Disconnect => {
                        let _ = socket.close(None).await;
                        fail_pending_acks(&mut pending_acks, "relay disconnected");
                        return RelayLoopState::Shutdown;
                    }
                }
            }
            message = socket.next() => {
                match message {
                    Some(Ok(Message::Text(text))) => {
                        if handle_relay_message(&text, events, forwarder.clone(), &mut pending_acks).await.is_err() {
                            fail_pending_acks(&mut pending_acks, "relay protocol error");
                            return RelayLoopState::Reconnect;
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        let Ok(text) = String::from_utf8(bytes.to_vec()) else {
                            continue;
                        };
                        if handle_relay_message(&text, events, forwarder.clone(), &mut pending_acks).await.is_err() {
                            fail_pending_acks(&mut pending_acks, "relay protocol error");
                            return RelayLoopState::Reconnect;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            fail_pending_acks(&mut pending_acks, "relay disconnected");
                            return RelayLoopState::Reconnect;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                        fail_pending_acks(&mut pending_acks, "relay disconnected");
                        return RelayLoopState::Reconnect;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Frame(_))) => {}
                }
            }
        }
    }
}

async fn handle_relay_message(
    text: &str,
    events: &broadcast::Sender<NostrEvent>,
    forwarder: Option<mpsc::Sender<NostrEvent>>,
    pending_acks: &mut BTreeMap<String, oneshot::Sender<Result<()>>>,
) -> Result<()> {
    let message: Value = serde_json::from_str(text)?;
    let Some(items) = message.as_array() else {
        return Ok(());
    };
    let Some(kind) = items.first().and_then(Value::as_str) else {
        return Ok(());
    };

    match kind {
        "EVENT" if items.len() >= 3 => {
            let event: NostrEvent = serde_json::from_value(items[2].clone())?;
            let _ = events.send(event.clone());
            if let Some(forwarder) = forwarder {
                let _ = forwarder.send(event).await;
            }
        }
        "OK" if items.len() >= 4 => {
            let Some(event_id) = items[1].as_str() else {
                return Ok(());
            };
            let accepted = items[2].as_bool().unwrap_or(false);
            let message = items[3].as_str().unwrap_or("relay rejected event");
            if let Some(ack) = pending_acks.remove(event_id) {
                let result = if accepted {
                    Ok(())
                } else {
                    Err(KeychatError::Nostr(message.to_owned()))
                };
                let _ = ack.send(result);
            }
        }
        "EOSE" => {}
        _ => {}
    }

    Ok(())
}

async fn send_publish(socket: &mut RelaySocket, event: &NostrEvent, stamp: Option<&str>) -> Result<()> {
    let payload = match stamp {
        Some(token) => serde_json::json!(["EVENT", event, token]),
        None => serde_json::json!(["EVENT", event]),
    };
    send_json(socket, &payload).await
}

async fn send_subscription(socket: &mut RelaySocket, id: &str, filter: &RelayFilter) -> Result<()> {
    send_json(socket, &serde_json::json!(["REQ", id, filter])).await
}

async fn send_close(socket: &mut RelaySocket, id: &str) -> Result<()> {
    send_json(socket, &serde_json::json!(["CLOSE", id])).await
}

async fn send_json(socket: &mut RelaySocket, value: &Value) -> Result<()> {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .map_err(|err| KeychatError::Nostr(err.to_string()))
}

fn fail_pending_acks(
    pending_acks: &mut BTreeMap<String, oneshot::Sender<Result<()>>>,
    reason: &str,
) {
    for (_, ack) in std::mem::take(pending_acks) {
        let _ = ack.send(Err(KeychatError::Nostr(reason.to_owned())));
    }
}

fn validate_relay_url(url: &str) -> Result<()> {
    if url.starts_with("ws://") || url.starts_with("wss://") {
        return Ok(());
    }
    Err(KeychatError::InvalidRelayUrl(url.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::RelayFilter;

    #[test]
    fn filter_serializes_as_nip01_json() {
        let filter = RelayFilter::new()
            .with_kind(1059)
            .with_author("alice")
            .with_p_tag("bob");
        let json = serde_json::to_string(&filter).expect("filter json");
        assert_eq!(
            json,
            r##"{"kinds":[1059],"authors":["alice"],"#p":["bob"]}"##
        );
    }
}
