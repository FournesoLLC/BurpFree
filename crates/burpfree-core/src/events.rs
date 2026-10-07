//! Thread-safe pub/sub event bus used by every engine.
//!
//! Every observation (new request/response, websocket message, scan
//! finding, extension log line) is wrapped in a [`TrafficEvent`] and
//! fanned out. Subscribers receive events through tokio broadcast
//! channels so slow consumers do not block fast producers. Each
//! subscriber gets its own [`Subscription`] that it polls.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::ids::TrafficId;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EventKind {
    /// A new transaction (request + optional response) has been observed.
    Transaction { id: TrafficId },
    /// A websocket session was opened.
    WsOpened { id: TrafficId },
    /// A websocket message was observed.
    WsMessage { session_id: TrafficId, message_id: TrafficId },
    /// A websocket session was closed.
    WsClosed { id: TrafficId },
    /// A new scanner finding was produced.
    Finding { id: TrafficId },
    /// A log line from any component.
    Log { source: String, level: String, message: String },
    /// Interceptor is holding a message awaiting user action.
    Intercept { id: TrafficId, direction: String },
    /// Project-level status change (loaded, closed…).
    Project { action: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEvent {
    pub ts_ms: i64,
    pub kind: EventKind,
}

impl TrafficEvent {
    pub fn new(kind: EventKind) -> Self {
        Self {
            ts_ms: crate::traffic::now_ms(),
            kind,
        }
    }
}

/// Fan-out event bus. Cheap to clone (`Arc` under the hood).
#[derive(Debug, Clone)]
pub struct EventBus {
    tx: Arc<broadcast::Sender<TrafficEvent>>,
}

/// A subscription that borrowers poll with [`Subscription::recv`].
pub struct Subscription {
    rx: broadcast::Receiver<TrafficEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(16));
        Self { tx: Arc::new(tx) }
    }

    pub fn subscribe(&self) -> Subscription {
        Subscription { rx: self.tx.subscribe() }
    }

    /// Publish an event. Slow subscribers may miss events (broadcast
    /// semantics); every event is still delivered to prompt ones.
    pub fn publish(&self, event: TrafficEvent) {
        let _ = self.tx.send(event);
    }

    pub fn publish_log(&self, source: &str, level: &str, message: impl Into<String>) {
        self.publish(TrafficEvent::new(EventKind::Log {
            source: source.to_string(),
            level: level.to_string(),
            message: message.into(),
        }));
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl Subscription {
    pub async fn recv(&mut self) -> Option<TrafficEvent> {
        loop {
            match self.rx.recv().await {
                Ok(ev) => return Some(ev),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn fan_out_delivers_to_all() {
        let bus = EventBus::new(16);
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        bus.publish(TrafficEvent::new(EventKind::Transaction { id: TrafficId::new() }));
        let ea = timeout(Duration::from_millis(500), a.recv()).await.unwrap().unwrap();
        let eb = timeout(Duration::from_millis(500), b.recv()).await.unwrap().unwrap();
        assert!(matches!(ea.kind, EventKind::Transaction { .. }));
        assert!(matches!(eb.kind, EventKind::Transaction { .. }));
    }

    #[tokio::test]
    async fn log_helper_works() {
        let bus = EventBus::new(8);
        let mut s = bus.subscribe();
        bus.publish_log("proxy", "info", "listening");
        let e = s.recv().await.unwrap();
        if let EventKind::Log { source, level, message } = e.kind {
            assert_eq!(source, "proxy");
            assert_eq!(level, "info");
            assert_eq!(message, "listening");
        } else {
            panic!("wrong kind");
        }
    }
}
