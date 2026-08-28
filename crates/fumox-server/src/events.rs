//! In-process event bus for admin-panel push updates (ADMIN_PLAN §9).
//!
//! The scheduler publishes fetch lifecycle events here; the SSE endpoint
//! (`GET /admin/events`) subscribes and forwards them to the browser,
//! interleaving periodic `probe.stats` / `heartbeat` events read from the
//! database. Polling fragments keep working as the no-JS fallback — SSE is
//! a pure enhancement.

use tokio::sync::broadcast;

/// One published event. `name` is the SSE event name (`fetch.done`, …),
/// `data` is the JSON payload.
#[derive(Clone, Debug)]
pub struct Event {
    pub name: &'static str,
    pub data: serde_json::Value,
}

/// Fan-out channel; cloning the bus shares the same underlying channel.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        // Small buffer: SSE consumers tolerate dropped events (the next
        // periodic stats tick repairs any missed state).
        let (tx, _) = broadcast::channel(64);
        Self { tx }
    }

    /// Publish an event; with no subscribers the value is dropped.
    pub fn publish(&self, name: &'static str, data: serde_json::Value) {
        let _ = self.tx.send(Event { name, data });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_reaches_subscribers() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();
        bus.publish("fetch.done", serde_json::json!({"source_id": "s1"}));
        let event = rx.recv().await.unwrap();
        assert_eq!(event.name, "fetch.done");
        assert_eq!(event.data["source_id"], "s1");
    }

    #[tokio::test]
    async fn publish_without_subscribers_is_fine() {
        let bus = EventBus::new();
        bus.publish("heartbeat", serde_json::json!({}));
    }
}
