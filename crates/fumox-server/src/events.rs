//! In-process event bus for admin-panel push updates.
//!
//! The scheduler publishes fetch lifecycle events here; the SSE endpoint
//! (`GET /admin/events`) subscribes and forwards them to the browser as
//! one-shot notifications. Polling fragments keep working as the no-JS
//! fallback, SSE is a pure enhancement: a missed event (for example a
//! lagged subscriber) costs a delayed update, not state, since every fragment
//! a `fetch.*` event triggers a refresh for polls on its own too.

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
        // Small buffer: SSE consumers tolerate dropped events (they are
        // notifications, the fragments they trigger refresh on their own
        // cadence: the polls and page loads are the source of truth).
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
        bus.publish("fetch.done", serde_json::json!({}));
    }
}
