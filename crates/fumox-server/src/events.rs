//! In-process event bus for admin-panel push updates.
//!
//! The scheduler publishes fetch lifecycle events here; the SSE endpoint
//! (`GET /admin/events`) subscribes and forwards them to the browser as
//! one-shot notifications. Polling fragments keep working as the no-JS
//! fallback, SSE is a pure enhancement: every fragment refreshes on its
//! own polling cadence as well, so a dropped event delays an update but
//! never loses state.
//!
//! The names ([`FETCH_QUEUED`], [`FETCH_STARTED`], [`FETCH_DONE`],
//! [`FETCH_FAILED`]) and the `data` fields each carries:
//!
//! - `fetch.queued`: `source_id` — the refresh has to wait for a
//!   concurrency permit (a free permit skips straight to `fetch.started`).
//! - `fetch.started`: `source_id` — the request can actually go out (a
//!   concurrency permit is in hand).
//! - `fetch.done`: `source_id`, `ok: true`, `proxies_found`, `dropped`,
//!   `duration_ms`.
//! - `fetch.failed`: `source_id`, `ok: false`, `error_class`, `message`,
//!   `http_status` (set when the server answered one), `duration_ms` (a
//!   panic before the fetch started reports none of the measured ones).

use tokio::sync::broadcast;

/// `fetch.queued`: the refresh has to wait for a concurrency permit; `data`
/// carries `source_id`.
pub const FETCH_QUEUED: &str = "fetch.queued";

/// `fetch.started`: a permit was in hand and the fetch went out; `data`
/// carries `source_id`.
pub const FETCH_STARTED: &str = "fetch.started";

/// `fetch.done`: the ingest finished; `data` carries `source_id`, `ok`,
/// `proxies_found`, `dropped` and `duration_ms`.
pub const FETCH_DONE: &str = "fetch.done";

/// `fetch.failed`: the ingest failed; `data` carries `source_id`, `ok`,
/// `error_class`, `message`, `http_status` (when the server answered one)
/// and, when the attempt was measured, `duration_ms`.
pub const FETCH_FAILED: &str = "fetch.failed";

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
        bus.publish(FETCH_DONE, serde_json::json!({"source_id": "s1"}));
        let event = rx.recv().await.unwrap();
        // The literal, not the constant: the value itself stays pinned.
        assert_eq!(event.name, "fetch.done");
        assert_eq!(event.data["source_id"], "s1");
    }

    #[tokio::test]
    async fn publish_without_subscribers_is_fine() {
        let bus = EventBus::new();
        bus.publish(FETCH_DONE, serde_json::json!({}));
    }
}
