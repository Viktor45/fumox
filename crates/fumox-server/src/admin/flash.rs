//! One-shot toast messages for the plain-browser path.
//!
//! An HTMX action hands its message to the client in the `HX-Trigger`
//! header. A plain browser follows the redirect as a normal navigation
//! and the header is gone, so the message needs another way back: it used
//! to ride on the redirect URL as a `flash` query parameter. That put the
//! text into the address bar, the browser history and every copied link,
//! and a crafted link could show a message of the attacker's choosing
//! (a fake "your session expired, sign in again" prompt).
//!
//! The message now waits here, keyed by the session, and the page picks
//! it up once: it is handed out on the first request and gone afterwards,
//! so a refresh or a copied link does not replay it and a crafted link
//! cannot add one.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Response header carrying the pending toast of a plain-browser action.
/// The middleware in `crate::admin` moves it into the session's slot and
/// strips it from the response.
pub(crate) const FLASH_HEADER: &str = "x-fumox-flash";

/// Response header carrying the level of the pending toast (`ok` or
/// `error`).
pub(crate) const FLASH_LEVEL_HEADER: &str = "x-fumox-flash-level";

/// The level of a pending toast. The client renders only two shapes
/// (`error` gets the error style, everything else the default one), so
/// the store keeps the level as this enum instead of a free-form string:
/// a producer's typo cannot park a level the payload cannot name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlashLevel {
    Ok,
    Error,
}

impl FlashLevel {
    /// The level a `FLASH_LEVEL_HEADER` value names. `error` is the only
    /// word the client tells from the rest, so anything else — a missing
    /// header included — is the default toast.
    pub fn from_header(value: &str) -> Self {
        if value == "error" {
            Self::Error
        } else {
            Self::Ok
        }
    }

    /// The wire word the `/admin/flash` payload carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// How many pending messages the store keeps. The panel has a handful of
/// operators, one message each; the ceiling only bounds a leak.
const CAPACITY: usize = 64;

/// How long a pending message waits before it is dropped. An operator
/// who walks away after an action should not find the message an hour
/// later.
const TTL: Duration = Duration::from_secs(300);

/// Pending toast messages, keyed by the session cookie value.
///
/// The store is shared by the admin state (a clone per request path),
/// hence the `Arc` around the lock.
#[derive(Clone, Default)]
pub struct FlashStore {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    /// `(message, level, stored at)` per session.
    entries: HashMap<String, (String, FlashLevel, Instant)>,
    /// The sessions in insertion order, oldest first.
    order: VecDeque<String>,
}

impl FlashStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Park a message for the session.
    ///
    /// The message is percent-encoded, the same shape the `HX-Trigger`
    /// header carries: a response header is Latin-1 on the wire, so raw
    /// UTF-8 would arrive as mojibake.
    pub fn put(&self, session: &str, message: String, level: FlashLevel) {
        if session.is_empty() {
            return;
        }
        let mut inner = self.lock();
        inner.expire();
        if inner
            .entries
            .insert(session.to_string(), (message, level, Instant::now()))
            .is_none()
        {
            inner.order.push_back(session.to_string());
        }
        while inner.order.len() > CAPACITY {
            if let Some(oldest) = inner.order.pop_front() {
                inner.entries.remove(&oldest);
            }
        }
    }

    /// Take the pending message of the session, if any. The message is
    /// handed out once: the second request finds nothing.
    pub fn take(&self, session: &str) -> Option<(String, FlashLevel)> {
        let mut inner = self.lock();
        inner.expire();
        let (message, level, _) = inner.entries.remove(session)?;
        inner.order.retain(|key| key != session);
        Some((message, level))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic in another request must not take the panel down: the
        // store holds no invariant that a poison would break.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Inner {
    /// Drop the entries that waited longer than the TTL.
    fn expire(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|_, (_, _, at)| now.duration_since(*at) < TTL);
        self.order
            .retain(|session| self.entries.contains_key(session));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_is_handed_out_once() {
        let store = FlashStore::new();
        store.put("s1", "hello".into(), FlashLevel::Ok);
        assert_eq!(
            store.take("s1"),
            Some(("hello".to_string(), FlashLevel::Ok))
        );
        assert_eq!(store.take("s1"), None, "the message was replayed");
    }

    #[test]
    fn the_messages_of_two_sessions_do_not_mix() {
        let store = FlashStore::new();
        store.put("s1", "one".into(), FlashLevel::Ok);
        store.put("s2", "two".into(), FlashLevel::Error);
        assert_eq!(store.take("s2").map(|(m, _)| m), Some("two".to_string()));
        assert_eq!(store.take("s1").map(|(m, _)| m), Some("one".to_string()));
        assert_eq!(store.take("s1"), None);
    }

    #[test]
    fn a_message_without_a_session_is_dropped() {
        let store = FlashStore::new();
        store.put("", "hello".into(), FlashLevel::Ok);
        assert_eq!(store.take(""), None);
    }

    #[test]
    fn the_store_stays_bounded() {
        let store = FlashStore::new();
        for idx in 0..(CAPACITY * 2) {
            store.put(&format!("s{idx}"), "m".into(), FlashLevel::Ok);
        }
        // The oldest entries are gone, the newest are still there.
        assert_eq!(store.take("s0"), None);
        assert!(store.take(&format!("s{}", CAPACITY * 2 - 1)).is_some());
    }

    #[test]
    fn an_unknown_level_header_is_the_default_toast() {
        assert_eq!(FlashLevel::from_header("error"), FlashLevel::Error);
        assert_eq!(FlashLevel::from_header("ok"), FlashLevel::Ok);
        assert_eq!(FlashLevel::from_header(""), FlashLevel::Ok);
        assert_eq!(FlashLevel::from_header("bogus"), FlashLevel::Ok);
        assert_eq!(FlashLevel::Ok.as_str(), "ok");
        assert_eq!(FlashLevel::Error.as_str(), "error");
    }
}
