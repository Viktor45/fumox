//! Probe overview screen and the SSE event stream (ADMIN_PLAN §4.5, §9).

use super::{fmt_ts, server_error};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use fumox_core::repo::{meta_get, proxies};
use futures_util::Stream;
use std::convert::Infallible;
use std::time::Duration;

/// How old the probe heartbeat may be before the daemon is considered down
/// (the daemon writes every 30 s by default).
const HEARTBEAT_STALE_SECS: i64 = 90;

/// Period for the `probe.stats` and `heartbeat` SSE events.
const STATS_INTERVAL: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Overview screen
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct QuarantineRow {
    id: i64,
    name: String,
    host: String,
    port: i64,
    scheme: String,
    quarantined_at: Option<i64>,
    second_chance_at: Option<i64>,
    recheck_15m_at: Option<i64>,
    recheck_30m_at: Option<i64>,
    recheck_1h_at: Option<i64>,
}

/// Parsed `probe_heartbeat` meta value.
struct Heartbeat {
    ts: i64,
    pid: u32,
    version: String,
    alive: bool,
}

#[derive(Template)]
#[template(path = "probe.html")]
struct ProbeTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    proxy_counts: Vec<(String, i64)>,
    heartbeat: Option<Heartbeat>,
    meow_last_ok: Option<i64>,
    queue: Vec<QuarantineRow>,
    state: AdminState,
}

impl ProbeTemplate {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts(*ts)
    }
    fn opt_ts(&self, ts: &Option<i64>) -> String {
        ts.map(fmt_ts).unwrap_or_else(|| "—".into())
    }
    fn proxy_total(&self) -> i64 {
        self.proxy_counts.iter().map(|(_, count)| count).sum()
    }
    /// The next scheduled check for a quarantined proxy (the one non-NULL
    /// schedule column).
    fn next_check(&self, row: &QuarantineRow) -> String {
        let next = row
            .recheck_15m_at
            .or(row.recheck_30m_at)
            .or(row.recheck_1h_at)
            .or(row.second_chance_at);
        next.map(fmt_ts).unwrap_or_else(|| "—".into())
    }
}

impl_i18n!(ProbeTemplate);

/// Probe overview (ADMIN_PLAN §4.5): status aggregates, daemon heartbeat,
/// meow-rs status, the quarantine queue and read-only cycle settings.
pub async fn probe_overview(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let pool = &state.pool;

    let proxy_counts = match proxies::count_by_status(pool).await {
        Ok(counts) => counts,
        Err(err) => return server_error(lang, &err),
    };

    let heartbeat = match meta_get(pool, "probe_heartbeat").await {
        Ok(Some(raw)) => serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|value| {
                let ts = value.get("ts")?.as_i64()?;
                Some(Heartbeat {
                    ts,
                    pid: value.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    version: value
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .to_string(),
                    alive: fumox_core::models::now_ts() - ts <= HEARTBEAT_STALE_SECS,
                })
            }),
        Ok(None) => None,
        Err(err) => return server_error(lang, &err),
    };

    let meow_last_ok = match meta_get(pool, "meow_last_ok").await {
        Ok(Some(raw)) => raw.parse::<i64>().ok(),
        Ok(None) => None,
        Err(err) => return server_error(lang, &err),
    };

    // The 50 quarantined proxies with the nearest upcoming check.
    let queue: Vec<QuarantineRow> = match sqlx::query_as(
        "SELECT id, name, host, port, scheme, quarantined_at, second_chance_at,
                recheck_15m_at, recheck_30m_at, recheck_1h_at
         FROM proxies
         WHERE status = 'quarantine'
         ORDER BY COALESCE(recheck_15m_at, recheck_30m_at, recheck_1h_at, second_chance_at, 0) ASC
         LIMIT 50",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    let langs = state.locales.choices().to_vec();
    render_html(
        lang.clone(),
        &ProbeTemplate {
            lang,
            langs,
            theme,
            active: "probe",
            csrf: state.csrf_for(&headers),
            proxy_counts,
            heartbeat,
            meow_last_ok,
            queue,
            state,
        },
        StatusCode::OK,
    )
}

// ---------------------------------------------------------------------------
// SSE stream
// ---------------------------------------------------------------------------

/// SSE endpoint (ADMIN_PLAN §9): forwards scheduler fetch events from the
/// event bus and interleaves periodic `probe.stats` / `heartbeat` events
/// read from the database. The browser wires this via `EventSource` in the
/// base template; without JS the polling fragments keep working.
pub async fn events_stream(
    State(state): State<AdminState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let mut receiver = state.events.subscribe();
    let pool = state.pool.clone();

    let stream = async_stream::stream! {
        // Emit an initial stats snapshot so a freshly opened page has data
        // without waiting for the first interval tick.
        if let Ok(counts) = proxies::count_by_status(&pool).await {
            let payload = serde_json::to_value(&counts).unwrap_or_default();
            yield Ok(SseEvent::default()
                .event("probe.stats")
                .data(payload.to_string()));
        }

        let mut tick = tokio::time::interval(STATS_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                event = receiver.recv() => {
                    match event {
                        Ok(event) => {
                            yield Ok(SseEvent::default()
                                .event(event.name)
                                .data(event.data.to_string()));
                        }
                        // Lagged: skip the lost events; the next periodic
                        // tick repairs the client's state.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = tick.tick() => {
                    if let Ok(counts) = proxies::count_by_status(&pool).await {
                        let payload = serde_json::to_value(&counts).unwrap_or_default();
                        yield Ok(SseEvent::default()
                            .event("probe.stats")
                            .data(payload.to_string()));
                    }
                    let heartbeat = meta_get(&pool, "probe_heartbeat").await.ok().flatten();
                    let meow = meta_get(&pool, "meow_last_ok").await.ok().flatten();
                    let payload = serde_json::json!({
                        "probe_heartbeat": heartbeat,
                        "meow_last_ok": meow,
                    });
                    yield Ok(SseEvent::default()
                        .event("heartbeat")
                        .data(payload.to_string()));
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}
