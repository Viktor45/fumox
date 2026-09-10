//! Probe overview screen and the SSE event stream (ADMIN_PLAN §4.5, §9).

use super::{fmt_opt_ts_element, fmt_ts_element, server_error};
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
/// Idle cap on a single SSE connection (security audit, 2026-09-10, M5):
/// even with `keep_alive` keepalive pings, a slow-loris client that never
/// reads from the stream would otherwise sit on a per-IP admin slot
/// forever. The browser-side `EventSource` reconnects on its own when the
/// socket closes, so closing after 10 minutes is harmless to the UI.
const SSE_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

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
    /// Next scheduled ladder check (0 = second chance, 1.. = recheck N).
    ladder_at: Option<i64>,
    ladder_step: i64,
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
    /// Check-coverage buckets (`none`/`t1_only`/`t2_only`/`both`), fixed
    /// order, zero-filled — each links into the filtered proxy browser.
    coverage: Vec<(String, i64)>,
    queue: Vec<QuarantineRow>,
}

impl ProbeTemplate {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts_element(*ts)
    }
    fn opt_ts(&self, ts: &Option<i64>) -> String {
        fmt_opt_ts_element(*ts)
    }
    fn proxy_total(&self) -> i64 {
        self.proxy_counts.iter().map(|(_, count)| count).sum()
    }
    /// The next scheduled check for a quarantined proxy.
    fn next_check(&self, row: &QuarantineRow) -> String {
        fmt_opt_ts_element(row.ladder_at)
    }

    /// Ladder step label: «второй шанс» or «повтор N» / "second chance" or
    /// "recheck N".
    fn step_label(&self, row: &QuarantineRow) -> String {
        if row.ladder_step < 1 {
            self.lang.t("probe.step_second_chance").to_string()
        } else {
            self.lang
                .t_args("probe.step_recheck", &[row.ladder_step.to_string()])
        }
    }

    /// Localized bucket label for the coverage panel.
    fn coverage_label(&self, bucket: &str) -> String {
        let key = match bucket {
            "none" => "px.checks_none",
            "t1_only" => "px.checks_t1_only",
            "t2_only" => "px.checks_t2_only",
            "both" => "px.checks_both",
            _ => "px.checks_none",
        };
        self.lang.t(key).to_string()
    }
}

impl_i18n!(ProbeTemplate);

/// Probe overview (ADMIN_PLAN §4.5): status aggregates, daemon heartbeat,
/// meow-rs status and the quarantine queue. The read-only config tables
/// live on the Settings page (ADMIN_PLAN §4.7).
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

    let coverage = match proxies::count_by_check_coverage(pool).await {
        Ok(coverage) => coverage,
        Err(err) => return server_error(lang, &err),
    };

    // The 50 quarantined proxies with the nearest upcoming check.
    let queue: Vec<QuarantineRow> = match sqlx::query_as(
        "SELECT id, name, host, port, scheme, quarantined_at, ladder_at, ladder_step
         FROM proxies
         WHERE status = 'quarantine'
         ORDER BY COALESCE(ladder_at, 0) ASC
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
            coverage,
            queue,
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
        let mut idle = tokio::time::interval(SSE_IDLE_TIMEOUT);
        idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        idle.tick().await; // first idle deadline is SSE_IDLE_TIMEOUT from now

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
                // Idle cap (security audit, 2026-09-10, M5): a connection
                // that produced no event and no tick for SSE_IDLE_TIMEOUT
                // is closed. The browser reconnects on its own.
                _ = idle.tick() => break,
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}
