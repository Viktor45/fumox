//! Probe overview screen and the SSE event stream.

use super::server_error;
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::presentation::fmt_opt_ts_element;
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use fumox_core::config::ProbeConfig;
use fumox_core::probe_backlog::{
    BacklogDiagnostic, BacklogInputs, BacklogLevel, compute_backlog, heartbeat_stale_after,
    meow_stale_after,
};
use fumox_core::repo::probe::meta::{Heartbeat as HeartbeatRecord, LastRotation, MeowMemory};
use fumox_core::repo::proxies::QuarantineQueueRow;
use fumox_core::repo::{meta_get_many, probe as probe_repo, proxies};
use futures_util::Stream;
use serde::de::DeserializeOwned;
use std::convert::Infallible;
use std::time::Duration;

/// Lifetime cap on a single SSE connection: even with `keep_alive`
/// keepalive pings, a slow-loris client that
/// never reads from the stream would otherwise sit on a per-IP admin slot
/// forever. Note the cap is a fixed connection lifetime, not an idle
/// timeout, the stream closes 10 minutes after connect regardless of
/// traffic. The browser-side `EventSource` reconnects on its own when the
/// socket closes, so this is harmless to the UI.
const SSE_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

// Overview screen.

/// One `meta` stamp as the panel reads it.
///
/// The three states are kept apart on purpose: "the daemon has not
/// written this yet" and "the daemon wrote something nobody can read"
/// are different facts, and the second one is a problem the operator
/// has to see.
#[derive(Debug)]
enum MetaRecord<T> {
    /// No row for the key: the daemon has not written it (yet).
    Missing,
    /// A row exists but does not parse: a daemon that wrote a shape
    /// this build does not know, or a write that was cut short.
    Unreadable,
    /// The parsed record.
    Value(T),
}

/// Parse one JSON `meta` payload. A record that does not parse is
/// logged and reported as [`MetaRecord::Unreadable`] instead of being
/// dropped silently.
fn meta_record<T: DeserializeOwned>(key: &str, raw: Option<&str>) -> MetaRecord<T> {
    match raw {
        None => MetaRecord::Missing,
        Some(text) => match serde_json::from_str::<T>(text) {
            Ok(value) => MetaRecord::Value(value),
            Err(err) => {
                tracing::warn!(key, error = %err, "probe meta record is unreadable");
                MetaRecord::Unreadable
            }
        },
    }
}

/// The same for the plain-text stamps (`meow_last_ok`).
fn meta_ts_record(key: &str, raw: Option<&str>) -> MetaRecord<i64> {
    match raw {
        None => MetaRecord::Missing,
        Some(text) => match text.trim().parse::<i64>() {
            Ok(ts) => MetaRecord::Value(ts),
            Err(err) => {
                tracing::warn!(key, error = %err, "probe meta record is unreadable");
                MetaRecord::Unreadable
            }
        },
    }
}

/// Parsed `probe_heartbeat` meta value. The wire parsing goes through the
/// shared [`fumox_core::repo::probe::meta::Heartbeat`] contract; this view
/// adds the staleness verdict the card renders.
struct Heartbeat {
    ts: i64,
    pid: u32,
    version: String,
    /// Effective beat period reported by the daemon. `None` for records
    /// written before the field existed; the staleness check then falls
    /// back to the server's own config.
    interval_secs: Option<u64>,
    /// Effective cycle period reported by the daemon (same contract as
    /// `interval_secs`): the meow-contact staleness must threshold against
    /// the cycle the daemon actually runs, not this server's config copy.
    cycle_interval_secs: Option<u64>,
    alive: bool,
}

/// Parsed `meow_last_ok` contact stamp with its staleness verdict. A
/// historical timestamp alone must not render as "available": the card
/// used to show green for a contact from any point in the past.
struct MeowContact {
    ts: i64,
    alive: bool,
}

/// RSS as a share of the limit, when meow-rs resolved one.
fn percent_of_limit(mem: &MeowMemory) -> Option<f64> {
    (mem.os_limit_bytes > 0).then(|| mem.rss_bytes as f64 * 100.0 / mem.os_limit_bytes as f64)
}

/// Human-readable byte count, one decimal above a KiB.
///
/// Unlike the settings page's whole-unit formatter (that one renders file
/// sizes), RSS moves continuously, so exact divisibility would print
/// `10412 KiB`.
fn fmt_rss_bytes(bytes: u64) -> String {
    const MIB: f64 = 1024.0 * 1024.0;
    const KIB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= MIB {
        format!("{:.1} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.0} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

/// The kernel RSS line, e.g. `RSS 24.5 MiB · 1.2% / 2.0 GiB`.
///
/// Plain text, and it has to stay that way: `probe.html` renders it through
/// an escaping handle, so any markup folded in here (a `time` element, say)
/// reaches the reader as literal `<time ...>` source. The timestamp is
/// rendered by the template instead, through `ts(..) | safe`.
fn rss_line(mem: &MeowMemory) -> String {
    let mut line = format!("RSS {}", fmt_rss_bytes(mem.rss_bytes));
    if let Some(pct) = percent_of_limit(mem) {
        line.push_str(&format!(
            " · {pct:.1}% / {}",
            fmt_rss_bytes(mem.os_limit_bytes)
        ));
    }
    line
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
    /// The heartbeat record exists but does not parse: the card shows it
    /// as a dead daemon with its own wording, and the banner calls it
    /// out as such.
    heartbeat_unreadable: bool,
    meow_last_ok: Option<MeowContact>,
    /// The meow contact record exists but does not parse.
    meow_unreadable: bool,
    /// Last retention run of the probe daemon (`last_rotation` meta),
    /// rendered with the current journal row counts.
    last_rotation: Option<LastRotation>,
    /// Current `probe_results` / `fetch_log` sizes, read against the
    /// rotation stamp: a fresh stamp on a growing table is still a leak.
    journal_probe_rows: i64,
    journal_fetch_rows: i64,
    /// Kernel RSS as published by the probe daemon (`meow_memory` meta,
    /// parsed through the shared `repo::probe::meta::MeowMemory` contract).
    meow_memory: Option<MeowMemory>,
    /// Check-coverage buckets (`none`/`t1_only`/`t2_only`/`both`), fixed
    /// order, zero-filled, each links into the filtered proxy browser.
    coverage: Vec<(String, i64)>,
    /// True count of proxies in `status = 'quarantine'` (from
    /// `proxy_counts`). The `queue` table view is truncated to 50 rows,
    /// so it cannot be used to size the card.
    quarantine_count: i64,
    queue: Vec<QuarantineQueueRow>,
    /// Read-only view of `[probe]` settings used by the banner and the
    /// config-snapshot line. Sourced from `AdminState::probe` so the
    /// banner always sees the same config the rest of the page would.
    probe_view: ProbeView,
    /// Backlog diagnostic for the banner. `None` when no heuristic
    /// fired, the template skips the entire block.
    backlog: Option<BacklogDiagnostic>,
}

/// Read-only DTO of the `[probe]` block: only the fields the
/// `/admin/probe` page actually surfaces (the config-snapshot line).
/// Decouples the template from `ProbeConfig`'s serde internals.
#[derive(Clone, Copy, Debug)]
struct ProbeView {
    cycle_interval_secs: u64,
    concurrency: usize,
}

impl ProbeView {
    fn from(cfg: &ProbeConfig) -> Self {
        Self {
            cycle_interval_secs: cfg.cycle_interval_secs,
            concurrency: cfg.concurrency,
        }
    }
}

/// CSS modifier suffix appended to `.flash`. `None` would also
/// work, but the existing `.flash` style is reserved for neutral
/// info bars, every diagnostic lands in a warning/danger variant.
fn backlog_level_class(level: BacklogLevel) -> &'static str {
    match level {
        BacklogLevel::Ok => "ok",
        BacklogLevel::Warning => "warning",
        BacklogLevel::Danger => "danger",
    }
}

/// `probe.level_*` key for the level label inside the title.
fn backlog_level_key(level: BacklogLevel) -> &'static str {
    match level {
        BacklogLevel::Ok => "probe.level_ok",
        BacklogLevel::Warning => "probe.level_warning",
        BacklogLevel::Danger => "probe.level_danger",
    }
}

impl ProbeTemplate {
    fn proxy_total(&self) -> i64 {
        self.proxy_counts.iter().map(|(_, count)| count).sum()
    }
    /// Number of quarantined proxies shown in the queue table below
    /// (`min(quarantine_count, 50)`).
    fn queue_shown(&self) -> i64 {
        self.queue.len() as i64
    }
    /// The truncation hint of the quarantine card: how many rows the
    /// table shows and how many there are in total. The two numbers are
    /// the ones the card shows next to it, so the hint cannot be read as
    /// "50 of 50" next to a card that counts 60.
    fn queue_hint(&self) -> String {
        self.lang
            .t("probe.queue_nearest")
            .replacen("{}", &self.queue_shown().to_string(), 1)
            .replacen("{}", &self.quarantine_count.to_string(), 1)
    }
    /// Human-readable byte count for the kernel RSS card.
    ///
    /// One decimal, unlike the settings page's whole-unit formatter: RSS
    /// moves continuously, so exact divisibility would print `10412 KiB`.
    /// The kernel RSS line for the card, empty when there is no reading.
    fn mem_line(&self) -> String {
        self.meow_memory.as_ref().map_or_else(String::new, rss_line)
    }

    /// When the reading was taken, for the template to render as a `time`
    /// element beside the rest of the line.
    fn mem_ts(&self) -> i64 {
        self.meow_memory.as_ref().map_or(0, |mem| mem.ts)
    }

    /// Whether a reading is worth showing at all.
    fn has_mem(&self) -> bool {
        self.meow_memory.is_some()
    }
    /// The next scheduled check for a quarantined proxy.
    fn next_check(&self, row: &QuarantineQueueRow) -> String {
        fmt_opt_ts_element(row.ladder_at)
    }

    /// Ladder step label: *second chance* or *recheck N*.
    fn step_label(&self, row: &QuarantineQueueRow) -> String {
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

    ///
    /// CSS modifier for the backlog banner: `ok`, `warning`, or `danger`.
    fn backlog_level_class(&self) -> &'static str {
        match self.backlog {
            Some(ref b) => backlog_level_class(b.level),
            None => "",
        }
    }

    /// Localized level label embedded in the banner title
    /// (`probe.level_warning` / `probe.level_danger`).
    fn backlog_level_label(&self) -> String {
        match self.backlog {
            Some(ref b) => self.lang.t(backlog_level_key(b.level)).to_string(),
            None => String::new(),
        }
    }

    /// Pre-localized text for a single backlog factor. The factor's
    /// numeric placeholders are filled by the template via the
    /// `factor_<key>` keys (see locales).
    fn backlog_factor_text(&self, idx: &usize) -> String {
        let Some(b) = self.backlog.as_ref() else {
            return String::new();
        };
        let Some(factor) = b.factors.get(*idx) else {
            return String::new();
        };
        let key = format!("probe.factor_{}", factor.key);
        match factor.key {
            "deep_queue" => self.lang.t_named(
                &key,
                &[
                    ("count", b.quarantine_count.to_string()),
                    (
                        "ratio",
                        (b.quarantine_count / b.due_capacity.max(1) as i64).to_string(),
                    ),
                ],
            ),
            "due_overflow" => self.lang.t_named(
                &key,
                &[
                    ("due", b.due_count.to_string()),
                    ("sample", b.due_capacity.to_string()),
                ],
            ),
            "stale_oldest" => {
                let days = b
                    .oldest_quarantined_age_secs
                    .map(|s| s / 86_400)
                    .unwrap_or(0);
                // The clamped value the heuristic actually compared
                // against, not the raw setting.
                self.lang.t_named(
                    &key,
                    &[
                        ("days", days.to_string()),
                        ("limit", b.stale_days.to_string()),
                    ],
                )
            }
            "heartbeat_dead" => {
                // The age the heuristic compared against, taken from the
                // diagnostic so the figure and the verdict come from one
                // place.
                let secs = b.heartbeat_age_secs.unwrap_or(0);
                self.lang.t_named(&key, &[("secs", secs.to_string())])
            }
            // Both drain-bearing arms read the figure off the model
            // instead of recomputing it: there is no second formula on
            // the rendering side that could drift from the one the
            // gate used. `drain_minutes` is `Some` in both arms by
            // construction. A missing figure is the `all_idle` arm.
            "drain_over_target" | "all_ok" => self.lang.t_named(
                &key,
                &[
                    ("count", b.quarantine_count.to_string()),
                    ("drain", b.drain_minutes.unwrap_or(0).to_string()),
                    ("target", b.target_drain_minutes.to_string()),
                ],
            ),
            // The cycle took nothing: report that, with the numbers the
            // operator needs to see it, instead of a cause the page
            // cannot support.
            "all_idle" => self.lang.t_named(
                &key,
                &[
                    ("count", b.quarantine_count.to_string()),
                    ("sample", b.due_capacity.to_string()),
                    ("due", b.due_count.to_string()),
                    ("target", b.target_drain_minutes.to_string()),
                ],
            ),
            _ => self.lang.t(&key).to_string(),
        }
    }

    /// Pre-localized text for a single tuning recommendation. The
    /// `probe.rec_<key>` entry carries the wording; `args` carries the
    /// values, so no recommendation is formatted in English here.
    fn backlog_rec_label(&self, idx: &usize) -> String {
        match self.backlog.as_ref() {
            Some(b) => b
                .recs
                .get(*idx)
                .map(|r| self.lang.t_named(&format!("probe.rec_{}", r.key), &r.args)),
            None => None,
        }
        .unwrap_or_default()
    }
}

impl_i18n!(ProbeTemplate);

/// Probe overview: status aggregates, daemon heartbeat,
/// meow-rs status and the quarantine queue. The read-only config tables
/// live on the Settings page.
pub async fn probe_overview(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let pool = &state.pool;
    let now = fumox_core::models::now_ts();

    // Every read below is independent of every other one: the four meta
    // stamps, the counters and the queue come from separate queries and
    // none of them waits for another. One `try_join!` runs them
    // concurrently (SQLite reads run concurrently in WAL mode) and
    // leaves one error site instead of nine.
    let (proxy_counts, coverage, queue, due_count, oldest_quarantined_at, meta) = match tokio::try_join!(
        proxies::count_by_status(pool),
        proxies::count_by_check_coverage(pool),
        proxies::list_quarantine_queue(pool, 50),
        proxies::count_due_quarantine(pool, now),
        proxies::oldest_quarantined_at(pool),
        meta_get_many(
            pool,
            &[
                probe_repo::meta::HEARTBEAT_KEY,
                probe_repo::meta::MEOW_LAST_OK_KEY,
                probe_repo::meta::MEOW_MEMORY_KEY,
                probe_repo::meta::LAST_ROTATION_KEY,
            ],
        ),
    ) {
        Ok(reads) => reads,
        Err(err) => return server_error(lang.clone(), &err),
    };

    // The journal row counts are two COUNT scans of a growing table, so
    // they are cached for a minute instead of running on every render.
    let (journal_probe_rows, journal_fetch_rows) = match state.journal_counts.get(pool).await {
        Ok(counts) => counts,
        Err(err) => return server_error(lang.clone(), &err),
    };

    let heartbeat_record = meta_record::<HeartbeatRecord>(
        probe_repo::meta::HEARTBEAT_KEY,
        meta.get(probe_repo::meta::HEARTBEAT_KEY)
            .map(String::as_str),
    );
    let heartbeat_unreadable = matches!(heartbeat_record, MetaRecord::Unreadable);
    let heartbeat = match heartbeat_record {
        MetaRecord::Value(hb) => Some(Heartbeat {
            ts: hb.ts,
            pid: hb.pid,
            version: hb.version,
            // Same threshold the banner applies, so the card and
            // the banner can never call the same daemon alive in
            // one place and dead in the other.
            alive: now - hb.ts <= heartbeat_stale_after(&state.probe(), hb.interval_secs),
            interval_secs: hb.interval_secs,
            cycle_interval_secs: hb.cycle_interval_secs,
        }),
        MetaRecord::Missing | MetaRecord::Unreadable => None,
    };

    let meow_record = meta_ts_record(
        probe_repo::meta::MEOW_LAST_OK_KEY,
        meta.get(probe_repo::meta::MEOW_LAST_OK_KEY)
            .map(String::as_str),
    );
    let meow_unreadable = matches!(meow_record, MetaRecord::Unreadable);
    let meow_last_ok = match meow_record {
        MetaRecord::Value(ts) => Some(MeowContact {
            ts,
            // Without this verdict a contact from last month rendered as
            // a green "available". The cycle period the daemon reported in
            // its own heartbeat outranks this server's config copy.
            alive: now - ts
                <= meow_stale_after(
                    &state.probe(),
                    heartbeat.as_ref().and_then(|hb| hb.cycle_interval_secs),
                ),
        }),
        MetaRecord::Missing | MetaRecord::Unreadable => None,
    };

    let meow_memory = match meta_record::<MeowMemory>(
        probe_repo::meta::MEOW_MEMORY_KEY,
        meta.get(probe_repo::meta::MEOW_MEMORY_KEY)
            .map(String::as_str),
    ) {
        MetaRecord::Value(mem) => Some(mem),
        MetaRecord::Missing | MetaRecord::Unreadable => None,
    };

    let last_rotation = match meta_record::<LastRotation>(
        probe_repo::meta::LAST_ROTATION_KEY,
        meta.get(probe_repo::meta::LAST_ROTATION_KEY)
            .map(String::as_str),
    ) {
        MetaRecord::Value(rot) => Some(rot),
        MetaRecord::Missing | MetaRecord::Unreadable => None,
    };

    // True population count for the quarantine card. `proxy_counts` already
    // ran; pull the entry out instead of issuing another query. Missing
    // status (e.g. empty DB) collapses to 0.
    let quarantine_count = proxy_counts
        .iter()
        .find(|(status, _)| status == "quarantine")
        .map(|(_, count)| *count)
        .unwrap_or(0);

    let oldest_quarantined_age_secs = oldest_quarantined_at.map(|ts| (now - ts).max(0));
    let heartbeat_age_secs = heartbeat.as_ref().map(|hb| (now - hb.ts).max(0));

    let probe_view = ProbeView::from(&state.probe());
    let backlog = compute_backlog(
        &BacklogInputs {
            quarantine_count,
            due_count,
            oldest_quarantined_age_secs,
            heartbeat_age_secs,
            reported_heartbeat_secs: heartbeat.as_ref().and_then(|hb| hb.interval_secs),
            heartbeat_unreadable,
        },
        &state.probe(),
    );

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
            heartbeat_unreadable,
            meow_last_ok,
            meow_unreadable,
            last_rotation,
            journal_probe_rows,
            journal_fetch_rows,
            meow_memory,
            coverage,
            quarantine_count,
            queue,
            probe_view,
            backlog: Some(backlog),
        },
        StatusCode::OK,
    )
}

// SSE stream.

/// SSE endpoint: forwards scheduler fetch events from the event bus to
/// the browser. The events are one-shot notifications: the browser reacts
/// to `fetch.*` by refreshing fragments that poll on their own cadence
/// anyway, and without JS those fragments keep working. SSE is a pure
/// enhancement, so a missed event only delays an update.
pub async fn events_stream(
    State(state): State<AdminState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let mut receiver = state.events.subscribe();

    let stream = async_stream::stream! {
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
                        // Lagged: the consumer lost events, not state,
                        // every fetch.* event merely tells the page to
                        // refresh a fragment that polls on its own, so the
                        // only cost is a delayed update. Logged so a
                        // persistently slow consumer stays visible.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!(
                                skipped,
                                "SSE client lagged; dropped event(s), a delayed refresh at most"
                            );
                            continue;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                // Connection lifetime cap:
                // the stream never outlives SSE_IDLE_TIMEOUT (10 min) even
                // under steady traffic, the interval is not reset on
                // activity, so this is a hard cap, not an idle timeout.
                // The browser's EventSource reconnects on its own, and the
                // reconnect passes auth again.
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

// Unit tests for the panel-side reading of the probe stamps. The cycle
// model itself lives in `fumox_core::probe_backlog` with its own tests.
#[cfg(test)]
mod tests {
    use super::*;

    /// A stamp that is not there is a daemon that has not written it
    /// yet, and a stamp that does not parse is a different fact: the
    /// panel has to be able to tell them apart.
    #[test]
    fn an_unreadable_record_is_not_a_missing_one() {
        let missing: MetaRecord<HeartbeatRecord> =
            meta_record(probe_repo::meta::HEARTBEAT_KEY, None);
        assert!(matches!(missing, MetaRecord::Missing));

        let broken: MetaRecord<HeartbeatRecord> =
            meta_record(probe_repo::meta::HEARTBEAT_KEY, Some("{not json"));
        assert!(matches!(broken, MetaRecord::Unreadable));

        let good: MetaRecord<HeartbeatRecord> = meta_record(
            probe_repo::meta::HEARTBEAT_KEY,
            Some(r#"{"ts":17,"pid":3,"version":"0.1.0"}"#),
        );
        match good {
            MetaRecord::Value(hb) => {
                assert_eq!(hb.ts, 17);
                assert_eq!(hb.pid, 3);
            }
            other => panic!("a parsable record must parse: {other:?}"),
        }
    }

    /// The plain-text stamp (`meow_last_ok`) fails the same way, and a
    /// number written with surrounding whitespace still parses.
    #[test]
    fn the_text_stamp_reads_a_timestamp_or_nothing() {
        assert!(matches!(
            meta_ts_record(probe_repo::meta::MEOW_LAST_OK_KEY, None),
            MetaRecord::Missing
        ));
        assert!(matches!(
            meta_ts_record(probe_repo::meta::MEOW_LAST_OK_KEY, Some("later")),
            MetaRecord::Unreadable
        ));
        match meta_ts_record(probe_repo::meta::MEOW_LAST_OK_KEY, Some(" 42 ")) {
            MetaRecord::Value(ts) => assert_eq!(ts, 42),
            other => panic!("a numeric stamp must parse: {other:?}"),
        }
    }

    /// Regression: the RSS line is rendered through an escaping handle, so
    /// it once shipped a `time` element inside and the reader saw literal
    /// `<time class="ts" ...>` source in the card, wrapped over four lines.
    /// The timestamp belongs to the template (`ts(..) | safe`); the line
    /// stays plain text.
    #[test]
    fn rss_line_carries_no_markup() {
        let mem = MeowMemory {
            rss_bytes: 25_780_224,
            os_limit_bytes: 2_147_483_648,
            ts: 1_700_000_000,
        };
        let line = rss_line(&mem);
        assert!(!line.contains('<'), "markup leaked into the line: {line}");
        assert!(!line.contains('>'), "markup leaked into the line: {line}");
        assert!(line.contains("24.6 MiB"), "{line}");
        // A missing limit hides the share instead of dividing by zero.
        let no_limit = MeowMemory {
            os_limit_bytes: 0,
            ..mem
        };
        assert_eq!(rss_line(&no_limit), "RSS 24.6 MiB");
    }
}
