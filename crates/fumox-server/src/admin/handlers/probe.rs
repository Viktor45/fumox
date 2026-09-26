//! Probe overview screen and the SSE event stream.

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
use fumox_core::config::ProbeConfig;
use fumox_core::repo::{meta_get, proxies};
use futures_util::Stream;
use std::convert::Infallible;
use std::time::Duration;

/// How old the probe heartbeat may be before the daemon is considered down
/// (the daemon writes every 30 s by default).
const HEARTBEAT_STALE_SECS: i64 = 90;

/// Period for the `probe.stats` and `heartbeat` SSE events.
const STATS_INTERVAL: Duration = Duration::from_secs(30);
/// Lifetime cap on a single SSE connection: even with `keep_alive`
/// keepalive pings, a slow-loris client that
/// never reads from the stream would otherwise sit on a per-IP admin slot
/// forever. Note the cap is a fixed connection lifetime, not an idle
/// timeout, the stream closes 10 minutes after connect regardless of
/// traffic. The browser-side `EventSource` reconnects on its own when the
/// socket closes, so this is harmless to the UI.
const SSE_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

// Overview screen.

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
    /// order, zero-filled, each links into the filtered proxy browser.
    coverage: Vec<(String, i64)>,
    /// True count of proxies in `status = 'quarantine'` (from
    /// `proxy_counts`). The `queue` table view is truncated to 50 rows,
    /// so it cannot be used to size the card.
    quarantine_count: i64,
    queue: Vec<QuarantineRow>,
    /// Read-only view of `[probe]` settings used by the banner and the
    /// config-snapshot line. Sourced from `AdminState::probe` so the
    /// banner always sees the same config the rest of the page would.
    probe_view: ProbeView,
    /// Backlog diagnostic for the banner. `None` when no heuristic
    /// fired, the template skips the entire block.
    backlog: Option<BacklogDiagnostic>,
}

/// Read-only DTO of the `[probe]` block: only the fields the
/// `/admin/probe` page actually surfaces. Decouples the template from
/// `ProbeConfig`'s serde internals.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
struct ProbeView {
    cycle_interval_secs: u64,
    sample_size: u32,
    concurrency: usize,
    queue_stale_days: u64,
    backlog_target_drain_minutes: u64,
}

impl ProbeView {
    fn from(cfg: &ProbeConfig) -> Self {
        Self {
            cycle_interval_secs: cfg.cycle_interval_secs,
            sample_size: cfg.sample_size,
            concurrency: cfg.concurrency,
            queue_stale_days: cfg.queue_stale_days,
            backlog_target_drain_minutes: cfg.backlog_target_drain_minutes,
        }
    }
}

/// Severity of a single trigger. The banner picks the highest severity
/// across all triggers. `Ok` is the positive state shown when no
/// heuristic fired and the current drain fits in the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BacklogLevel {
    Ok,
    Warning,
    Danger,
}

impl BacklogLevel {
    /// CSS modifier suffix appended to `.flash`. `None` would also
    /// work, but the existing `.flash` style is reserved for neutral
    /// info bars, every diagnostic lands in a warning/danger variant.
    fn css_class(self) -> &'static str {
        match self {
            BacklogLevel::Ok => "ok",
            BacklogLevel::Warning => "warning",
            BacklogLevel::Danger => "danger",
        }
    }
    /// `probe.level_*` key for the level label inside the title.
    fn i18n_key(self) -> &'static str {
        match self {
            BacklogLevel::Ok => "probe.level_ok",
            BacklogLevel::Warning => "probe.level_warning",
            BacklogLevel::Danger => "probe.level_danger",
        }
    }
    /// Pick the highest severity across `self` and `other`.
    fn escalate(self, other: BacklogLevel) -> BacklogLevel {
        match (self, other) {
            (BacklogLevel::Danger, _) | (_, BacklogLevel::Danger) => BacklogLevel::Danger,
            (BacklogLevel::Warning, _) | (_, BacklogLevel::Warning) => BacklogLevel::Warning,
            _ => BacklogLevel::Ok,
        }
    }
}

/// One trigger that fired. `key` maps to a `probe.factor_<key>`
/// i18n entry, `severity` feeds the banner level.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
struct BacklogFactor {
    key: &'static str,
    severity: BacklogLevel,
}

/// One concrete suggested change. `target_value` is the new value the
/// recommendation asks for (rendered into the localized label and used
/// by tests). `key` maps to a `probe.rec_<key>` i18n entry.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct TuningRec {
    key: &'static str,
    target_value: String,
    /// Localized label already formatted with current/target values.
    label: String,
}

/// Bundle of facts the banner needs to render. Carried in `Option`:
/// `None` skips the block entirely.
#[derive(Clone, Debug)]
struct BacklogDiagnostic {
    level: BacklogLevel,
    factors: Vec<BacklogFactor>,
    recs: Vec<TuningRec>,
    target_drain_minutes: u64,
    quarantine_count: i64,
    due_count: i64,
    due_capacity: u32,
    oldest_quarantined_age_secs: Option<i64>,
}

/// Heuristics + recommendation math for the backlog banner. Pure
/// function, no I/O, so the test suite can hit every branch without
/// seeding a database.
///
/// `oldest_quarantined_age_secs` = `now - MIN(quarantined_at)` if any
/// quarantine row exists, `None` otherwise. `heartbeat_alive` and
/// `heartbeat_age_secs` come from the parsed `Heartbeat` (the daemon
/// itself decides whether the row is *alive* via a 90 s ceiling, but
/// this function uses `[probe].heartbeat_interval_secs × 3` so the
/// threshold follows the operator's heartbeat setting).
fn compute_backlog(
    quarantine_count: i64,
    due_count: i64,
    oldest_quarantined_age_secs: Option<i64>,
    heartbeat_alive: bool,
    heartbeat_age_secs: Option<i64>,
    cfg: &ProbeConfig,
) -> Option<BacklogDiagnostic> {
    let sample_size = cfg.sample_size.max(1) as i64;
    let cycle = cfg.cycle_interval_secs.max(1);
    let concurrency = cfg.concurrency.max(1);
    let heartbeat_interval = cfg.heartbeat_interval_secs.max(1);

    let mut level = BacklogLevel::Warning;
    let mut factors: Vec<BacklogFactor> = Vec::new();

    if quarantine_count > sample_size * 20 {
        factors.push(BacklogFactor {
            key: "deep_queue",
            severity: BacklogLevel::Warning,
        });
    }
    if due_count > sample_size * 5 {
        factors.push(BacklogFactor {
            key: "due_overflow",
            severity: BacklogLevel::Warning,
        });
    }
    if let Some(age) = oldest_quarantined_age_secs {
        let stale_after = cfg.queue_stale_days.saturating_mul(86_400);
        if age > (stale_after as f64 * 0.8) as i64 {
            level = level.escalate(BacklogLevel::Danger);
            factors.push(BacklogFactor {
                key: "stale_oldest",
                severity: BacklogLevel::Danger,
            });
        }
    }
    // `heartbeat_dead` requires a recorded heartbeat, otherwise a
    // freshly started daemon would trigger the banner before its
    // first beat (already surfaced as "no heartbeat" on the daemon
    // card).
    if heartbeat_age_secs.is_some() && !heartbeat_alive {
        level = level.escalate(BacklogLevel::Danger);
        factors.push(BacklogFactor {
            key: "heartbeat_dead",
            severity: BacklogLevel::Danger,
        });
    } else if let Some(age) = heartbeat_age_secs
        && age > (heartbeat_interval as i64) * 3
    {
        level = level.escalate(BacklogLevel::Danger);
        factors.push(BacklogFactor {
            key: "heartbeat_dead",
            severity: BacklogLevel::Danger,
        });
    }

    if factors.is_empty() {
        // No heuristic fired: surface the green OK banner when the
        // current drain fits the target; otherwise escalate to a
        // warning so the operator notices the queue is accumulating
        // even though no hard threshold has tripped yet.
        let target_minutes = cfg.backlog_target_drain_minutes.max(1);
        let cycles_to_drain = (quarantine_count.max(1) + sample_size - 1) / sample_size.max(1);
        let drain_minutes_now: u64 = ((cycles_to_drain * cycle as i64 + 59) / 60).max(1) as u64;
        if drain_minutes_now > target_minutes {
            return Some(BacklogDiagnostic {
                level: BacklogLevel::Warning,
                factors: vec![BacklogFactor {
                    key: "drain_over_target",
                    severity: BacklogLevel::Warning,
                }],
                recs: compute_recs(
                    cfg,
                    quarantine_count,
                    sample_size as u32,
                    cycle,
                    concurrency,
                ),
                target_drain_minutes: target_minutes,
                quarantine_count,
                due_count,
                due_capacity: cfg.sample_size,
                oldest_quarantined_age_secs,
            });
        }
        return Some(BacklogDiagnostic {
            level: BacklogLevel::Ok,
            factors: vec![BacklogFactor {
                key: "all_ok",
                severity: BacklogLevel::Ok,
            }],
            recs: Vec::new(),
            target_drain_minutes: target_minutes,
            quarantine_count,
            due_count,
            due_capacity: cfg.sample_size,
            oldest_quarantined_age_secs,
        });
    }

    // Recommendations only when drain exceeds the target; otherwise
    // the banner shows the factors without prescriptive knobs.
    let target_minutes = cfg.backlog_target_drain_minutes.max(1);
    let cycles_to_drain = (quarantine_count.max(1) + sample_size - 1) / sample_size.max(1);
    let drain_seconds = cycles_to_drain * cycle as i64;
    let drain_minutes_now: u64 = ((drain_seconds + 59) / 60).max(1) as u64;

    let recs = if drain_minutes_now > target_minutes {
        compute_recs(
            cfg,
            quarantine_count,
            sample_size as u32,
            cycle,
            concurrency,
        )
    } else {
        Vec::new()
    };

    Some(BacklogDiagnostic {
        level,
        factors,
        recs,
        target_drain_minutes: target_minutes,
        quarantine_count,
        due_count,
        due_capacity: cfg.sample_size,
        oldest_quarantined_age_secs,
    })
}

/// Build up to three concrete suggestions. Returns an empty Vec when
/// the operator's settings are already inside the target window. Each
/// suggestion's `label` is the localized text the template renders ,
/// the `target_value` field is what tests assert against.
fn compute_recs(
    cfg: &ProbeConfig,
    quarantine_count: i64,
    sample_size: u32,
    cycle: u64,
    concurrency: usize,
) -> Vec<TuningRec> {
    let mut out = Vec::new();
    let target_minutes = cfg.backlog_target_drain_minutes.max(1);
    let target_seconds = (target_minutes as i64).saturating_mul(60);

    // Required sample_size to drain in `target_minutes` at the current
    // cycle, capped at 500.
    let cycles_needed =
        (quarantine_count.max(1) + sample_size as i64 - 1) / sample_size.max(1) as i64;
    let required_sample_raw =
        ((quarantine_count * cycle as i64) + target_seconds - 1) / target_seconds;
    let required_sample = required_sample_raw.clamp(1, 500) as u32;

    if required_sample > (sample_size as f64 * 1.2) as u32 {
        out.push(TuningRec {
            key: "sample_size",
            target_value: required_sample.to_string(),
            label: format!("[probe].sample_size = {required_sample} (current {sample_size})"),
        });
    }

    // Cycle-interval knob: only when sample_size is already huge or
    // the required sample exceeds the cap.
    let cycle_cap_hit = required_sample_raw > 500;
    if cycle_cap_hit || sample_size >= 400 {
        let required_cycle_secs =
            ((target_seconds + cycles_needed - 1) / cycles_needed).clamp(5, cycle as i64) as u64;
        if required_cycle_secs < (cycle as f64 * 0.8) as u64 {
            out.push(TuningRec {
                key: "cycle_interval_secs",
                target_value: required_cycle_secs.to_string(),
                label: format!(
                    "[probe].cycle_interval_secs = {required_cycle_secs}s (current {cycle}s)"
                ),
            });
        }
    }

    // Concurrency: only when each cycle exceeds the interval, i.e.
    // parallelism is the bottleneck, not throughput.
    let worst_case_check_secs = (cfg.connect_timeout_secs + cfg.tls_timeout_secs).max(1) as i64;
    let current_cycle_secs = ((sample_size as i64 + concurrency as i64 - 1) / concurrency as i64)
        * worst_case_check_secs;
    if current_cycle_secs > cycle as i64 {
        let required_concurrency_raw =
            ((sample_size as i64 * worst_case_check_secs) + cycle as i64 - 1) / cycle as i64;
        let required_concurrency = required_concurrency_raw.clamp(1, 64) as usize;
        if required_concurrency > concurrency {
            out.push(TuningRec {
                key: "concurrency",
                target_value: required_concurrency.to_string(),
                label: format!(
                    "[probe].concurrency = {required_concurrency} (current {concurrency}); cycle ~{current_cycle_secs}s > interval {cycle}s"
                ),
            });
        }
    }

    out
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
    /// Number of quarantined proxies shown in the queue table below
    /// (`min(quarantine_count, 50)`).
    fn queue_shown(&self) -> i64 {
        self.queue.len() as i64
    }
    /// The next scheduled check for a quarantined proxy.
    fn next_check(&self, row: &QuarantineRow) -> String {
        fmt_opt_ts_element(row.ladder_at)
    }

    /// Ladder step label: *second chance* or *recheck N*.
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

    ///
    /// CSS modifier for the backlog banner: `ok`, `warning`, or `danger`.
    fn backlog_level_class(&self) -> &'static str {
        match self.backlog {
            Some(ref b) => b.level.css_class(),
            None => "",
        }
    }

    /// Localized level label embedded in the banner title
    /// (`probe.level_warning` / `probe.level_danger`).
    fn backlog_level_label(&self) -> String {
        match self.backlog {
            Some(ref b) => self.lang.t(b.level.i18n_key()).to_string(),
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
                self.lang.t_named(
                    &key,
                    &[
                        ("days", days.to_string()),
                        ("limit", self.probe_view.queue_stale_days.to_string()),
                    ],
                )
            }
            "heartbeat_dead" => {
                let secs = self
                    .heartbeat
                    .as_ref()
                    .map(|hb| (fumox_core::models::now_ts() - hb.ts).max(0))
                    .unwrap_or(0);
                self.lang.t_named(&key, &[("secs", secs.to_string())])
            }
            "drain_over_target" => {
                let sample = self.probe_view.sample_size.max(1) as i64;
                let cycle = self.probe_view.cycle_interval_secs.max(1) as i64;
                let cycles = (b.quarantine_count.max(1) + sample - 1) / sample;
                let drain = ((cycles * cycle) + 59) / 60;
                self.lang.t_named(
                    &key,
                    &[
                        ("count", b.quarantine_count.to_string()),
                        ("drain", drain.to_string()),
                        ("target", b.target_drain_minutes.to_string()),
                    ],
                )
            }
            "all_ok" => {
                let sample = self.probe_view.sample_size.max(1) as i64;
                let cycle = self.probe_view.cycle_interval_secs.max(1) as i64;
                let cycles = (b.quarantine_count.max(1) + sample - 1) / sample;
                let drain = ((cycles * cycle) + 59) / 60;
                self.lang.t_named(
                    &key,
                    &[
                        ("count", b.quarantine_count.to_string()),
                        ("drain", drain.to_string()),
                        ("target", b.target_drain_minutes.to_string()),
                    ],
                )
            }
            _ => self.lang.t(&key).to_string(),
        }
    }

    /// Pre-localized text for a single tuning recommendation.
    fn backlog_rec_label(&self, idx: &usize) -> String {
        match self.backlog.as_ref() {
            Some(b) => b
                .recs
                .get(*idx)
                .map(|r| r.label.clone())
                .unwrap_or_default(),
            None => String::new(),
        }
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

    // True population count for the quarantine card. `proxy_counts` already
    // ran; pull the entry out instead of issuing another query. Missing
    // status (e.g. empty DB) collapses to 0.
    let quarantine_count = proxy_counts
        .iter()
        .find(|(status, _)| status == "quarantine")
        .map(|(_, count)| *count)
        .unwrap_or(0);

    // Backlog-banner inputs. Two extra SQL queries, both are index hits
    // on `proxies(status, ladder_at)` and `proxies(status, quarantined_at)`
    // and run once per page render (not per row).
    let now = fumox_core::models::now_ts();
    let due_count = match proxies::count_due_quarantine(pool, now).await {
        Ok(n) => n,
        Err(err) => return server_error(lang, &err),
    };
    let oldest_quarantined_at = match proxies::oldest_quarantined_at(pool).await {
        Ok(v) => v,
        Err(err) => return server_error(lang, &err),
    };
    let oldest_quarantined_age_secs = oldest_quarantined_at.map(|ts| (now - ts).max(0));
    let (heartbeat_alive, heartbeat_age_secs) = match heartbeat.as_ref() {
        Some(hb) => (hb.alive, Some((now - hb.ts).max(0))),
        None => (false, None),
    };

    let probe_view = ProbeView::from(&state.probe);
    let backlog = compute_backlog(
        quarantine_count,
        due_count,
        oldest_quarantined_age_secs,
        heartbeat_alive,
        heartbeat_age_secs,
        &state.probe,
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
            meow_last_ok,
            coverage,
            quarantine_count,
            queue,
            probe_view,
            backlog,
        },
        StatusCode::OK,
    )
}

// SSE stream.

/// SSE endpoint: forwards scheduler fetch events from the
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
