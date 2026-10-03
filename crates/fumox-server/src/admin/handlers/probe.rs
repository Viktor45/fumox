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

/// How old the probe heartbeat may be before the daemon is considered
/// down, in seconds. Follows the operator's setting: three beat
/// periods. The `.max(5)` mirrors the daemon's own beat period
/// (`heartbeat_interval_secs.max(5)`, `fumox-probe/src/main.rs`), which
/// is what keeps a daemon beating on schedule from being reported dead
/// when the operator configures a period below 5 s, the settings form
/// accepts `1..=86400`. Used for both the daemon card and the backlog
/// banner, so the two never disagree.
fn heartbeat_stale_after(cfg: &ProbeConfig) -> i64 {
    (cfg.heartbeat_interval_secs.max(5) as i64).saturating_mul(3)
}

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

/// Parsed `meow_memory` meta value, stamped by the probe daemon from
/// meow-rs' `GET /memory`.
#[derive(serde::Deserialize)]
struct MeowMemoryView {
    rss_bytes: u64,
    os_limit_bytes: u64,
    ts: i64,
}

impl MeowMemoryView {
    /// RSS as a share of the limit, when meow-rs resolved one.
    fn percent_of_limit(&self) -> Option<f64> {
        (self.os_limit_bytes > 0)
            .then(|| self.rss_bytes as f64 * 100.0 / self.os_limit_bytes as f64)
    }
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
fn rss_line(mem: &MeowMemoryView) -> String {
    let mut line = format!("RSS {}", fmt_rss_bytes(mem.rss_bytes));
    if let Some(pct) = mem.percent_of_limit() {
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
    meow_last_ok: Option<i64>,
    /// Kernel RSS as published by the probe daemon (`meow_memory` meta).
    meow_memory: Option<MeowMemoryView>,
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
/// by tests). `key` maps to a `probe.rec_<key>` i18n entry, `args` are
/// the named placeholders that entry needs. The label is resolved
/// through the catalog, never formatted here.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct TuningRec {
    key: &'static str,
    target_value: String,
    /// Named substitutions for the `probe.rec_<key>` entry.
    args: Vec<(&'static str, String)>,
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
    /// Modelled drain from [`CycleModel`], `None` when the cycle picks
    /// up no quarantine row at all and there is no drain to estimate.
    /// Every figure the page prints about draining comes from here.
    drain_minutes: Option<u64>,
    /// `queue_stale_days` after the `.max(1)` the daemon's retention
    /// applies, i.e. the number the stale heuristic actually compared
    /// against.
    stale_days: u64,
}

/// Integer ceiling division. The caller guarantees a positive
/// denominator; a `.max(1)` fallback would return a wrong-but-quiet
/// number instead, which is exactly the kind of silent miscalculation
/// this model exists to remove.
fn ceil_div(numerator: i128, denominator: i128) -> i128 {
    debug_assert!(denominator > 0, "ceil_div by zero");
    (numerator + denominator - 1) / denominator
}

/// The one model of "what one probe cycle does" in this file. Every
/// cycle-derived number the banner prints, the drain figure, the
/// level, the recommendation gate and the recommendations themselves,
/// comes from one `CycleModel` built per render, so no formula can
/// drift at a second call site.
#[derive(Clone, Copy, Debug)]
struct CycleModel {
    quarantine_count: i64,
    due_count: i64,
    sample_size: u32,
    concurrency: usize,
    /// Configured period, not the effective one; `period_secs` is.
    cycle_interval_secs: u64,
    /// Worst-case duration of a single T1 check.
    check_secs: u64,
    /// Rows a cycle can actually retire: the quarantine lane only
    /// takes rows whose `ladder_at` is in the past, capped at
    /// `sample_size`. Zero when nothing is due (the normal state for
    /// 12–16 h after any quarantine) or when `sample_size` is 0.
    retire_per_cycle: i64,
    /// Estimated wall time of the quarantine lane: the only lane that
    /// retires queue rows. `run_cycle` also awaits the queued-checks,
    /// T1 sample and T2 batch lanes sequentially, and this estimate
    /// deliberately does not claim their work.
    lane_secs: u64,
    /// Effective period between cycle starts. The daemon's ticker uses
    /// `Skip` on missed ticks, so a lane longer than the interval
    /// pushes the next start out by the work.
    period_secs: u64,
    /// `retire_per_cycle == 0` means the cycle picks up no quarantine
    /// row at all, so there is no drain to estimate, neither "0
    /// minutes" nor "infinite". Both derived fields stay `None`, the
    /// soft gate cannot fire, and no recommendation is computed.
    cycles_to_drain: Option<i64>,
    drain_minutes: Option<u64>,
}

impl CycleModel {
    fn new(cfg: &ProbeConfig, quarantine_count: i64, due_count: i64) -> Self {
        derive_cycle_model(
            cycle_model_inputs(cfg),
            quarantine_count,
            due_count,
            cfg.sample_size,
            cfg.concurrency,
        )
    }

    /// Re-derive with a different per-cycle sample. Used to ask "what
    /// would the cycle look like if the operator raised `sample_size`?".
    fn with_sample(self, sample_size: u32) -> Self {
        derive_cycle_model(
            (self.cycle_interval_secs, self.check_secs),
            self.quarantine_count,
            self.due_count,
            sample_size,
            self.concurrency,
        )
    }

    fn with_concurrency(self, concurrency: usize) -> Self {
        derive_cycle_model(
            (self.cycle_interval_secs, self.check_secs),
            self.quarantine_count,
            self.due_count,
            self.sample_size,
            concurrency,
        )
    }
}

/// The two config-derived inputs the model reads, clamped the way the
/// daemon clamps them. `concurrency` is a bare `usize` in
/// `ProbeConfig` with a serde default and no bounds (`AppConfig::validate`
/// only checks `[meow]`), so `0` is reachable from a config file; the
/// daemon applies `.max(1)` before building its semaphore, and the
/// divide in `derive` is unguarded by design.
fn cycle_model_inputs(cfg: &ProbeConfig) -> (u64, u64) {
    (
        cfg.cycle_interval_secs.max(1),
        cfg.connect_timeout_secs
            .saturating_add(cfg.tls_timeout_secs)
            .max(1),
    )
}

fn derive_cycle_model(
    inputs: (u64, u64),
    quarantine_count: i64,
    due_count: i64,
    sample_size: u32,
    concurrency: usize,
) -> CycleModel {
    let concurrency = concurrency.max(1);
    let (cycle_interval_secs, check_secs) = inputs;
    // `retire_per_cycle` is deliberately *not* clamped with `.max(1)`:
    // `sample_size = 0` is accepted by the settings form and makes the
    // daemon take literally nothing, so 0 is the honest rate.
    let retire_per_cycle = (sample_size as i64).min(due_count.max(0));
    let lane_secs = if retire_per_cycle == 0 {
        0
    } else {
        ceil_div(retire_per_cycle as i128, concurrency as i128) as u64 * check_secs
    };
    let period_secs = cycle_interval_secs.max(lane_secs);
    let cycles_to_drain = (retire_per_cycle > 0)
        .then(|| ceil_div(quarantine_count as i128, retire_per_cycle as i128) as i64);
    let drain_minutes = cycles_to_drain
        .map(|c| ceil_div((c as i128).saturating_mul(period_secs as i128), 60) as u64);
    CycleModel {
        quarantine_count,
        due_count,
        sample_size,
        concurrency,
        cycle_interval_secs,
        check_secs,
        retire_per_cycle,
        lane_secs,
        period_secs,
        cycles_to_drain,
        drain_minutes,
    }
}

/// Heuristics + recommendation math for the backlog banner. Pure
/// function, no I/O, so the test suite can hit every branch without
/// seeding a database.
///
/// `oldest_quarantined_age_secs` = `now - MIN(quarantined_at)` if any
/// quarantine row exists, `None` otherwise. `heartbeat_age_secs` is
/// `now - heartbeat.ts` when a heartbeat row exists, `None` when it
/// does not. A *missing* heartbeat is not a dead daemon, it is a
/// daemon that has not beaten yet (surfaced on the card instead).
/// The server applies one threshold, [`heartbeat_stale_after`], to
/// both the daemon card and this banner, so the two never disagree.
fn compute_backlog(
    quarantine_count: i64,
    due_count: i64,
    oldest_quarantined_age_secs: Option<i64>,
    heartbeat_age_secs: Option<i64>,
    cfg: &ProbeConfig,
) -> Option<BacklogDiagnostic> {
    // The raw configured value, not a clamped one. `sample_size = 0` is
    // reachable from the settings form (it accepts `0..=100000`) and
    // makes the daemon take literally nothing, so the two
    // sample-proportional triggers below have no sample to compare
    // against: "N× the per-cycle sample" over a zero sample states
    // nothing. `all_idle` reports that state with the numbers the
    // operator needs, so the triggers stay off at zero rather than
    // measuring a sample that does not exist.
    let sample_size = cfg.sample_size as i64;
    let model = CycleModel::new(cfg, quarantine_count, due_count);
    let target_minutes = cfg.backlog_target_drain_minutes.max(1);
    // Same `.max(1)` the daemon's retention applies before it computes
    // its cutoff (main.rs), so `queue_stale_days = 0` cannot pin the
    // banner at Danger on a queue the daemon itself considers fresh.
    let stale_days = cfg.queue_stale_days.max(1);

    let mut level = BacklogLevel::Warning;
    let mut factors: Vec<BacklogFactor> = Vec::new();

    if sample_size > 0 && quarantine_count > sample_size * 20 {
        factors.push(BacklogFactor {
            key: "deep_queue",
            severity: BacklogLevel::Warning,
        });
    }
    if sample_size > 0 && due_count > sample_size * 5 {
        factors.push(BacklogFactor {
            key: "due_overflow",
            severity: BacklogLevel::Warning,
        });
    }
    if let Some(age) = oldest_quarantined_age_secs {
        // 80 % of the retention window, in integer seconds.
        let stale_after = stale_days.saturating_mul(86_400).saturating_mul(4) / 5;
        // An age is a duration, so compare unsigned; a negative one
        // (a clock that moved backwards) clamps to 0 and stays below
        // any window.
        if age.max(0) as u64 > stale_after {
            level = level.escalate(BacklogLevel::Danger);
            factors.push(BacklogFactor {
                key: "stale_oldest",
                severity: BacklogLevel::Danger,
            });
        }
    }
    if let Some(age) = heartbeat_age_secs
        && age > heartbeat_stale_after(cfg)
    {
        level = level.escalate(BacklogLevel::Danger);
        factors.push(BacklogFactor {
            key: "heartbeat_dead",
            severity: BacklogLevel::Danger,
        });
    }

    let hard_factors = !factors.is_empty();
    let over_target = model.drain_minutes.is_some_and(|d| d > target_minutes);

    // One state factor on top of the hard triggers. It is `all_idle`
    // whenever the cycle retires nothing (and so there is no drain
    // figure to print), whatever else fired, that wording reports
    // what the cycle took rather than asserting why, which is the only
    // claim the page can actually support.
    if model.retire_per_cycle == 0 {
        factors.push(BacklogFactor {
            key: "all_idle",
            severity: BacklogLevel::Ok,
        });
        if !hard_factors {
            level = BacklogLevel::Ok;
        }
    } else if !hard_factors {
        if over_target {
            factors.push(BacklogFactor {
                key: "drain_over_target",
                severity: BacklogLevel::Warning,
            });
        } else {
            factors.push(BacklogFactor {
                key: "all_ok",
                severity: BacklogLevel::Ok,
            });
            level = BacklogLevel::Ok;
        }
    }

    // Recommendations only when the modelled drain exceeds the target;
    // otherwise the banner shows the factors without prescriptive
    // knobs. `drain_minutes == None` can never reach here, `over_target`
    // is false and the sample rec below is gated on a modelled drain.
    let recs = if over_target {
        compute_recs(cfg, &model)
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
        drain_minutes: model.drain_minutes,
        stale_days,
    })
}

/// Smallest period the banner will recommend. The settings form accepts
/// `cycle_interval_secs` from `1`, but a cycle is several `SELECT`s
/// across the pool plus the writes its lanes make, and the daemon's own
/// beat period already carries a `.max(5)` floor, the same reason
/// [`heartbeat_stale_after`] starts its threshold there. Shortening the
/// cycle below the cadence the daemon considers sane for its heartbeat
/// is advice that costs more than the drain it buys, so the third
/// recommendation stays quiet instead of printing it.
const MIN_RECOMMENDED_CYCLE_SECS: u64 = 5;

/// Build up to three concrete suggestions, or none at all.
///
/// The three are evaluated *in sequence on a chained model*, not as
/// three independent guesses, so the printed set is self-consistent:
/// applying everything the banner prints leaves the modelled cycle
/// inside `cycle_interval_secs`. Returns an empty Vec when the drain
/// is unknown (the cycle picks up nothing) or already inside the target
/// window.
fn compute_recs(cfg: &ProbeConfig, model: &CycleModel) -> Vec<TuningRec> {
    let mut out = Vec::new();
    let Some(drain_now) = model.drain_minutes else {
        return out;
    };
    let target_minutes = cfg.backlog_target_drain_minutes.max(1);
    if drain_now <= target_minutes {
        return out;
    }
    let target_seconds = (target_minutes as i128).saturating_mul(60);
    // Everything below is evaluated on `planned`, which starts as the
    // current model and moves on when a recommendation is accepted.
    let mut planned = *model;

    // (1) Throughput. Gated on the queue actually holding more due
    // rows than a cycle can take, and capped at the number of rows
    // that can ever be due. A sample larger than `due_count` retires
    // exactly as many rows, so recommending it buys nothing.
    if model.due_count > model.sample_size as i64 {
        let required = ceil_div(
            (model.quarantine_count as i128).saturating_mul(model.period_secs as i128),
            target_seconds,
        )
        .min(model.due_count as i128)
        .clamp(1, 500) as u32;
        // 20 % margin: without it a queue one row over the sample prints
        // "recommend 51", which is noise. The cap cannot suppress a rec
        // worth printing, because the gate already requires
        // `due_count > sample_size`.
        if required as u64 * 5 > model.sample_size as u64 * 6
            && model.with_sample(required).drain_minutes < Some(drain_now)
        {
            out.push(TuningRec {
                key: "sample_size",
                target_value: required.to_string(),
                args: vec![
                    ("target", required.to_string()),
                    ("current", model.sample_size.to_string()),
                ],
            });
            planned = model.with_sample(required);
        }
    }

    // (2) Parallelism. Only when the modelled lane no longer fits the
    // period, and the value is the smallest `c <= 64` that brings it
    // back *at the sample size now in effect*, the recommended one if
    // (1) fired. When no such `c` exists, nothing is printed: a
    // concurrency number that does not fit would not help.
    if planned.lane_secs > planned.cycle_interval_secs {
        // `saturating_add`: `concurrency` is unbounded in the config,
        // and a start past 64 makes the range empty, i.e. no rec.
        let candidate = (planned.concurrency.saturating_add(1)..=64)
            .find(|c| planned.with_concurrency(*c).lane_secs <= planned.cycle_interval_secs);
        if let Some(c) = candidate {
            let lane_secs = planned.with_concurrency(c).lane_secs;
            out.push(TuningRec {
                key: "concurrency",
                target_value: c.to_string(),
                args: vec![
                    ("target", c.to_string()),
                    ("current", planned.concurrency.to_string()),
                    ("sample", planned.sample_size.to_string()),
                    ("interval_secs", planned.cycle_interval_secs.to_string()),
                    ("lane_secs", lane_secs.to_string()),
                ],
            });
        }
    }

    // (3) Period. Only when the shortened period still fits the work.
    // No `clamp`: the two comparisons are ordered, so the old
    // `min > max` panic has no way back. (2) and (3) stay mutually
    // exclusive, (2) needs `lane_secs > cycle`, (3) then needs
    // `required_period >= lane_secs > cycle > required_period`.
    if let Some(cycles) = planned.cycles_to_drain
        && cycles > 0
    {
        let required_period = ceil_div(target_seconds, cycles as i128) as u64;
        if required_period >= planned.lane_secs
            && required_period >= MIN_RECOMMENDED_CYCLE_SECS
            && required_period < planned.cycle_interval_secs.saturating_mul(8) / 10
        {
            out.push(TuningRec {
                key: "cycle_interval_secs",
                target_value: required_period.to_string(),
                args: vec![
                    ("target", required_period.to_string()),
                    ("current", planned.cycle_interval_secs.to_string()),
                ],
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
                let secs = self
                    .heartbeat
                    .as_ref()
                    .map(|hb| (fumox_core::models::now_ts() - hb.ts).max(0))
                    .unwrap_or(0);
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

    let proxy_counts = match proxies::count_by_status(pool).await {
        Ok(counts) => counts,
        Err(err) => return server_error(lang, &err),
    };

    let heartbeat_stale_after = heartbeat_stale_after(&state.probe);
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
                    // Same threshold the banner applies, so the card and
                    // the banner can never call the same daemon alive in
                    // one place and dead in the other.
                    alive: fumox_core::models::now_ts() - ts <= heartbeat_stale_after,
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

    let meow_memory = match meta_get(pool, "meow_memory").await {
        Ok(Some(raw)) => serde_json::from_str::<MeowMemoryView>(&raw).ok(),
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
    let heartbeat_age_secs = heartbeat.as_ref().map(|hb| (now - hb.ts).max(0));

    let probe_view = ProbeView::from(&state.probe);
    let backlog = compute_backlog(
        quarantine_count,
        due_count,
        oldest_quarantined_age_secs,
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
            meow_memory,
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

// Unit tests for the cycle model. Both functions are pure, so every
// branch is reachable without seeding a database, the integration
// tests in `admin::tests` only cover the states the daemon can
// actually produce.
#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(sample_size: u32, cycle_interval_secs: u64, target_minutes: u64) -> ProbeConfig {
        ProbeConfig {
            sample_size,
            cycle_interval_secs,
            backlog_target_drain_minutes: target_minutes,
            ..ProbeConfig::default()
        }
    }

    /// No quarantined row old enough to trip `stale_oldest` and no
    /// heartbeat: isolates the queue-driven factors.
    fn backlog(quarantine_count: i64, due_count: i64, cfg: &ProbeConfig) -> BacklogDiagnostic {
        compute_backlog(quarantine_count, due_count, None, None, cfg)
            .expect("compute_backlog always returns a diagnostic")
    }

    fn rec_pairs(diag: &BacklogDiagnostic) -> Vec<(&'static str, String)> {
        diag.recs
            .iter()
            .map(|r| (r.key, r.target_value.clone()))
            .collect()
    }

    fn factor_keys(diag: &BacklogDiagnostic) -> Vec<&'static str> {
        diag.factors.iter().map(|f| f.key).collect()
    }

    /// The old code clamped the recommended period with
    /// `clamp(5, cycle_interval_secs)`, which panics whenever
    /// `cycle_interval_secs < 5`, reachable straight from a config
    /// file, since `AppConfig::validate` does not bound the field and
    /// the settings form accepts 1..=86400.
    #[test]
    fn compute_backlog_does_not_panic_on_short_cycle_interval() {
        let mut cfg = cfg_with(400, 60, 1);
        cfg.cycle_interval_secs = 1;
        for cycle in 1..=4u64 {
            cfg.cycle_interval_secs = cycle;
            let diag = backlog(100_000, 100_000, &cfg);
            // No panic, and no recommendation the daemon cannot cash in.
            assert!(
                diag.recs.is_empty(),
                "cycle {cycle}: {:?}",
                rec_pairs(&diag)
            );
        }

        // Same fixture with `concurrency = 0`. Not reachable as a crash
        // before the model (the old code clamped at `.max(1)`, as does
        // the daemon before building its semaphore), this guards the
        // divide-by-zero a rewrite could introduce.
        cfg.cycle_interval_secs = 60;
        cfg.concurrency = 0;
        for cycle in 1..=4u64 {
            cfg.cycle_interval_secs = cycle;
            let _ = backlog(100_000, 100_000, &cfg);
        }
    }

    /// Same fixture: the sample rec is suppressed because raising the
    /// sample does not lower the modelled drain, and the concurrency
    /// search finds no value that fits a 1–4 s period, so nothing is
    /// printed rather than a knob that cannot change the outcome.
    #[test]
    fn recs_are_empty_when_no_knob_can_help() {
        let mut cfg = cfg_with(400, 60, 1);
        for cycle in 1..=4u64 {
            cfg.cycle_interval_secs = cycle;
            let diag = backlog(100_000, 100_000, &cfg);
            assert_eq!(diag.level, BacklogLevel::Warning, "cycle {cycle}");
            assert!(
                diag.recs.is_empty(),
                "cycle {cycle}: {:?}",
                rec_pairs(&diag)
            );
        }
    }

    /// The ladder only offers rows whose `ladder_at` is in the past, so
    /// a queue with nothing due has no drain to estimate and no knob
    /// that can change it.
    #[test]
    fn drain_model_uses_due_count() {
        let cfg = cfg_with(50, 60, 60);

        let model = CycleModel::new(&cfg, 4_000, 50);
        assert_eq!(model.retire_per_cycle, 50);
        assert_eq!(model.drain_minutes, Some(187));
        let diag = backlog(4_000, 50, &cfg);
        // 4 000 rows against a sample of 50 trips `deep_queue` (20x the
        // per-cycle sample), and a hard trigger replaces the soft state
        // factor: the operator is told the queue is oversized, and the
        // recommendations below carry the drain consequence.
        assert!(
            factor_keys(&diag).contains(&"deep_queue"),
            "{:?}",
            factor_keys(&diag)
        );
        assert!(
            !diag.recs.is_empty(),
            "expected recs: {:?}",
            rec_pairs(&diag)
        );

        // 4 000 rows, none due: the state the daemon sits in for 12–16 h
        // after any quarantine.
        let idle = CycleModel::new(&cfg, 4_000, 0);
        assert_eq!(idle.retire_per_cycle, 0);
        assert_eq!(idle.cycles_to_drain, None);
        assert_eq!(idle.drain_minutes, None);
        let diag = backlog(4_000, 0, &cfg);
        let keys = factor_keys(&diag);
        assert!(keys.contains(&"all_idle"), "{keys:?}");
        assert!(!keys.contains(&"drain_over_target"), "{keys:?}");
        assert!(diag.recs.is_empty(), "{:?}", rec_pairs(&diag));
    }

    /// A sample larger than the number of due rows retires exactly as
    /// many rows, so recommending it buys nothing. Over a grid of queue
    /// depths, due counts, targets and samples, no emitted `sample_size`
    /// rec may exceed `due_count`.
    #[test]
    fn sample_size_rec_is_capped_by_rows_due() {
        let mut emitted = 0;
        for quarantine_count in [500i64, 4_000, 100_000] {
            for due_count in [0i64, 51, 120, 900, 3_000, 100_000] {
                for target in [5u64, 15, 60, 1440] {
                    for sample_size in [50u32, 400, 500] {
                        let cfg = cfg_with(sample_size, 60, target);
                        for (key, value) in rec_pairs(&backlog(quarantine_count, due_count, &cfg)) {
                            if key != "sample_size" {
                                continue;
                            }
                            emitted += 1;
                            let value: i64 = value.parse().unwrap();
                            assert!(
                                value <= due_count,
                                "q={quarantine_count} due={due_count} target={target} \
                                 sample={sample_size}: rec {value} exceeds the rows that can be due"
                            );
                        }
                    }
                }
            }
        }
        assert!(emitted > 0, "grid produced no sample_size rec at all");

        // Concrete fixture: the uncapped formula asks for 156, but the
        // daemon can only ever take 120 rows while 120 are due.
        let cfg = cfg_with(50, 60, 60);
        assert_eq!(
            rec_pairs(&backlog(4_000, 120, &cfg)),
            vec![
                ("sample_size", "120".to_string()),
                ("concurrency", "40".to_string())
            ]
        );
    }

    /// The 20 % margin: a queue one row over the sample must not get a
    /// "recommend 51" nudge. It is a noise floor, not a gate: the
    /// concurrency rec still fires.
    #[test]
    fn sample_size_rec_respects_the_twenty_percent_margin() {
        let cfg = cfg_with(50, 60, 1);
        assert_eq!(
            rec_pairs(&backlog(51, 51, &cfg)),
            vec![("concurrency", "17".to_string())]
        );
    }

    /// The whole printed set must be simultaneously applicable: a
    /// concurrency rec is only useful if it brings the modelled lane
    /// back inside the period *at the sample size in effect*. The
    /// independent evaluation this replaces printed `sample_size = 156`
    /// together with `concurrency = 17`, and following both left
    /// `ceil(156 / 17) × 20 = 200 s` in a 60 s period.
    #[test]
    fn concurrency_rec_is_certified_with_the_recommended_sample() {
        let cfg = cfg_with(50, 60, 60);
        let recs = rec_pairs(&backlog(4_000, 4_000, &cfg));
        assert_eq!(
            recs,
            vec![
                ("sample_size", "156".to_string()),
                ("concurrency", "52".to_string())
            ]
        );

        let mut model = CycleModel::new(&cfg, 4_000, 4_000);
        for (key, value) in recs {
            match key {
                "sample_size" => model = model.with_sample(value.parse().unwrap()),
                "concurrency" => model = model.with_concurrency(value.parse().unwrap()),
                other => panic!("unexpected rec {other}"),
            }
        }
        assert_eq!(model.lane_secs, 60);
        assert!(model.lane_secs <= model.cycle_interval_secs);
    }

    /// The worked example in both user guides.
    #[test]
    fn modelled_drain_pins_the_guide_worked_example() {
        let cfg = cfg_with(50, 60, 60);

        // 800 due rows is past the `due_overflow` trigger, so the guide
        // must not call this state silent even though its drain fits
        // the target and no knob is recommended.
        let model = CycleModel::new(&cfg, 800, 800);
        assert_eq!(model.drain_minutes, Some(38));
        let diag = backlog(800, 800, &cfg);
        assert!(factor_keys(&diag).contains(&"due_overflow"));
        assert!(diag.recs.is_empty(), "{:?}", rec_pairs(&diag));

        let model = CycleModel::new(&cfg, 4_000, 4_000);
        assert_eq!(model.drain_minutes, Some(187));
        assert_eq!(
            rec_pairs(&backlog(4_000, 4_000, &cfg)),
            vec![
                ("sample_size", "156".to_string()),
                ("concurrency", "52".to_string())
            ]
        );

        // 389 rows in a lane need 980 s at any concurrency up to 64, so
        // no parallelism value is printed. One that did not fit would
        // be a knob the operator turns for nothing.
        let model = CycleModel::new(&cfg, 10_000, 10_000);
        assert_eq!(model.drain_minutes, Some(467));
        assert_eq!(
            rec_pairs(&backlog(10_000, 10_000, &cfg)),
            vec![("sample_size", "389".to_string())]
        );

        let model = CycleModel::new(&cfg, 100_000, 100_000);
        assert_eq!(model.drain_minutes, Some(4_667));
        assert_eq!(
            rec_pairs(&backlog(100_000, 100_000, &cfg)),
            vec![("sample_size", "500".to_string())]
        );
    }

    /// Keeps the scaling axis of the integration test this replaces,
    /// at a level the model can pin. At defaults the 20 s worst case
    /// per check caps throughput at `concurrency / check` rows/s, so a
    /// 4 000-row queue simply cannot drain in 15 min at any sample.
    #[test]
    fn sample_size_rec_saturates_as_the_target_tightens() {
        let recs = |target| {
            let cfg = cfg_with(50, 60, target);
            rec_pairs(&backlog(4_000, 4_000, &cfg))
                .into_iter()
                .find(|(k, _)| *k == "sample_size")
                .map(|(_, v)| v)
                .expect("sample_size rec")
        };
        assert_eq!(recs(60), "156");
        assert_eq!(recs(15), "500");
    }

    /// Three beat periods, with the daemon's own `.max(5)` floor on the
    /// period: at `heartbeat_interval_secs = 1` a daemon beating every
    /// 5 s is not dead after 3 s.
    #[test]
    fn heartbeat_threshold_mirrors_the_daemon_beat_period() {
        let stale_after = |secs: u64| {
            let cfg = ProbeConfig {
                heartbeat_interval_secs: secs,
                ..ProbeConfig::default()
            };
            heartbeat_stale_after(&cfg)
        };
        assert_eq!(stale_after(1), 15);
        assert_eq!(stale_after(5), 15);
        assert_eq!(stale_after(30), 90);
        assert_eq!(stale_after(300), 900);
    }

    /// `queue_stale_days = 0` means "keep one day" to the daemon's
    /// retention, so the banner must not pin Danger on a queue it would
    /// purge tomorrow.
    #[test]
    fn queue_stale_days_zero_does_not_pin_danger() {
        let mut cfg = ProbeConfig {
            queue_stale_days: 0,
            ..ProbeConfig::default()
        };
        let two_hours = 2 * 3_600;
        let diag = compute_backlog(1, 0, Some(two_hours), None, &cfg).unwrap();
        assert_eq!(diag.stale_days, 1);
        assert_ne!(diag.level, BacklogLevel::Danger);
        assert!(!factor_keys(&diag).contains(&"stale_oldest"));

        // The clamp is a clamp, not a switch-off: 30 days is still stale.
        cfg.queue_stale_days = 7;
        let diag = compute_backlog(1, 0, Some(30 * 86_400), None, &cfg).unwrap();
        assert_eq!(diag.level, BacklogLevel::Danger);
        assert!(factor_keys(&diag).contains(&"stale_oldest"));
    }

    /// `sample_size = 0` is reachable from the settings form. The
    /// sample-proportional triggers would compare the queue against a
    /// sample that does not exist and print a ratio over zero; the
    /// one true statement about that state is the one `all_idle`
    /// makes, and the configured `0` has to survive into it.
    #[test]
    fn sample_size_zero_reports_idleness_not_a_ratio_over_zero() {
        let cfg = cfg_with(0, 60, 60);
        for (quarantine, due) in [(0, 0), (1, 0), (25, 0), (400, 400), (100_000, 100_000)] {
            let diag = backlog(quarantine, due, &cfg);
            assert_eq!(
                factor_keys(&diag),
                vec!["all_idle"],
                "{quarantine}/{due}: {:?}",
                factor_keys(&diag)
            );
            assert_eq!(diag.level, BacklogLevel::Ok, "{quarantine}/{due}");
            assert_eq!(diag.due_capacity, 0);
            assert_eq!(diag.drain_minutes, None);
            assert!(rec_pairs(&diag).is_empty());
        }

        // A dead daemon and a stale row still speak over it: those are
        // measured in seconds and days, not against the sample.
        let diag = compute_backlog(400, 400, Some(9 * 86_400), Some(600), &cfg).unwrap();
        assert_eq!(diag.level, BacklogLevel::Danger);
        assert!(factor_keys(&diag).contains(&"stale_oldest"));
        assert!(factor_keys(&diag).contains(&"heartbeat_dead"));

        // One row is the smallest non-idle sample, and it behaves as
        // it always did: the triggers come back rather than staying
        // off for every value below some threshold.
        let diag = backlog(21, 0, &cfg_with(1, 60, 60));
        assert!(factor_keys(&diag).contains(&"deep_queue"));
    }

    /// The third recommendation shortens the cycle. With aggressive
    /// timeouts the modelled lane is short enough that the arithmetic
    /// lands on a 2-second cycle. A period faster than the daemon's own
    /// beat floor, which is churn the operator cannot use. The gate
    /// stays silent instead of printing it, while a period it can
    /// certify above the floor still prints.
    #[test]
    fn period_rec_never_lands_below_the_beating_floor() {
        // `due <= sample_size`, so the throughput rec cannot fire and
        // take the chained model out from under the period arithmetic.
        let cfg = ProbeConfig {
            sample_size: 100,
            cycle_interval_secs: 60,
            backlog_target_drain_minutes: 5,
            connect_timeout_secs: 1,
            tls_timeout_secs: 1,
            concurrency: 64,
            ..ProbeConfig::default()
        };
        let rec = |quarantine| rec_pairs(&backlog(quarantine, 50, &cfg));

        // 1 500 rows, 50 retired per cycle, a 2 s lane inside a 60 s
        // period: 30 min to drain against a 5 min target, and the
        // arithmetic answers 10 s.
        let model = CycleModel::new(&cfg, 1_500, 50);
        assert_eq!(model.cycles_to_drain, Some(30));
        assert_eq!(model.drain_minutes, Some(30));
        assert_eq!(
            rec(1_500),
            vec![("cycle_interval_secs", "10".to_string())],
            "the floor must gate the value, not the knob"
        );

        // Ten times the queue over the same period: the arithmetic
        // answers 2 s, which is under the floor. Before it existed this
        // printed `cycle_interval_secs = 2`.
        let model = CycleModel::new(&cfg, 10_000, 50);
        assert_eq!(model.cycles_to_drain, Some(200));
        assert_eq!(
            rec(10_000),
            Vec::<(&str, String)>::new(),
            "a 2 s cycle is not a recommendation"
        );
    }

    /// Every value the banner prints has to be one an operator can
    /// actually set, and one the daemon can live with. Swept over the
    /// ranges the settings form offers rather than asserted on the few
    /// states the worked example reaches, because the arithmetic is
    /// the part that has no test of its own.
    #[test]
    fn recs_stay_inside_the_range_the_form_accepts() {
        for sample in [0u32, 1, 7, 50, 500, 5_000, 100_000] {
            for cycle in [1u64, 2, 5, 60, 3_600, 86_400] {
                for concurrency in [1usize, 2, 8, 64, 1_024] {
                    for target in [5u64, 60, 1_440] {
                        let mut cfg = cfg_with(sample, cycle, target);
                        cfg.concurrency = concurrency;
                        for quarantine in [0i64, 1, 800, 4_000, 100_000, 10_000_000] {
                            for (key, value) in rec_pairs(&backlog(quarantine, quarantine, &cfg)) {
                                let n: u64 = value.parse().expect("rec value is a number");
                                let bound = match key {
                                    "sample_size" => 1..=500,
                                    // The search stops at 64 by design: past
                                    // that, a recommendation is a load test.
                                    "concurrency" => 1..=64,
                                    "cycle_interval_secs" => MIN_RECOMMENDED_CYCLE_SECS..=cycle,
                                    other => panic!("unexpected rec {other}"),
                                };
                                assert!(
                                    bound.contains(&n),
                                    "sample {sample} cycle {cycle} conc {concurrency} \
                                     target {target} q {quarantine}: {key} = {value}, \
                                     want {bound:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Regression: the RSS line is rendered through an escaping handle, so
    /// it once shipped a `time` element inside and the reader saw literal
    /// `<time class="ts" ...>` source in the card, wrapped over four lines.
    /// The timestamp belongs to the template (`ts(..) | safe`); the line
    /// stays plain text.
    #[test]
    fn rss_line_carries_no_markup() {
        let mem = MeowMemoryView {
            rss_bytes: 25_780_224,
            os_limit_bytes: 2_147_483_648,
            ts: 1_700_000_000,
        };
        let line = rss_line(&mem);
        assert!(!line.contains('<'), "markup leaked into the line: {line}");
        assert!(!line.contains('>'), "markup leaked into the line: {line}");
        assert!(line.contains("24.6 MiB"), "{line}");
        // A missing limit hides the share instead of dividing by zero.
        let no_limit = MeowMemoryView {
            os_limit_bytes: 0,
            ..mem
        };
        assert_eq!(rss_line(&no_limit), "RSS 24.6 MiB");
    }
}
