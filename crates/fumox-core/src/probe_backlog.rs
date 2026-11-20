//! The probe cycle model: what one cycle of the probe daemon does, and what
//! the backlog banner derives from it. It lives in the core crate because it
//! is a statement about the daemon's behaviour, not about the admin panel:
//! the panel keeps the input gathering (the SQL reads) and the rendering
//! (the wording), everything in between is here, so there is exactly one
//! formula behind every number the banner prints.

use crate::config::ProbeConfig;

/// Smallest period the banner will recommend. The settings form accepts
/// `cycle_interval_secs` from `1`, but a cycle is several `SELECT`s across
/// the pool plus the writes its lanes make, and the daemon's own beat period
/// already carries a `.max(5)` floor (the same reason
/// [`heartbeat_stale_after`] starts its threshold there), so a shorter
/// recommendation would cost more than the drain it buys.
pub const MIN_RECOMMENDED_CYCLE_SECS: u64 = 5;

/// How old the probe heartbeat may be before the daemon is considered down,
/// in seconds: three beat periods. One threshold for both the daemon card and
/// the backlog banner, so the two never disagree.
///
/// `reported_secs` is the beat period the daemon published in its heartbeat
/// payload, authoritative when present (server and probe may read different
/// config files); `None` falls back to this server's config. The `.max(5)`
/// mirrors the daemon's own beat floor (`fumox-probe/src/main.rs`).
pub fn heartbeat_stale_after(cfg: &ProbeConfig, reported_secs: Option<u64>) -> i64 {
    let secs = reported_secs.unwrap_or(cfg.heartbeat_interval_secs);
    (secs.max(5) as i64).saturating_mul(3)
}

/// How old the last successful meow-rs contact may be before the engine card
/// calls the contact stale, in seconds: three probe cycles (the T2 batch
/// contacts it once per cycle). Reported as stale rather than dead because
/// the silence can also mean the pool has no T2 candidates at all.
///
/// `reported_secs` (`cycle_interval_secs`) is authoritative when present,
/// same reason as in [`heartbeat_stale_after`].
pub fn meow_stale_after(cfg: &ProbeConfig, reported_secs: Option<u64>) -> i64 {
    let secs = reported_secs.unwrap_or(cfg.cycle_interval_secs);
    (secs.max(5) as i64).saturating_mul(3)
}

/// Severity of a single trigger; the banner picks the highest severity across
/// all triggers. `Ok` shows when no heuristic fired and the drain fits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BacklogLevel {
    Ok,
    Warning,
    Danger,
}

impl BacklogLevel {
    pub fn escalate(self, other: BacklogLevel) -> BacklogLevel {
        match (self, other) {
            (BacklogLevel::Danger, _) | (_, BacklogLevel::Danger) => BacklogLevel::Danger,
            (BacklogLevel::Warning, _) | (_, BacklogLevel::Warning) => BacklogLevel::Warning,
            _ => BacklogLevel::Ok,
        }
    }
}

/// One trigger that fired: `key` maps to a `probe.factor_<key>` entry of the
/// message catalog; the panel resolves it, the model only names it.
#[derive(Clone, Copy, Debug)]
pub struct BacklogFactor {
    pub key: &'static str,
}

/// One concrete suggested change: `key` maps to a `probe.rec_<key>` catalog
/// entry, `args` are the named placeholders it needs (the new value rides in
/// them under `target`).
#[derive(Clone, Debug)]
pub struct TuningRec {
    pub key: &'static str,
    pub args: Vec<(&'static str, String)>,
}

/// Bundle of facts the banner needs to render.
#[derive(Clone, Debug)]
pub struct BacklogDiagnostic {
    pub level: BacklogLevel,
    pub factors: Vec<BacklogFactor>,
    pub recs: Vec<TuningRec>,
    pub target_drain_minutes: u64,
    pub quarantine_count: i64,
    pub due_count: i64,
    pub due_capacity: u32,
    pub oldest_quarantined_age_secs: Option<i64>,
    /// Age of the daemon heartbeat when it could be read; printed with the
    /// `heartbeat_dead` verdict, from the same source.
    pub heartbeat_age_secs: Option<i64>,
    /// Modelled drain from [`CycleModel`]; `None` when the cycle picks up no
    /// quarantine row at all, so there is no drain to estimate.
    pub drain_minutes: Option<u64>,
    /// `queue_stale_days` after the `.max(1)` the daemon's retention
    /// applies, i.e. the number the stale heuristic actually compared
    /// against.
    pub stale_days: u64,
}

/// The facts the backlog banner is computed from; independent of each other,
/// so the panel gathers them in parallel.
#[derive(Clone, Copy, Debug, Default)]
pub struct BacklogInputs {
    /// Proxies in `status = 'quarantine'`.
    pub quarantine_count: i64,
    /// Quarantined rows whose next check is due.
    pub due_count: i64,
    /// Age of the oldest quarantined row in seconds, `None` when no row
    /// is quarantined.
    pub oldest_quarantined_age_secs: Option<i64>,
    /// Age of the daemon heartbeat in seconds. `None` when the daemon
    /// has not beaten yet: a daemon that has not started is not a dead
    /// one.
    pub heartbeat_age_secs: Option<i64>,
    /// The beat period the daemon published in its own heartbeat.
    pub reported_heartbeat_secs: Option<u64>,
    /// The daemon wrote a heartbeat the panel cannot read: the age is
    /// unknown, and a stamp nobody can read is not a working daemon.
    pub heartbeat_unreadable: bool,
}

/// The caller guarantees a positive denominator; a `.max(1)` fallback would
/// return a wrong-but-quiet number instead.
fn ceil_div(numerator: i128, denominator: i128) -> i128 {
    debug_assert!(denominator > 0, "ceil_div by zero");
    (numerator + denominator - 1) / denominator
}

/// The one model of "what one probe cycle does": every cycle-derived number
/// the banner prints comes from one `CycleModel` built per render, so no
/// formula can drift at a second call site.
#[derive(Clone, Copy, Debug)]
pub struct CycleModel {
    pub quarantine_count: i64,
    pub due_count: i64,
    pub sample_size: u32,
    pub concurrency: usize,
    /// Configured period, not the effective one; `period_secs` is.
    pub cycle_interval_secs: u64,
    /// Worst-case duration of a single T1 check.
    pub check_secs: u64,
    /// Rows a cycle can actually retire: the quarantine lane only takes rows
    /// whose `ladder_at` is in the past, capped at `sample_size`. Zero when
    /// nothing is due (the normal state for 12-16 h after any quarantine) or
    /// when `sample_size` is 0.
    pub retire_per_cycle: i64,
    /// Estimated wall time of the quarantine lane, the only lane that
    /// retires queue rows; the estimate deliberately does not claim the
    /// queued-checks, T1 sample and T2 batch lanes `run_cycle` also awaits.
    pub lane_secs: u64,
    /// Effective period between cycle starts. The daemon's ticker uses
    /// `Skip` on missed ticks, so a lane longer than the interval
    /// pushes the next start out by the work.
    pub period_secs: u64,
    /// `None` when `retire_per_cycle == 0`: no quarantine row picked up, no
    /// drain to estimate (neither "0 minutes" nor "infinite"); both derived
    /// fields stay `None`, the soft gate cannot fire.
    pub cycles_to_drain: Option<i64>,
    pub drain_minutes: Option<u64>,
}

impl CycleModel {
    pub fn new(cfg: &ProbeConfig, quarantine_count: i64, due_count: i64) -> Self {
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
    pub fn with_sample(self, sample_size: u32) -> Self {
        derive_cycle_model(
            (self.cycle_interval_secs, self.check_secs),
            self.quarantine_count,
            self.due_count,
            sample_size,
            self.concurrency,
        )
    }

    pub fn with_concurrency(self, concurrency: usize) -> Self {
        derive_cycle_model(
            (self.cycle_interval_secs, self.check_secs),
            self.quarantine_count,
            self.due_count,
            self.sample_size,
            concurrency,
        )
    }
}

/// Clamped the way the daemon clamps them: the config bounds table starts
/// `probe.cycle_interval_secs` and `probe.concurrency` at 1 and refuses the
/// file otherwise, so the clamps are guards for a `ProbeConfig` built in
/// code rather than read from a file; the divide in `derive` is unguarded by
/// design.
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
    // a zero sample makes the daemon take literally nothing, so 0 is
    // the honest rate
    let retire_per_cycle = (sample_size as i64).min(due_count.max(0));
    let lane_secs = if retire_per_cycle == 0 {
        0
    } else {
        (ceil_div(retire_per_cycle as i128, concurrency as i128) as u64).saturating_mul(check_secs)
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

/// Heuristics + recommendation math for the backlog banner. Pure function, no
/// I/O, so the test suite can hit every branch without seeding a database.
///
/// `oldest_quarantined_age_secs` = `now - MIN(quarantined_at)` if any
/// quarantine row exists, `None` otherwise. `heartbeat_age_secs` is
/// `now - heartbeat.ts` when a heartbeat row exists. A *missing* heartbeat is
/// not a dead daemon, it is one that has not beaten yet (surfaced on the card
/// instead); the server applies one threshold, [`heartbeat_stale_after`], to
/// both the daemon card and this banner.
pub fn compute_backlog(inputs: &BacklogInputs, cfg: &ProbeConfig) -> BacklogDiagnostic {
    let quarantine_count = inputs.quarantine_count;
    let due_count = inputs.due_count;
    // The raw configured value, not a clamped one. The bounds table starts
    // the sample at 1, so a zero sample is not a state an operator can
    // reach; the branches below still guard it, because a `ProbeConfig`
    // built in code can carry one and the sample-proportional triggers have
    // no sample to compare against. `all_idle` reports that state with the
    // numbers the operator needs
    let sample_size = cfg.sample_size as i64;
    let model = CycleModel::new(cfg, quarantine_count, due_count);
    let target_minutes = cfg.backlog_target_drain_minutes.max(1);
    // Same `.max(1)` the daemon's retention applies before it computes
    // its cutoff (main.rs), so `queue_stale_days = 0` cannot pin the
    // banner at Danger on a queue the daemon itself considers fresh
    let stale_days = cfg.queue_stale_days.max(1);

    let mut level = BacklogLevel::Warning;
    let mut factors: Vec<BacklogFactor> = Vec::new();

    if sample_size > 0 && quarantine_count > sample_size * 20 {
        factors.push(BacklogFactor { key: "deep_queue" });
    }
    if sample_size > 0 && due_count > sample_size * 5 {
        factors.push(BacklogFactor {
            key: "due_overflow",
        });
    }
    if let Some(age) = inputs.oldest_quarantined_age_secs {
        // 80 % of the retention window, in integer seconds
        let stale_after = stale_days.saturating_mul(86_400).saturating_mul(4) / 5;
        // An age is a duration, so compare unsigned; a negative one
        // (a clock that moved backwards) clamps to 0 and stays below
        // any window
        if age.max(0) as u64 > stale_after {
            level = level.escalate(BacklogLevel::Danger);
            factors.push(BacklogFactor {
                key: "stale_oldest",
            });
        }
    }
    if let Some(age) = inputs.heartbeat_age_secs
        && age > heartbeat_stale_after(cfg, inputs.reported_heartbeat_secs)
    {
        level = level.escalate(BacklogLevel::Danger);
        factors.push(BacklogFactor {
            key: "heartbeat_dead",
        });
    }
    // A heartbeat record nobody can read carries no age; it reads as a dead
    // daemon, with its own factor so the operator sees *why* the card is red
    if inputs.heartbeat_unreadable {
        level = level.escalate(BacklogLevel::Danger);
        factors.push(BacklogFactor {
            key: "heartbeat_unreadable",
        });
    }

    let hard_factors = !factors.is_empty();
    let over_target = model.drain_minutes.is_some_and(|d| d > target_minutes);

    // One state factor on top of the hard triggers: `all_idle` whenever the
    // cycle retires nothing (no drain figure to print), whatever else fired,
    // because that wording reports what the cycle took rather than asserting
    // why
    if model.retire_per_cycle == 0 {
        factors.push(BacklogFactor { key: "all_idle" });
        // A zero sample while rows wait in the queue is not the calm state
        // `all_idle` alone suggests: nothing will drain until the sample
        // rises. The wording stays, the level rises to Warning
        let disabled_but_queued = sample_size == 0 && quarantine_count > 0;
        if !hard_factors && !disabled_but_queued {
            level = BacklogLevel::Ok;
        }
    } else if !hard_factors {
        if over_target {
            factors.push(BacklogFactor {
                key: "drain_over_target",
            });
        } else {
            factors.push(BacklogFactor { key: "all_ok" });
            level = BacklogLevel::Ok;
        }
    }

    // Recommendations only when the modelled drain exceeds the target;
    // otherwise the banner shows the factors without prescriptive knobs
    let recs = if over_target {
        compute_recs(cfg, &model)
    } else {
        Vec::new()
    };

    BacklogDiagnostic {
        level,
        factors,
        recs,
        target_drain_minutes: target_minutes,
        quarantine_count,
        due_count,
        due_capacity: cfg.sample_size,
        oldest_quarantined_age_secs: inputs.oldest_quarantined_age_secs,
        heartbeat_age_secs: inputs.heartbeat_age_secs,
        drain_minutes: model.drain_minutes,
        stale_days,
    }
}

/// The three suggestions are evaluated *in sequence on a chained model*, not
/// as three independent guesses, so the printed set is self-consistent:
/// applying everything the banner prints leaves the modelled cycle inside
/// `cycle_interval_secs`. Empty when the drain is unknown or already inside
/// the target window.
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
    // current model and moves on when a recommendation is accepted
    let mut planned = *model;

    // (1) Throughput. Gated on the queue actually holding more due
    // rows than a cycle can take, and capped at the number of rows
    // that can ever be due. A sample larger than `due_count` retires
    // exactly as many rows, so recommending it buys nothing
    if model.due_count > model.sample_size as i64 {
        let required = ceil_div(
            (model.quarantine_count as i128).saturating_mul(model.period_secs as i128),
            target_seconds,
        )
        .min(model.due_count as i128)
        .clamp(1, 500) as u32;
        // 20 % margin: without it a queue one row over the sample prints
        // "recommend 51", which is noise. The cap cannot suppress a rec worth
        // printing, the gate already requires `due_count > sample_size`
        if required as u64 * 5 > model.sample_size as u64 * 6
            && model.with_sample(required).drain_minutes < Some(drain_now)
        {
            out.push(TuningRec {
                key: "sample_size",
                args: vec![
                    ("target", required.to_string()),
                    ("current", model.sample_size.to_string()),
                ],
            });
            planned = model.with_sample(required);
        }
    }

    // (2) Parallelism. Only when the modelled lane no longer fits the
    // period, and the value is the smallest `c <= 64` that brings it back
    // *at the sample size now in effect*, the recommended one if (1) fired
    // When no such `c` exists, nothing is printed
    if planned.lane_secs > planned.cycle_interval_secs {
        // `saturating_add`: `concurrency` is unbounded in the config,
        // and a start past 64 makes the range empty, i.e. no rec
        let candidate = (planned.concurrency.saturating_add(1)..=64)
            .find(|c| planned.with_concurrency(*c).lane_secs <= planned.cycle_interval_secs);
        if let Some(c) = candidate {
            let lane_secs = planned.with_concurrency(c).lane_secs;
            out.push(TuningRec {
                key: "concurrency",
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

    // (3) Period. Only when the shortened period still fits the work. No
    // `clamp`: the comparisons are ordered, so the old `min > max` panic has
    // no way back. (2) and (3) stay mutually exclusive
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
                args: vec![
                    ("target", required_period.to_string()),
                    ("current", planned.cycle_interval_secs.to_string()),
                ],
            });
        }
    }

    out
}

// The functions are pure, so every branch is reachable without seeding a
// database.
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
        compute_backlog(
            &BacklogInputs {
                quarantine_count,
                due_count,
                ..BacklogInputs::default()
            },
            cfg,
        )
    }

    fn rec_pairs(diag: &BacklogDiagnostic) -> Vec<(&'static str, String)> {
        diag.recs
            .iter()
            .map(|r| {
                let target = r
                    .args
                    .iter()
                    .find(|(k, _)| *k == "target")
                    .expect("every rec carries its new value as the `target` arg")
                    .1
                    .clone();
                (r.key, target)
            })
            .collect()
    }

    fn factor_keys(diag: &BacklogDiagnostic) -> Vec<&'static str> {
        diag.factors.iter().map(|f| f.key).collect()
    }

    /// The old code clamped the recommended period with
    /// `clamp(5, cycle_interval_secs)`, which panics whenever
    /// `cycle_interval_secs < 5`, reachable straight from a config file:
    /// `AppConfig::validate` does not bound the field.
    #[test]
    fn compute_backlog_does_not_panic_on_short_cycle_interval() {
        let mut cfg = cfg_with(400, 60, 1);
        cfg.cycle_interval_secs = 1;
        for cycle in 1..=4u64 {
            cfg.cycle_interval_secs = cycle;
            let diag = backlog(100_000, 100_000, &cfg);
            // No panic, and no recommendation the daemon cannot cash in
            assert!(
                diag.recs.is_empty(),
                "cycle {cycle}: {:?}",
                rec_pairs(&diag)
            );
        }

        // Same fixture with `concurrency = 0`: guards the divide-by-zero a
        // rewrite could introduce for a `ProbeConfig` built in code, not a
        // state an operator can reach
        cfg.cycle_interval_secs = 60;
        cfg.concurrency = 0;
        for cycle in 1..=4u64 {
            cfg.cycle_interval_secs = cycle;
            let _ = backlog(100_000, 100_000, &cfg);
        }
    }

    /// The sample rec is suppressed (raising the sample does not lower the
    /// modelled drain) and the concurrency search finds no value that fits a
    /// 1-4 s period, so nothing is printed.
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

    #[test]
    fn drain_model_uses_due_count() {
        let cfg = cfg_with(50, 60, 60);

        let model = CycleModel::new(&cfg, 4_000, 50);
        assert_eq!(model.retire_per_cycle, 50);
        assert_eq!(model.drain_minutes, Some(187));
        let diag = backlog(4_000, 50, &cfg);
        // 4 000 rows against a sample of 50 trips `deep_queue` (20x the
        // per-cycle sample); a hard trigger replaces the soft state factor
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
        // after any quarantine
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

    /// Over a grid of queue depths, due counts, targets and samples, no
    /// emitted `sample_size` rec may exceed `due_count`.
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
        // daemon can only ever take 120 rows while 120 are due
        let cfg = cfg_with(50, 60, 60);
        assert_eq!(
            rec_pairs(&backlog(4_000, 120, &cfg)),
            vec![
                ("sample_size", "120".to_string()),
                ("concurrency", "40".to_string())
            ]
        );
    }

    /// A noise floor, not a gate: the queue one row over the sample gets no
    /// nudge, the concurrency rec still fires.
    #[test]
    fn sample_size_rec_respects_the_twenty_percent_margin() {
        let cfg = cfg_with(50, 60, 1);
        assert_eq!(
            rec_pairs(&backlog(51, 51, &cfg)),
            vec![("concurrency", "17".to_string())]
        );
    }

    /// The whole printed set must be simultaneously applicable: a concurrency
    /// rec is only useful if it brings the modelled lane back inside the
    /// period *at the sample size in effect*.
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

        // 800 due rows is past the `due_overflow` trigger: the guide must not
        // call this state silent
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

        // 389 rows in a lane need 980 s at any concurrency up to 64, so no
        // parallelism value is printed
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

    /// At defaults the 20 s worst case per check caps throughput at
    /// `concurrency / check` rows/s, so a 4 000-row queue cannot drain in
    /// 15 min at any sample.
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

    #[test]
    fn heartbeat_threshold_mirrors_the_daemon_beat_period() {
        let cfg = |secs: u64| ProbeConfig {
            heartbeat_interval_secs: secs,
            ..ProbeConfig::default()
        };
        assert_eq!(heartbeat_stale_after(&cfg(1), None), 15);
        assert_eq!(heartbeat_stale_after(&cfg(5), None), 15);
        assert_eq!(heartbeat_stale_after(&cfg(30), None), 90);
        assert_eq!(heartbeat_stale_after(&cfg(300), None), 900);
        assert_eq!(heartbeat_stale_after(&cfg(300), Some(30)), 90);
        assert_eq!(heartbeat_stale_after(&cfg(300), Some(1)), 15);
    }

    #[test]
    fn meow_stale_threshold_is_three_cycles() {
        let cfg = |secs: u64| ProbeConfig {
            cycle_interval_secs: secs,
            ..ProbeConfig::default()
        };
        assert_eq!(meow_stale_after(&cfg(1), None), 15);
        assert_eq!(meow_stale_after(&cfg(5), None), 15);
        assert_eq!(meow_stale_after(&cfg(60), None), 180);
        assert_eq!(meow_stale_after(&cfg(3_600), None), 10_800);
        assert_eq!(meow_stale_after(&cfg(3_600), Some(30)), 90);
        assert_eq!(meow_stale_after(&cfg(3_600), Some(1)), 15);
    }

    #[test]
    fn queue_stale_days_zero_does_not_pin_danger() {
        let mut cfg = ProbeConfig {
            queue_stale_days: 0,
            ..ProbeConfig::default()
        };
        let two_hours = 2 * 3_600;
        let diag = compute_backlog(
            &BacklogInputs {
                quarantine_count: 1,
                due_count: 0,
                oldest_quarantined_age_secs: Some(two_hours),
                ..BacklogInputs::default()
            },
            &cfg,
        );
        assert_eq!(diag.stale_days, 1);
        assert_ne!(diag.level, BacklogLevel::Danger);
        assert!(!factor_keys(&diag).contains(&"stale_oldest"));

        // The clamp is a clamp, not a switch-off: 30 days is still stale
        cfg.queue_stale_days = 7;
        let diag = compute_backlog(
            &BacklogInputs {
                quarantine_count: 1,
                due_count: 0,
                oldest_quarantined_age_secs: Some(30 * 86_400),
                ..BacklogInputs::default()
            },
            &cfg,
        );
        assert_eq!(diag.level, BacklogLevel::Danger);
        assert!(factor_keys(&diag).contains(&"stale_oldest"));
    }

    /// The config bounds table starts the sample at 1, so an operator cannot
    /// reach a zero sample; the model still guards it, because a
    /// `ProbeConfig` built in code can carry one and the sample-proportional
    /// triggers would print a ratio over zero. The one true statement about
    /// that state is the one `all_idle` makes.
    ///
    /// A queue that waits while checking is switched off is not the calm
    /// state the wording alone suggests, so the level rises to Warning; an
    /// empty queue stays Ok.
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
            let level = if quarantine > 0 {
                BacklogLevel::Warning
            } else {
                BacklogLevel::Ok
            };
            assert_eq!(diag.level, level, "{quarantine}/{due}");
            assert_eq!(diag.due_capacity, 0);
            assert_eq!(diag.drain_minutes, None);
            assert!(rec_pairs(&diag).is_empty());
        }

        // A dead daemon and a stale row still speak over it: those are
        // measured in seconds and days, not against the sample
        let diag = compute_backlog(
            &BacklogInputs {
                quarantine_count: 400,
                due_count: 400,
                oldest_quarantined_age_secs: Some(9 * 86_400),
                heartbeat_age_secs: Some(600),
                ..BacklogInputs::default()
            },
            &cfg,
        );
        assert_eq!(diag.level, BacklogLevel::Danger);
        assert!(factor_keys(&diag).contains(&"stale_oldest"));
        assert!(factor_keys(&diag).contains(&"heartbeat_dead"));

        // One row is the smallest non-idle sample: the triggers come back
        let diag = backlog(21, 0, &cfg_with(1, 60, 60));
        assert!(factor_keys(&diag).contains(&"deep_queue"));
    }

    #[test]
    fn an_unreadable_heartbeat_reads_as_a_dead_daemon() {
        let cfg = cfg_with(50, 60, 60);
        let diag = compute_backlog(
            &BacklogInputs {
                quarantine_count: 0,
                due_count: 0,
                heartbeat_unreadable: true,
                ..BacklogInputs::default()
            },
            &cfg,
        );
        assert_eq!(diag.level, BacklogLevel::Danger);
        assert!(factor_keys(&diag).contains(&"heartbeat_unreadable"));
        assert!(!factor_keys(&diag).contains(&"heartbeat_dead"));
    }

    /// With aggressive timeouts the arithmetic can land on a 2-second cycle,
    /// faster than the daemon's own beat floor: churn the operator cannot
    /// use. The gate stays silent instead of printing it.
    #[test]
    fn period_rec_never_lands_below_the_beating_floor() {
        // `due <= sample_size`, so the throughput rec cannot fire and
        // take the chained model out from under the period arithmetic
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
        // arithmetic answers 10 s
        let model = CycleModel::new(&cfg, 1_500, 50);
        assert_eq!(model.cycles_to_drain, Some(30));
        assert_eq!(model.drain_minutes, Some(30));
        assert_eq!(
            rec(1_500),
            vec![("cycle_interval_secs", "10".to_string())],
            "the floor must gate the value, not the knob"
        );

        // Ten times the queue over the same period: the arithmetic answers
        // 2 s, under the floor
        let model = CycleModel::new(&cfg, 10_000, 50);
        assert_eq!(model.cycles_to_drain, Some(200));
        assert_eq!(
            rec(10_000),
            Vec::<(&str, String)>::new(),
            "a 2 s cycle is not a recommendation"
        );
    }

    /// Every printed value must be one the operator can set and the daemon
    /// can live with; swept over the ranges the settings form offers.
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
                                    // that, a recommendation is a load test
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
}
