//! Source ingestion: fetch → decode → parse → reconcile → journal.
//!
//! One [`ingest_source`] call refreshes a single source end to end and
//! records the outcome in `fetch_log` and on the source row itself
//! (`last_fetched_at` / `last_error` / `error_class`).
//!
//! Parse failures are soft: HTTP 200 with unrecognizable content is
//! classified `parse_error`, including the "zero recognized
//! lines" case, and never panics.
//!
//! Reconciliation keeps alive-linger links for sources without `drop`
//! rules: a probe-verified proxy missing from the feed stays
//! linked until the probe itself retires it. A source that *does* carry
//! drop rules behaves differently: with `[ingest].drop_gate` on (the
//! default) its rules detach the proxies they would have discarded, so a
//! rule added later cannot be held off by still-alive rows.

use crate::fetcher::{FetchFailure, FetchedPayload, Fetcher};
use crate::pipeline::{CompiledPipeline, PipelineIssue, asn_number};
use fumox_core::db::DbPool;
use fumox_core::geo::{GEO_LOOKUP_CONCURRENCY, GeoResolver, HostGeo};
use fumox_core::models::{ProxyEntry, Source};
use fumox_core::repo::{fetch_log, probe, proxies, sources};

/// Outcome of one ingestion pass, for callers (scheduler, admin "refresh").
#[derive(Debug)]
pub enum IngestOutcome {
    /// Fetched and reconciled successfully.
    Ok {
        /// The proxies stored from this payload: what the journal and the
        /// admin panel report as `proxies_found`.
        proxies_found: usize,
        /// The proxies the source's own filters discarded (protocol
        /// allowlist and pipeline `drop` rules). Together with
        /// `proxies_found` this is the recognized count: found = dropped +
        /// kept.
        dropped: usize,
        stats: proxies::ReconciliationStats,
        /// Wall-clock duration of the fetch attempt in milliseconds,
        /// retries and their backoff included; `None` when no fetch
        /// happened at all (the freshness short-circuit answered from the
        /// source row).
        duration_ms: Option<i64>,
    },
    /// The fetch failed with a classified error (already journaled).
    FetchFailed {
        failure: FetchFailure,
        /// Duration of the failed attempt, retries and backoff included.
        duration_ms: i64,
    },
    /// HTTP 200 but the payload did not parse (already journaled).
    ParseFailed {
        message: String,
        /// Duration of the fetch that produced the payload.
        duration_ms: i64,
    },
    /// The payload was fetched and parsed, but the database refused to
    /// store it (already journaled under its own error class).
    StorageFailed {
        message: String,
        /// Duration of the fetch that produced the payload.
        duration_ms: i64,
    },
}

/// Fixed ingest settings from the config, everything not per-source.
#[derive(Debug, Clone, Copy)]
pub struct IngestSettings {
    /// `[ingest].refresh_check_limit`: how many newly inserted unknown
    /// proxies per refresh are enqueued for priority probing (0 disables
    /// the queue).
    pub refresh_check_limit: u32,
    /// `[ingest].drop_gate`: whether pipeline `drop` rules switch off the
    /// alive-linger link policy for their source (see
    /// [`fumox_core::ingest::IngestPolicy`]). On by default: a source whose
    /// rules would discard a proxy must not keep it linked.
    pub drop_gate: bool,
    /// `[ingest].removed_as_unknown`: whether a `removed` proxy the feed
    /// still carries is revived to `unknown` (via `proxies::revive_removed`)
    /// and re-enters the probe cycle.
    pub removed_as_unknown: bool,
}

/// Fetch, parse and reconcile one source; journal the result.
///
/// With `force = false` a `last_fetched_at` on the source row younger than
/// the source TTL short-circuits the HTTP fetch: the database is already
/// reconciled from that payload, so the row itself is the freshness marker.
/// Forced refreshes (the admin *Refresh now* button) always hit the network.
///
/// Geo facts are resolved per proxy host while the raw payload is already
/// parsed (the resolver caches both DNS and lookups) and persisted onto the
/// `proxies.geo_*` columns during reconciliation, so the admin panel's
/// country filter and geo card work without waiting for a subscription
/// render.
///
/// Freshly inserted proxies are enqueued for priority probing (up to
/// `settings.refresh_check_limit`): the probe drains the queue
/// at the start of its next cycle, newest first, so new servers get
/// verified instead of waiting out the random sample.
///
/// Rendered outputs are invalidated by the *callers* (the scheduler drops
/// the processed entries whose sources changed, see the outcome's
/// `stats`), so this function takes no cache handle.
pub async fn ingest_source(
    pool: &DbPool,
    fetcher: &Fetcher,
    geo: &GeoResolver,
    settings: IngestSettings,
    source: &Source,
    force: bool,
) -> IngestOutcome {
    let now = fumox_core::models::now_ts();

    // The freshness check reads the source row the caller loaded (the
    // scheduler re-reads every sweep, the admin *Refresh now* passes
    // `force`): no in-memory marker of our own to keep in step with the DB
    // stamp that `journal_success` writes. An unset or expired stamp means
    // the payload must be fetched; the comparison is the same
    // [`source_is_fresh`] predicate the scheduler's due check asks, this
    // being the second, row-fresh guard.
    if !force && source_is_fresh(now, source.last_fetched_at, source.cache_ttl_seconds) {
        tracing::debug!(source = %source.id, "raw snapshot still fresh; skipping fetch");
        return IngestOutcome::Ok {
            proxies_found: 0,
            dropped: 0,
            stats: proxies::ReconciliationStats::default(),
            duration_ms: None,
        };
    }

    // The fetch clock starts here and stops at the verdict, retries and
    // their backoff included: one `fetch` call can legitimately stretch far
    // past a minute ([fetch].max_retries × capped backoff), holds a
    // concurrency permit the whole time, and without a measurement a slow
    // upstream is indistinguishable from a fast one. Journaled into
    // `fetch_log.duration_ms` and carried on the outcome for the caller's
    // logs and events.
    let fetch_started = std::time::Instant::now();
    let fetched = match fetch_and_filter(fetcher, geo, source).await {
        Ok(fetched) => fetched,
        Err(FetchAndFilterError::Fetch(failure)) => {
            let duration_ms = elapsed_ms(fetch_started);
            journal_failure(pool, source, &failure, now, duration_ms).await;
            return IngestOutcome::FetchFailed {
                failure,
                duration_ms,
            };
        }
        Err(FetchAndFilterError::Parse { payload, message }) => {
            let duration_ms = elapsed_ms(fetch_started);
            journal_parse_failure(pool, source, &payload, &message, now, duration_ms).await;
            return IngestOutcome::ParseFailed {
                message,
                duration_ms,
            };
        }
    };
    let duration_ms = elapsed_ms(fetch_started);
    // `last_fetched_at` is a *freshness* stamp, not a download log: it
    // stands for "the database is already reconciled from this payload"
    // (the TTL short-circuit above reads it). It is therefore written only
    // once the payload has parsed and reconciled (`journal_success` runs
    // after the reconcile): stamping it before that made a single parse or
    // DB failure suppress every non-forced re-fetch for a whole TTL while
    // the scheduler kept reporting successful ingests.
    let payload = fetched.payload;
    let found = fetched.kept.len();
    // Alive-linger. `[ingest].drop_gate` decides whether a source's drop
    // rules disable it, see [`fumox_core::ingest::IngestPolicy`].
    let policy =
        fumox_core::ingest::IngestPolicy::refresh(settings.drop_gate, fetched.has_drop_rules);
    match proxies::reconcile_source(
        pool,
        &source.id,
        &fetched.kept,
        &fetched.kept_geo,
        now,
        policy,
    )
    .await
    {
        Ok(stats) => {
            // The database is now the content of this payload, so
            // `journal_success` stamps `last_fetched_at`, the freshness
            // marker the TTL short-circuit checks before the next
            // re-fetch.
            journal_success(pool, source, &payload, found, now, duration_ms).await;
            if fetched.dropped > 0 {
                tracing::info!(
                    source = %source.id,
                    recognised = fetched.recognized,
                    dropped = fetched.dropped,
                    kept = found,
                    "the source's own filters discarded entries before reconcile"
                );
            }
            // `[ingest].removed_as_unknown`: a removed proxy the feed
            // still carries resets to the pristine `unknown` state and
            // gets the same priority-queue handoff as a fresh insert.
            // A failure is logged and never fails the ingest, the
            // next refresh simply retries.
            let mut queue_ids = stats.inserted_ids.clone();
            if settings.removed_as_unknown {
                let fps: Vec<String> = fetched.kept.iter().map(ProxyEntry::fingerprint).collect();
                match proxies::revive_removed(pool, &fps, now).await {
                    Ok(ids) => queue_ids.extend(ids),
                    Err(err) => {
                        tracing::warn!(
                            source = %source.id,
                            fingerprints = fps.len(),
                            error = %err,
                            "removed-as-unknown revival failed"
                        )
                    }
                }
            }
            enqueue_probe_requests(
                pool,
                &source.id,
                &queue_ids,
                settings.refresh_check_limit,
                now,
            )
            .await;
            IngestOutcome::Ok {
                proxies_found: found,
                dropped: fetched.dropped,
                stats,
                duration_ms: Some(duration_ms),
            }
        }
        Err(err) => {
            // The payload was fetched and parsed, but this
            // process could not store it. That is not an upstream
            // failure: the feed answered with HTTP 200, and
            // reporting it as a fetch error would send the
            // operator looking at the wrong side. It gets its own
            // error class and the real status of the response.
            let message = err.to_string();
            tracing::error!(error = %err, source = %source.id, "reconciliation failed");
            journal_storage_failure(pool, source, &payload, &message, now, duration_ms).await;
            IngestOutcome::StorageFailed {
                message,
                duration_ms,
            }
        }
    }
}

/// Milliseconds since `started`. The u128 elapsed only overflows i64 after
/// roughly three hundred million years, so the clamp is formal.
fn elapsed_ms(started: std::time::Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// Result of an admin dry-run fetch: everything a real
/// ingestion does up to parsing, same SSRF vetting, same decode/parse ,
/// but nothing is reconciled or journaled.
#[derive(Debug)]
pub enum DryRunOutcome {
    /// Fetched and parsed successfully.
    Ok {
        http_status: u16,
        bytes: u64,
        proxies_found: usize,
        /// How many recognized proxies the source's own filters threw away
        /// (protocol allowlist, pipeline `drop` rules).
        dropped: usize,
        /// First few recognized lines for the preview.
        sample: Vec<String>,
    },
    /// The fetch failed with a classified error.
    FetchFailed { failure: FetchFailure },
    /// HTTP 200 but the payload did not parse.
    ParseFailed { http_status: u16, message: String },
}

/// Fetch and parse a source without touching the database (dry run).
///
/// The pipeline runs through the same [`fetch_and_filter`] the real ingest
/// uses, so the preview's counters are the real pass's counters by
/// construction; the two paths differ only in what happens after —
/// journaling and reconcile versus a preview sample.
pub async fn dry_run_source(
    fetcher: &Fetcher,
    geo: &GeoResolver,
    source: &Source,
) -> DryRunOutcome {
    match fetch_and_filter(fetcher, geo, source).await {
        Ok(fetched) => {
            let sample = fetched
                .kept
                .iter()
                .take(10)
                .map(|entry| {
                    if entry.name.is_empty() {
                        format!("{}://{}:{}", entry.scheme, entry.host, entry.port)
                    } else {
                        format!(
                            "{}://{}:{}, {}",
                            entry.scheme, entry.host, entry.port, entry.name
                        )
                    }
                })
                .collect();
            DryRunOutcome::Ok {
                http_status: fetched.payload.http_status,
                bytes: fetched.payload.bytes,
                proxies_found: fetched.recognized,
                dropped: fetched.dropped,
                sample,
            }
        }
        Err(FetchAndFilterError::Fetch(failure)) => DryRunOutcome::FetchFailed { failure },
        Err(FetchAndFilterError::Parse { payload, message }) => DryRunOutcome::ParseFailed {
            http_status: payload.http_status,
            message,
        },
    }
}

/// Whether a source row's freshness stamp (`last_fetched_at`) still covers
/// `now` under the source's TTL. The one freshness question both the
/// scheduler's due check and the ingest's fetch short-circuit ask, kept in
/// a single function so the two answers can never drift apart.
pub(crate) fn source_is_fresh(now: i64, last_fetched_at: Option<i64>, ttl_seconds: i64) -> bool {
    last_fetched_at.is_some_and(|fetched_at| now.saturating_sub(fetched_at) < ttl_seconds)
}

/// Everything a real ingest and a dry run do identically: the fetch, the
/// decode/parse, the geo resolution over the whole payload and the drop
/// rules. Both callers branch on the same outcome and differ only in what
/// they do next — journaling and reconcile versus a preview sample — so
/// their kept/dropped counters and recognized counts cannot drift apart.
struct FetchedAndFiltered {
    payload: FetchedPayload,
    /// Recognised count before any filter (for logging / dry-run totals).
    recognized: usize,
    /// Whether the source's pipeline carries drop rules at all: gates the
    /// alive-linger policy.
    has_drop_rules: bool,
    /// The entries that survived the protocol allowlist and the drop
    /// rules, and the stamps that belong to exactly those entries (same
    /// length, same order — reconcile pairs the two by index).
    kept: Vec<ProxyEntry>,
    kept_geo: Vec<Option<proxies::GeoStamp>>,
    /// What the source's own filters discarded (protocol allowlist and
    /// pipeline drop rules together): recognized = dropped + kept.len().
    dropped: usize,
}

/// Why [`fetch_and_filter`] gave up: the fetch failed with a classified
/// error, or the payload did not parse (the payload comes along so the
/// caller journals the real status and size of the response).
enum FetchAndFilterError {
    Fetch(FetchFailure),
    Parse {
        payload: FetchedPayload,
        message: String,
    },
}

/// The shared fetch → decode → parse → geo → drop-rules pass behind
/// [`ingest_source`] and [`dry_run_source`]. Geo resolution covers the
/// whole payload in both paths: drop rules may target ASNs anywhere in the
/// feed, so a truncated preview would count differently from the pass it
/// previews.
async fn fetch_and_filter(
    fetcher: &Fetcher,
    geo: &GeoResolver,
    source: &Source,
) -> Result<FetchedAndFiltered, FetchAndFilterError> {
    let payload = fetcher
        .fetch(
            &source.url,
            &source.headers.clone().unwrap_or_default(),
            source.ip_family,
        )
        .await
        .map_err(FetchAndFilterError::Fetch)?;
    let filtered =
        parse_payload(source, &payload).map_err(|message| FetchAndFilterError::Parse {
            payload: payload.clone(),
            message,
        })?;
    // Drop rules (including ASN-targeted ones) run after geo resolution,
    // see [`apply_drop_rules`]. The resolver is async-and-cached so the
    // lookups cost at most one round-trip per unseen host.
    let geo_stamps = resolve_geo_stamps(geo, &filtered.entries, None).await;
    let has_drop_rules = filtered.has_drop_rules();
    let (kept, kept_geo, _) = apply_drop_rules(
        filtered.pipeline.as_ref(),
        filtered.entries,
        &geo_stamps,
        &source.id,
    );
    // The protocol allowlist threw away part of the payload before the
    // drop rules ran, and the rules threw away more. Both belong to the
    // report: recognized = dropped + kept holds in both paths.
    let dropped = filtered.recognized.saturating_sub(kept.len());
    Ok(FetchedAndFiltered {
        payload,
        recognized: filtered.recognized,
        has_drop_rules,
        kept,
        kept_geo,
        dropped,
    })
}

/// Priority-check handoff: enqueue up to `limit` of the pass's
/// newly inserted (and, with `[ingest].removed_as_unknown`, revived)
/// proxies (repo-side filtering keeps only T1-probeable
/// `unknown` rows). A failure is logged and never fails the ingest, the
/// random sample covers those proxies anyway.
async fn enqueue_probe_requests(pool: &DbPool, source_id: &str, ids: &[i64], limit: u32, now: i64) {
    if limit == 0 || ids.is_empty() {
        return;
    }
    match probe::enqueue_checks(pool, ids, limit, now).await {
        Ok(0) => {}
        Ok(queued) => {
            tracing::debug!(
                source = %source_id,
                ids = ids.len(),
                limit,
                queued,
                "new proxies queued for priority probing"
            );
        }
        Err(err) => {
            tracing::warn!(
                source = %source_id,
                ids = ids.len(),
                limit,
                error = %err,
                "failed to queue new proxies for probing"
            );
        }
    }
}

/// Hard cap on the unique hosts one pass resolves. A feed with thousands
/// of distinct hosts would otherwise cost thousands of DNS round-trips
/// per pass; the hosts beyond the cap keep the geo facts already stored.
const GEO_HOST_BUDGET: usize = 256;

/// Wall-clock ceiling for the geo batch of one pass. Every unseen host
/// can cost up to `[geo].dns_timeout`, so the batch is bounded in time
/// as well as in size: on expiry the pass continues with "keep what is
/// stored" instead of blocking the ingest.
const GEO_PASS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Resolve geo facts for the parsed entries; the returned vector stays
/// index-aligned with `entries`. With an inactive resolver (geo disabled
/// or database missing) every stamp is `None`, which the upsert treats as
/// "keep what is stored". The one [`GeoResolver`] call it makes goes
/// through the shared [`HostGeo`] seam (implemented once in
/// `fumox_core::geo`, also used by the serving pipeline), so the lookup
/// *shape* (concurrent, capped, input-ordered) is observable without a
/// MaxMind database and a slow DNS server on the test machine: the test
/// drives [`resolve_geo_stamps`] itself, not a copy of its loop.
///
/// The pass is bounded twice over: only the unique hosts are looked up
/// (a feed repeats the same host many times over) and at most
/// [`GEO_HOST_BUDGET`] of them, and the whole batch is wrapped in
/// [`GEO_PASS_TIMEOUT`]. Both bounds end the same way — the entries
/// without facts keep what the database already stores — so a feed full
/// of dead hosts slows the pass down but never breaks it.
///
/// `limit` restricts the lookup to the first records of the pass (the
/// dry run passes one); the records beyond it keep "no facts".
async fn resolve_geo_stamps<G: HostGeo>(
    geo: &G,
    entries: &[ProxyEntry],
    limit: Option<usize>,
) -> Vec<Option<proxies::GeoStamp>> {
    if !geo.is_active() {
        return Vec::new();
    }
    let window = limit.map_or(entries.len(), |limit| limit.min(entries.len()));
    let window = &entries[..window];

    let mut hosts: Vec<&str> = Vec::new();
    for entry in window {
        if !hosts.contains(&entry.host.as_str()) {
            hosts.push(&entry.host);
        }
    }
    if hosts.len() > GEO_HOST_BUDGET {
        tracing::warn!(
            hosts = hosts.len(),
            budget = GEO_HOST_BUDGET,
            "geo lookup budget of this pass exhausted; the remaining hosts keep their stored facts"
        );
        hosts.truncate(GEO_HOST_BUDGET);
    }

    use futures_util::StreamExt;
    // `buffered` (not `buffer_unordered`) keeps the input order, which the
    // drop rules and the reconcile upsert both rely on, while holding at
    // most `GEO_LOOKUP_CONCURRENCY` lookups in flight.
    let lookups = hosts
        .iter()
        .map(|host| geo.resolve_host(host))
        .collect::<Vec<_>>();
    let resolved = match tokio::time::timeout(
        GEO_PASS_TIMEOUT,
        futures_util::stream::iter(lookups)
            .buffered(GEO_LOOKUP_CONCURRENCY)
            .collect::<Vec<_>>(),
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(_) => {
            tracing::warn!(
                timeout_secs = GEO_PASS_TIMEOUT.as_secs(),
                "geo resolution exceeded the budget of this pass; the pass continues with the stored facts"
            );
            return vec![None; entries.len()];
        }
    };

    let by_host: std::collections::HashMap<&str, Option<proxies::GeoStamp>> = hosts
        .iter()
        .copied()
        .zip(resolved)
        .map(|(host, info)| (host, info.map(|info| proxies::GeoStamp::from_info(&info))))
        .collect();
    entries
        .iter()
        .map(|entry| by_host.get(entry.host.as_str()).cloned().flatten())
        .collect()
}

/// What [`parse_payload`] produced: the entries that survived the
/// protocol allowlist, the total recognised before any filtering and the
/// source's compiled pipeline.
///
/// Drop rules do not run inside `parse_payload`, they need a resolved
/// ASN stamp per entry, which only exists after [`resolve_geo_stamps`].
/// The caller runs the drop step explicitly once the geo stamps are
/// ready; this struct carries the pre-drop entries plus the pipeline,
/// compiled once here and reused for the drop step (a second compile
/// would re-run every regex build for nothing).
#[derive(Debug)]
struct FilteredPayload {
    entries: Vec<ProxyEntry>,
    /// Recognised count before any filter (for logging / dry-run totals).
    recognized: usize,
    /// The source's compiled pipeline, `None` when it has none. Gates the
    /// alive-linger policy (a source with drop rules must not keep links
    /// its rules would have discarded) and carries the drop rules.
    pipeline: Option<CompiledPipeline>,
}

impl FilteredPayload {
    /// Whether the source's pipeline carries drop rules at all: gates the
    /// alive-linger policy.
    fn has_drop_rules(&self) -> bool {
        self.pipeline
            .as_ref()
            .is_some_and(CompiledPipeline::has_drop_rules)
    }
}

/// Decode + parse the raw payload according to the source settings.
/// Returns the recognised entries that survived the protocol allowlist
/// (and pipeline compile-validation, which fails closed), or an error
/// message for `parse_error`. Drop rules are NOT evaluated here, see
/// [`apply_drop_rules`] for that step.
fn parse_payload(source: &Source, payload: &FetchedPayload) -> Result<FilteredPayload, String> {
    let text = std::str::from_utf8(&payload.body)
        .map_err(|e| format!("payload is not valid UTF-8: {e}"))?;
    let encoding = source.encoding;
    let parsed = fumox_core::parsers::parse_subscription(text, encoding, source.input_format)
        .map_err(|e| e.to_string())?;
    if parsed.entries.is_empty() {
        // HTTP 200 with zero recognized lines is parse_error. The message
        // spells the parser's counts out in the operator's terms — how
        // many lines matched nothing, how many recognized entries were
        // dropped, how many structured entries were skipped — instead of
        // internal field names.
        return Err(format!(
            "no proxies recognized: {} lines matched no supported format, \
             {} duplicates discarded, {} clash entries skipped — check the \
             source's input format setting",
            parsed.unrecognized, parsed.discarded, parsed.skipped
        ));
    }
    let recognized = parsed.entries.len();
    // Optional per-source protocol allowlist.
    let entries = match &source.protocols {
        Some(allowed) => parsed
            .entries
            .into_iter()
            .filter(|entry| allowed.contains(&entry.scheme))
            .collect(),
        None => parsed.entries,
    };
    // The pipeline is compiled exactly once, here: the compiled value
    // rides along in [`FilteredPayload`] for the drop step. Only the
    // source's own pipeline participates in ingestion, profiles may
    // override the section on serving, but they never take part here
    // (one source feeds many profiles).
    let pipeline = match &source.pipeline {
        None => None,
        Some(value) => match CompiledPipeline::from_json(Some(value)) {
            Ok(compiled) => Some(compiled),
            Err(issues) => {
                return Err(format!(
                    "pipeline config failed validation: {}; refusing to ingest",
                    pipeline_issues_text(&issues)
                ));
            }
        },
    };
    if entries.is_empty() {
        return Err("no proxies left after the protocol allowlist".to_string());
    }
    Ok(FilteredPayload {
        recognized,
        pipeline,
        entries,
    })
}

/// Render pipeline validation issues in their technical debug form for the
/// ingest error message. Not localized (unlike the admin form, which maps
/// the same catalog keys through `Lang::t_args`), but naming every issue
/// the compiler found: `last_error` is the only trace a hand-edited row
/// leaves.
fn pipeline_issues_text(issues: &[PipelineIssue]) -> String {
    issues
        .iter()
        .map(|issue| {
            if issue.args.is_empty() {
                issue.key.to_string()
            } else {
                format!("{} ({})", issue.key, issue.args.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// What a drop-rule pass hands back: the surviving entries, the stamps that
/// belong to exactly those entries (same length, same order, reconcile
/// pairs the two by index), and how many entries were discarded.
type DropOutcome = (Vec<ProxyEntry>, Vec<Option<proxies::GeoStamp>>, usize);

/// Run the source's compiled drop rules against the entries paired with
/// their resolved ASN stamps. Returns the surviving entries, the stamps
/// that belong to exactly those entries, and how many were discarded. The
/// pipeline arrives already compiled (`parse_payload` validated it and
/// fails closed there), so this step cannot fail.
///
/// The stamp ASNs parse exactly once here — the boundary between the
/// stored `AS{n}` column and the drop pass, which compares plain numbers.
fn apply_drop_rules(
    pipeline: Option<&CompiledPipeline>,
    entries: Vec<ProxyEntry>,
    geo: &[Option<proxies::GeoStamp>],
    source_id: &str,
) -> DropOutcome {
    let Some(compiled) = pipeline.filter(|compiled| compiled.has_drop_rules()) else {
        return (entries, geo.to_vec(), 0);
    };
    let asns: Vec<Option<u32>> = geo
        .iter()
        .map(|stamp| {
            stamp
                .as_ref()
                .and_then(|stamp| stamp.asn.as_deref())
                .and_then(asn_number)
        })
        .collect();
    let before_count = entries.len();
    let (after, after_geo) = compiled.drop_entries_with_geo(entries, &asns, geo, source_id);
    let dropped = before_count - after.len();
    (after, after_geo, dropped)
}

async fn journal_success(
    pool: &DbPool,
    source: &Source,
    payload: &FetchedPayload,
    found: usize,
    now: i64,
    duration_ms: i64,
) {
    let log = fetch_log::FetchLogEntry {
        source_id: &source.id,
        fetched_at: now,
        ok: true,
        http_status: Some(payload.http_status as i64),
        bytes: Some(payload.bytes as i64),
        proxies_found: Some(found as i64),
        error: None,
        error_class: None,
    };
    let timing = fetch_log::FetchTiming {
        duration_ms: Some(duration_ms),
        attempts: Some(i64::from(payload.attempts)),
    };
    if let Err(err) = fetch_log::insert(pool, &log, timing).await {
        tracing::error!(source = %source.id, error = %err, "failed to write fetch_log");
    }
    if let Err(err) = sources::record_fetch_outcome(
        pool,
        &source.id,
        &sources::FetchOutcome::Success { at: now },
    )
    .await
    {
        tracing::error!(source = %source.id, error = %err, "failed to update source after success");
    }
}

async fn journal_failure(
    pool: &DbPool,
    source: &Source,
    failure: &FetchFailure,
    now: i64,
    duration_ms: i64,
) {
    let message = failure.to_string();
    let class = failure.error_class();
    let log = fetch_log::FetchLogEntry {
        source_id: &source.id,
        fetched_at: now,
        ok: false,
        http_status: failure.http_status().map(i64::from),
        bytes: None,
        proxies_found: None,
        error: Some(&message),
        error_class: Some(class),
    };
    let timing = fetch_log::FetchTiming {
        duration_ms: Some(duration_ms),
        attempts: Some(i64::from(failure.attempts())),
    };
    if let Err(err) = fetch_log::insert(pool, &log, timing).await {
        tracing::error!(source = %source.id, error = %err, "failed to write fetch_log");
    }
    if let Err(err) = sources::record_fetch_outcome(
        pool,
        &source.id,
        &sources::FetchOutcome::Failure {
            at: now,
            error: &message,
            class,
        },
    )
    .await
    {
        tracing::error!(source = %source.id, error = %err, "failed to update source after failure");
    }
}

/// Journal a payload that could not be stored.
///
/// The response was fine (its real status is written, not a substituted
/// 500) and the error class says the failure was this process's: an
/// operator reading `storage` looks at the database, not at the feed.
async fn journal_storage_failure(
    pool: &DbPool,
    source: &Source,
    payload: &FetchedPayload,
    message: &str,
    now: i64,
    duration_ms: i64,
) {
    let class = fumox_core::models::ErrorClass::Storage;
    let log = fetch_log::FetchLogEntry {
        source_id: &source.id,
        fetched_at: now,
        ok: false,
        http_status: Some(payload.http_status as i64),
        bytes: Some(payload.bytes as i64),
        proxies_found: Some(0),
        error: Some(message),
        error_class: Some(class),
    };
    let timing = fetch_log::FetchTiming {
        duration_ms: Some(duration_ms),
        attempts: Some(i64::from(payload.attempts)),
    };
    if let Err(err) = fetch_log::insert(pool, &log, timing).await {
        tracing::error!(source = %source.id, error = %err, "failed to write fetch_log");
    }
    if let Err(err) = sources::record_fetch_outcome(
        pool,
        &source.id,
        &sources::FetchOutcome::Failure {
            at: now,
            error: message,
            class,
        },
    )
    .await
    {
        tracing::error!(source = %source.id, error = %err, "failed to update source after failure");
    }
}

async fn journal_parse_failure(
    pool: &DbPool,
    source: &Source,
    payload: &FetchedPayload,
    message: &str,
    now: i64,
    duration_ms: i64,
) {
    let log = fetch_log::FetchLogEntry {
        source_id: &source.id,
        fetched_at: now,
        ok: false,
        http_status: Some(payload.http_status as i64),
        bytes: Some(payload.bytes as i64),
        proxies_found: Some(0),
        error: Some(message),
        error_class: Some(fumox_core::models::ErrorClass::ParseError),
    };
    let timing = fetch_log::FetchTiming {
        duration_ms: Some(duration_ms),
        attempts: Some(i64::from(payload.attempts)),
    };
    if let Err(err) = fetch_log::insert(pool, &log, timing).await {
        tracing::error!(source = %source.id, error = %err, "failed to write fetch_log");
    }
    if let Err(err) = sources::record_fetch_outcome(
        pool,
        &source.id,
        &sources::FetchOutcome::Failure {
            at: now,
            error: message,
            class: fumox_core::models::ErrorClass::ParseError,
        },
    )
    .await
    {
        tracing::error!(source = %source.id, error = %err, "failed to update source after parse failure");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::geo::GeoInfo;
    use fumox_core::models::{Encoding, InputFormat, Scheme};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn source_with(encoding: Encoding, input_format: Option<InputFormat>) -> Source {
        let now = fumox_core::models::now_ts();
        Source {
            id: "srcA0000000".into(),
            slug: None,
            access_token: None,
            name: "s".into(),
            url: "https://example.com".into(),
            enabled: true,
            encoding,
            input_format,
            protocols: None,
            cache_ttl_seconds: 3600,
            tags: None,
            pipeline: None,
            headers: None,
            ip_family: None,
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        }
    }

    fn payload(body: &str) -> FetchedPayload {
        FetchedPayload {
            http_status: 200,
            bytes: body.len() as u64,
            body: body.as_bytes().to_vec(),
            attempts: 1,
        }
    }

    /// A `Fetcher` pointed at a one-shot local HTTP server, plus the
    /// database one `ingest_source` call needs. The private-IP policy is
    /// switched off so the loopback test server is reachable. The counter
    /// tracks how many requests reached the upstream. The first tuple
    /// element owns the scratch directory: it removes itself on drop, so
    /// a test cannot leave its database behind.
    async fn ingest_env(
        body: &'static str,
    ) -> (
        fumox_core::tempdir_lite::TempDir,
        DbPool,
        Fetcher,
        Source,
        Arc<AtomicUsize>,
    ) {
        ingest_env_with_bodies(vec![body]).await
    }

    /// The same, but the upstream answers with a different body per
    /// request: the first request gets `bodies[0]`, the second `bodies[1]`,
    /// and a request beyond the list gets the last body again. A second
    /// ingest of the same source needs a second, different feed.
    async fn ingest_env_with_bodies(
        bodies: Vec<&'static str>,
    ) -> (
        fumox_core::tempdir_lite::TempDir,
        DbPool,
        Fetcher,
        Source,
        Arc<AtomicUsize>,
    ) {
        assert!(!bodies.is_empty(), "the upstream needs at least one body");
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = listener.accept().await {
                // The counter doubles as the index of the body this
                // request is answered with: the requests are sequential.
                let index = counted.fetch_add(1, Ordering::SeqCst);
                let body = bodies[index.min(bodies.len() - 1)];
                // Read the request out before answering, like a real HTTP
                // server. Closing a socket that still holds unread client
                // bytes makes the kernel send RST, which can clobber the
                // client's buffered read of the response; the fetcher then
                // retries, opening a second connection the counter sees,
                // and the exact-fetch-count assertions below would flake.
                let mut received = Vec::with_capacity(1024);
                loop {
                    let mut scratch = [0u8; 1024];
                    match sock.read(&mut scratch).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            received.extend_from_slice(&scratch[..n]);
                            if received.windows(4).any(|w| w == b"\r\n\r\n")
                                || received.len() >= 16 * 1024
                            {
                                break;
                            }
                        }
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
            }
        });

        let dir = fumox_core::tempdir_lite::TempDir::new("ingest-test");
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.path().join("test.db"),
            ..Default::default()
        };
        let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();

        let mut source = source_with(Encoding::Auto, None);
        source.url = format!("http://{addr}/sub");
        sources::create(&pool, &source).await.unwrap();

        let fetcher = Fetcher::new(
            fumox_core::config::FetchConfig::default(),
            true, // allow_private_urls: the mirror above is loopback
            std::time::Duration::from_secs(5),
        );
        (dir, pool, fetcher, source, requests)
    }

    fn settings() -> IngestSettings {
        IngestSettings {
            refresh_check_limit: 0,
            drop_gate: false,
            removed_as_unknown: false,
        }
    }

    /// The same settings with the alive-linger gate at the given position.
    fn settings_with_drop_gate(drop_gate: bool) -> IngestSettings {
        IngestSettings {
            drop_gate,
            ..settings()
        }
    }

    fn inactive_geo() -> std::sync::Arc<GeoResolver> {
        std::sync::Arc::new(GeoResolver::new(&fumox_core::config::GeoConfig {
            enabled: false,
            ..Default::default()
        }))
    }

    /// The freshness stamp (`last_fetched_at`) is the marker for the *next*
    /// pass, so it may only be written once the payload has been parsed and
    /// reconciled. Stamping it before that let one parse error suppress
    /// every non-forced re-fetch for a whole TTL.
    #[tokio::test]
    async fn a_parse_failure_leaves_no_freshness_stamp() {
        let (_dir, pool, fetcher, source, _requests) =
            ingest_env("this is not a subscription").await;
        let outcome =
            ingest_source(&pool, &fetcher, &inactive_geo(), settings(), &source, false).await;
        assert!(matches!(outcome, IngestOutcome::ParseFailed { .. }));

        let stored = sources::get(&pool, &source.id).await.unwrap().unwrap();
        assert!(
            stored.last_fetched_at.is_none(),
            "a failed ingest must not stamp the source as freshly fetched"
        );
    }

    /// The converse: a reconciled payload is what the DB now holds, so its
    /// `last_fetched_at` stamp is exactly what the freshness short-circuit
    /// may trust: the next non-forced pass skips the HTTP fetch entirely,
    /// while a forced one always hits the network.
    #[tokio::test]
    async fn a_reconciled_payload_stamps_freshness_and_skips_the_next_fetch() {
        let (_dir, pool, fetcher, source, requests) =
            ingest_env("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let outcome =
            ingest_source(&pool, &fetcher, &inactive_geo(), settings(), &source, false).await;
        assert!(matches!(outcome, IngestOutcome::Ok { .. }));
        assert_eq!(requests.load(Ordering::SeqCst), 1, "the first pass fetches");

        let stamped = sources::get(&pool, &source.id).await.unwrap().unwrap();
        assert!(
            stamped.last_fetched_at.is_some(),
            "a reconciled payload stamps last_fetched_at"
        );

        // The next pass reads the stamp from a freshly loaded row, as the
        // scheduler does every sweep: still younger than the TTL, so no
        // fetch goes out and nothing is reconciled.
        let outcome = ingest_source(
            &pool,
            &fetcher,
            &inactive_geo(),
            settings(),
            &stamped,
            false,
        )
        .await;
        assert!(
            matches!(
                outcome,
                IngestOutcome::Ok {
                    proxies_found: 0,
                    ..
                }
            ),
            "a fresh stamp must short-circuit, got {outcome:?}"
        );
        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "a fresh stamp must skip the HTTP fetch"
        );

        // A forced refresh (the admin *Refresh now* button) bypasses the
        // stamp and hits the network.
        let outcome =
            ingest_source(&pool, &fetcher, &inactive_geo(), settings(), &stamped, true).await;
        assert!(matches!(outcome, IngestOutcome::Ok { .. }));
        assert_eq!(
            requests.load(Ordering::SeqCst),
            2,
            "a forced refresh must fetch even behind a fresh stamp"
        );
    }

    /// The measured fetch duration is journaled and carried on the
    /// outcome: a real fetch records `Some(ms)` in `fetch_log.duration_ms`
    /// and on the `Ok` outcome, the freshness short-circuit measures
    /// nothing (`None`) and writes no journal row at all. Without the
    /// measurement a slow upstream (or a long retry-backoff chain) is
    /// indistinguishable from a fast one.
    #[tokio::test]
    async fn fetch_duration_is_journaled_and_carried_in_the_outcome() {
        let (_dir, pool, fetcher, source, requests) =
            ingest_env("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let outcome =
            ingest_source(&pool, &fetcher, &inactive_geo(), settings(), &source, false).await;
        assert!(
            matches!(outcome, IngestOutcome::Ok { .. }),
            "expected a successful ingest, got {outcome:?}"
        );
        let IngestOutcome::Ok { duration_ms, .. } = outcome else {
            unreachable!("asserted above")
        };
        let measured = duration_ms.expect("a real fetch measures its duration");
        assert!(measured >= 0);
        assert_eq!(requests.load(Ordering::SeqCst), 1, "the first pass fetches");

        let rows = fetch_log::recent_for_source(&pool, &source.id, 10)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].duration_ms,
            Some(measured),
            "the journaled row carries the measured duration"
        );

        // The short-circuit pass measures nothing and journals nothing.
        let stamped = sources::get(&pool, &source.id).await.unwrap().unwrap();
        let outcome = ingest_source(
            &pool,
            &fetcher,
            &inactive_geo(),
            settings(),
            &stamped,
            false,
        )
        .await;
        assert!(
            matches!(outcome, IngestOutcome::Ok { .. }),
            "expected a successful ingest, got {outcome:?}"
        );
        let IngestOutcome::Ok { duration_ms, .. } = outcome else {
            unreachable!("asserted above")
        };
        assert!(
            duration_ms.is_none(),
            "no fetch happened, so there is no measurement"
        );
        assert_eq!(
            fetch_log::recent_for_source(&pool, &source.id, 10)
                .await
                .unwrap()
                .len(),
            1,
            "the short-circuit pass writes no journal row"
        );
    }

    /// Geo lookups run concurrently, capped: a feed of dead hosts must not
    /// cost one `dns_timeout` per entry, and the results must stay aligned
    /// with the input order the drop rules and the upsert rely on.
    ///
    /// Driven through [`resolve_geo_stamps`] itself: the assertions are
    /// about how the production function drives the resolver, so reverting
    /// it to a sequential `for entry in entries { geo.resolve(...).await }`
    /// loop fails the peak-concurrency assertion.
    #[tokio::test]
    async fn geo_lookups_are_concurrent_capped_and_keep_input_order() {
        // More entries than the cap, so the cap is genuinely engaged.
        const ENTRIES: usize = 40;
        let entries: Vec<ProxyEntry> = (0..ENTRIES)
            .map(|i| ProxyEntry {
                scheme: Scheme::Vless,
                name: format!("n{i}"),
                host: format!("host-{i}.invalid"),
                port: 443,
                credential: "uuid".into(),
                params: Vec::new(),
                raw_path: String::new(),
                raw_line: String::new(),
                canonical: None,
            })
            .collect();

        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let geo = CountingGeo {
            in_flight: Arc::clone(&in_flight),
            peak: Arc::clone(&peak),
        };
        let stamps = resolve_geo_stamps(&geo, &entries, None).await;

        // Order: the stamp for entry i still carries entry i's host.
        assert_eq!(stamps.len(), ENTRIES);
        for (stamp, entry) in stamps.iter().zip(&entries) {
            assert_eq!(
                stamp.as_ref().and_then(|s| s.country.as_deref()),
                Some(entry.host.as_str()),
                "stamps must stay index-aligned with the input order"
            );
        }

        let peak = peak.load(Ordering::SeqCst);
        assert!(
            peak > 1,
            "lookups must overlap; peak concurrency was {peak}, a sequential \
             loop would report 1"
        );
        assert!(
            peak <= GEO_LOOKUP_CONCURRENCY,
            "the concurrency cap must hold, peak was {peak}"
        );
    }

    /// A stand-in resolver that counts how many lookups are in flight at
    /// once. Each lookup takes long enough for the others to be polled
    /// meanwhile, and answers with the host it was asked about so the
    /// ordering assertion has something to read back.
    ///
    /// The counter moves inside the returned future, on its first poll:
    /// building a future starts no work, exactly as `GeoResolver::resolve`
    /// does, so the count reflects lookups actually running and not the
    /// ones `resolve_geo_stamps` merely created.
    struct CountingGeo {
        in_flight: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl HostGeo for CountingGeo {
        fn is_active(&self) -> bool {
            true
        }

        fn resolve_host<'a>(
            &'a self,
            host: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Arc<GeoInfo>>> + Send + 'a>>
        {
            let in_flight = Arc::clone(&self.in_flight);
            let peak = Arc::clone(&self.peak);
            let host = host.to_string();
            Box::pin(async move {
                let running = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(running, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Some(Arc::new(GeoInfo {
                    ip: host.clone(),
                    country_code: Some(host),
                    ..Default::default()
                }))
            })
        }
    }

    /// A resolver that remembers which hosts it was asked about.
    struct RecordingGeo {
        asked: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl HostGeo for RecordingGeo {
        fn is_active(&self) -> bool {
            true
        }

        fn resolve_host<'a>(
            &'a self,
            host: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Arc<GeoInfo>>> + Send + 'a>>
        {
            let asked = Arc::clone(&self.asked);
            let host = host.to_string();
            Box::pin(async move {
                asked.lock().unwrap().push(host.clone());
                Some(Arc::new(GeoInfo {
                    ip: host.clone(),
                    country_code: Some(host),
                    ..Default::default()
                }))
            })
        }
    }

    fn entry_with_host(host: &str) -> ProxyEntry {
        ProxyEntry {
            scheme: Scheme::Vless,
            name: host.to_string(),
            host: host.to_string(),
            port: 443,
            credential: "uuid".into(),
            params: Vec::new(),
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        }
    }

    /// The per-pass budget starts with the unique hosts: a feed that lists
    /// the same host over and over costs one lookup, not one per line.
    #[tokio::test]
    async fn only_the_unique_hosts_of_a_pass_are_looked_up() {
        let entries: Vec<ProxyEntry> = (0..10)
            .map(|i| entry_with_host(&format!("host-{}.invalid", i % 3)))
            .collect();
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let geo = RecordingGeo {
            asked: Arc::clone(&asked),
        };
        let stamps = resolve_geo_stamps(&geo, &entries, None).await;

        assert_eq!(stamps.len(), entries.len(), "stamps stay aligned");
        let asked = asked.lock().unwrap();
        assert_eq!(asked.len(), 3, "one lookup per unique host: {asked:?}");
        for host in ["host-0.invalid", "host-1.invalid", "host-2.invalid"] {
            assert_eq!(
                asked.iter().filter(|h| *h == host).count(),
                1,
                "{host} was looked up more than once"
            );
        }
    }

    /// The budget is hard: a feed with thousands of distinct hosts cannot
    /// fan out into thousands of DNS round-trips. The hosts beyond the
    /// budget keep the facts already stored (no stamp).
    #[tokio::test]
    async fn the_host_budget_of_a_pass_is_capped() {
        let entries: Vec<ProxyEntry> = (0..GEO_HOST_BUDGET + 10)
            .map(|i| entry_with_host(&format!("host-{i}.invalid")))
            .collect();
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let geo = RecordingGeo {
            asked: Arc::clone(&asked),
        };
        let stamps = resolve_geo_stamps(&geo, &entries, None).await;

        assert_eq!(stamps.len(), entries.len(), "stamps stay aligned");
        assert_eq!(
            asked.lock().unwrap().len(),
            GEO_HOST_BUDGET,
            "the budget bounds the lookups of one pass"
        );
        assert!(
            stamps[0].is_some(),
            "the hosts within the budget are resolved"
        );
        assert!(
            stamps[entries.len() - 1].is_none(),
            "the hosts beyond the budget keep their stored facts"
        );
    }

    /// The dry-run report adds up: recognised = dropped + kept, with the
    /// protocol allowlist counted among the dropped.
    #[tokio::test]
    async fn the_dry_run_report_adds_up() {
        let body = "vless://uuid@1.2.3.4:443#keep\n\
                    vless://uuid@1.2.3.5:443#drop-me\n\
                    trojan://pw@1.2.3.6:443#other-protocol\n";
        let (_dir, _pool, fetcher, mut source, _requests) = ingest_env(body).await;
        source.protocols = Some(vec![fumox_core::models::Scheme::Vless]);
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": [{ "match": "drop-me", "target": "name" }]
        }));

        let outcome = dry_run_source(&fetcher, &inactive_geo(), &source).await;
        let DryRunOutcome::Ok {
            proxies_found,
            dropped,
            sample,
            ..
        } = outcome
        else {
            panic!("expected a successful dry run, got {outcome:?}");
        };
        assert_eq!(proxies_found, 3, "all three lines are recognized");
        assert_eq!(
            dropped, 2,
            "the allowlist and the drop rule discarded one line each"
        );
        assert_eq!(proxies_found - dropped, 1, "found = dropped + kept");
        assert_eq!(sample.len(), 1, "only the survivor is previewed");
    }

    /// A payload that cannot be stored is not an upstream failure: the
    /// journal keeps the real status of the response and the error class
    /// points the operator at the database, not at the feed.
    #[tokio::test]
    async fn a_storage_failure_is_journaled_as_a_storage_error() {
        let (_dir, pool, _fetcher, source, _requests) =
            ingest_env("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let payload = FetchedPayload {
            http_status: 200,
            bytes: 12,
            body: b"vless://x".to_vec(),
            attempts: 1,
        };
        journal_storage_failure(&pool, &source, &payload, "the disk is on fire", 1, 5).await;

        let rows = fetch_log::recent_for_source(&pool, &source.id, 10)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ok, 0);
        assert_eq!(
            rows[0].error_class.as_deref(),
            Some("storage"),
            "the class says the fault was this process's"
        );
        assert_eq!(
            rows[0].http_status,
            Some(200),
            "the real status of the response, not a substituted 500"
        );

        let stored = sources::get(&pool, &source.id).await.unwrap().unwrap();
        assert_eq!(
            stored.error_class,
            Some(fumox_core::models::ErrorClass::Storage)
        );
    }

    /// The same fault seen from the ingest path: a database that refuses
    /// the reconcile is reported as a storage failure, not as a fetch or
    /// parse failure. The feed answered with HTTP 200.
    #[tokio::test]
    async fn a_closed_database_is_a_storage_failure() {
        let (_dir, pool, fetcher, source, _requests) =
            ingest_env("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        pool.close().await;
        let outcome =
            ingest_source(&pool, &fetcher, &inactive_geo(), settings(), &source, false).await;
        assert!(
            matches!(outcome, IngestOutcome::StorageFailed { .. }),
            "got {outcome:?}"
        );
    }

    #[test]
    fn parses_plain_uri_list() {
        let source = source_with(Encoding::Auto, None);
        let body = "vless://uuid@1.2.3.4:443?security=reality#A\ntrojan://pw@h:443#B\n";
        let entries = parse_payload(&source, &payload(body)).unwrap().entries;
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parses_base64_wrapped_payload() {
        use base64::Engine;
        let inner = "vless://uuid@1.2.3.4:443#A\n";
        let wrapped = base64::engine::general_purpose::STANDARD.encode(inner);
        let source = source_with(Encoding::Auto, None);
        let entries = parse_payload(&source, &payload(&wrapped)).unwrap().entries;
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn zero_recognized_lines_is_parse_error() {
        let source = source_with(Encoding::Auto, None);
        let err = parse_payload(&source, &payload("hello world\nno proxies here\n")).unwrap_err();
        assert!(err.contains("no proxies recognized"));
        // The counts are spelled out in the operator's terms, not as
        // internal field names.
        assert!(
            err.contains("2 lines matched no supported format"),
            "the unrecognized count must be explained: {err}"
        );
        assert!(err.contains("duplicates discarded"), "{err}");
        assert!(err.contains("clash entries skipped"), "{err}");
        assert!(err.contains("input format setting"), "{err}");
        assert!(
            !err.contains("unrecognized=") && !err.contains("discarded="),
            "no internal field names in the message: {err}"
        );
    }

    #[test]
    fn protocol_allowlist_filters_entries() {
        let mut source = source_with(Encoding::Auto, None);
        source.protocols = Some(vec![fumox_core::models::Scheme::Trojan]);
        let body = "vless://uuid@1.2.3.4:443#A\ntrojan://pw@h:443#B\n";
        let entries = parse_payload(&source, &payload(body)).unwrap().entries;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].scheme, fumox_core::models::Scheme::Trojan);

        // Allowlist that matches nothing is also a parse_error.
        source.protocols = Some(vec![fumox_core::models::Scheme::Ss]);
        assert!(parse_payload(&source, &payload(body)).is_err());
    }

    #[test]
    fn non_utf8_body_is_parse_error() {
        let source = source_with(Encoding::Auto, None);
        let bad = FetchedPayload {
            http_status: 200,
            bytes: 2,
            body: vec![0xff, 0xfe],
            attempts: 1,
        };
        assert!(parse_payload(&source, &bad).is_err());
    }

    #[test]
    fn pipeline_drop_rules_filter_entries_before_storage() {
        // Drop rules now run after geo resolution, the parsing stage only
        // reports `has_drop_rules`. The full path goes through
        // `apply_drop_rules` with a parallel (all-None) geo stamp slice.
        let mut source = source_with(Encoding::Auto, None);
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": [
                { "match": "free", "flags": "i" },
                { "match": "\\.cn$", "target": "host" }
            ]
        }));
        let body = "vless://uuid@1.2.3.4:443#free node\nvless://uuid@h.cn:443#cn\nvless://uuid@h.example.com:443#keep\n";
        let filtered = parse_payload(&source, &payload(body)).unwrap();
        let entries = filtered.entries;
        assert_eq!(entries.len(), 3);
        let geo = vec![None; entries.len()];
        let (kept, _geo, dropped) =
            apply_drop_rules(filtered.pipeline.as_ref(), entries, &geo, "test-source");
        assert_eq!(dropped, 2);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].host, "h.example.com");
    }

    #[test]
    fn pipeline_drop_of_everything_is_a_parse_error_not_a_silent_zero() {
        // A pipeline that matches every entry is reported as
        // `dropped == recognised` (and zero entries reach the DB), not as
        // a soft parse error. The dry-run surfaces the count; the real
        // ingest simply reconciles nothing. This keeps the parser free of
        // heuristics about what an admin meant by `.*`.
        let mut source = source_with(Encoding::Auto, None);
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": [{ "match": ".*", "target": "name" }]
        }));
        let body = "vless://uuid@1.2.3.4:443#A\nvless://uuid@h:443#B\n";
        let filtered = parse_payload(&source, &payload(body)).unwrap();
        let geo = vec![None; filtered.entries.len()];
        let (kept, _geo, dropped) = apply_drop_rules(
            filtered.pipeline.as_ref(),
            filtered.entries,
            &geo,
            "test-source",
        );
        assert!(kept.is_empty());
        assert_eq!(dropped, filtered.recognized);
    }

    /// Regression: a drop rule shortens the entry list, and the geo stamps
    /// must be shortened with it. Returning the survivors alone made
    /// `reconcile_source` pair entry *n* with the stamp of entry *n-1* (or
    /// worse, from the start of the feed), so a proxy was stored carrying
    /// another host's country and ASN, and one IP could end up stamped
    /// with several different AS numbers. Every surviving entry must keep
    /// the stamp its own host resolved to.
    #[test]
    fn drop_rules_keep_every_surviving_entry_paired_with_its_own_geo_stamp() {
        let mut source = source_with(Encoding::Auto, None);
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": [{ "match": "drop-me", "target": "name" }]
        }));
        let stamp = |asn: &str| {
            Some(fumox_core::repo::proxies::GeoStamp {
                asn: Some(asn.into()),
                ..Default::default()
            })
        };
        let body = "vless://uuid@1.1.1.1:443#drop-me\n\
                    vless://uuid@2.2.2.2:443#keep-a\n\
                    vless://uuid@3.3.3.3:443#drop-me-too\n\
                    vless://uuid@4.4.4.4:443#keep-b\n";
        let entries = parse_payload(&source, &payload(body)).unwrap().entries;
        assert_eq!(entries.len(), 4);
        let geo = vec![
            stamp("AS100"),
            stamp("AS200"),
            stamp("AS300"),
            stamp("AS400"),
        ];
        let compiled = CompiledPipeline::from_json(source.pipeline.as_ref()).unwrap();
        let (kept, kept_geo, dropped) =
            apply_drop_rules(Some(&compiled), entries, &geo, "test-source");
        assert_eq!(dropped, 2);
        assert_eq!(kept.len(), 2, "the two survivors remain");
        assert_eq!(
            kept_geo.len(),
            kept.len(),
            "stamps and entries must stay index-aligned for reconcile"
        );
        // keep-a is entry 1 and must keep AS200, not the AS100 of the
        // dropped entry that preceded it.
        assert_eq!(kept[0].host, "2.2.2.2");
        assert_eq!(
            kept_geo[0].as_ref().and_then(|s| s.asn.as_deref()),
            Some("AS200")
        );
        assert_eq!(kept[1].host, "4.4.4.4");
        assert_eq!(
            kept_geo[1].as_ref().and_then(|s| s.asn.as_deref()),
            Some("AS400"),
            "two drops before it must not shift its stamp"
        );
    }

    #[test]
    fn corrupted_pipeline_config_fails_closed() {
        // Cannot happen through the admin forms (save-time validation), but
        // a hand-edited row must not let its proxies slip past the rules.
        // The message carries the compiler's issues, so `last_error` and
        // the dry-run response say what exactly failed validation.
        let mut source = source_with(Encoding::Auto, None);
        source.pipeline = Some(serde_json::json!({ "version": 2 }));
        let body = "vless://uuid@1.2.3.4:443#A\n";
        let err = parse_payload(&source, &payload(body)).unwrap_err();
        assert!(err.contains("failed validation"), "{err}");
        assert!(
            err.contains("pipeline.version"),
            "the issue catalog keys must reach the message: {err}"
        );
        assert!(
            err.contains("2"),
            "the offending value must reach the message: {err}"
        );
    }

    #[test]
    fn no_pipeline_section_means_no_drop() {
        // A pipeline without a `drop` section changes nothing at ingestion.
        let mut source = source_with(Encoding::Auto, None);
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "rename": [{ "match": "a", "replace": "b" }]
        }));
        let body = "vless://uuid@1.2.3.4:443#A\nvless://uuid@h:443#B\n";
        let entries = parse_payload(&source, &payload(body)).unwrap().entries;
        assert_eq!(entries.len(), 2);
        // Rename is serving-side only, the stored entries keep their names.
        assert_eq!(entries[0].name, "A");
    }

    #[test]
    fn drop_rules_gate_off_the_alive_linger() {
        // `[ingest].drop_gate` decides the linger, the drop section of the
        // source's pipeline decides whether it applies: with the gate on
        // (the default) a source with drop rules lets them detach live
        // proxies, with the gate off everyone lingers and only the probe
        // retires a proxy.
        use fumox_core::ingest::IngestPolicy;
        assert!(
            !IngestPolicy::refresh(true, true).keep_alive_linger(),
            "gated: alive leaves on the next refresh"
        );
        assert!(
            IngestPolicy::refresh(false, true).keep_alive_linger(),
            "gate off: everyone lingers"
        );
        assert!(
            IngestPolicy::refresh(true, false).keep_alive_linger(),
            "no drop rules: linger"
        );
        assert!(
            IngestPolicy::refresh(false, false).keep_alive_linger(),
            "no drop rules: linger"
        );

        // The gate follows the source's own drop section: an empty drop
        // section (it resets a profile override, not the source's own
        // linger) does not switch it off…
        let mut source = source_with(Encoding::Auto, None);
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": []
        }));
        assert!(
            !parse_payload(&source, &payload("vless://uuid@h:443#A\n"))
                .unwrap()
                .has_drop_rules()
        );

        // …a drop section that matches nothing still does (the rules are
        // there, they simply did not fire this time)…
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": [{ "match": "^zzz-nonexistent$" }]
        }));
        assert!(
            parse_payload(&source, &payload("vless://uuid@h:443#A\n"))
                .unwrap()
                .has_drop_rules()
        );

        // …and neither a pipeline without drop nor no pipeline at all does.
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "rename": [{ "match": "a", "replace": "b" }]
        }));
        assert!(
            !parse_payload(&source, &payload("vless://uuid@h:443#A\n"))
                .unwrap()
                .has_drop_rules()
        );
        source.pipeline = None;
        assert!(
            !parse_payload(&source, &payload("vless://uuid@h:443#A\n"))
                .unwrap()
                .has_drop_rules()
        );
    }

    /// The two ingests the alive-linger gate is about: the first feed
    /// carries the proxy, the second one does not any more. Returns the
    /// proxy's status and the number of its source links afterwards.
    ///
    /// The link of the first pass is aged before the second pass: the
    /// reconcile judges staleness with `seen_at < now` and both passes run
    /// inside the same wall-clock second, which would leave the link
    /// looking fresh.
    async fn vanished_proxy_after_two_ingests(drop_gate: bool) -> (String, usize) {
        let (_dir, pool, fetcher, mut source, _requests) = ingest_env_with_bodies(vec![
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n",
            "vless://22222222-2222-2222-2222-222222222222@5.6.7.8:443#B\n",
        ])
        .await;
        // The source carries a drop rule that matches nothing: the rules
        // are there (the gate applies), they simply do not fire.
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": [{ "match": "^zzz-nonexistent$", "target": "name" }]
        }));
        sources::update_settings(&pool, &source).await.unwrap();

        let settings = settings_with_drop_gate(drop_gate);
        let first = ingest_source(&pool, &fetcher, &inactive_geo(), settings, &source, false).await;
        assert!(matches!(first, IngestOutcome::Ok { .. }), "got {first:?}");

        let id: i64 = sqlx::query_scalar("SELECT id FROM proxies WHERE host = '1.2.3.4'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            proxies::links_for_proxy(&pool, id).await.unwrap().len(),
            1,
            "the first pass links the stored proxy to its source"
        );

        sqlx::query("UPDATE proxy_source_links SET seen_at = seen_at - 5")
            .execute(&pool)
            .await
            .unwrap();

        // The second pass is forced: the first one stamped the source row
        // as fresh, and the admin *Refresh now* bypasses that stamp.
        let second = ingest_source(&pool, &fetcher, &inactive_geo(), settings, &source, true).await;
        assert!(matches!(second, IngestOutcome::Ok { .. }), "got {second:?}");

        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        let links = proxies::links_for_proxy(&pool, id).await.unwrap().len();
        (row.status, links)
    }

    /// The gate, end to end through the ingest path: with the gate on and
    /// a source that carries drop rules, a proxy that left the feed is
    /// detached from the source and retired by the same pass.
    #[tokio::test]
    async fn a_vanished_proxy_is_detached_and_retired_with_the_gate_on() {
        let (status, links) = vanished_proxy_after_two_ingests(true).await;
        assert_eq!(
            links, 0,
            "the proxy left the feed: its link to the source is gone"
        );
        assert_eq!(
            status, "removed",
            "the rules of the source may reach the rows it already stored"
        );
    }

    /// The other half of the same gate: with the gate off, only the probe
    /// retires a proxy. One that vanished from the feed keeps its link and
    /// its `unknown` status, so the upstream's churn cannot end a node
    /// that has not failed.
    #[tokio::test]
    async fn a_vanished_proxy_lingers_with_the_gate_off() {
        let (status, links) = vanished_proxy_after_two_ingests(false).await;
        assert_eq!(
            links, 1,
            "the gate is off: the proxy keeps its link to the source"
        );
        assert_eq!(
            status, "unknown",
            "the gate is off: only the probe's own verdict may retire it"
        );
    }

    /// `[ingest].removed_as_unknown`: a proxy the feed dropped (and the
    /// drop gate retired) comes back to the pristine `unknown` state on
    /// the refresh whose feed carries it again, and re-enters the priority
    /// probe queue like a fresh insert.
    #[tokio::test]
    async fn a_removed_proxy_the_feed_carries_again_is_revived_and_queued() {
        let (_dir, pool, fetcher, mut source, _requests) = ingest_env_with_bodies(vec![
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n",
            "vless://22222222-2222-2222-2222-222222222222@5.6.7.8:443#B\n",
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n",
        ])
        .await;
        // A drop rule that matches nothing: the rules are there (the gate
        // applies), they simply do not fire on any feed content.
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": [{ "match": "^zzz-nonexistent$", "target": "name" }]
        }));
        sources::update_settings(&pool, &source).await.unwrap();

        // First pass stores the proxy; the second (a feed without it,
        // forced past the freshness stamp) detaches and retires it.
        let gate_on = settings_with_drop_gate(true);
        let first = ingest_source(&pool, &fetcher, &inactive_geo(), gate_on, &source, false).await;
        assert!(matches!(first, IngestOutcome::Ok { .. }), "got {first:?}");
        let id: i64 = sqlx::query_scalar("SELECT id FROM proxies WHERE host = '1.2.3.4'")
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE proxy_source_links SET seen_at = seen_at - 5")
            .execute(&pool)
            .await
            .unwrap();
        let second = ingest_source(&pool, &fetcher, &inactive_geo(), gate_on, &source, true).await;
        assert!(matches!(second, IngestOutcome::Ok { .. }), "got {second:?}");
        assert_eq!(
            proxies::get_by_id(&pool, id).await.unwrap().unwrap().status,
            "removed",
            "the vanished proxy was retired by the gate"
        );

        // The feed carries the proxy again: with removed_as_unknown the
        // same refresh revives it and hands it to the priority queue.
        let reviving = IngestSettings {
            refresh_check_limit: 5,
            removed_as_unknown: true,
            ..settings()
        };
        // The links are aged before this pass, exactly as
        // `vanished_proxy_after_two_ingests` does: all three passes run
        // inside one wall-clock second, and the reconcile's
        // strictly-increasing link stamp would otherwise sit ahead of
        // `now`, making this pass's own fresh link look stale to the
        // linger sweep — and a link-less row cannot be revived.
        sqlx::query("UPDATE proxy_source_links SET seen_at = seen_at - 5")
            .execute(&pool)
            .await
            .unwrap();
        let third = ingest_source(&pool, &fetcher, &inactive_geo(), reviving, &source, true).await;
        assert!(matches!(third, IngestOutcome::Ok { .. }), "got {third:?}");
        assert_eq!(
            proxies::get_by_id(&pool, id).await.unwrap().unwrap().status,
            "unknown",
            "the proxy the feed carries again is revived to unknown"
        );
        let queued: Vec<i64> = probe::select_queued_checks(&pool, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|candidate| candidate.id)
            .collect();
        assert!(
            queued.contains(&id),
            "the revived proxy is queued for priority probing: {queued:?}"
        );
    }

    /// `[ingest].refresh_check_limit`: at most that many newly inserted
    /// unknown proxies per refresh reach the priority probe queue, and the
    /// ids that do are exactly the pass's inserts.
    #[tokio::test]
    async fn the_priority_queue_takes_at_most_refresh_check_limit_ids() {
        let (_dir, pool, fetcher, source, _requests) = ingest_env(
            "vless://11111111-1111-1111-1111-111111111111@10.0.0.1:443#n1\n\
             vless://11111111-1111-1111-1111-111111111111@10.0.0.2:443#n2\n\
             vless://11111111-1111-1111-1111-111111111111@10.0.0.3:443#n3\n\
             vless://11111111-1111-1111-1111-111111111111@10.0.0.4:443#n4\n\
             vless://11111111-1111-1111-1111-111111111111@10.0.0.5:443#n5\n",
        )
        .await;
        let settings = IngestSettings {
            refresh_check_limit: 3,
            ..settings()
        };
        let outcome =
            ingest_source(&pool, &fetcher, &inactive_geo(), settings, &source, false).await;
        assert!(
            matches!(outcome, IngestOutcome::Ok { .. }),
            "got {outcome:?}"
        );

        let inserted: Vec<i64> = sqlx::query_scalar("SELECT id FROM proxies ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(inserted.len(), 5, "the whole feed is stored");
        let queued: Vec<i64> = probe::select_queued_checks(&pool, 10)
            .await
            .unwrap()
            .into_iter()
            .map(|candidate| candidate.id)
            .collect();
        assert!(
            queued.len() <= 3,
            "the limit bounds the queue handoff, got {queued:?}"
        );
        for id in &queued {
            assert!(
                inserted.contains(id),
                "only ids the pass inserted are queued, {id} is not"
            );
        }
        assert_eq!(queued.len(), 3, "the limit is reached, not hit early");
    }
}
