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
//! linked until the probe itself retires it.

use crate::cache::Caches;
use crate::fetcher::{FetchFailure, FetchedPayload, Fetcher};
use fumox_core::db::DbPool;
use fumox_core::geo::{GeoInfo, GeoResolver};
use fumox_core::models::{ProxyEntry, Source};
use fumox_core::repo::{fetch_log, probe, proxies, sources};

/// Outcome of one ingestion pass, for callers (scheduler, admin "refresh").
#[derive(Debug)]
pub enum IngestOutcome {
    /// Fetched and reconciled successfully.
    Ok {
        proxies_found: usize,
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
}

/// Fixed ingest settings from the config, everything not per-source.
#[derive(Debug, Clone, Copy)]
pub struct IngestSettings {
    /// `[ingest].refresh_check_limit`: how many newly inserted unknown
    /// proxies per refresh are enqueued for priority probing (0 disables
    /// the queue).
    pub refresh_check_limit: u32,
    /// `[ingest].drop_gate`: whether pipeline `drop` rules switch off the
    /// alive-linger link policy for their source (see `reconcile_source`).
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
/// The `caches` handle stays in the signature for its callers (the
/// scheduler hands one in; the invalidations happen at the call sites that
/// know the outcome) — the freshness marker this function used to maintain
/// in it now lives on the source row alone.
pub async fn ingest_source(
    pool: &DbPool,
    fetcher: &Fetcher,
    _caches: &Caches,
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
    // the payload must be fetched; the comparison mirrors `is_due` in the
    // scheduler, of which this is the second, row-fresh guard.
    if !force
        && source
            .last_fetched_at
            .is_some_and(|fetched_at| now.saturating_sub(fetched_at) < source.cache_ttl_seconds)
    {
        tracing::debug!(source = %source.id, "raw snapshot still fresh; skipping fetch");
        return IngestOutcome::Ok {
            proxies_found: 0,
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
    let payload = match fetcher
        .fetch(
            &source.url,
            &source.headers.clone().unwrap_or_default(),
            source.ip_family,
        )
        .await
    {
        Ok(payload) => payload,
        Err(failure) => {
            let duration_ms = elapsed_ms(fetch_started);
            journal_failure(pool, source, &failure, None, now, duration_ms).await;
            return IngestOutcome::FetchFailed {
                failure,
                duration_ms,
            };
        }
    };
    let duration_ms = elapsed_ms(fetch_started);
    // `last_fetched_at` is a *freshness* stamp, not a download log: it
    // stands for "the database is already reconciled from this payload"
    // (the TTL short-circuit above reads it). It is therefore written only
    // once the payload has parsed and reconciled — `journal_success` runs
    // after the reconcile — stamping it before that made a single parse or
    // DB failure suppress every non-forced re-fetch for a whole TTL while
    // the scheduler kept reporting successful ingests.

    match parse_payload(source, &payload) {
        Ok(filtered) => {
            let recognised = filtered.recognized;
            let geo_stamps = resolve_geo_stamps(geo, &filtered.entries).await;
            // Drop rules (including ASN-targeted ones) run after ASN
            // resolution, see [`apply_drop_rules`]. They run before the
            // `removed_as_unknown` revival handoff so the revived set is
            // the same one that survives drop.
            let (entries_after_drop, geo_after_drop, dropped_by_pipeline) =
                match apply_drop_rules(source, filtered.entries, &geo_stamps) {
                    Ok(triple) => triple,
                    Err(message) => {
                        journal_parse_failure(pool, source, &payload, &message, now, duration_ms)
                            .await;
                        return IngestOutcome::ParseFailed {
                            message,
                            duration_ms,
                        };
                    }
                };
            let found = entries_after_drop.len(); // Alive-linger. `[ingest].drop_gate` decides whether
            // a source's drop rules disable it: gated (true), a rule added
            // later reaches the already-stored rows on the very next
            // refresh; ungated (false, the default), the probe alone
            // retires live proxies, drop rules only stop new matches.
            let keep_alive_linger = !(settings.drop_gate && filtered.has_drop_rules);
            match proxies::reconcile_source(
                pool,
                &source.id,
                &entries_after_drop,
                &geo_after_drop,
                now,
                keep_alive_linger,
            )
            .await
            {
                Ok(stats) => {
                    // The database is now the content of this payload, so
                    // `journal_success` stamps `last_fetched_at` — the
                    // freshness marker the TTL short-circuit checks before
                    // the next re-fetch.
                    journal_success(pool, source, &payload, recognised, now, duration_ms).await;
                    if dropped_by_pipeline > 0 {
                        tracing::info!(
                            source = %source.id,
                            recognised,
                            dropped = dropped_by_pipeline,
                            kept = found,
                            "pipeline drop rules discarded entries before reconcile"
                        );
                    }
                    // `[ingest].removed_as_unknown`: a removed proxy the feed
                    // still carries resets to the pristine `unknown` state and
                    // gets the same priority-queue handoff as a fresh insert.
                    // A failure is logged and never fails the ingest, the
                    // next refresh simply retries.
                    let mut queue_ids = stats.inserted_ids.clone();
                    if settings.removed_as_unknown {
                        let fps: Vec<String> = entries_after_drop
                            .iter()
                            .map(ProxyEntry::fingerprint)
                            .collect();
                        match proxies::revive_removed(pool, &fps, now).await {
                            Ok(ids) => queue_ids.extend(ids),
                            Err(err) => {
                                tracing::warn!(error = %err, "removed-as-unknown revival failed")
                            }
                        }
                    }
                    enqueue_probe_requests(pool, &queue_ids, settings.refresh_check_limit, now)
                        .await;
                    IngestOutcome::Ok {
                        proxies_found: recognised,
                        stats,
                        duration_ms: Some(duration_ms),
                    }
                }
                Err(err) => {
                    // Database failure during reconciliation, treat as a
                    // server-side (recoverable) problem.
                    let failure = FetchFailure::HttpServer { status: 500 };
                    tracing::error!(error = %err, source = %source.id, "reconciliation failed");
                    journal_failure(
                        pool,
                        source,
                        &failure,
                        Some(&err.to_string()),
                        now,
                        duration_ms,
                    )
                    .await;
                    IngestOutcome::FetchFailed {
                        failure,
                        duration_ms,
                    }
                }
            }
        }
        Err(message) => {
            journal_parse_failure(pool, source, &payload, &message, now, duration_ms).await;
            IngestOutcome::ParseFailed {
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
pub async fn dry_run_source(
    fetcher: &Fetcher,
    geo: &GeoResolver,
    source: &Source,
) -> DryRunOutcome {
    let payload = match fetcher
        .fetch(
            &source.url,
            &source.headers.clone().unwrap_or_default(),
            source.ip_family,
        )
        .await
    {
        Ok(payload) => payload,
        Err(failure) => return DryRunOutcome::FetchFailed { failure },
    };
    match parse_payload(source, &payload) {
        Ok(filtered) => {
            // Drop rules run after geo resolution so ASN-targeted rules
            // (and any future geo-aware rules) get a fair preview; the
            // resolver is async-and-cached so a re-fetch in dry-run adds
            // at most one round-trip per unseen host.
            let geo_stamps = resolve_geo_stamps(geo, &filtered.entries).await;
            let (kept_entries, _, dropped) =
                match apply_drop_rules(source, filtered.entries, &geo_stamps) {
                    Ok(triple) => triple,
                    Err(message) => {
                        return DryRunOutcome::ParseFailed {
                            http_status: payload.http_status,
                            message,
                        };
                    }
                };
            let sample = kept_entries
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
                http_status: payload.http_status,
                bytes: payload.bytes,
                proxies_found: filtered.recognized,
                dropped,
                sample,
            }
        }
        Err(message) => DryRunOutcome::ParseFailed {
            http_status: payload.http_status,
            message,
        },
    }
}

/// Priority-check handoff: enqueue up to `limit` of the pass's
/// newly inserted (and, with `[ingest].removed_as_unknown`, revived)
/// proxies (repo-side filtering keeps only T1-probeable
/// `unknown` rows). A failure is logged and never fails the ingest, the
/// random sample covers those proxies anyway.
async fn enqueue_probe_requests(pool: &DbPool, ids: &[i64], limit: u32, now: i64) {
    if limit == 0 || ids.is_empty() {
        return;
    }
    match probe::enqueue_checks(pool, ids, limit, now).await {
        Ok(0) => {}
        Ok(queued) => {
            tracing::debug!(queued, "new proxies queued for priority probing");
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to queue new proxies for probing");
        }
    }
}

/// Ceiling on concurrent host lookups inside one ingest pass. Every
/// unseen host costs up to `[geo].dns_timeout` (5 s by default) when DNS
/// hangs, so the lookups run concurrently instead of one await per entry;
/// the cap keeps a large feed from fanning out into thousands of sockets.
const GEO_LOOKUP_CONCURRENCY: usize = 32;

/// The two [`GeoResolver`] calls [`resolve_geo_stamps`] makes. The real
/// resolver implements it as-is; the seam exists so the lookup *shape*
/// (concurrent, capped, input-ordered) can be observed without a MaxMind
/// database and a slow DNS server on the test machine. The test drives
/// [`resolve_geo_stamps`] itself, not a copy of its loop.
trait GeoLookup {
    /// Whether the resolver can enrich at all.
    fn is_active(&self) -> bool;
    /// Resolve one host, `None` when nothing is known about it.
    fn resolve_host(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = Option<std::sync::Arc<GeoInfo>>> + Send;
}

impl GeoLookup for GeoResolver {
    fn is_active(&self) -> bool {
        GeoResolver::is_active(self)
    }

    fn resolve_host(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = Option<std::sync::Arc<GeoInfo>>> + Send {
        self.resolve(host)
    }
}

/// Resolve geo facts for every parsed entry; the returned vector stays
/// index-aligned with `entries`. With an inactive resolver (geo disabled
/// or database missing) every stamp is `None`, which the upsert treats as
/// "keep what is stored".
async fn resolve_geo_stamps<G: GeoLookup>(
    geo: &G,
    entries: &[ProxyEntry],
) -> Vec<Option<proxies::GeoStamp>> {
    if !geo.is_active() {
        return Vec::new();
    }
    use futures_util::StreamExt;
    // `buffered` (not `buffer_unordered`) keeps the input order, which the
    // drop rules and the reconcile upsert both rely on, while holding at
    // most `GEO_LOOKUP_CONCURRENCY` lookups in flight.
    futures_util::stream::iter(
        entries
            .iter()
            .map(|entry| geo.resolve_host(&entry.host))
            .collect::<Vec<_>>(),
    )
    .buffered(GEO_LOOKUP_CONCURRENCY)
    .collect::<Vec<_>>()
    .await
    .into_iter()
    .map(|info| info.map(|info| proxies::GeoStamp::from_info(&info)))
    .collect()
}

/// What [`parse_payload`] produced: the entries that survived the
/// protocol allowlist, the total recognised before any filtering and
/// whether the source's pipeline has any drop rules at all.
///
/// Drop rules do not run inside `parse_payload`, they need a resolved
/// ASN stamp per entry, which only exists after [`resolve_geo_stamps`].
/// The caller runs the drop step explicitly once the geo stamps are
/// ready; this struct only carries the pre-drop entries plus the
/// `has_drop_rules` flag that gates the alive-linger policy.
#[derive(Debug)]
struct FilteredPayload {
    entries: Vec<ProxyEntry>,
    /// Recognised count before any filter (for logging / dry-run totals).
    recognized: usize,
    /// Gates the alive-linger policy: a source with drop rules
    /// must not keep links its rules would have discarded.
    has_drop_rules: bool,
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
        // HTTP 200 with zero recognized lines is parse_error.
        return Err(format!(
            "no proxies recognized (discarded={}, unrecognized={}, clash_skipped={})",
            parsed.discarded, parsed.unrecognized, parsed.clash_skipped
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
    // The pipeline is compiled only to learn whether drop rules exist
    // (alive-linger gate) and to fail closed on a broken config. Drop
    // rules themselves run later, after ASN stamps are available. Only
    // the source's own pipeline participates in ingestion, profiles may
    // override the section on serving, but they never take part here
    // (one source feeds many profiles).
    let has_drop_rules = match &source.pipeline {
        None => false,
        Some(value) => match crate::pipeline::CompiledPipeline::from_json(Some(value)) {
            Ok(compiled) => compiled.has_drop_rules(),
            Err(_) => {
                return Err("pipeline config failed validation; refusing to ingest".to_string());
            }
        },
    };
    if entries.is_empty() {
        return Err("no proxies left after the protocol allowlist".to_string());
    }
    Ok(FilteredPayload {
        recognized,
        has_drop_rules,
        entries,
    })
}

/// What a drop-rule pass hands back: the surviving entries, the stamps that
/// belong to exactly those entries (same length, same order, reconcile
/// pairs the two by index), and how many entries were discarded.
type DropOutcome = (Vec<ProxyEntry>, Vec<Option<proxies::GeoStamp>>, usize);

/// Compile the source's pipeline and run its drop rules against the
/// entries paired with their resolved ASN stamps. Returns the surviving
/// entries, the stamps that belong to exactly those entries, and how many
/// were discarded. Fails closed when the pipeline does not compile (the
/// previous `parse_payload` already validated this path; the re-check is
/// defensive).
fn apply_drop_rules(
    source: &Source,
    entries: Vec<ProxyEntry>,
    geo: &[Option<proxies::GeoStamp>],
) -> Result<DropOutcome, String> {
    let before_count = entries.len();
    let compiled = match &source.pipeline {
        None => return Ok((entries, geo.to_vec(), 0)),
        Some(value) => crate::pipeline::CompiledPipeline::from_json(Some(value))
            .map_err(|_| "pipeline config failed validation; refusing to ingest".to_string())?,
    };
    if !compiled.has_drop_rules() {
        return Ok((entries, geo.to_vec(), 0));
    }
    let (after, after_geo) = compiled.drop_entries_with_geo(entries, geo);
    let dropped = before_count - after.len();
    Ok((after, after_geo, dropped))
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
    if let Err(err) = fetch_log::insert_timed(pool, &log, Some(duration_ms)).await {
        tracing::error!(error = %err, "failed to write fetch_log");
    }
    if let Err(err) = sources::record_fetch_outcome(
        pool,
        &source.id,
        &sources::FetchOutcome::Success { at: now },
    )
    .await
    {
        tracing::error!(error = %err, "failed to update source after success");
    }
}

async fn journal_failure(
    pool: &DbPool,
    source: &Source,
    failure: &FetchFailure,
    override_message: Option<&str>,
    now: i64,
    duration_ms: i64,
) {
    let failure_text = failure.to_string();
    let message = override_message.unwrap_or(&failure_text);
    let class = failure.error_class();
    let log = fetch_log::FetchLogEntry {
        source_id: &source.id,
        fetched_at: now,
        ok: false,
        http_status: failure.http_status().map(i64::from),
        bytes: None,
        proxies_found: None,
        error: Some(message),
        error_class: Some(class),
    };
    if let Err(err) = fetch_log::insert_timed(pool, &log, Some(duration_ms)).await {
        tracing::error!(error = %err, "failed to write fetch_log");
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
        tracing::error!(error = %err, "failed to update source after failure");
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
    if let Err(err) = fetch_log::insert_timed(pool, &log, Some(duration_ms)).await {
        tracing::error!(error = %err, "failed to write fetch_log");
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
        tracing::error!(error = %err, "failed to update source after parse failure");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::models::{Encoding, InputFormat, Scheme};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn source_with(encoding: Encoding, input_format: Option<InputFormat>) -> Source {
        let now = fumox_core::models::now_ts();
        Source {
            id: "srcA0000000".into(),
            slug: None,
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
        }
    }

    /// A `Fetcher` pointed at a one-shot local HTTP server, plus the
    /// database and caches one `ingest_source` call needs. The private-IP
    /// policy is switched off so the loopback test server is reachable.
    /// The counter tracks how many requests reached the upstream.
    async fn ingest_env(body: &'static str) -> (DbPool, Caches, Fetcher, Source, Arc<AtomicUsize>) {
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut sock, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                // Read the request out before answering, like a real HTTP
                // server. Closing a socket that still holds unread client
                // bytes makes the kernel send RST, which can clobber the
                // client's buffered read of the response; the fetcher then
                // retries, opening a second connection the counter sees —
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

        let dir = std::env::temp_dir().join(format!(
            "fumox-ingest-test-{}",
            fumox_core::models::new_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
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
        (pool, Caches::new(), fetcher, source, requests)
    }

    fn settings() -> IngestSettings {
        IngestSettings {
            refresh_check_limit: 0,
            drop_gate: false,
            removed_as_unknown: false,
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
        let (pool, caches, fetcher, source, _requests) =
            ingest_env("this is not a subscription").await;
        let outcome = ingest_source(
            &pool,
            &fetcher,
            &caches,
            &inactive_geo(),
            settings(),
            &source,
            false,
        )
        .await;
        assert!(matches!(outcome, IngestOutcome::ParseFailed { .. }));

        let stored = sources::get(&pool, &source.id).await.unwrap().unwrap();
        assert!(
            stored.last_fetched_at.is_none(),
            "a failed ingest must not stamp the source as freshly fetched"
        );
    }

    /// The converse: a reconciled payload is what the DB now holds, so its
    /// `last_fetched_at` stamp is exactly what the freshness short-circuit
    /// may trust — the next non-forced pass skips the HTTP fetch entirely,
    /// while a forced one always hits the network.
    #[tokio::test]
    async fn a_reconciled_payload_stamps_freshness_and_skips_the_next_fetch() {
        let (pool, caches, fetcher, source, requests) =
            ingest_env("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let outcome = ingest_source(
            &pool,
            &fetcher,
            &caches,
            &inactive_geo(),
            settings(),
            &source,
            false,
        )
        .await;
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
            &caches,
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
        let outcome = ingest_source(
            &pool,
            &fetcher,
            &caches,
            &inactive_geo(),
            settings(),
            &stamped,
            true,
        )
        .await;
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
    /// measurement a slow upstream — or a long retry-backoff chain — is
    /// indistinguishable from a fast one.
    #[tokio::test]
    async fn fetch_duration_is_journaled_and_carried_in_the_outcome() {
        let (pool, caches, fetcher, source, requests) =
            ingest_env("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443#A\n").await;
        let outcome = ingest_source(
            &pool,
            &fetcher,
            &caches,
            &inactive_geo(),
            settings(),
            &source,
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
            &caches,
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
            })
            .collect();

        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let geo = CountingGeo {
            in_flight: Arc::clone(&in_flight),
            peak: Arc::clone(&peak),
        };
        let stamps = resolve_geo_stamps(&geo, &entries).await;

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

    impl GeoLookup for CountingGeo {
        fn is_active(&self) -> bool {
            true
        }

        fn resolve_host(
            &self,
            host: &str,
        ) -> impl std::future::Future<Output = Option<Arc<GeoInfo>>> + Send {
            let in_flight = Arc::clone(&self.in_flight);
            let peak = Arc::clone(&self.peak);
            let host = host.to_string();
            async move {
                let running = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(running, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Some(Arc::new(GeoInfo {
                    ip: host.clone(),
                    country_code: Some(host),
                    ..Default::default()
                }))
            }
        }
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
        let entries = parse_payload(&source, &payload(body)).unwrap().entries;
        assert_eq!(entries.len(), 3);
        let geo = vec![None; entries.len()];
        let (kept, _geo, dropped) = apply_drop_rules(&source, entries, &geo).unwrap();
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
        let (kept, _geo, dropped) = apply_drop_rules(&source, filtered.entries, &geo).unwrap();
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
        let (kept, kept_geo, dropped) = apply_drop_rules(&source, entries, &geo).unwrap();
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
        let mut source = source_with(Encoding::Auto, None);
        source.pipeline = Some(serde_json::json!({ "version": 2 }));
        let body = "vless://uuid@1.2.3.4:443#A\n";
        let err = parse_payload(&source, &payload(body)).unwrap_err();
        assert!(err.contains("failed validation"), "{err}");
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
        // + `[ingest].drop_gate`: the linger decision is
        // `!(drop_gate && has_drop_rules)`, has_drop_rules alone never
        // disables linger when the config leaves the gate off (the
        // default: the probe alone retires live proxies, drop rules only
        // stop new matches).
        let body = "vless://uuid@h.example.com:443#keep\n";
        let linger =
            |drop_gate: bool, filtered: &FilteredPayload| !(drop_gate && filtered.has_drop_rules);

        // A drop section (even one that matches nothing) switches the gate…
        let mut source = source_with(Encoding::Auto, None);
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": [{ "match": "^zzz-nonexistent$" }]
        }));
        let filtered = parse_payload(&source, &payload(body)).unwrap();
        assert!(filtered.has_drop_rules);
        assert!(
            !linger(true, &filtered),
            "gated: alive leaves on next refresh"
        );
        assert!(linger(false, &filtered), "gate off: everyone lingers");

        // …an empty drop section does not (it resets a profile override,
        // not the source's own linger)…
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "drop": []
        }));
        let filtered = parse_payload(&source, &payload(body)).unwrap();
        assert!(!filtered.has_drop_rules);
        assert!(linger(true, &filtered));
        assert!(linger(false, &filtered));

        // …and neither does no pipeline or a pipeline without drop.
        source.pipeline = None;
        assert!(
            !parse_payload(&source, &payload(body))
                .unwrap()
                .has_drop_rules
        );
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "rename": [{ "match": "a", "replace": "b" }]
        }));
        assert!(
            !parse_payload(&source, &payload(body))
                .unwrap()
                .has_drop_rules
        );
    }
}
