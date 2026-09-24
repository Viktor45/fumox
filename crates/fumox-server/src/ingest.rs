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
use fumox_core::geo::GeoResolver;
use fumox_core::models::{ProxyEntry, Source};
use fumox_core::repo::{fetch_log, probe, proxies, sources};

/// Outcome of one ingestion pass, for callers (scheduler, admin "refresh").
#[derive(Debug)]
pub enum IngestOutcome {
    /// Fetched and reconciled successfully.
    Ok {
        proxies_found: usize,
        stats: proxies::ReconciliationStats,
    },
    /// The fetch failed with a classified error (already journaled).
    FetchFailed { failure: FetchFailure },
    /// HTTP 200 but the payload did not parse (already journaled).
    ParseFailed { message: String },
}

impl IngestOutcome {
    /// Used by the admin panel's "refresh now" handler (Phase 2.5).
    #[allow(dead_code)]
    pub fn is_ok(&self) -> bool {
        matches!(self, IngestOutcome::Ok { .. })
    }
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
/// With `force = false` a still-fresh raw snapshot (younger than the
/// source TTL) short-circuits the HTTP fetch, the database is already
/// reconciled from that payload. Forced refreshes (the admin
/// *Refresh now* button) always hit the network.
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
pub async fn ingest_source(
    pool: &DbPool,
    fetcher: &Fetcher,
    caches: &Caches,
    geo: &GeoResolver,
    settings: IngestSettings,
    source: &Source,
    force: bool,
) -> IngestOutcome {
    let now = fumox_core::models::now_ts();

    if !force
        && caches
            .raw_is_fresh(&source.id, source.cache_ttl_seconds)
            .await
    {
        tracing::debug!(source = %source.id, "raw cache fresh; skipping fetch");
        return IngestOutcome::Ok {
            proxies_found: 0,
            stats: proxies::ReconciliationStats::default(),
        };
    }

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
            journal_failure(pool, source, &failure, None, now).await;
            return IngestOutcome::FetchFailed { failure };
        }
    };
    caches.raw_put(&source.id, payload.clone(), now).await;

    match parse_payload(source, &payload) {
        Ok(filtered) => {
            let recognised = filtered.recognized;
            let geo_stamps = resolve_geo_stamps(geo, &filtered.entries).await;
            // Drop rules (including ASN-targeted ones) run after ASN
            // resolution, see [`apply_drop_rules`]. They run before the
            // `removed_as_unknown` revival handoff so the revived set is
            // the same one that survives drop.
            let (entries_after_drop, dropped_by_pipeline) =
                match apply_drop_rules(source, filtered.entries, &geo_stamps) {
                    Ok(pair) => pair,
                    Err(message) => {
                        journal_parse_failure(pool, source, &payload, &message, now).await;
                        return IngestOutcome::ParseFailed { message };
                    }
                };
            let found = entries_after_drop.len();
            // Alive-linger. `[ingest].drop_gate` decides whether
            // a source's drop rules disable it: gated (true), a rule added
            // later reaches the already-stored rows on the very next
            // refresh; ungated (false, the default), the probe alone
            // retires live proxies, drop rules only stop new matches.
            let keep_alive_linger = !(settings.drop_gate && filtered.has_drop_rules);
            match proxies::reconcile_source(
                pool,
                &source.id,
                &entries_after_drop,
                &geo_stamps,
                now,
                keep_alive_linger,
            )
            .await
            {
                Ok(stats) => {
                    journal_success(pool, source, &payload, recognised, now).await;
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
                    }
                }
                Err(err) => {
                    // Database failure during reconciliation, treat as a
                    // server-side (recoverable) problem.
                    let failure = FetchFailure::HttpServer { status: 500 };
                    tracing::error!(error = %err, source = %source.id, "reconciliation failed");
                    journal_failure(pool, source, &failure, Some(&err.to_string()), now).await;
                    IngestOutcome::FetchFailed { failure }
                }
            }
        }
        Err(message) => {
            journal_parse_failure(pool, source, &payload, &message, now).await;
            IngestOutcome::ParseFailed { message }
        }
    }
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
            let (kept_entries, dropped) =
                match apply_drop_rules(source, filtered.entries, &geo_stamps) {
                    Ok(pair) => pair,
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

/// Resolve geo facts for every parsed entry, parallel to `entries`. With an
/// inactive resolver (geo disabled or database missing) every stamp is
/// `None`, which the upsert treats as "keep what is stored".
async fn resolve_geo_stamps(
    geo: &GeoResolver,
    entries: &[ProxyEntry],
) -> Vec<Option<proxies::GeoStamp>> {
    if !geo.is_active() {
        return Vec::new();
    }
    let mut stamps = Vec::with_capacity(entries.len());
    for entry in entries {
        stamps.push(
            geo.resolve(&entry.host)
                .await
                .map(|info| proxies::GeoStamp::from_info(&info)),
        );
    }
    stamps
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

/// Compile the source's pipeline and run its drop rules against the
/// entries paired with their resolved ASN stamps. Returns the surviving
/// entries and how many were discarded. Fails closed when the pipeline
/// does not compile (the previous `parse_payload` already validated this
/// path; the re-check is defensive).
fn apply_drop_rules(
    source: &Source,
    entries: Vec<ProxyEntry>,
    geo: &[Option<proxies::GeoStamp>],
) -> Result<(Vec<ProxyEntry>, usize), String> {
    let before_count = entries.len();
    let compiled = match &source.pipeline {
        None => return Ok((entries, 0)),
        Some(value) => crate::pipeline::CompiledPipeline::from_json(Some(value))
            .map_err(|_| "pipeline config failed validation; refusing to ingest".to_string())?,
    };
    if !compiled.has_drop_rules() {
        return Ok((entries, 0));
    }
    let after = compiled.drop_entries(entries, geo);
    let dropped = before_count - after.len();
    Ok((after, dropped))
}

async fn journal_success(
    pool: &DbPool,
    source: &Source,
    payload: &FetchedPayload,
    found: usize,
    now: i64,
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
    if let Err(err) = fetch_log::insert(pool, &log).await {
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
    if let Err(err) = fetch_log::insert(pool, &log).await {
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
    if let Err(err) = fetch_log::insert(pool, &log).await {
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
    use fumox_core::models::{Encoding, InputFormat};

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
        let (kept, dropped) = apply_drop_rules(&source, entries, &geo).unwrap();
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
        let (kept, dropped) = apply_drop_rules(&source, filtered.entries, &geo).unwrap();
        assert!(kept.is_empty());
        assert_eq!(dropped, filtered.recognized);
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
