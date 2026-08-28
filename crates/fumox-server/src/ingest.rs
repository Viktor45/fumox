//! Source ingestion: fetch → decode → parse → reconcile → journal.
//!
//! One [`ingest_source`] call refreshes a single source end to end and
//! records the outcome in `fetch_log` and on the source row itself
//! (`last_fetched_at` / `last_error` / `error_class`, SPEC §10.2).
//!
//! Parse failures are soft: HTTP 200 with unrecognizable content is
//! classified `parse_error` (SPEC §16.11) — including the "zero recognized
//! lines" case — and never panics.

use crate::cache::Caches;
use crate::fetcher::{FetchFailure, FetchedPayload, Fetcher};
use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use fumox_core::models::{ProxyEntry, Source};
use fumox_core::repo::{fetch_log, proxies, sources};

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

/// Fetch, parse and reconcile one source; journal the result.
///
/// With `force = false` a still-fresh raw snapshot (younger than the
/// source TTL) short-circuits the HTTP fetch — the database is already
/// reconciled from that payload (SPEC §7 raw cache). Forced refreshes
/// ("обновить сейчас" from the admin panel) always hit the network.
///
/// Geo facts are resolved per proxy host while the raw payload is already
/// parsed (the resolver caches both DNS and lookups) and persisted onto the
/// `proxies.geo_*` columns during reconciliation, so the admin panel's
/// country filter and geo card work without waiting for a subscription
/// render (SPEC §6).
pub async fn ingest_source(
    pool: &DbPool,
    fetcher: &Fetcher,
    caches: &Caches,
    geo: &GeoResolver,
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
        .fetch(&source.url, &source.headers.clone().unwrap_or_default())
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
        Ok(entries) => {
            let found = entries.len();
            let geo_stamps = resolve_geo_stamps(geo, &entries).await;
            match proxies::reconcile_source(pool, &source.id, &entries, &geo_stamps, now).await {
                Ok(stats) => {
                    journal_success(pool, source, &payload, found, now).await;
                    IngestOutcome::Ok {
                        proxies_found: found,
                        stats,
                    }
                }
                Err(err) => {
                    // Database failure during reconciliation — treat as a
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

/// Result of an admin dry-run fetch (ADMIN_PLAN §13.11): everything a real
/// ingestion does up to parsing — same SSRF vetting, same decode/parse —
/// but nothing is reconciled or journaled.
#[derive(Debug)]
pub enum DryRunOutcome {
    /// Fetched and parsed successfully.
    Ok {
        http_status: u16,
        bytes: u64,
        proxies_found: usize,
        /// First few recognized lines for the preview.
        sample: Vec<String>,
    },
    /// The fetch failed with a classified error.
    FetchFailed { failure: FetchFailure },
    /// HTTP 200 but the payload did not parse.
    ParseFailed { http_status: u16, message: String },
}

/// Fetch and parse a source without touching the database (dry run).
pub async fn dry_run_source(fetcher: &Fetcher, source: &Source) -> DryRunOutcome {
    let payload = match fetcher
        .fetch(&source.url, &source.headers.clone().unwrap_or_default())
        .await
    {
        Ok(payload) => payload,
        Err(failure) => return DryRunOutcome::FetchFailed { failure },
    };
    match parse_payload(source, &payload) {
        Ok(entries) => {
            let sample = entries
                .iter()
                .take(10)
                .map(|entry| {
                    if entry.name.is_empty() {
                        format!("{}://{}:{}", entry.scheme, entry.host, entry.port)
                    } else {
                        format!(
                            "{}://{}:{} — {}",
                            entry.scheme, entry.host, entry.port, entry.name
                        )
                    }
                })
                .collect();
            DryRunOutcome::Ok {
                http_status: payload.http_status,
                bytes: payload.bytes,
                proxies_found: entries.len(),
                sample,
            }
        }
        Err(message) => DryRunOutcome::ParseFailed {
            http_status: payload.http_status,
            message,
        },
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

/// Decode + parse the raw payload according to the source settings.
/// Returns the recognized entries, or an error message for `parse_error`.
fn parse_payload(source: &Source, payload: &FetchedPayload) -> Result<Vec<ProxyEntry>, String> {
    let text = std::str::from_utf8(&payload.body)
        .map_err(|e| format!("payload is not valid UTF-8: {e}"))?;
    let encoding = source.encoding;
    let parsed = fumox_core::parsers::parse_subscription(text, encoding, source.input_format)
        .map_err(|e| e.to_string())?;
    if parsed.entries.is_empty() {
        // HTTP 200 with zero recognized lines is parse_error (SPEC §16.11).
        return Err(format!(
            "no proxies recognized (discarded={}, unrecognized={}, clash_skipped={})",
            parsed.discarded, parsed.unrecognized, parsed.clash_skipped
        ));
    }
    // Optional per-source protocol allowlist.
    let entries = match &source.protocols {
        Some(allowed) => parsed
            .entries
            .into_iter()
            .filter(|entry| allowed.contains(&entry.scheme))
            .collect(),
        None => parsed.entries,
    };
    if entries.is_empty() {
        return Err("no proxies left after the source protocol filter".to_string());
    }
    Ok(entries)
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
        let entries = parse_payload(&source, &payload(body)).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parses_base64_wrapped_payload() {
        use base64::Engine;
        let inner = "vless://uuid@1.2.3.4:443#A\n";
        let wrapped = base64::engine::general_purpose::STANDARD.encode(inner);
        let source = source_with(Encoding::Auto, None);
        let entries = parse_payload(&source, &payload(&wrapped)).unwrap();
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
        let entries = parse_payload(&source, &payload(body)).unwrap();
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
}
