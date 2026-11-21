//! Proxy upsert and reconciliation (`proxies`, `proxy_source_links`).
//!
//! Reconciliation runs after every successful source fetch: entries are
//! upserted by `fingerprint`, mutable fields (name, params, raw_line, geo)
//! refresh, but the lifecycle state is never touched — `status`,
//! `fail_count` and the quarantine fields are owned by the probe state
//! machine; the opt-in `[ingest].removed_as_unknown` revival
//! ([`revive_removed`], called by the server right after reconciliation)
//! is the only exception. `proxy_source_links.seen_at` is stamped for
//! every proxy still present, links of this source not stamped are
//! deleted, and a proxy left without any link by that deletion is marked
//! `removed` — only the proxies this pass unlinked; a row that was
//! already link-less (the admin source-delete path deliberately leaves
//! the statuses it protects behind, see [`mark_source_orphans_removed`])
//! is none of this source's business and stays as it is.
//!
//! Every timestamp this module reads or writes is Unix time in seconds,
//! the [`crate::models::now_ts()`] scale.

use super::BindWhereFilter;
use crate::db::DbPool;
use crate::geo::{GeoFactMask, GeoInfo};
use crate::models::{Param, ProxyEntry, ProxyStatus, Scheme};
use sqlx::FromRow;

/// The geo facts of one proxy, as stored in the `proxies.geo_*` columns.
///
/// `None` fields mean "unknown", never "erase": the upsert keeps existing
/// values when a fresh lookup yields nothing, so transient DNS failures
/// do not wipe stored facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoStamp {
    /// ISO-3166-1 alpha-2 code, e.g. `"DE"` (Country/City database).
    pub country: Option<String>,
    /// City name (City database only).
    pub city: Option<String>,
    /// Autonomous system as `AS{n}` (ASN database only).
    pub asn: Option<String>,
}

impl GeoStamp {
    pub fn from_info(info: &GeoInfo) -> Self {
        Self {
            country: info.country_code.clone(),
            city: info.city_name.clone(),
            asn: info.asn.map(crate::geo::asn_text),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.city.is_none() && self.asn.is_none()
    }
}

/// Outcome counters of one reconciliation pass (logging/admin metrics).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconciliationStats {
    pub inserted: usize,
    pub updated: usize,
    pub unlinked: usize,
    pub removed: usize,
    /// Ids of the rows inserted by this pass, unsorted (a superset of what
    /// the caller may enqueue for priority probing; consumers must not
    /// rely on order).
    pub inserted_ids: Vec<i64>,
}

/// Full `proxies` row for reads (admin browser, probe, serving).
///
/// The `Debug` implementation is hand-written and masks `credential` and
/// `raw_line`: a row lands in log lines and panic messages through its
/// `Debug` form, and the proxy's secret must not ride along
/// (`fingerprint` is safe to print, it derives from scheme, host and port
/// only).
#[derive(Clone, FromRow)]
pub struct ProxyRow {
    pub id: i64,
    pub fingerprint: String,
    pub scheme: String,
    pub name: String,
    pub host: String,
    pub port: i64,
    pub credential: String,
    pub params: Option<String>,
    pub unknown_params: Option<String>,
    pub raw_line: Option<String>,
    /// The path segment of the parsed URI, preserved verbatim.
    pub raw_path: Option<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_asn: Option<String>,
    /// Consecutive failed geo lookups of this row.
    pub geo_attempts: i64,
    /// When the last geo lookup of this row ran (unix seconds).
    pub last_geo_attempt_at: Option<i64>,
    pub resolved_ip: Option<String>,
    pub status: String,
    pub fail_count: i64,
    pub last_checked_at: Option<i64>,
    pub last_alive_at: Option<i64>,
    pub quarantined_at: Option<i64>,
    /// Next scheduled quarantine check (NULL outside `quarantine`).
    pub ladder_at: Option<i64>,
    /// Which ladder step the row waits on: 0 = second chance, `1..` = the
    /// Nth recheck (delays from `[probe] recheck_delays_secs`).
    pub ladder_step: i64,
    pub removed_at: Option<i64>,
    pub latency_ms: Option<i64>,
    pub speed_mbps: Option<f64>,
    /// When `speed_mbps` was measured (unix seconds); NULL = never
    /// measured. The T2 lane re-measures when this is older than
    /// `[network].speed_interval_secs`.
    pub speed_at: Option<i64>,
    /// The Cloudflare trace facts of the row: the egress address
    /// the proxy appears from, the datacenter and country it hit, and the
    /// WARP state; everything beyond these four lives in `trace_json`. All
    /// probe-written; NULL = not traced yet.
    pub egress_ip: Option<String>,
    pub cf_colo: Option<String>,
    pub cf_loc: Option<String>,
    pub cf_warp: Option<String>,
    pub trace_json: Option<String>,
    /// The egress GeoIP facts, server-derived from `egress_ip`
    /// by the egress backfill; the probe's authorizer denies them.
    pub egress_country: Option<String>,
    pub egress_asn: Option<String>,
    pub egress_asn_org: Option<String>,
    /// The egress backfill's bookkeeping (the `geo_*` pattern of 0012).
    pub egress_geo_attempts: i64,
    pub last_egress_geo_attempt_at: Option<i64>,
    /// When the most recent T2 attempt failed; NULL means either no T2
    /// attempt yet or a successful T2 since. Filters T1 candidates
    /// ([`select_t1_candidates`]) until the next T2 succeeds.
    pub last_t2_failed_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl std::fmt::Debug for ProxyRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_masked(f)
    }
}

impl ProxyRow {
    /// The masked `Debug` form: credential elided, raw feed line reduced
    /// to its length (shape visible, secret not).
    fn fmt_masked(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyRow")
            .field("id", &self.id)
            .field("fingerprint", &self.fingerprint)
            .field("scheme", &self.scheme)
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("credential", &"<redacted>")
            .field("params", &self.params)
            .field("unknown_params", &self.unknown_params)
            .field("raw_line", &self.raw_line.as_ref().map(|line| line.len()))
            .field("raw_path", &self.raw_path)
            .field("geo_country", &self.geo_country)
            .field("geo_city", &self.geo_city)
            .field("geo_asn", &self.geo_asn)
            .field("geo_attempts", &self.geo_attempts)
            .field("last_geo_attempt_at", &self.last_geo_attempt_at)
            .field("resolved_ip", &self.resolved_ip)
            .field("status", &self.status)
            .field("fail_count", &self.fail_count)
            .field("last_checked_at", &self.last_checked_at)
            .field("last_alive_at", &self.last_alive_at)
            .field("quarantined_at", &self.quarantined_at)
            .field("ladder_at", &self.ladder_at)
            .field("ladder_step", &self.ladder_step)
            .field("removed_at", &self.removed_at)
            .field("latency_ms", &self.latency_ms)
            .field("speed_mbps", &self.speed_mbps)
            .field("speed_at", &self.speed_at)
            .field("egress_ip", &self.egress_ip)
            .field("cf_colo", &self.cf_colo)
            .field("cf_loc", &self.cf_loc)
            .field("cf_warp", &self.cf_warp)
            .field("trace_json", &self.trace_json)
            .field("egress_country", &self.egress_country)
            .field("egress_asn", &self.egress_asn)
            .field("egress_asn_org", &self.egress_asn_org)
            .field("egress_geo_attempts", &self.egress_geo_attempts)
            .field(
                "last_egress_geo_attempt_at",
                &self.last_egress_geo_attempt_at,
            )
            .field("last_t2_failed_at", &self.last_t2_failed_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }

    /// Rebuild a serializable [`ProxyEntry`] from the stored row. The
    /// database stores parameters as two JSON objects (recognized /
    /// unknown), so the original on-the-wire order is not recoverable.
    pub fn to_entry(&self) -> crate::Result<ProxyEntry> {
        let mut params: Vec<Param> = Vec::new();
        for (column, known) in [(&self.params, true), (&self.unknown_params, false)] {
            if let Some(text) = column {
                params.extend(stored_params(text, known)?);
            }
        }
        Ok(ProxyEntry {
            scheme: self.scheme.parse::<Scheme>()?,
            name: self.name.clone(),
            host: self.host.clone(),
            port: u16::try_from(self.port)
                .map_err(|_| crate::Error::Parse(format!("port out of range: {}", self.port)))?,
            credential: self.credential.clone(),
            params,
            raw_path: self.raw_path.clone().unwrap_or_default(),
            raw_line: self.raw_line.clone().unwrap_or_default(),
            canonical: None,
        })
    }
}

/// The predicate that keeps the mutable identity fields of a shared
/// proxy with its first writer: a row linked to a *different* source
/// keeps the name, raw feed line and parameter sets that source wrote,
/// so two feeds advertising the same server under different names cannot
/// flip the row back and forth on every refresh.
///
/// One bind (the source being reconciled) per use; the placeholder
/// order follows the text order of the statement, so these binds come
/// after the row binds of the chunk.
const FOREIGN_SOURCE_LINK: &str = "EXISTS (SELECT 1 FROM proxy_source_links l
                 WHERE l.proxy_id = proxies.id AND l.source_id != ?)";

/// One multi-row upsert statement per this many entries, so the
/// transaction holds the WAL write lock for few round-trips: a per-row
/// loop kept it long enough for a large refresh to overrun the probe
/// daemon's `busy_timeout` and drop its journals. Two ceilings bound
/// this: 250 * 15 columns = 3750 binds against SQLite's 32766-variable
/// limit, and a multi-row VALUES is a compound SELECT against
/// SQLITE_MAX_COMPOUND_SELECT (500 in the bundled build, 256 in some
/// others); the link stamp below uses 500, which is at that ceiling.
const UPSERT_CHUNK: usize = 250;

/// The SET fragment of every "move to removed" transition, shared
/// verbatim (the guarantee [`RESET_SET`] gives the reset/revive family):
/// the ladder bookkeeping goes with the retirement, a stale
/// `quarantined_at`/`ladder_at` on a `removed` row describes a recheck
/// schedule nobody walks any more. Each statement adds only the WHERE it
/// retires under; binds are `removed_at`, `updated_at`, then the
/// statement's own predicates. A compile-time constant of this module
/// passed through `AssertSqlSafe`; every value flows through `.bind()`.
const RETIRE_SET: &str = "status = 'removed',
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             removed_at = ?,
             updated_at = ?";

/// Upsert all entries of one fetch and reconcile links for the source.
/// One transaction per pass (that is what makes the link sweep sound);
/// inside it the per-row work is batched into multi-row statements, so
/// the write-lock span stays short enough that the probe daemon's
/// concurrent writes survive `busy_timeout` on large feeds.
///
/// `geo` runs parallel to `entries` (indexed access): a shorter slice or
/// a `None` element means "no fresh geo facts", the COALESCE upsert
/// branch keeps what is stored. A *longer* slice is refused rather than
/// truncated: a caller that filtered the entries but passed the
/// unfiltered stamps back would otherwise store every proxy past the
/// first drop with another host's country and ASN.
///
/// `policy` ([`crate::ingest::IngestPolicy`]) decides what the refresh
/// may do to the proxies that left the feed. With the alive-linger
/// policy this pass never retires anything and keeps the link on every
/// status the probe still owns (`alive`, `ready`, `unknown`,
/// `quarantine`), so upstream churn cannot end a node that has not
/// failed; with the strict policy and a source that has `drop` rules,
/// the sweep and the unlink run unrestricted, so a rule added later
/// reaches the rows already stored. The admin's source deletion path
/// ([`mark_source_orphans_removed`]) honours the same policy.
///
/// `now` (and every stamp the pass writes) is Unix time in seconds
/// ([`crate::models::now_ts()`]).
pub async fn reconcile_source(
    pool: &DbPool,
    source_id: &str,
    entries: &[ProxyEntry],
    geo: &[Option<GeoStamp>],
    now: i64,
    policy: crate::ingest::IngestPolicy,
) -> crate::Result<ReconciliationStats> {
    let started = std::time::Instant::now();
    let result = reconcile_source_pass(pool, source_id, entries, geo, now, policy).await;
    match &result {
        Ok(stats) => tracing::debug!(
            source_id,
            elapsed_ms = started.elapsed().as_millis() as u64,
            inserted = stats.inserted,
            updated = stats.updated,
            unlinked = stats.unlinked,
            removed = stats.removed,
            "reconcile_source: pass finished"
        ),
        Err(error) if error.is_busy() => tracing::warn!(
            source_id,
            elapsed_ms = started.elapsed().as_millis() as u64,
            error = %error,
            "reconcile_source: the write lock stayed busy, the pass was abandoned"
        ),
        Err(_) => {}
    }
    result
}

/// The timed body of [`reconcile_source`]: one `BEGIN IMMEDIATE` ..
/// `commit` transaction over the whole pass, run through the private
/// helpers below in call order, nothing commits before the sweep is
/// done.
async fn reconcile_source_pass(
    pool: &DbPool,
    source_id: &str,
    entries: &[ProxyEntry],
    geo: &[Option<GeoStamp>],
    now: i64,
    policy: crate::ingest::IngestPolicy,
) -> crate::Result<ReconciliationStats> {
    let mut stats = ReconciliationStats::default();
    // BEGIN IMMEDIATE grabs the WAL write lock up front instead of
    // upgrading a deferred read transaction: the upgrade fails with
    // SQLITE_BUSY_SNAPSHOT (code 517) when another process (the probe
    // daemon) committed since our snapshot, busy_timeout does not apply
    // to it, so refreshes surfaced as "database is locked". With
    // IMMEDIATE the whole critical section waits inside busy_timeout
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    ensure_geo_alignment(entries, geo)?;

    // Pre-existing fingerprints, for insert/update accounting
    let fingerprints: Vec<String> = entries.iter().map(ProxyEntry::fingerprint).collect();
    let existing = lookup_existing_fingerprints(&mut tx, &fingerprints).await?;

    let ids_by_fingerprint =
        upsert_entries(&mut tx, source_id, entries, geo, &fingerprints, now).await?;
    let proxy_ids = account_upserted(&mut stats, &fingerprints, &ids_by_fingerprint, &existing)?;

    let stamp = next_link_stamp(&mut tx, source_id, now).await?;
    stamp_source_links(&mut tx, source_id, &proxy_ids, stamp).await?;

    // The retire sweep runs *before* the links go away (see
    // [`retire_unlinked_proxies`]). Under `keep_alive_linger` it is
    // skipped: the probe alone retires a proxy, and one that dropped out
    // of the feed has not failed anything. `quarantine` lingers with the
    // live tiers for the same reason: unlinking it would strand the row
    // in no probe lane, which kills it just as surely as the sweep did,
    // only without the record
    let keep_alive_linger = policy.keep_alive_linger();
    if !keep_alive_linger {
        stats.removed = retire_unlinked_proxies(&mut tx, source_id, now).await?;
    }
    stats.unlinked = delete_stale_links(&mut tx, source_id, now, policy).await?;

    tx.commit().await?;
    Ok(stats)
}

/// Refuse a stamp slice longer than the entry slice: the slices are
/// paired by index in the upsert ([`upsert_entry_chunk`]), and a caller
/// that filtered the entries but passed the unfiltered stamps back would
/// otherwise store every proxy past the first drop with another host's
/// country and ASN.
fn ensure_geo_alignment(entries: &[ProxyEntry], geo: &[Option<GeoStamp>]) -> crate::Result<()> {
    if geo.len() > entries.len() {
        tracing::error!(
            entries = entries.len(),
            stamps = geo.len(),
            "reconcile_source: more geo stamps than entries, refusing to stamp misaligned pairs"
        );
        return Err(crate::Error::Database(
            "reconcile_source: geo stamp count does not match entry count".to_string(),
        ));
    }
    Ok(())
}

/// The fingerprints already present in `proxies`, for the insert/update
/// accounting ([`account_upserted`]), looked up in placeholder-sized
/// chunks.
async fn lookup_existing_fingerprints(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    fingerprints: &[String],
) -> crate::Result<std::collections::HashSet<String>> {
    let mut existing: std::collections::HashSet<String> = std::collections::HashSet::new();
    for chunk in fingerprints.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!("SELECT fingerprint FROM proxies WHERE fingerprint IN ({placeholders})");
        // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound
        let mut query = sqlx::query_as::<_, (String,)>(sqlx::AssertSqlSafe(sql.as_str()));
        for fp in chunk {
            query = query.bind(fp);
        }
        let rows: Vec<(String,)> = query.fetch_all(&mut **tx).await?;
        existing.extend(rows.into_iter().map(|(fp,)| fp));
    }
    Ok(existing)
}

/// Upsert each entry; the ON CONFLICT branch refreshes the mutable
/// identity fields only. Lifecycle fields (status, fail_count, quarantine
/// schedules, removed_at) are deliberately absent: the probe state
/// machine is their sole owner, and a reappearing proxy keeps its state.
/// One multi-row statement per chunk ([`upsert_entry_chunk`]).
///
/// Keyed by fingerprint because RETURNING emits rows in unspecified
/// order, and duplicate fingerprints in one batch must collapse onto
/// the one id.
async fn upsert_entries(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    entries: &[ProxyEntry],
    geo: &[Option<GeoStamp>],
    fingerprints: &[String],
    now: i64,
) -> crate::Result<std::collections::HashMap<String, i64>> {
    let mut ids_by_fingerprint: std::collections::HashMap<String, i64> =
        std::collections::HashMap::with_capacity(entries.len());
    for (chunk_idx, (chunk, chunk_fingerprints)) in entries
        .chunks(UPSERT_CHUNK)
        .zip(fingerprints.chunks(UPSERT_CHUNK))
        .enumerate()
    {
        let rows = upsert_entry_chunk(
            &mut *tx,
            source_id,
            chunk,
            chunk_fingerprints,
            geo,
            chunk_idx * UPSERT_CHUNK,
            now,
        )
        .await?;
        for (id, fingerprint) in rows {
            ids_by_fingerprint.insert(fingerprint, id);
        }
    }
    Ok(ids_by_fingerprint)
}

/// One multi-row upsert statement for one chunk: builds the statement,
/// binds the chunk's rows, then the [`FOREIGN_SOURCE_LINK`] guard binds
/// (they sit behind the VALUES list), and returns the
/// `RETURNING id, fingerprint` rows. `base` is the chunk's offset in the
/// full entry list, the index the `geo` stamps pair at.
async fn upsert_entry_chunk(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    chunk: &[ProxyEntry],
    fingerprints: &[String],
    geo: &[Option<GeoStamp>],
    base: usize,
    now: i64,
) -> crate::Result<Vec<(i64, String)>> {
    let placeholders =
        vec!["(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"; chunk.len()].join(", ");
    let sql = format!(
        "INSERT INTO proxies
            (fingerprint, scheme, name, host, port, credential,
             params, unknown_params, raw_line, raw_path,
             geo_country, geo_city, geo_asn, created_at, updated_at)
         VALUES {placeholders}
         ON CONFLICT(fingerprint) DO UPDATE SET
            name = CASE WHEN {FOREIGN_SOURCE_LINK}
                        THEN proxies.name ELSE excluded.name END,
            params = CASE WHEN {FOREIGN_SOURCE_LINK}
                          THEN proxies.params ELSE excluded.params END,
            unknown_params = CASE WHEN {FOREIGN_SOURCE_LINK}
                                  THEN proxies.unknown_params
                                  ELSE excluded.unknown_params END,
            raw_line = CASE WHEN {FOREIGN_SOURCE_LINK}
                            THEN proxies.raw_line ELSE excluded.raw_line END,
            raw_path = CASE WHEN {FOREIGN_SOURCE_LINK}
                            THEN proxies.raw_path ELSE excluded.raw_path END,
            geo_country = COALESCE(excluded.geo_country, proxies.geo_country),
            geo_city = COALESCE(excluded.geo_city, proxies.geo_city),
            geo_asn = COALESCE(excluded.geo_asn, proxies.geo_asn),
            geo_attempts = CASE WHEN excluded.geo_country IS NOT NULL
                                   OR excluded.geo_city IS NOT NULL
                                   OR excluded.geo_asn IS NOT NULL
                                 THEN 0 ELSE proxies.geo_attempts END,
            last_geo_attempt_at = CASE WHEN excluded.geo_country IS NOT NULL
                                          OR excluded.geo_city IS NOT NULL
                                          OR excluded.geo_asn IS NOT NULL
                                        THEN NULL ELSE proxies.last_geo_attempt_at END,
            updated_at = excluded.updated_at
         RETURNING id, fingerprint"
    );
    // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound
    let mut query = sqlx::query_as::<_, (i64, String)>(sqlx::AssertSqlSafe(sql.as_str()));
    for (idx, entry) in chunk.iter().enumerate() {
        let fingerprint = fingerprints[idx].as_str();
        let params_json =
            super::json_to_text(&serde_json::Value::Object(entry.known_params_json()))?;
        let unknown_json =
            super::json_to_text(&serde_json::Value::Object(entry.unknown_params_json()))?;
        let geostamp = geo
            .get(base + idx)
            .and_then(|stamp| stamp.as_ref())
            .cloned()
            .unwrap_or_default();
        query = query
            .bind(fingerprint)
            .bind(entry.scheme.as_str())
            .bind(&entry.name)
            .bind(&entry.host)
            .bind(entry.port)
            .bind(&entry.credential)
            .bind(params_json)
            .bind(unknown_json)
            .bind(&entry.raw_line)
            .bind(&entry.raw_path)
            .bind(geostamp.country)
            .bind(geostamp.city)
            .bind(geostamp.asn)
            .bind(now)
            .bind(now);
    }
    let guard_binds = sql.matches(FOREIGN_SOURCE_LINK).count();
    for _ in 0..guard_binds {
        query = query.bind(source_id);
    }
    Ok(query.fetch_all(&mut **tx).await?)
}

/// Rebuild the per-entry id list in entry order and do the insert/update
/// accounting: a fingerprint already in the DB, or already seen earlier
/// in this batch, counts as an update.
fn account_upserted(
    stats: &mut ReconciliationStats,
    fingerprints: &[String],
    ids_by_fingerprint: &std::collections::HashMap<String, i64>,
    existing: &std::collections::HashSet<String>,
) -> crate::Result<Vec<i64>> {
    let mut proxy_ids: Vec<i64> = Vec::with_capacity(fingerprints.len());
    let mut seen_in_batch: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for fingerprint in fingerprints {
        let id = ids_by_fingerprint
            .get(fingerprint.as_str())
            .copied()
            .ok_or_else(|| {
                crate::Error::Database(
                    "reconcile_source: upsert returned no id for a bound fingerprint".to_string(),
                )
            })?;
        proxy_ids.push(id);
        if existing.contains(fingerprint.as_str()) || !seen_in_batch.insert(fingerprint.as_str()) {
            stats.updated += 1;
        } else {
            stats.inserted += 1;
            stats.inserted_ids.push(id);
        }
    }
    Ok(proxy_ids)
}

/// The stamp of this pass: `now`, but strictly greater than any
/// `seen_at` this source's links already carry, so two passes of one
/// source inside the same wall-clock second cannot stamp the same value
/// (the sweeps compare `seen_at <> stamp`, not `<`). The read sits
/// inside the `BEGIN IMMEDIATE` transaction, so no concurrent writer can
/// slip a fresher stamp in between.
async fn next_link_stamp(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    now: i64,
) -> crate::Result<i64> {
    let max_seen: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seen_at), 0) FROM proxy_source_links WHERE source_id = ?",
    )
    .bind(source_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(now.max(max_seen + 1))
}

/// Stamp the links of everything still present in this source,
/// batched like the upserts (3 binds per row).
async fn stamp_source_links(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    proxy_ids: &[i64],
    stamp: i64,
) -> crate::Result<()> {
    for chunk in proxy_ids.chunks(500) {
        let placeholders = vec!["(?, ?, ?)"; chunk.len()].join(", ");
        let sql = format!(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
             VALUES {placeholders}
             ON CONFLICT(proxy_id, source_id) DO UPDATE SET seen_at = excluded.seen_at"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
        for id in chunk {
            query = query.bind(id).bind(source_id).bind(stamp);
        }
        query.execute(&mut **tx).await?;
    }
    Ok(())
}

/// The retire sweep of the pass: it runs *before* the links go away and
/// retires exactly the proxies the link DELETE ([`delete_stale_links`])
/// leaves with no link at all, per source. The unscoped
/// `NOT EXISTS (link)` version swept up every link-less row in the
/// table, including the deliberate residue of the admin source-delete
/// path: [`mark_source_orphans_removed`] protects `ready` and `unknown`
/// rows and leaves them link-less on purpose, and the very next
/// reconcile of any *other* source retired them, undoing the operator's
/// choice. The protected rows have no link to this source, so they are
/// not in the candidate set here. Both EXISTS share the same arguments:
/// a stale link of this source (about to be deleted) and no link that
/// survives it.
///
/// Idempotent: proxies already removed keep their removed_at (the
/// `status != 'removed'` guard). Returns the number of rows retired.
async fn retire_unlinked_proxies(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    now: i64,
) -> crate::Result<usize> {
    let retire_sql = format!(
        "UPDATE proxies
         SET {RETIRE_SET}
         WHERE status != 'removed'
           AND EXISTS (SELECT 1 FROM proxy_source_links l
                       WHERE l.proxy_id = proxies.id AND l.source_id = ? AND l.seen_at <> ?)
           AND NOT EXISTS (SELECT 1 FROM proxy_source_links l
                           WHERE l.proxy_id = proxies.id
                             AND NOT (l.source_id = ? AND l.seen_at <> ?))"
    );
    Ok(sqlx::query(sqlx::AssertSqlSafe(retire_sql.as_str()))
        .bind(now)
        .bind(now)
        .bind(source_id)
        .bind(now)
        .bind(source_id)
        .bind(now)
        .execute(&mut **tx)
        .await?
        .rows_affected() as usize)
}

/// Drop the links of this source this fetch no longer saw; the proxies
/// the DELETE leaves with no link at all are retired by
/// [`retire_unlinked_proxies`], which runs before this DELETE inside the
/// same transaction.
///
/// With the alive-linger policy an alive *or ready* proxy keeps a link
/// the fetch did not re-stamp and keeps running the probe cycle; only
/// the probe's own verdict can end it. Stale means "not stamped by this
/// pass", compared against the strictly-increasing stamp of
/// [`next_link_stamp`], so two passes inside one second still part last
/// pass's links from this pass's.
async fn delete_stale_links(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    now: i64,
    policy: crate::ingest::IngestPolicy,
) -> crate::Result<usize> {
    let unlinked_sql = if policy.keep_alive_linger() {
        format!(
            "DELETE FROM proxy_source_links
             WHERE source_id = ?
               AND seen_at <> ?
               AND proxy_id NOT IN (SELECT id FROM proxies WHERE {})",
            policy.live_tiers_clause()
        )
    } else {
        "DELETE FROM proxy_source_links WHERE source_id = ? AND seen_at <> ?".to_string()
    };
    Ok(sqlx::query(sqlx::AssertSqlSafe(unlinked_sql))
        .bind(source_id)
        .bind(now)
        .execute(&mut **tx)
        .await?
        .rows_affected() as usize)
}

/// Batch of `(id, host)` rows still missing a fact the loaded databases
/// can supply, ordered by id past `after_id`, keyset pagination.
///
/// Per fact, not per row: a row that resolved a country but no ASN is
/// exactly what a later pass must retry. A fact no database can answer
/// (`mask`) is left out of the criterion. Rows looked up within
/// [`GEO_RETRY_WINDOW_SECS`] are left out as well: their host was asked
/// recently and did not answer, and asking again before the window
/// passed only takes the budget away from rows that were never tried.
/// `removed` rows are never walked: nothing will ever serve their facts.
pub async fn list_missing_geo(
    pool: &DbPool,
    after_id: i64,
    limit: i64,
    mask: GeoFactMask,
    now: i64,
) -> crate::Result<Vec<(i64, String)>> {
    let Some(criterion) = missing_geo_criterion(mask) else {
        return Ok(Vec::new());
    };
    let sql = format!(
        "SELECT id, host FROM proxies
         WHERE id > ? AND ({criterion})
           AND status != 'removed'
           AND (last_geo_attempt_at IS NULL OR last_geo_attempt_at <= ?)
         ORDER BY id LIMIT ?"
    );
    let rows: Vec<(i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(after_id)
        .bind(now - GEO_RETRY_WINDOW_SECS)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// How long a row whose geo lookup failed is left alone before it is
/// asked again: long enough that a hopeless host does not take the
/// backfill budget away from fresh rows on every pass, short enough that
/// a host that comes back is filled within the day. Six hours matches
/// the lifetime of the resolver's own fact cache.
pub const GEO_RETRY_WINDOW_SECS: i64 = 6 * 3600;

/// The `geo_* IS NULL` predicate for the facts this installation could
/// still fill, or `None` when it could fill none of them.
fn missing_geo_criterion(mask: GeoFactMask) -> Option<&'static str> {
    match (mask.country, mask.asn) {
        (true, true) => Some("geo_country IS NULL OR geo_asn IS NULL"),
        (true, false) => Some("geo_country IS NULL"),
        (false, true) => Some("geo_asn IS NULL"),
        (false, false) => None,
    }
}

/// How many rows still miss a fact the loaded databases can supply; the
/// backfill's "still missing" figure. Excludes `removed` rows, the same
/// population [`list_missing_geo`] walks, so the figure can reach zero.
pub async fn count_missing_geo(pool: &DbPool, mask: GeoFactMask) -> crate::Result<i64> {
    let Some(criterion) = missing_geo_criterion(mask) else {
        return Ok(0);
    };
    let sql = format!("SELECT COUNT(*) FROM proxies WHERE {criterion} AND status != 'removed'");
    let (count,): (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Store resolved geo facts on one proxy row. Only the facts the stamp
/// carries are written: a partial stamp fills its gap without erasing
/// what the row already knows (the invariant the reconcile upsert keeps
/// too), and a stored fact clears the attempt counter.
pub async fn update_geo(pool: &DbPool, id: i64, geo: &GeoStamp) -> crate::Result<()> {
    update_geo_on(pool, id, geo).await
}

/// [`update_geo`] against an open transaction, so a caller can commit a
/// whole batch of rows atomically (the geo backfill's per-batch loop).
pub async fn update_geo_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: i64,
    geo: &GeoStamp,
) -> crate::Result<()> {
    update_geo_on(&mut **tx, id, geo).await
}

async fn update_geo_on<'e, E>(ex: E, id: i64, geo: &GeoStamp) -> crate::Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "UPDATE proxies
         SET geo_country = COALESCE(?, geo_country),
             geo_city = COALESCE(?, geo_city),
             geo_asn = COALESCE(?, geo_asn),
             geo_attempts = 0,
             last_geo_attempt_at = NULL
         WHERE id = ?",
    )
    .bind(&geo.country)
    .bind(&geo.city)
    .bind(&geo.asn)
    .bind(id)
    .execute(ex)
    .await?;
    Ok(())
}

/// Record that a geo lookup for this row failed: the row keeps its
/// (missing) facts, but the backfill leaves it alone until the retry
/// window ([`GEO_RETRY_WINDOW_SECS`]) passed instead of asking again on
/// every pass.
pub async fn mark_geo_attempt(pool: &DbPool, id: i64, now: i64) -> crate::Result<()> {
    mark_geo_attempt_on(pool, id, now).await
}

/// [`mark_geo_attempt`] against an open transaction, the pair of
/// [`update_geo_tx`]: the backfill commits one batch's attempts and
/// facts together.
pub async fn mark_geo_attempt_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: i64,
    now: i64,
) -> crate::Result<()> {
    mark_geo_attempt_on(&mut **tx, id, now).await
}

async fn mark_geo_attempt_on<'e, E>(ex: E, id: i64, now: i64) -> crate::Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "UPDATE proxies
         SET geo_attempts = geo_attempts + 1,
             last_geo_attempt_at = ?
         WHERE id = ?",
    )
    .bind(now)
    .bind(id)
    .execute(ex)
    .await?;
    Ok(())
}

// Egress GeoIP backfill
//
// The probe stamps `egress_ip` from the Cloudflare trace but holds no mmdb,
// so the server derives the egress geo facts from it with the same walk the
// host geo backfill runs. These helpers mirror the `geo_*` ones above; the
// facts they write are server-owned (the probe's authorizer denies them).

/// The egress geo facts of one proxy row, as the resolver produced them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EgressGeoStamp {
    /// ISO country code of the egress address.
    pub country: Option<String>,
    /// Autonomous system in the canonical `AS<n>` form of `geo_asn`.
    pub asn: Option<String>,
    /// The AS organization name, when the ASN database carries one.
    pub asn_org: Option<String>,
}

impl EgressGeoStamp {
    /// Map one resolver answer onto the egress stamp.
    pub fn from_info(info: &crate::geo::GeoInfo) -> Self {
        Self {
            country: info.country_code.clone(),
            asn: info.asn.map(|n| format!("AS{n}")),
            asn_org: info.asn_org.clone(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.asn.is_none() && self.asn_org.is_none()
    }
}

/// Rows whose egress geo facts this installation could still fill, oldest
/// id first: `(id, egress_ip)` pairs. Same shape and retry window as
/// [`list_missing_geo`] — a row whose address nothing knows is marked and
/// left alone until the window passed.
pub async fn list_missing_egress_geo(
    pool: &DbPool,
    after_id: i64,
    limit: i64,
    mask: GeoFactMask,
    now: i64,
) -> crate::Result<Vec<(i64, String)>> {
    let Some(criterion) = missing_egress_geo_criterion(mask) else {
        return Ok(Vec::new());
    };
    let sql = format!(
        "SELECT id, egress_ip FROM proxies
         WHERE id > ? AND egress_ip IS NOT NULL AND ({criterion})
           AND status != 'removed'
           AND (last_egress_geo_attempt_at IS NULL OR last_egress_geo_attempt_at <= ?)
         ORDER BY id LIMIT ?"
    );
    let rows: Vec<(i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(after_id)
        .bind(now - GEO_RETRY_WINDOW_SECS)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// How many rows still miss an egress fact the loaded databases can
/// supply; the egress backfill's "still missing" figure.
pub async fn count_missing_egress_geo(pool: &DbPool, mask: GeoFactMask) -> crate::Result<i64> {
    let Some(criterion) = missing_egress_geo_criterion(mask) else {
        return Ok(0);
    };
    let sql = format!(
        "SELECT COUNT(*) FROM proxies
         WHERE egress_ip IS NOT NULL AND ({criterion}) AND status != 'removed'"
    );
    let (count,): (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// The `egress_* IS NULL` predicate for the facts this installation could
/// still fill, or `None` when it could fill none of them. The egress stamp
/// carries no city: the City database is consulted for the country only.
fn missing_egress_geo_criterion(mask: GeoFactMask) -> Option<&'static str> {
    match (mask.country, mask.asn) {
        (true, true) => Some("egress_country IS NULL OR egress_asn IS NULL"),
        (true, false) => Some("egress_country IS NULL"),
        (false, true) => Some("egress_asn IS NULL"),
        (false, false) => None,
    }
}

/// Store the egress geo facts on one proxy row. Only the facts the stamp
/// carries are written (a partial answer fills its gap without erasing
/// what a previous pass established), and a filled row clears the attempt
/// counter — the same contract [`update_geo`] keeps for the host geo.
pub async fn update_egress_geo(
    pool: &DbPool,
    id: i64,
    stamp: &EgressGeoStamp,
) -> crate::Result<()> {
    update_egress_geo_on(pool, id, stamp).await
}

/// [`update_egress_geo`] against an open transaction, the pair the
/// backfill commits one batch through.
pub async fn update_egress_geo_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: i64,
    stamp: &EgressGeoStamp,
) -> crate::Result<()> {
    update_egress_geo_on(&mut **tx, id, stamp).await
}

async fn update_egress_geo_on<'e, E>(ex: E, id: i64, stamp: &EgressGeoStamp) -> crate::Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "UPDATE proxies
         SET egress_country = COALESCE(?, egress_country),
             egress_asn = COALESCE(?, egress_asn),
             egress_asn_org = COALESCE(?, egress_asn_org),
             egress_geo_attempts = 0,
             last_egress_geo_attempt_at = NULL
         WHERE id = ?",
    )
    .bind(&stamp.country)
    .bind(&stamp.asn)
    .bind(&stamp.asn_org)
    .bind(id)
    .execute(ex)
    .await?;
    Ok(())
}

/// Record that the egress geo lookup for this row failed: the row keeps
/// its (missing) facts and is left alone until the retry window passed.
pub async fn mark_egress_geo_attempt(pool: &DbPool, id: i64, now: i64) -> crate::Result<()> {
    mark_egress_geo_attempt_on(pool, id, now).await
}

/// [`mark_egress_geo_attempt`] against an open transaction.
pub async fn mark_egress_geo_attempt_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: i64,
    now: i64,
) -> crate::Result<()> {
    mark_egress_geo_attempt_on(&mut **tx, id, now).await
}

async fn mark_egress_geo_attempt_on<'e, E>(ex: E, id: i64, now: i64) -> crate::Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        "UPDATE proxies
         SET egress_geo_attempts = egress_geo_attempts + 1,
             last_egress_geo_attempt_at = ?
         WHERE id = ?",
    )
    .bind(now)
    .bind(id)
    .execute(ex)
    .await?;
    Ok(())
}

/// Store the full outcome of an on-demand geo resolution: the facts plus
/// the IP they were resolved from (admin proxy-card action).
///
/// `COALESCE`, exactly like the reconcile upsert: a `None` field means
/// "not known from this lookup", never "erase". An ASN-only hit (the
/// City record decodes with an empty country, as it does for the
/// Cloudflare `104.16.0.0/12` block) must not wipe a country the ingest
/// path already resolved. `resolved_ip` is always a concrete address
/// from the lookup that just ran and is written as-is.
pub async fn update_geo_full(
    pool: &DbPool,
    id: i64,
    geo: &GeoStamp,
    resolved_ip: &str,
) -> crate::Result<()> {
    sqlx::query(
        "UPDATE proxies SET
             geo_country = COALESCE(?, geo_country),
             geo_city = COALESCE(?, geo_city),
             geo_asn = COALESCE(?, geo_asn),
             resolved_ip = ?
         WHERE id = ?",
    )
    .bind(&geo.country)
    .bind(&geo.city)
    .bind(&geo.asn)
    .bind(resolved_ip)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_by_fingerprint(
    pool: &DbPool,
    fingerprint: &str,
) -> crate::Result<Option<ProxyRow>> {
    let row: Option<ProxyRow> = sqlx::query_as("SELECT * FROM proxies WHERE fingerprint = ?")
        .bind(fingerprint)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

pub async fn get_by_id(pool: &DbPool, id: i64) -> crate::Result<Option<ProxyRow>> {
    let row: Option<ProxyRow> = sqlx::query_as("SELECT * FROM proxies WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Proxy counts grouped by status (dashboard aggregates).
pub async fn count_by_status(pool: &DbPool) -> crate::Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, COUNT(*) FROM proxies GROUP BY status ORDER BY status")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// One row of the dashboard's aggregate over the proxy table: the status
/// it groups by plus the per-status counters.
#[derive(Debug, Clone, FromRow)]
pub struct StatusAggregateRow {
    pub status: String,
    pub count: i64,
    pub never_checked: i64,
    pub second_chance: i64,
    /// Rows of an unprobeable scheme (they stay `unknown` forever).
    pub unprobeable: i64,
    /// Fastest measured latency of this status (`NULL` without one).
    pub latency_min: Option<i64>,
    /// Sum and count of the measured latencies of this status; the mean
    /// is their quotient, kept split so the integers do not overflow.
    pub latency_sum: Option<i64>,
    pub latency_count: Option<i64>,
}

/// The dashboard's counters over the whole proxy table, read in one
/// grouped pass, so the numbers cannot contradict each other the way
/// four independent scans of the same table could.
#[derive(Debug, Clone, Default)]
pub struct StatusAggregates {
    pub counts: Vec<(String, i64)>,
    pub total: i64,
    pub in_quarantine: i64,
    pub quarantine_second_chance: i64,
    /// Rows that were never checked (removed rows excluded).
    pub never_checked: i64,
    /// Rows of an unprobeable scheme (removed rows excluded).
    pub unprobeable: i64,
    /// Fastest measured latency of a live proxy (`alive` or `ready`).
    pub latency_min: Option<i64>,
    pub latency_avg: Option<i64>,
}

/// The schemes the probe daemon cannot check: their proxies stay
/// `unknown` for good, and the dashboard counts them apart.
fn unprobeable_schemes() -> Vec<&'static str> {
    Scheme::all()
        .iter()
        .filter(|scheme| !scheme.is_probeable())
        .map(|scheme| scheme.as_str())
        .collect()
}

/// Read the dashboard's proxy counters in one grouped pass: the table is
/// grouped by status and the scalar counters are per-group sums, so the
/// whole dashboard reads the table once. The latency figures cover the
/// live pool (`alive` and `ready`).
pub async fn status_aggregates<'e, E>(executor: E) -> crate::Result<StatusAggregates>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let schemes = unprobeable_schemes();
    let placeholders = vec!["?"; schemes.len()].join(", ");
    let sql = format!(
        "SELECT status,
                COUNT(*) AS count,
                COALESCE(SUM(status != 'removed' AND last_checked_at IS NULL), 0) AS never_checked,
                COALESCE(SUM(status = 'quarantine' AND ladder_step = 0), 0) AS second_chance,
                COALESCE(SUM(status != 'removed' AND scheme IN ({placeholders})), 0) AS unprobeable,
                MIN(CASE WHEN status IN ('alive', 'ready') AND latency_ms IS NOT NULL
                         THEN latency_ms END) AS latency_min,
                SUM(CASE WHEN status IN ('alive', 'ready') AND latency_ms IS NOT NULL
                         THEN latency_ms ELSE 0 END) AS latency_sum,
                SUM(CASE WHEN status IN ('alive', 'ready') AND latency_ms IS NOT NULL
                         THEN 1 ELSE 0 END) AS latency_count
         FROM proxies
         GROUP BY status
         ORDER BY status"
    );
    // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound
    let mut query = sqlx::query_as::<_, StatusAggregateRow>(sqlx::AssertSqlSafe(sql));
    for scheme in &schemes {
        query = query.bind(scheme);
    }
    let rows = query.fetch_all(executor).await?;

    let mut out = StatusAggregates::default();
    let mut latency_sum = 0i64;
    let mut latency_count = 0i64;
    for row in rows {
        out.counts.push((row.status.clone(), row.count));
        out.total += row.count;
        out.never_checked += row.never_checked;
        out.unprobeable += row.unprobeable;
        if row.status == ProxyStatus::Quarantine.as_str() {
            out.in_quarantine += row.count;
            out.quarantine_second_chance += row.second_chance;
        }
        if let Some(min) = row.latency_min {
            out.latency_min = Some(out.latency_min.map_or(min, |current: i64| current.min(min)));
        }
        latency_sum += row.latency_sum.unwrap_or(0);
        latency_count += row.latency_count.unwrap_or(0);
    }
    if latency_count > 0 {
        out.latency_avg = Some(latency_sum / latency_count);
    }
    Ok(out)
}

/// The median measured latency of the live proxies (`alive` and
/// `ready`). SQLite has no median builtin: the middle element(s) are
/// picked with a window function over the measured rows and averaged
/// (odd count: one element, even count: the mean of the two middle).
pub async fn latency_median<'e, E>(executor: E) -> crate::Result<Option<i64>>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let median: Option<i64> = sqlx::query_scalar(
        "WITH ordered AS (
             SELECT latency_ms, ROW_NUMBER() OVER (ORDER BY latency_ms) AS rn,
                    COUNT(*) OVER () AS n
             FROM proxies
             WHERE status IN ('alive', 'ready') AND latency_ms IS NOT NULL
         )
         SELECT CAST(AVG(latency_ms) AS INTEGER) FROM ordered
         WHERE rn IN ((n + 1) / 2, (n + 2) / 2)",
    )
    .fetch_one(executor)
    .await?;
    Ok(median)
}

/// Alias of the joined coverage aggregate over the preserved probe
/// history ([`coverage_aggregate_sql`]): the journal is read once and
/// grouped, not once per tier or once per candidate row. The bucket
/// filter and the list query read the same alias, so the WHERE clause
/// and the JOIN it depends on cannot drift apart.
const COVERAGE_ALIAS: &str = "cov";

/// The join that brings the coverage aggregate into the query under the
/// shared alias. The list query always carries it (the per-row T1/T2
/// flags read it); the count query carries it only when the filter
/// constrains the coverage, so an unfiltered count does not pay for a
/// pass over the journal.
fn coverage_join_sql() -> String {
    format!(
        "LEFT JOIN ({}) {alias} ON {alias}.proxy_id = p.id",
        coverage_aggregate_sql(),
        alias = COVERAGE_ALIAS
    )
}

fn coverage_aggregate_sql() -> String {
    format!(
        "SELECT proxy_id,
                MAX(CASE WHEN probe_kind IN ('tcp', 'tls') THEN 1 ELSE 0 END) AS t1,
                MAX(CASE WHEN probe_kind IN ({}) THEN 1 ELSE 0 END) AS t2
         FROM probe_results GROUP BY proxy_id",
        crate::repo::probe::T2_KINDS_SQL
    )
}

/// Check-coverage buckets of the whole population (probe overview panel):
/// `none`, no journaled attempt at all; `t1_only` / `t2_only`, exactly
/// one of the check tiers has history; `both`, T1 and T2 both do. T1 is
/// `probe_kind IN ('tcp', 'tls')`, T2 is any of the T2 kinds
/// ([`crate::repo::probe::T2_KINDS_SQL`]), so an attempt the engine never
/// verified still counts as a T2 attempt.
///
/// The buckets cover *preserved* history only: `probe_results` rotates
/// after `[retention].probe_results_days`, so a long-unseen proxy may
/// look unverified even though it was checked once. The order is fixed
/// and missing buckets are zero-filled, so the panel never reshuffles.
pub async fn count_by_check_coverage(pool: &DbPool) -> crate::Result<Vec<(String, i64)>> {
    let sql = format!(
        "SELECT bucket, COUNT(*) FROM (
             SELECT CASE
                 WHEN COALESCE(cov.t1, 0) = 1 AND COALESCE(cov.t2, 0) = 1 THEN 'both'
                 WHEN COALESCE(cov.t1, 0) = 1 THEN 't1_only'
                 WHEN COALESCE(cov.t2, 0) = 1 THEN 't2_only'
                 ELSE 'none'
             END AS bucket
             FROM proxies p
             LEFT JOIN ({}) cov ON cov.proxy_id = p.id
         ) GROUP BY bucket",
        coverage_aggregate_sql()
    );
    let rows: Vec<(String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await?;
    let mut out: Vec<(String, i64)> = ["none", "t1_only", "t2_only", "both"]
        .iter()
        .map(|bucket| (bucket.to_string(), 0))
        .collect();
    for (bucket, count) in rows {
        if let Some(slot) = out.iter_mut().find(|(name, _)| name == &bucket) {
            slot.1 = count;
        }
    }
    Ok(out)
}

// Admin proxy browser: filter clauses are whitelisted fragments assembled
// through the shared [`super::WhereFilter`], every value flows through a
// bind.

/// Which check tiers have preserved history for a proxy, the coverage
/// buckets of the admin proxy browser and the probe overview. T1 is
/// `probe_kind IN ('tcp', 'tls')`, T2 is any of the T2 kinds (an attempt
/// the engine never verified still counts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckCoverage {
    None,
    T1Only,
    T2Only,
    Both,
}

impl CheckCoverage {
    /// Bucket name as the admin query string and the
    /// [`count_by_check_coverage`] rows carry it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::T1Only => "t1_only",
            Self::T2Only => "t2_only",
            Self::Both => "both",
        }
    }

    /// Parse a bucket name; `None` for anything else, which the caller
    /// renders as "no filter".
    pub fn from_bucket(bucket: &str) -> Option<Self> {
        Some(match bucket {
            "none" => Self::None,
            "t1_only" => Self::T1Only,
            "t2_only" => Self::T2Only,
            "both" => Self::Both,
            _ => return None,
        })
    }

    /// The WHERE fragment of the bucket over the joined coverage
    /// aggregate (see [`coverage_aggregate_sql`]), a fixed literal per
    /// variant over the shared alias: caller text never reaches the SQL.
    /// The aggregate row is absent for a proxy without history, so the
    /// `none` bucket is "no aggregate row" and the other three read the
    /// per-tier flags.
    fn filter_clause(self) -> String {
        let alias = COVERAGE_ALIAS;
        match self {
            Self::None => format!("{alias}.proxy_id IS NULL"),
            Self::T1Only => format!("{alias}.t1 = 1 AND {alias}.t2 = 0"),
            Self::T2Only => format!("{alias}.t1 = 0 AND {alias}.t2 = 1"),
            Self::Both => format!("{alias}.t1 = 1 AND {alias}.t2 = 1"),
        }
    }
}

/// Sort orders of the admin proxy browser. `order_sql` returns a
/// compile-time fragment per variant; caller text never reaches the
/// ORDER BY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyListOrder {
    /// Newest `updated_at` first (the default).
    #[default]
    Updated,
    /// Measured latency ascending, unmeasured rows last.
    Latency,
    /// Case-insensitive display name ascending.
    Name,
}

impl ProxyListOrder {
    /// Parse the `sort` query parameter; anything unrecognized falls
    /// back to the default.
    pub fn from_param(value: &str) -> Self {
        match value {
            "latency" => Self::Latency,
            "name" => Self::Name,
            _ => Self::Updated,
        }
    }

    pub fn as_param(self) -> &'static str {
        match self {
            Self::Updated => "updated",
            Self::Latency => "latency",
            Self::Name => "name",
        }
    }

    fn order_sql(self) -> &'static str {
        match self {
            Self::Updated => "p.updated_at DESC, p.id DESC",
            Self::Latency => "p.latency_ms IS NULL ASC, p.latency_ms ASC, p.id DESC",
            Self::Name => "p.name COLLATE NOCASE ASC, p.id DESC",
        }
    }

    /// The same order, walked backwards: how a page before the cursor is
    /// fetched and then turned back into the reading order.
    fn reverse_order_sql(self) -> &'static str {
        match self {
            Self::Updated => "p.updated_at ASC, p.id ASC",
            Self::Latency => "p.latency_ms IS NULL DESC, p.latency_ms DESC, p.id ASC",
            Self::Name => "p.name COLLATE NOCASE DESC, p.id ASC",
        }
    }

    /// Whether `cursor` is a position in this order; a cursor of another
    /// sort is not, the browser falls back to the first page instead of
    /// paging from a key that means nothing here.
    pub fn accepts_cursor(self, cursor: &ProxyListCursor) -> bool {
        matches!(
            (self, cursor),
            (Self::Updated, ProxyListCursor::Updated { .. })
                | (Self::Latency, ProxyListCursor::Latency { .. })
                | (Self::Name, ProxyListCursor::Name { .. })
        )
    }

    /// The keyset predicate that selects the rows on one side of
    /// `cursor`, with the values the predicate binds. The predicate
    /// repeats the sort key of the order, so "after the cursor" means
    /// exactly "the rows the next page shows"; the tie-break direction
    /// of the order decides which of two equal keys comes first. `None`
    /// when the cursor does not belong to this order.
    fn keyset(
        self,
        cursor: &ProxyListCursor,
        direction: ProxyListDirection,
    ) -> Option<(String, Vec<KeysetValue>)> {
        if !self.accepts_cursor(cursor) {
            return None;
        }
        let forward = direction == ProxyListDirection::Forward;
        match (self, cursor) {
            (Self::Updated, ProxyListCursor::Updated { updated_at, id }) => {
                let cmp = if forward { "<" } else { ">" };
                Some((
                    format!("(p.updated_at {cmp} ?) OR (p.updated_at = ? AND p.id {cmp} ?)"),
                    vec![
                        KeysetValue::Int(*updated_at),
                        KeysetValue::Int(*updated_at),
                        KeysetValue::Int(*id),
                    ],
                ))
            }
            (
                Self::Latency,
                ProxyListCursor::Latency {
                    latency_ms: Some(latency),
                    id,
                },
            ) => {
                // The measured rows come first, the unmeasured last: a
                // cursor inside the measured tier sees the rest of that
                // tier and, past its end, the unmeasured rows; a cursor
                // inside the unmeasured tier sees only the rows behind it
                // in that tier
                let (clause, values) = if forward {
                    (
                        "(p.latency_ms IS NULL) OR (p.latency_ms IS NOT NULL AND \
                         (p.latency_ms > ? OR (p.latency_ms = ? AND p.id < ?)))"
                            .to_string(),
                        vec![
                            KeysetValue::Int(*latency),
                            KeysetValue::Int(*latency),
                            KeysetValue::Int(*id),
                        ],
                    )
                } else {
                    (
                        "(p.latency_ms IS NOT NULL AND \
                         (p.latency_ms < ? OR (p.latency_ms = ? AND p.id > ?)))"
                            .to_string(),
                        vec![
                            KeysetValue::Int(*latency),
                            KeysetValue::Int(*latency),
                            KeysetValue::Int(*id),
                        ],
                    )
                };
                Some((clause, values))
            }
            (
                Self::Latency,
                ProxyListCursor::Latency {
                    latency_ms: None,
                    id,
                },
            ) => {
                let clause = if forward {
                    "(p.latency_ms IS NULL AND p.id < ?)"
                } else {
                    "(p.latency_ms IS NOT NULL OR (p.latency_ms IS NULL AND p.id > ?))"
                };
                Some((clause.to_string(), vec![KeysetValue::Int(*id)]))
            }
            (Self::Name, ProxyListCursor::Name { name, id }) => {
                let cmp = if forward { ">" } else { "<" };
                let tie = if forward { "<" } else { ">" };
                Some((
                    format!(
                        "(p.name COLLATE NOCASE {cmp} ?) OR \
                         (p.name COLLATE NOCASE = ? AND p.id {tie} ?)"
                    ),
                    vec![
                        KeysetValue::Text(name.clone()),
                        KeysetValue::Text(name.clone()),
                        KeysetValue::Int(*id),
                    ],
                ))
            }
            _ => None,
        }
    }
}

/// One bound value of a keyset predicate: the key is a mix of integers
/// and text (a display name), so the values cannot go through the
/// text-only filter binder.
#[derive(Debug, Clone)]
enum KeysetValue {
    Int(i64),
    Text(String),
}

/// The sort key of one row of the admin proxy browser: the next keyset
/// page starts after the key of the last row of the current one, so a
/// page costs one index seek instead of a walk over everything it skips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyListCursor {
    /// `(updated_at, id)` of the default order.
    Updated { updated_at: i64, id: i64 },
    /// `(latency_ms, id)`; `None` is an unmeasured row, which the order
    /// puts last.
    Latency { latency_ms: Option<i64>, id: i64 },
    /// `(name, id)`; the name compares case-insensitively.
    Name { name: String, id: i64 },
}

/// Which side of the cursor a keyset page takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyListDirection {
    Forward,
    Backward,
}

/// Where one page of the admin proxy browser starts.
#[derive(Debug, Clone)]
pub struct ProxyListPage {
    pub cursor: ProxyListCursor,
    pub direction: ProxyListDirection,
}

/// Filter parameters of the admin proxy browser ([`count_filtered`] /
/// [`list_filtered`]). An empty string or an empty list means "no
/// constraint" for that field.
#[derive(Debug, Clone, Default)]
pub struct ProxyListFilter {
    pub statuses: Vec<String>,
    pub scheme: String,
    pub country: String,
    pub source_id: String,
    /// Literal case-insensitive substring match against host and name:
    /// the query is interpolated into a `LIKE %..% ESCAPE '\'` needle
    /// with `%`, `_` and `\` escaped, so the `LIKE` wildcards in the
    /// input mean themselves (`100%` finds `100%`, not `100` + anything).
    pub query: String,
    pub coverage: Option<CheckCoverage>,
    /// The speed-measurement bucket of the browser: `Some(true)` = rows
    /// with a measurement, `Some(false)` = rows without one, `None` = no
    /// filter. A measurement is `speed_mbps IS NOT NULL`; its age is the
    /// pipeline's concern, the browser does not second-guess it.
    pub speed_measured: Option<bool>,
    /// Exact match against `egress_country` (`""` = no filter); the
    /// dropdown is fed by [`distinct_egress_countries`].
    pub egress_country: String,
}

impl ProxyListFilter {
    /// The WHERE fragment and bound values shared by [`count_filtered`]
    /// and [`list_filtered`]: the one place the proxies list's dynamic
    /// clause set is defined.
    fn where_filter(&self) -> super::WhereFilter {
        let mut wf = super::WhereFilter::new();
        if !self.statuses.is_empty() {
            wf = wf.text_in("p.status", &self.statuses);
        }
        if !self.scheme.is_empty() {
            wf = wf.text("p.scheme = ?", &self.scheme);
        }
        if !self.country.is_empty() {
            wf = wf.text("p.geo_country = ?", &self.country);
        }
        if !self.source_id.is_empty() {
            wf = wf.text(
                "EXISTS (SELECT 1 FROM proxy_source_links l
                          WHERE l.proxy_id = p.id AND l.source_id = ?)",
                &self.source_id,
            );
        }
        if !self.query.is_empty() {
            let escaped = self
                .query
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let needle = format!("%{escaped}%");
            wf = wf
                .text(
                    "(p.host LIKE ? ESCAPE '\\' OR p.name LIKE ? ESCAPE '\\')",
                    needle.clone(),
                )
                .text_value(needle);
        }
        if let Some(coverage) = self.coverage {
            wf = wf.clause(coverage.filter_clause());
        }
        match self.speed_measured {
            Some(true) => wf = wf.clause("p.speed_mbps IS NOT NULL"),
            Some(false) => wf = wf.clause("p.speed_mbps IS NULL"),
            None => {}
        }
        if !self.egress_country.is_empty() {
            wf = wf.text("p.egress_country = ?", &self.egress_country);
        }
        wf
    }

    /// The join that brings the coverage aggregate into the query, or
    /// nothing when the filter does not constrain the coverage.
    fn coverage_join(&self) -> Option<String> {
        self.coverage.map(|_| coverage_join_sql())
    }
}

/// One row of the admin proxy browser list: the display columns plus the
/// T1/T2 coverage flags the "Checks" cell renders (from the preserved
/// `probe_results` history).
#[derive(Debug, FromRow)]
pub struct ProxyListRow {
    pub id: i64,
    pub scheme: String,
    pub name: String,
    pub host: String,
    pub port: i64,
    pub status: String,
    pub latency_ms: Option<i64>,
    pub geo_country: Option<String>,
    /// The measurement facts the browser shows: the measured download rate, the
    /// egress country the server derived from `egress_ip`, and the
    /// Cloudflare datacenter the trace hit. All three may be absent.
    pub speed_mbps: Option<f64>,
    pub egress_country: Option<String>,
    pub cf_colo: Option<String>,
    /// The moment the row was last touched; the sort key of the default
    /// order and part of its keyset cursor.
    pub updated_at: i64,
    /// Whether the preserved probe history carries any T1 attempt.
    pub t1_checked: bool,
    /// Whether the preserved probe history carries any T2 attempt.
    pub t2_checked: bool,
    /// Whether the row has no source link at all ("detached"): no feed
    /// reaches it any more and no probe lane can pick it up.
    pub detached: bool,
}

impl ProxyListRow {
    /// The keyset cursor of this row: the sort key the next page resumes
    /// after.
    pub fn cursor(&self, order: ProxyListOrder) -> ProxyListCursor {
        match order {
            ProxyListOrder::Updated => ProxyListCursor::Updated {
                updated_at: self.updated_at,
                id: self.id,
            },
            ProxyListOrder::Latency => ProxyListCursor::Latency {
                latency_ms: self.latency_ms,
                id: self.id,
            },
            ProxyListOrder::Name => ProxyListCursor::Name {
                name: self.name.clone(),
                id: self.id,
            },
        }
    }
}

/// Count the rows the admin proxy browser would show for `filter`: the
/// same clause set [`list_filtered`] applies.
pub async fn count_filtered(pool: &DbPool, filter: &ProxyListFilter) -> crate::Result<i64> {
    let wf = filter.where_filter();
    let join = filter.coverage_join().unwrap_or_default();
    let sql = format!("SELECT COUNT(*) FROM proxies p {join}{}", wf.sql());
    let count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
        .bind_where_filter(wf.values())
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// One page of the admin proxy browser for `filter`, ordered by `order`.
///
/// Keyset cursor, not `OFFSET`: the page resumes from the sort key of a
/// row (`page`), so the database seeks straight to it instead of walking
/// over every row the page skips. A page taken *before* the cursor comes
/// out in the reading order even though it is fetched backwards.
pub async fn list_filtered(
    pool: &DbPool,
    filter: &ProxyListFilter,
    order: ProxyListOrder,
    limit: i64,
    page: Option<&ProxyListPage>,
) -> crate::Result<Vec<ProxyListRow>> {
    let wf = filter.where_filter();
    let filter_sql = wf.sql();
    let keyset = page.and_then(|page| order.keyset(&page.cursor, page.direction));
    let (clause, keyset_values) = match keyset {
        Some((predicate, values)) => {
            let clause = if filter_sql.is_empty() {
                format!(" WHERE {predicate}")
            } else {
                format!("{filter_sql} AND {predicate}")
            };
            (clause, values)
        }
        None => (filter_sql, Vec::new()),
    };
    let backwards = page.is_some_and(|page| page.direction == ProxyListDirection::Backward);
    let sort = if backwards {
        order.reverse_order_sql()
    } else {
        order.order_sql()
    };
    let sql = format!(
        "SELECT p.id, p.scheme, p.name, p.host, p.port, p.status, p.latency_ms, p.geo_country,
                p.speed_mbps, p.egress_country, p.cf_colo, p.updated_at,
                COALESCE({alias}.t1, 0) AS t1_checked,
                COALESCE({alias}.t2, 0) AS t2_checked,
                (lnk.proxy_id IS NULL AND p.status != 'removed') AS detached
         FROM proxies p
         LEFT JOIN (SELECT proxy_id FROM proxy_source_links GROUP BY proxy_id) lnk
                ON lnk.proxy_id = p.id
         {join}{clause}
         ORDER BY {sort}
         LIMIT ?",
        alias = COVERAGE_ALIAS,
        join = coverage_join_sql(),
    );
    let mut query =
        sqlx::query_as::<_, ProxyListRow>(sqlx::AssertSqlSafe(sql)).bind_where_filter(wf.values());
    for value in &keyset_values {
        query = match value {
            KeysetValue::Int(value) => query.bind(*value),
            KeysetValue::Text(value) => query.bind(value.as_str()),
        };
    }
    let mut rows = query.bind(limit).fetch_all(pool).await?;
    if backwards {
        rows.reverse();
    }
    Ok(rows)
}

/// Number of rows in terminal `removed` status. The purge dialog shows it
/// so the destructive confirm does not hide its blast radius; the count is
/// deliberately unfiltered, it is not the browser's filtered total.
pub async fn count_removed(pool: &DbPool) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies WHERE status = 'removed'")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Country codes with at least one stored proxy, ascending; the country
/// filter dropdown of the admin proxy browser.
pub async fn distinct_countries(pool: &DbPool) -> crate::Result<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT geo_country FROM proxies
         WHERE geo_country IS NOT NULL ORDER BY geo_country",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Country codes the egress backfill derived (`egress_country`), ascending;
/// the egress-country filter dropdown of the admin proxy browser. Empty
/// until the first trace wrote an `egress_ip` the backfill resolved.
pub async fn distinct_egress_countries(pool: &DbPool) -> crate::Result<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT egress_country FROM proxies
         WHERE egress_country IS NOT NULL ORDER BY egress_country",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Rows carrying a speed measurement (`speed_mbps` set), retired ones
/// excluded: the same population the probe overview's speed card talks
/// about ([`count_speed_stale`] mirrors the status guard).
pub async fn count_speed_measured(pool: &DbPool) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxies
         WHERE speed_mbps IS NOT NULL AND status != 'removed'",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Rows whose measurement is older than `stale_before` (or lost its
/// `speed_at`, which the column pair's invariant forbids but a future
/// migration could regress): the "freshness" line of the probe overview's
/// speed card.
pub async fn count_speed_stale(pool: &DbPool, stale_before: i64) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxies
         WHERE speed_mbps IS NOT NULL AND status != 'removed'
           AND (speed_at IS NULL OR speed_at < ?)",
    )
    .bind(stale_before)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Number of not-yet-retired proxies of a scheme the probe cannot judge
/// at all (tuic/mieru stay `unknown` forever). Rendered as a sub-line of
/// the "Never checked yet" card, so it counts the same population that
/// card does: retired rows are excluded, the cleanup button moves
/// exactly these rows to `removed` ([`remove_unprobeable_unknown`]).
pub async fn count_unprobeable(pool: &DbPool) -> crate::Result<i64> {
    let unprobeable_schemes: Vec<&'static str> = Scheme::all()
        .iter()
        .filter(|scheme| !scheme.is_probeable())
        .map(|scheme| scheme.as_str())
        .collect();
    let placeholders = vec!["?"; unprobeable_schemes.len()].join(", ");
    let sql = format!(
        "SELECT COUNT(*) FROM proxies WHERE status != 'removed' AND scheme IN ({placeholders})"
    );
    // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound
    let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql));
    for scheme in &unprobeable_schemes {
        query = query.bind(scheme);
    }
    Ok(query.fetch_one(pool).await?)
}

/// One row of the probe overview's quarantine queue panel.
#[derive(Debug, Clone, FromRow)]
pub struct QuarantineQueueRow {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: i64,
    pub scheme: String,
    pub quarantined_at: Option<i64>,
    /// Next scheduled ladder check (NULL only while a check is in flight).
    pub ladder_at: Option<i64>,
    /// 0 = second chance, `1..` = the Nth recheck.
    pub ladder_step: i64,
}

/// The `limit` quarantined proxies with the nearest upcoming check (probe
/// overview queue panel). An in-flight check sorts first (`COALESCE`).
pub async fn list_quarantine_queue(
    pool: &DbPool,
    limit: i64,
) -> crate::Result<Vec<QuarantineQueueRow>> {
    let rows: Vec<QuarantineQueueRow> = sqlx::query_as(
        "SELECT id, name, host, port, scheme, quarantined_at, ladder_at, ladder_step
         FROM proxies
         WHERE status = 'quarantine'
         ORDER BY COALESCE(ladder_at, 0) ASC
         LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Source link of a proxy joined with the source display name (proxy card).
#[derive(Debug, Clone, FromRow)]
pub struct ProxyLinkRow {
    pub source_id: String,
    pub seen_at: i64,
    /// Source display name; `None` when the source row is gone.
    pub name: Option<String>,
}

/// Source links of one proxy with the source display names, newest seen
/// first (proxy card). Unlike [`links_for_proxy`] a deleted source
/// renders as nameless instead of dropping the link row.
pub async fn links_with_source_name(
    pool: &DbPool,
    proxy_id: i64,
) -> crate::Result<Vec<ProxyLinkRow>> {
    let rows: Vec<ProxyLinkRow> = sqlx::query_as(
        "SELECT l.source_id, l.seen_at, s.name
         FROM proxy_source_links l LEFT JOIN sources s ON s.id = l.source_id
         WHERE l.proxy_id = ?
         ORDER BY l.seen_at DESC",
    )
    .bind(proxy_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// A proxy row joined with the source it is linked to (`#[sqlx(flatten)]`
/// maps the `p.*` columns onto the nested [`ProxyRow`]); `Debug` is
/// hand-written so the nested row's masking survives the join wrapper.
#[derive(Clone, FromRow)]
pub struct ProxyWithSource {
    pub source_id: String,
    #[sqlx(flatten)]
    pub proxy: ProxyRow,
}

impl std::fmt::Debug for ProxyWithSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyWithSource")
            .field("source_id", &self.source_id)
            .field("proxy", &self.proxy)
            .finish()
    }
}

/// Load proxies together with each source they are linked to, for
/// pipeline processing: a proxy linked from several of the selected
/// sources appears once per link, so every source can run its own merged
/// pipeline before the results are merged and deduplicated. Rows are
/// ordered by proxy id within each source; the caller imposes the
/// profile's source order.
pub async fn list_with_source(
    pool: &DbPool,
    source_ids: &[String],
) -> crate::Result<Vec<ProxyWithSource>> {
    if source_ids.is_empty() {
        return Ok(Vec::new());
    }
    let src_ph = vec!["?"; source_ids.len()].join(", ");
    let sql = format!(
        "SELECT l.source_id, p.* FROM proxy_source_links l
         JOIN proxies p ON p.id = l.proxy_id
         WHERE l.source_id IN ({src_ph})
         ORDER BY p.id"
    );
    let mut query = sqlx::query_as::<_, ProxyWithSource>(sqlx::AssertSqlSafe(sql.as_str()));
    for id in source_ids {
        query = query.bind(id);
    }
    Ok(query.fetch_all(pool).await?)
}

/// The predicate of a proxy that is still served: linked to a source,
/// and that source enabled. A disabled source is one the operator
/// switched off; its proxies must not keep appearing in the export
/// links, and the counters that describe the lists have to count the
/// same rows. Rides `idx_links_source`, so the check is an index seek
/// per proxy.
const LINKED_TO_ENABLED_SOURCE: &str = "EXISTS (SELECT 1 FROM proxy_source_links l
           JOIN sources s ON s.id = l.source_id
           WHERE l.proxy_id = p.id AND s.enabled = 1)";

/// At most `limit` currently-`alive` proxies still linked to at least
/// one *enabled* source, in stable id order, the backing query of the
/// public «all alive» export link. Fingerprints are unique in the table,
/// so the set is already deduplicated.
///
/// The cap is applied in SQL, not by truncating a full read: the export
/// serializes and ships every row it gets, so an unbounded `fetch_all`
/// here is an unbounded response body on a public, cacheable link.
/// `limit` is a `u32` clamped into `1..=i64::MAX`, so a caller cannot
/// turn it into a negative `LIMIT` (SQLite reads a negative limit as
/// "no limit") or overflow the bind.
///
/// Truncation takes the lowest ids (oldest rows), stable across requests
/// but *not* health-ordered: a caller that needs a different slice (the
/// admin browser, which pages) must not use this function. Strictly
/// `alive`: `ready` rows are served by [`list_ready`] and the ready
/// export link.
pub async fn list_alive(pool: &DbPool, limit: u32) -> crate::Result<Vec<ProxyRow>> {
    let sql = format!(
        "SELECT p.* FROM proxies p
         WHERE p.status = 'alive'
           AND {LINKED_TO_ENABLED_SOURCE}
         ORDER BY p.id
         LIMIT ?"
    );
    let rows: Vec<ProxyRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(i64::from(limit).clamp(1, i64::MAX))
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// At most `limit` currently-`ready` proxies (tunnel-verified tier) still
/// linked to at least one *enabled* source, the verified twin of
/// [`list_alive`], backing the public `/export/ready/{token}` link. Same
/// cap semantics, same stable truncation.
pub async fn list_ready(pool: &DbPool, limit: u32) -> crate::Result<Vec<ProxyRow>> {
    let sql = format!(
        "SELECT p.* FROM proxies p
         WHERE p.status = 'ready'
           AND {LINKED_TO_ENABLED_SOURCE}
         ORDER BY p.id
         LIMIT ?"
    );
    let rows: Vec<ProxyRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(i64::from(limit).clamp(1, i64::MAX))
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// Number of proxies [`list_alive`] would return (admin screen badge).
pub async fn count_alive(pool: &DbPool) -> crate::Result<i64> {
    let sql = format!(
        "SELECT COUNT(*) FROM proxies p
         WHERE p.status = 'alive'
           AND {LINKED_TO_ENABLED_SOURCE}"
    );
    let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()))
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Number of proxies [`list_ready`] would return (admin screen badge).
pub async fn count_ready(pool: &DbPool) -> crate::Result<i64> {
    let sql = format!(
        "SELECT COUNT(*) FROM proxies p
         WHERE p.status = 'ready'
           AND {LINKED_TO_ENABLED_SOURCE}"
    );
    let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()))
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// The lifecycle fields every pristine reset clears, shared verbatim by
/// [`reset_status`] and the `revive_*` statements so a new lifecycle
/// column cannot be reset in one path and missed in another (the miss is
/// what strands a row in no probe lane: a stale `last_t2_failed_at`
/// suppresses T1 and only a later T2 success lifts it, see
/// [`revive_removed_never_checked`]). Each statement adds the pieces it
/// owns around this core (`status`, `removed_at`, the `updated_at = ?`
/// stamp); `status` is deliberately absent, the frozen-`unknown` release
/// arm of [`revive_removed_never_checked`] must not retouch it.
const RESET_SET: &str = "fail_count = 0,
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             last_t2_failed_at = NULL";

/// Manual "re-check as new" action from the admin panel: reset the
/// lifecycle to a pristine `unknown` (fail counter and every quarantine /
/// second-chance / recheck timestamp cleared, `last_t2_failed_at`
/// included: a T2 failure is the only verdict that suppresses T1, and a
/// row that keeps the block is in no lane at all) and hand the id to the
/// priority queue. The probe daemon stays the sole owner of the state
/// machine, this only puts the proxy back at its starting square.
///
/// The reset only runs on a row a probe lane can actually pick up, which
/// is what the `true` return means. A row without a
/// `proxy_source_links` entry is retired, and every lane filters on the
/// link ([`select_t1_candidates`],
/// [`crate::repo::probe::select_queued_checks`],
/// [`select_t2_candidates`]), so resetting it would hand the operator a
/// success toast for a row that then belongs to no lane: not probed, not
/// served, and not revived by the `removed_as_unknown` path either.
/// Worse for a `quarantine` row: the recheck ladder
/// ([`select_due_quarantine`]) is the one lane without a link predicate,
/// so a reset would cancel the last chance that row still had and strand
/// it in `unknown` forever. The unprobeable schemes are refused for the
/// same reason: a `tuic`/`mieru` row is in no lane either (hysteria2 is
/// T1-excluded but is the one scheme T2 offers while still `unknown`). A
/// refused row is left completely untouched and the function reports
/// `false`.
pub async fn reset_status(pool: &DbPool, id: i64) -> crate::Result<bool> {
    let now = crate::models::now_ts();
    let excluded = vec!["?"; T1_EXCLUDED_SCHEMES.len()].join(", ");
    let sql = format!(
        "UPDATE proxies SET
             status = 'unknown',
             {RESET_SET},
             removed_at = NULL,
             updated_at = ?
         WHERE id = ?
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)
           AND (scheme NOT IN ({excluded}) OR scheme = 'hysteria2')"
    );
    // sqlx 0.9 SqlSafeStr: the format! only expands a `?` placeholder
    // list, every value flows through .bind()
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(now)
        .bind(id);
    for scheme in T1_EXCLUDED_SCHEMES {
        query = query.bind(scheme);
    }
    let result = query.execute(pool).await?;
    if result.rows_affected() == 0 {
        return Ok(false);
    }
    super::probe::enqueue_checks(pool, &[id], 1, now).await?;
    Ok(true)
}

/// Opt-in revival (`[ingest].removed_as_unknown`): a `removed` proxy the
/// feed still carries returns to the probe state machine. Every row whose
/// fingerprint is listed, whose status is `removed` and that is still
/// linked to a source resets to the same pristine state the admin "reset
/// status" action leaves, so a later recheck or a source refresh that
/// stops carrying the proxy behaves exactly as if the row had never been
/// removed. Returns the ids of the revived rows, the caller hands them
/// to the priority-probe queue like a fresh insert.
///
/// The link predicate is the point of the revival: the T1 lanes
/// ([`select_t1_candidates`], [`crate::repo::probe::select_queued_checks`])
/// and the T2 sample ([`select_t2_candidates`]) all need a live
/// `proxy_source_links` row, so a link-less row moved back to `unknown`
/// is a row the probe can never look at again — the panel would report
/// it revived and the next reconcile would retire it once more. It runs
/// right after reconciliation re-stamped the links, so the predicate
/// costs nothing there. `last_t2_failed_at` goes with the rest of the
/// lifecycle: a revival is a re-check from scratch, and a row that keeps
/// a stale T2 block is in no lane at all.
pub async fn revive_removed(
    pool: &DbPool,
    fingerprints: &[String],
    now: i64,
) -> crate::Result<Vec<i64>> {
    let mut revived = Vec::new();
    for chunk in fingerprints.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "UPDATE proxies SET
                 status = 'unknown',
                 {RESET_SET},
                 removed_at = NULL,
                 updated_at = ?
             WHERE status = 'removed' AND fingerprint IN ({placeholders})
               AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)
             RETURNING id"
        );
        // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound
        let mut query = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(sql.as_str())).bind(now);
        for fp in chunk {
            query = query.bind(fp);
        }
        let rows: Vec<(i64,)> = query.fetch_all(pool).await?;
        revived.extend(rows.into_iter().map(|(id,)| id));
    }
    Ok(revived)
}

const REVIVE_BATCH_SIZE: i64 = 1_000;

/// How many revived ids one bulk revival hands back for the priority
/// queue: the revival itself touches every matching row, the ids are
/// only the head of that population and the rows beyond the cap wait for
/// the random T1 sample like any other unchecked row. The number is the
/// shared ceiling of `[ingest].refresh_check_limit`
/// ([`crate::config::bounds::REFRESH_CHECK_LIMIT_MAX`]): the hand-off
/// ignores that knob but never exceeds its range.
pub const REVIVED_ID_CAP: usize = crate::config::bounds::REFRESH_CHECK_LIMIT_MAX as usize;

/// The outcome of a bulk revival: how many rows were moved and which of
/// them may be handed to the priority queue.
#[derive(Debug, Default)]
pub struct RevivedRows {
    pub revived: u64,
    /// The ids of the revived rows, at most [`REVIVED_ID_CAP`] of them
    /// (the newest ones).
    pub ids: Vec<i64>,
}

/// One revival batch: at most [`REVIVE_BATCH_SIZE`] rows above `cursor`
/// that match `predicate`, moved by `set_clause`. One bounded `UPDATE`
/// (a CTE picks the batch, `RETURNING id` hands back what changed), each
/// batch its own transaction so the write lock is released between
/// batches.
async fn revive_batch(
    pool: &DbPool,
    set_clause: &str,
    predicate: &str,
    now: i64,
    text: Option<&str>,
    cursor: i64,
) -> crate::Result<Vec<i64>> {
    let sql = format!(
        "WITH batch AS (
             SELECT id FROM proxies
             WHERE {predicate} AND id > ?
             ORDER BY id
             LIMIT {REVIVE_BATCH_SIZE}
         )
         UPDATE proxies SET {set_clause}
         WHERE id IN (SELECT id FROM batch)
         RETURNING id"
    );
    // Binds follow the textual placeholder order: the predicate and the
    // cursor live in the CTE, the `updated_at` stamp in the SET clause
    let mut query = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(sql.as_str()));
    if let Some(value) = text {
        query = query.bind(value);
    }
    let rows = query.bind(cursor).bind(now).fetch_all(pool).await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Revive every row that matches `predicate`, in bounded batches that
/// walk the population in id order, so a revival of a whole country does
/// not hold the write lock for the whole sweep. The ids of the last
/// batches win the cap: the priority queue prefers the freshest rows.
async fn revive_population(
    pool: &DbPool,
    set_clause: &str,
    predicate: &str,
    now: i64,
    text: Option<&str>,
) -> crate::Result<RevivedRows> {
    let mut outcome = RevivedRows::default();
    let mut cursor = 0i64;
    loop {
        let batch = revive_batch(pool, set_clause, predicate, now, text, cursor).await?;
        if batch.is_empty() {
            break;
        }
        outcome.revived += batch.len() as u64;
        outcome.ids.extend(batch.iter().copied());
        if outcome.ids.len() > REVIVED_ID_CAP {
            let excess = outcome.ids.len() - REVIVED_ID_CAP;
            outcome.ids.drain(..excess);
        }
        cursor = batch.iter().copied().max().unwrap_or(cursor);
        if (batch.len() as i64) < REVIVE_BATCH_SIZE {
            break;
        }
    }
    Ok(outcome)
}

/// Bulk revival (admin *Revival* panel): bring every `removed` proxy of
/// the given country back to `unknown`, same shape as [`revive_removed`]
/// but keyed on `geo_country` instead of a fingerprint IN-list. Bounded
/// batches, so a whole-country revival does not hold the write lock for
/// the whole sweep. Returns how many rows were revived and the ids the
/// caller may hand to the priority-probe queue; a row with no source
/// link is left `removed` (see [`revive_removed`]).
pub async fn revive_removed_by_country(
    pool: &DbPool,
    code: &str,
    now: i64,
) -> crate::Result<RevivedRows> {
    let set_clause = format!("status = 'unknown', {RESET_SET}, removed_at = NULL, updated_at = ?");
    let predicate = "status = 'removed' AND geo_country = ?
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)";
    revive_population(pool, &set_clause, predicate, now, Some(code)).await
}

/// Bulk revival (admin *Revival* panel): bring every `removed` proxy of
/// the given autonomous system back to `unknown`. `asn` is the AS number
/// in either spelling, `24940` or `AS24940`; it is normalised to the
/// canonical `AS{n}` text the `geo_asn` column stores
/// ([`crate::geo::canonical_asn`]), so both spellings reach the same
/// rows. An input that is not an AS number revives nothing; link-less
/// rows stay `removed` (see [`revive_removed`]).
pub async fn revive_removed_by_asn(
    pool: &DbPool,
    asn: &str,
    now: i64,
) -> crate::Result<RevivedRows> {
    let Some(canonical) = crate::geo::canonical_asn(asn) else {
        return Ok(RevivedRows::default());
    };
    let set_clause = format!("status = 'unknown', {RESET_SET}, removed_at = NULL, updated_at = ?");
    let predicate = "status = 'removed' AND geo_asn = ?
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)";
    revive_population(pool, &set_clause, predicate, now, Some(&canonical)).await
}

/// Bulk revival (admin *Revival* panel): every proxy that never received
/// a probe verdict, in either of the two states such a row can be stuck
/// in, comes back into the rotation.
///
/// The predicate is `last_checked_at IS NULL`, the row's own record of
/// having been checked, which no retention pass ever rotates away. The
/// journal (`probe_results`) cannot answer the question, because the
/// journal *does* rotate: a proxy checked once and then dropped from the
/// preserved history looked "never checked" and was revived on every
/// pass, undoing a verdict the probe had already given.
///
/// 1. `removed` rows the cleanup retired without ever being probed go
///    back to `unknown`.
/// 2. `unknown` rows frozen by the T2 block (`last_t2_failed_at` set) are
///    released. Such a row is in no probe lane at all: the queue drain
///    and the T1 sample both require `last_t2_failed_at IS NULL`, and the
///    T2 selector only offers `alive`/`ready`, so nothing can ever clear
///    the flag. Clearing it is what actually matters here.
///
/// Link-less rows are left alone in both halves (see [`revive_removed`]).
pub async fn revive_removed_never_checked(pool: &DbPool, now: i64) -> crate::Result<RevivedRows> {
    let revive_set = format!("status = 'unknown', {RESET_SET}, removed_at = NULL, updated_at = ?");
    let removed_predicate = "status = 'removed'
           AND last_checked_at IS NULL
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)";
    let mut outcome = revive_population(pool, &revive_set, removed_predicate, now, None).await?;

    // The frozen-`unknown` arm keeps the row's status (and its absent
    // `removed_at`) and takes only the shared reset core
    let release_set = format!("{RESET_SET}, updated_at = ?");
    let frozen_predicate = "status = 'unknown'
           AND last_t2_failed_at IS NOT NULL
           AND last_checked_at IS NULL
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)";
    let released = revive_population(pool, &release_set, frozen_predicate, now, None).await?;
    outcome.revived += released.revived;
    outcome.ids.extend(released.ids);
    Ok(outcome)
}

/// Bulk revival (admin *Revival* panel): bring every `quarantine` proxy
/// back to `unknown`, skipping the recheck ladder. Symmetric to
/// [`quarantine_to_removed`]; `removed_at` stays NULL because quarantined
/// rows never had one, `last_t2_failed_at` is cleared like every
/// revival. Returns how many rows were revived and the ids for
/// enqueueing; link-less rows stay `quarantine` (see [`revive_removed`]:
/// the ladder it was on is exactly the one this call drops).
pub async fn revive_quarantine(pool: &DbPool, now: i64) -> crate::Result<RevivedRows> {
    let set_clause = format!("status = 'unknown', {RESET_SET}, updated_at = ?");
    let predicate = "status = 'quarantine'
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)";
    revive_population(pool, &set_clause, predicate, now, None).await
}

/// Sources currently linking a proxy, with the last-seen timestamp.
pub async fn links_for_proxy(pool: &DbPool, proxy_id: i64) -> crate::Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT l.source_id, l.seen_at FROM proxy_source_links l
         WHERE l.proxy_id = ? ORDER BY l.seen_at DESC",
    )
    .bind(proxy_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Per-source proxy counts grouped by status (source card aggregates).
pub async fn count_by_status_for_source(
    pool: &DbPool,
    source_id: &str,
) -> crate::Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT p.status, COUNT(*) FROM proxies p
         JOIN proxy_source_links l ON l.proxy_id = p.id
         WHERE l.source_id = ?
         GROUP BY p.status ORDER BY p.status",
    )
    .bind(source_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// What the orphan sweep did with the rows that lost their last source
/// link.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrphanSweep {
    pub retired: u64,
    /// Rows the sweep left link-less because their status is protected:
    /// the "detached" rows of the admin panel, in no probe lane until the
    /// operator cleans them up (see [`remove_detached`]).
    pub protected: u64,
}

/// Mark the proxies of one source that lost their last link as
/// `removed` (deleting a source is soft: `removed` is terminal for
/// reconciliation, the ways back are the admin "reset status" action or
/// purge removed followed by a re-insert). Returns how many proxies were
/// retired and how many were left alone.
///
/// The sweep is restricted to the proxies the source was linked to, so
/// deleting one source does not walk the whole table; a proxy still
/// linked to another source keeps its link and stays untouched. The rows
/// are selected while the source still exists, because deleting it
/// cascades its links away: the caller runs this first and deletes the
/// source afterwards.
///
/// `protected_statuses` lists the lifecycle states the caller does not
/// want to retire just because their last source link vanished. The
/// admin source-delete handler passes `["ready", "unknown"]` when
/// `[ingest].drop_gate = false`: a `ready` proxy was tunnel-verified by
/// hand and an `unknown` one has not yet had its first verdict, so
/// retiring either from a single click would be too aggressive. Pass an
/// empty slice to retire every orphan (the strict policy).
pub async fn mark_source_orphans_removed(
    pool: &DbPool,
    source_id: &str,
    protected_statuses: &[&str],
) -> crate::Result<OrphanSweep> {
    // The protected-status list only widens the WHERE clause when
    // non-empty (the no-protection path keeps the original
    // single-statement shape); it is expanded into a parameterised
    // `IN (?, ?, …)` list, never concatenated into SQL
    //
    // The link subquery names the source's own proxies and the NOT EXISTS
    // excludes the source's own link, so a proxy that another source
    // still feeds is not an orphan
    let mut sql = format!(
        "UPDATE proxies SET {RETIRE_SET}
         WHERE status != 'removed'
           AND id IN (SELECT proxy_id FROM proxy_source_links WHERE source_id = ?)
           AND NOT EXISTS (SELECT 1 FROM proxy_source_links l
                           WHERE l.proxy_id = proxies.id AND l.source_id != ?)"
    );
    if !protected_statuses.is_empty() {
        let placeholders = vec!["?"; protected_statuses.len()].join(", ");
        sql.push_str(&format!(" AND status NOT IN ({placeholders})"));
    }
    let now = crate::models::now_ts();
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(now)
        .bind(now)
        .bind(source_id)
        .bind(source_id);
    for status in protected_statuses {
        query = query.bind(*status);
    }
    let retired = query.execute(pool).await?.rows_affected();

    // The rows the sweep left behind, counted not hidden: a link-less row
    // is in no probe lane, so the operator has to know that it is there
    let mut protected_sql = String::from(
        "SELECT COUNT(*) FROM proxies
         WHERE status != 'removed'
           AND id IN (SELECT proxy_id FROM proxy_source_links WHERE source_id = ?)
           AND NOT EXISTS (SELECT 1 FROM proxy_source_links l
                           WHERE l.proxy_id = proxies.id AND l.source_id != ?)",
    );
    if !protected_statuses.is_empty() {
        let placeholders = vec!["?"; protected_statuses.len()].join(", ");
        protected_sql.push_str(&format!(" AND status IN ({placeholders})"));
    }
    let mut count_query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(protected_sql.as_str()))
        .bind(source_id)
        .bind(source_id);
    for status in protected_statuses {
        count_query = count_query.bind(*status);
    }
    let protected = count_query.fetch_one(pool).await?.max(0) as u64;
    Ok(OrphanSweep { retired, protected })
}

/// Number of proxies without any source link ("detached"): no probe lane
/// can reach them, so the operator can see how much of the table no feed
/// reaches any more.
pub async fn count_detached(pool: &DbPool) -> crate::Result<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM proxies
         WHERE status != 'removed'
           AND id NOT IN (SELECT proxy_id FROM proxy_source_links)",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Move every proxy without a source link into `removed` (admin
/// «cleanup» panel). The link-less rows the source-delete path left
/// behind on purpose (see [`mark_source_orphans_removed`]) have no probe
/// lane and no feed that could bring them back, so this is the path that
/// ends them.
pub async fn remove_detached(pool: &DbPool) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE proxies SET {RETIRE_SET}
         WHERE status != 'removed'
           AND id NOT IN (SELECT proxy_id FROM proxy_source_links)"
    )))
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

const PURGE_BATCH_SIZE: i64 = 1000;

/// Physically delete every `removed` proxy and, via `ON DELETE CASCADE`,
/// its source links and probe/speed history («purge removed»). The only
/// hard delete in the system, guarded by a confirmation dialog in the
/// admin UI; the bulk cleanup actions above it only transition rows
/// *into* `removed`. The unfiltered half of [`purge_removed_before`]:
/// the admin button wipes the whole `removed` tier, the retention sweep
/// only the rows past its TTL window.
pub async fn purge_removed(pool: &DbPool) -> crate::Result<u64> {
    purge_removed_before(pool, None).await
}

/// The `removed`-tier delete of [`purge_removed`] with no time filter.
const PURGE_ALL_SQL: &str = "DELETE FROM proxies WHERE id IN (
     SELECT id FROM proxies WHERE status = 'removed'
     ORDER BY id LIMIT ?
 )";

/// The TTL delete of [`purge_removed_before`]: only rows stamped
/// `removed_at <= ?`; a hypothetical `removed` row without the stamp can
/// only reach the unfiltered purge, `NULL` never compares true.
const PURGE_STALE_SQL: &str = "DELETE FROM proxies WHERE id IN (
     SELECT id FROM proxies WHERE status = 'removed' AND removed_at <= ?
     ORDER BY id LIMIT ?
 )";

/// Physically delete `removed` proxies in bounded batches, one
/// transaction each: `None` takes every row in the tier (the admin
/// «purge removed» button, [`purge_removed`]), `Some(cutoff)` only the
/// ones stamped `removed_at <= cutoff` (the retention sweep's «wipe
/// removed proxies older than N days»). Bounded because a single
/// `DELETE` over the whole population holds the write lock until the
/// last cascade is done, long enough to time out the probe daemon's own
/// writes; the batch commits release the lock and the pause between them
/// lets the other writer in.
pub async fn purge_removed_before(pool: &DbPool, before: Option<i64>) -> crate::Result<u64> {
    super::purge_batched(
        pool,
        match before {
            Some(_) => PURGE_STALE_SQL,
            None => PURGE_ALL_SQL,
        },
        before,
        PURGE_BATCH_SIZE,
    )
    .await
}

// Bulk cleanup actions: one-click ways to move whole groups of proxies
// into `removed`. Status transitions, never hard deletes, so every action
// stays reversible via the per-proxy «reset status» until purged.

/// Move every `quarantine` proxy into `removed` (admin «cleanup» panel):
/// a bulk shortcut past the recheck ladder for proxies the admin has
/// already given up on. Returns how many rows were affected.
pub async fn quarantine_to_removed(pool: &DbPool) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE proxies SET {RETIRE_SET}
         WHERE status = 'quarantine'"
    )))
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Move every `alive` or `ready` proxy with no resolved country into
/// `removed` (admin «cleanup» panel). `geo_country IS NULL` means the
/// country was never resolved, failed lookups keep NULL rather than
/// writing an empty string, so this predicate catches exactly the
/// never-resolved rows.
pub async fn remove_alive_without_country(pool: &DbPool) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE proxies SET {RETIRE_SET}
         WHERE status IN ('alive', 'ready') AND geo_country IS NULL"
    )))
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Move every `alive` or `ready` proxy of the given autonomous system
/// into `removed` (admin «cleanup» panel). `asn` is the AS number in
/// either spelling, `12345` or `AS12345`, normalised to the canonical
/// `AS{n}` text ([`crate::geo::canonical_asn`]); an input that is not an
/// AS number removes nothing.
pub async fn remove_alive_by_asn(pool: &DbPool, asn: &str) -> crate::Result<u64> {
    let Some(canonical) = crate::geo::canonical_asn(asn) else {
        return Ok(0);
    };
    let now = crate::models::now_ts();
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE proxies SET {RETIRE_SET}
         WHERE status IN ('alive', 'ready') AND geo_asn = ?"
    )))
    .bind(now)
    .bind(now)
    .bind(canonical)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Move every `alive` or `ready` proxy of the given country into
/// `removed` (admin «cleanup» panel). `code` is an ISO-3166-1 alpha-2
/// code, e.g. `"DE"`.
pub async fn remove_alive_by_country(pool: &DbPool, code: &str) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE proxies SET {RETIRE_SET}
         WHERE status IN ('alive', 'ready') AND geo_country = ?"
    )))
    .bind(now)
    .bind(now)
    .bind(code)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Move every `unknown` proxy of an unprobeable scheme into `removed`
/// (admin «cleanup» panel). tuic/mieru cannot be checked at all, so such
/// rows sit in `unknown` forever unless the admin retires them; probeable
/// schemes are untouched, their `unknown` rows are simply not yet
/// checked.
pub async fn remove_unprobeable_unknown(pool: &DbPool) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE proxies SET {RETIRE_SET}
         WHERE status = 'unknown' AND scheme IN ('tuic', 'mieru')"
    )))
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// Probe state machine: the probe daemon is the sole driver; every
// transition is a single atomic UPDATE so a crash between "check finished"
// and "state written" cannot corrupt the lifecycle. All scheduling
// timestamps live in the DB, which makes the daemon restart-safe.

// The quarantine schedule is a generic ladder: step 0 is the second
// chance inside the `[24h, 48h)` window after quarantining, steps
// `1..=N` are the consecutive rechecks whose delays come from
// `[probe] recheck_delays_secs` (default 15m / 30m / 1h). The failed step
// number travels in `ladder_step`, `ladder_at` holds the moment the next
// check fires; failing step `k` schedules `delays[k]`, or, past the end
// of the configured delays, removes the proxy.

/// Minimal row needed to run a T1 connectivity check.
#[derive(Debug, Clone, FromRow)]
pub struct T1Candidate {
    pub id: i64,
    pub scheme: String,
    pub host: String,
    pub port: i64,
    /// Recognized parameters as JSON text (used to decide TCP vs TLS).
    pub params: Option<String>,
}

impl T1Candidate {
    /// The entry the stored columns describe: the probe needs the
    /// parameters to answer TCP vs TLS and the TLS handshake name, from
    /// the same set the ingest parsed.
    pub fn to_entry(&self) -> crate::Result<ProxyEntry> {
        stored_entry(&self.scheme, &self.host, self.port, self.params.as_deref())
    }
}

/// Quarantined proxy whose next scheduled check has come due.
#[derive(Debug, Clone, FromRow)]
pub struct DueQuarantine {
    pub id: i64,
    pub scheme: String,
    pub host: String,
    pub port: i64,
    pub params: Option<String>,
    /// The ladder step this row is waiting on (0 = second chance).
    pub ladder_step: i64,
}

impl DueQuarantine {
    /// The entry the stored columns describe; see [`T1Candidate::to_entry`].
    pub fn to_entry(&self) -> crate::Result<ProxyEntry> {
        stored_entry(&self.scheme, &self.host, self.port, self.params.as_deref())
    }
}

/// The entry a stored proxy row describes, rebuilt from the columns a
/// probe candidate carries: the parameters come back from their JSON
/// projection, credential and raw line stay empty (not part of a
/// connectivity check).
fn stored_entry(
    scheme: &str,
    host: &str,
    port: i64,
    params: Option<&str>,
) -> crate::Result<ProxyEntry> {
    let list = match params {
        Some(text) => stored_params(text, true)?,
        None => Vec::new(),
    };
    Ok(ProxyEntry {
        scheme: scheme.parse::<Scheme>()?,
        name: String::new(),
        host: host.to_string(),
        port: u16::try_from(port)
            .map_err(|_| crate::Error::Parse(format!("port out of range: {port}")))?,
        credential: String::new(),
        params: list,
        raw_path: String::new(),
        raw_line: String::new(),
        canonical: None,
    })
}

/// The parameters a stored params column holds, as an ordered list: the
/// column is a JSON object, a non-string value is stored as its textual
/// form.
fn stored_params(text: &str, known: bool) -> crate::Result<Vec<Param>> {
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(text)
        .map_err(|e| crate::Error::Parse(format!("corrupt proxy params JSON: {e}")))?;
    Ok(map
        .into_iter()
        .map(|(key, value)| Param {
            key,
            value: value.as_str().unwrap_or_default().to_string(),
            known,
            bare: false,
        })
        .collect())
}

/// Result of applying a check outcome to the lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Still `unknown`/`alive`; the fail counter was bumped (or reset).
    Unchanged,
    /// The consecutive-failure limit was reached: now `quarantine` with a
    /// second chance scheduled.
    Quarantined,
    /// The success write landed: the row is `alive` or `ready` now. Every
    /// successful check reports this, so the name is deliberately not
    /// "revived": a plain `unknown → alive` success is not a revival and
    /// must not be counted as one.
    Succeeded,
    /// The final recheck failed: now `removed`.
    Removed,
}

/// Schemes the T1 connectivity check cannot judge: a TCP/TLS
/// connect to a UDP-only port would quarantine healthy proxies. Shared by
/// the random sample and the priority queue; tuic/mieru are additionally
/// absent from T2 (meow-rs cannot tunnel them).
pub const T1_EXCLUDED_SCHEMES: &[&str] = &["hysteria2", "tuic", "mieru"];

/// The WHERE fragment every T1 lane shares: a fixed status literal of
/// the caller (never request text), T1-probeable scheme
/// ([`T1_EXCLUDED_SCHEMES`]) and still linked to a source. The
/// excluded-scheme placeholders bind the [`T1_EXCLUDED_SCHEMES`] values,
/// in order, wherever the fragment sits in the statement. The
/// T2-suppression guard (`last_t2_failed_at IS NULL`) is deliberately
/// not part of it: the priority enqueue does not apply that guard, the
/// select lanes add it explicitly on top.
pub(crate) fn t1_lane_predicate(statuses: &str) -> String {
    let excluded = vec!["?"; T1_EXCLUDED_SCHEMES.len()].join(", ");
    format!(
        "{statuses}
           AND p.scheme NOT IN ({excluded})
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)"
    )
}

/// Schemes meow-rs can actually tunnel (the T2 allowlist). Mirrors
/// `fumox_core::formats::clash::is_supported`, and the probe filters the
/// batch by it after the SQL: under the recency-priority order a row the
/// selector offered but the engine drops again would sit at the head of
/// the sample forever (starvation).
pub const T2_SCHEMES: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria2",
    "socks5",
    "snell",
    "anytls",
];

/// Schemes whose quarantined rows revive through the T2 tunnel check: a TCP
/// connect to a QUIC port proves nothing. Exactly hysteria2; tuic/mieru keep
/// the T1 recheck ladder.
pub const T2_REVIVAL_SCHEMES: &[&str] = &["hysteria2"];

/// Per-slot size of the bounded candidate window: one draw reads
/// `SAMPLE_WINDOW_FACTOR * limit` eligible rows around a uniformly random
/// id anchor and shuffles that window down to `limit`. The factor is the
/// knob between per-cycle cost and how much of the pool one draw ranges
/// over; 4 keeps the fetch a rounding error next to the checks themselves.
const SAMPLE_WINDOW_FACTOR: u32 = 4;

/// A bind value of the shared bounded-window selector: the lane
/// predicates only ever bind timestamps and scheme names.
enum SelectorBind {
    Int(i64),
    Text(&'static str),
}

/// The id of a row the bounded-window sampler fetched, needed to
/// continue the window *below* the last row it read (the window is a
/// ring segment, the second leg starts where the first one stopped).
trait SampledRow: Send + Unpin {
    fn row_id(&self) -> i64;
}

impl SampledRow for T1Candidate {
    fn row_id(&self) -> i64 {
        self.id
    }
}

impl SampledRow for DueQuarantine {
    fn row_id(&self) -> i64 {
        self.id
    }
}

impl SampledRow for ProxyRow {
    fn row_id(&self) -> i64 {
        self.id
    }
}

/// The anchor of a bounded-window draw: a uniformly drawn id inside the
/// *eligible* rows' own id range, not the table's (a lane that only
/// serves a fraction of the rows must not spend its draw on ids it
/// cannot serve). The random source is a parameter so a test can pin the
/// draw.
fn choose_anchor<R: rand::RngExt>(min_id: i64, max_id: i64, rng: &mut R) -> i64 {
    rng.random_range(min_id..=max_id)
}

/// The Fisher–Yates shuffle of the fetched window, so every row has the
/// same chance to survive the cut. The random source is a parameter so a
/// test can pin the permutation.
fn shuffle_window<T, R: rand::RngExt>(rows: &mut [T], rng: &mut R) {
    use rand::seq::SliceRandom;
    rows.shuffle(rng);
}

/// One leg of a bounded-window draw: up to `window` eligible rows on one
/// side of `anchor` in id order. The id comparison rides the rowid
/// index, so the leg stops after `window` matches without materializing
/// the rest of the pool, the property `ORDER BY RANDOM() LIMIT ?` lacks.
/// The full statement is assembled by the caller (one string per ring
/// leg, the legs differ only in the fixed id-comparison fragment, a
/// literal of this module); this helper only binds and runs what it is
/// given.
async fn fetch_window<T>(
    pool: &DbPool,
    sql: &str,
    binds: &[SelectorBind],
    anchor: i64,
    window: i64,
) -> crate::Result<Vec<T>>
where
    T: for<'r> FromRow<'r, sqlx::sqlite::SqliteRow> + Send + Unpin,
{
    let mut query = sqlx::query_as::<_, T>(sqlx::AssertSqlSafe(sql));
    for bind in binds {
        query = match bind {
            SelectorBind::Int(value) => query.bind(*value),
            SelectorBind::Text(scheme) => query.bind(*scheme),
        };
    }
    Ok(query.bind(anchor).bind(window).fetch_all(pool).await?)
}

/// The eligible pool of a lane: how many rows match its predicate, and
/// the id range they span, in one aggregate pass. The range is the
/// *eligible* one: an anchor drawn over the whole table's id space lands
/// on rows the lane cannot serve, and the rows below the first eligible
/// id are then reachable only from a vanishingly narrow band of anchors.
async fn eligible_pool_bounds(
    pool: &DbPool,
    predicate: &str,
    binds: &[SelectorBind],
) -> crate::Result<(i64, i64, i64)> {
    let sql = format!(
        "SELECT COUNT(*), COALESCE(MIN(p.id), 0), COALESCE(MAX(p.id), 0)
         FROM proxies p
         WHERE {predicate}"
    );
    let mut query = sqlx::query_as::<_, (i64, i64, i64)>(sqlx::AssertSqlSafe(sql.as_str()));
    for bind in binds {
        query = match bind {
            SelectorBind::Int(value) => query.bind(*value),
            SelectorBind::Text(scheme) => query.bind(*scheme),
        };
    }
    let (count, min_id, max_id) = query.fetch_one(pool).await?;
    Ok((count, min_id, max_id))
}

/// Draw `limit` rows at random from a *bounded window* of the eligible
/// pool instead of shuffling the pool itself.
///
/// 1. the eligible pool is counted and its id range measured in one
///    aggregate pass ([`eligible_pool_bounds`]);
/// 2. the anchor is drawn uniformly from that id range, and the window is
///    the `SAMPLE_WINDOW_FACTOR * limit` eligible rows that follow it in
///    **id order, wrapping around the end of the range** (a ring segment,
///    so every eligible row is covered by the same number of anchors);
/// 3. the window is shuffled and cut to `limit`.
///
/// The ring is what makes the draw fair: without the wrap, the lowest ids
/// are covered only by the anchors that sit below them, and the lowest
/// ids are exactly the ones an admin wants re-probed. A pool at or below
/// the window size is fetched whole, which *is* the full-pool shuffle.
/// The marginal per-cycle chance of a row stays `limit / eligible-pool`
/// for an evenly spread pool; what is traded away is independence within
/// a cycle: rows are drawn together with their id neighbours (the
/// keyset-anchor compromise).
async fn select_window_sample<T>(
    pool: &DbPool,
    select_list: &str,
    predicate: &str,
    binds: &[SelectorBind],
    limit: u32,
) -> crate::Result<Vec<T>>
where
    T: for<'r> FromRow<'r, sqlx::sqlite::SqliteRow> + SampledRow,
{
    if limit == 0 {
        return Ok(Vec::new());
    }
    let window = i64::from(limit) * i64::from(SAMPLE_WINDOW_FACTOR);

    let (eligible, min_id, max_id) = eligible_pool_bounds(pool, predicate, binds).await?;
    if eligible == 0 {
        return Ok(Vec::new());
    }

    let mut rng = rand::rng();
    // One full statement per ring leg: both legs read ascending, the
    // second starts *below* the first leg's head; they differ only in the
    // id comparison
    let leg_sql = |comparison: &str| {
        format!(
            "SELECT {select_list}
             FROM proxies p
             WHERE {predicate} AND p.id {comparison} ?
             ORDER BY p.id ASC
             LIMIT ?"
        )
    };
    let mut rows = if eligible <= window {
        // A pool at or below the window is fetched whole: that *is* the
        // full-pool shuffle the windowed draw replaced
        fetch_window::<T>(pool, &leg_sql(">="), binds, min_id, window).await?
    } else {
        let anchor = choose_anchor(min_id, max_id, &mut rng);
        let mut window_rows =
            fetch_window::<T>(pool, &leg_sql(">="), binds, anchor, window).await?;
        // The ring continues at the *bottom* of the id range: the first
        // leg ran out of ids at the top, so the next ring successors are
        // the smallest eligible ids, which keeps the segment contiguous
        // in ring order and the two legs disjoint
        if (window_rows.len() as i64) < window
            && let Some(first) = window_rows.first()
        {
            let short = window - window_rows.len() as i64;
            let lower =
                fetch_window::<T>(pool, &leg_sql("<"), binds, first.row_id(), short).await?;
            window_rows.extend(lower);
        }
        window_rows
    };

    shuffle_window(&mut rows, &mut rng);
    rows.truncate(limit as usize);
    Ok(rows)
}

/// Random sample of probeable proxies for one T1 cycle. Eligible:
/// `unknown` or `alive` (quarantine rows follow their own schedule,
/// `removed` is terminal), still linked to at least one source, not one
/// of the unprobeable schemes ([`T1_EXCLUDED_SCHEMES`]), and not
/// T2-blocked (`last_t2_failed_at IS NULL`, this lane's explicit
/// addition to the shared candidate predicate).
///
/// The sample comes from [`select_window_sample`]: a bounded window of
/// the eligible pool, anchored in the eligible rows' own id range,
/// shuffled down to `limit`.
pub async fn select_t1_candidates(pool: &DbPool, limit: u32) -> crate::Result<Vec<T1Candidate>> {
    let predicate = format!(
        "{} AND p.last_t2_failed_at IS NULL",
        t1_lane_predicate("p.status IN ('unknown', 'alive')")
    );
    let binds: Vec<SelectorBind> = T1_EXCLUDED_SCHEMES
        .iter()
        .map(|scheme| SelectorBind::Text(scheme))
        .collect();
    select_window_sample(
        pool,
        "p.id, p.scheme, p.host, p.port, p.params",
        &predicate,
        &binds,
        limit,
    )
    .await
}

/// Batch for a T2 tunnel check through meow-rs: every `alive` **and
/// `ready`** proxy of a T2-supported scheme (T2 re-verifies the tunnel; a
/// failed T2 must be able to demote `ready`), plus `unknown` hysteria2,
/// which is excluded from T1 by design (a TCP connect to a QUIC port
/// proves nothing) so T2 is its first and only check; a failure counts
/// through the regular `fail_limit`, it does not quarantine straight
/// away.
///
/// The order is **checked longest ago first**: proxies with no T2 attempt
/// yet come first, then the ones whose last T2 check is the oldest, so a
/// proxy cannot sit tunnel-unverified for months in a large pool while
/// its `alive` status rests on T1 connectivity alone. The moment of the
/// last attempt is the denormalised `last_t2_checked_at` stamp on the
/// proxy row (migration 0014), which the journal write path keeps up to
/// date; `idx_proxies_last_t2_checked_at` answers the order without a
/// sort step, and SQLite sorts NULLs first in ascending order, so the
/// never-checked tier comes before everything else. The stamp is
/// permanent while the journal it was derived from is not: a proxy whose
/// history was trimmed by retention keeps its stamp instead of falling
/// back into the never-checked tier.
///
/// The caller drops the rows its T1 lanes already gave a verdict in the
/// same cycle before checking the batch: both lanes charge `fail_count`,
/// so a row covered by both quarantines in half the cycles `fail_limit`
/// promises (see the probe daemon's `run_cycle` hand-off).
pub async fn select_t2_candidates(pool: &DbPool, limit: u32) -> crate::Result<Vec<ProxyRow>> {
    // The allowlist is built from `T2_SCHEMES` so the SQL can never drift
    // from the const the mirror test pins (a hardcoded literal once
    // omitted snell/anytls, silently keeping those rows out of every T2
    // batch)
    let supported = vec!["?"; T2_SCHEMES.len()].join(", ");
    let sql = format!(
        "SELECT p.*
         FROM proxies p
         WHERE (p.status IN ('alive', 'ready') OR (p.status = 'unknown' AND p.scheme = 'hysteria2'))
           AND p.scheme IN ({supported})
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
         ORDER BY p.last_t2_checked_at ASC, p.id ASC
         LIMIT ?",
    );
    let mut query = sqlx::query_as::<_, ProxyRow>(sqlx::AssertSqlSafe(sql.as_str()));
    for scheme in T2_SCHEMES {
        query = query.bind(scheme);
    }
    let rows: Vec<ProxyRow> = query.bind(i64::from(limit)).fetch_all(pool).await?;
    Ok(rows)
}

/// Number of quarantined proxies whose `ladder_at <= now` (i.e. the
/// rows the probe will consider on its very next quarantine pass, before
/// the `sample_size` cap clamps the actual fetch. Used by the
/// `/admin/probe` backlog banner to detect the *due* queue growing
/// faster than the cycle can consume it.
pub async fn count_due_quarantine(pool: &DbPool, now: i64) -> crate::Result<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxies
         WHERE status = 'quarantine'
           AND ladder_at IS NOT NULL
           AND ladder_at <= ?",
    )
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Oldest `quarantined_at` across the whole quarantine pool, or `None`
/// if the pool is empty. Used by the `/admin/probe` backlog banner to
/// flag rows that have been waiting longer than `[probe].queue_stale_days`.
pub async fn oldest_quarantined_at(pool: &DbPool) -> crate::Result<Option<i64>> {
    let row: (Option<i64>,) =
        sqlx::query_as("SELECT MIN(quarantined_at) FROM proxies WHERE status = 'quarantine'")
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}

/// Every `quarantine` row due at `now` (second chance or recheck ladder
/// step): each row carries exactly one `ladder_at` (NULL only while a
/// check is in flight), so a single comparison suffices and the failed
/// step travels in `ladder_step`.
///
/// Rows of the [`T2_REVIVAL_SCHEMES`] schemes are not offered here: their
/// lane is [`select_due_quarantine_t2`], so a due row is never charged by
/// both lanes in one cycle.
///
/// The due rows are drawn through [`select_window_sample`] (bounded
/// id-anchored window, shuffled down to `limit`): the due pool is usually
/// small, but a backlog outpacing the cycle must not push a full-pool
/// random sort into every cycle. `now` is Unix time in seconds
/// ([`crate::models::now_ts()`]), the scale of every `ladder_at` stamp.
pub async fn select_due_quarantine(
    pool: &DbPool,
    now: i64,
    limit: u32,
) -> crate::Result<Vec<DueQuarantine>> {
    let excluded = vec!["?"; T2_REVIVAL_SCHEMES.len()].join(", ");
    let predicate = format!(
        "p.status = 'quarantine'
           AND p.ladder_at IS NOT NULL
           AND p.ladder_at <= ?
           AND p.scheme NOT IN ({excluded})"
    );
    let mut binds = vec![SelectorBind::Int(now)];
    binds.extend(
        T2_REVIVAL_SCHEMES
            .iter()
            .map(|scheme| SelectorBind::Text(scheme)),
    );
    select_window_sample(
        pool,
        "p.id, p.scheme, p.host, p.port, p.params, p.ladder_step",
        &predicate,
        &binds,
        limit,
    )
    .await
}

/// The T2 counterpart of [`select_due_quarantine`]: due rows of the
/// [`T2_REVIVAL_SCHEMES`] schemes, as full rows (the tunnel check needs
/// the credentials and the ladder step [`DueQuarantine`] omits). Drawn
/// through [`select_window_sample`] like its T1-side sibling.
pub async fn select_due_quarantine_t2(
    pool: &DbPool,
    now: i64,
    limit: u32,
) -> crate::Result<Vec<ProxyRow>> {
    let supported = vec!["?"; T2_REVIVAL_SCHEMES.len()].join(", ");
    let predicate = format!(
        "p.status = 'quarantine'
           AND p.ladder_at IS NOT NULL
           AND p.ladder_at <= ?
           AND p.scheme IN ({supported})"
    );
    let mut binds = vec![SelectorBind::Int(now)];
    binds.extend(
        T2_REVIVAL_SCHEMES
            .iter()
            .map(|scheme| SelectorBind::Text(scheme)),
    );
    select_window_sample(pool, "p.*", &predicate, &binds, limit).await
}

/// Apply a successful check: `status_to` picks the tier (a T1 success never
/// demotes `ready`) and is the only thing that lifts `last_t2_failed_at`.
/// `reset_fail_count` follows the T2-priority rule: the caller that saw no
/// T2 failure (see [`crate::repo::probe::last_failed_kind`]) resets it.
/// `status != 'removed'` keeps a removed row terminal.
pub async fn check_succeeded(
    pool: &DbPool,
    id: i64,
    now: i64,
    latency_ms: Option<i64>,
    reset_fail_count: bool,
    status_to: ProxyStatus,
) -> crate::Result<Transition> {
    // Fixed literal per target tier, never a bind of caller text
    let status_expr = match status_to {
        ProxyStatus::Ready => "'ready'",
        _ => "CASE WHEN status = 'ready' THEN 'ready' ELSE 'alive' END",
    };
    let clear_t2_failed = status_to == ProxyStatus::Ready;
    let sql = format!(
        "UPDATE proxies SET
             status = {status_expr},
             fail_count = CASE WHEN ? THEN 0 ELSE fail_count END,
             last_checked_at = ?,
             last_alive_at = ?,
             latency_ms = COALESCE(?, latency_ms),
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             last_t2_failed_at = CASE WHEN ? THEN NULL ELSE last_t2_failed_at END,
             updated_at = ?
         WHERE id = ? AND status != 'removed'"
    );
    let result = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(reset_fail_count)
        .bind(now)
        .bind(now)
        .bind(latency_ms)
        .bind(clear_t2_failed)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(if result.rows_affected() > 0 {
        Transition::Succeeded
    } else {
        Transition::Unchanged
    })
}

/// The trace facts of one proxy, parsed from the Cloudflare
/// `/cdn-cgi/trace` answer. `ip`/`colo`/`loc`/`warp` are the
/// first-class columns the pipeline filters on; everything else the
/// operator asked to keep rides in `extra` as one JSON object (already
/// serialized by the caller — the probe owns the field list).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TraceFacts {
    /// trace `ip=`: the proxy's egress address, IPv4 or IPv6.
    pub ip: Option<String>,
    /// trace `colo=`: the Cloudflare datacenter (IATA code).
    pub colo: Option<String>,
    /// trace `loc=`: the country the egress appears from.
    pub loc: Option<String>,
    /// trace `warp=`: `on` | `off` | `plus`.
    pub warp: Option<String>,
    /// The remaining saved fields as a JSON object string; `None` when
    /// nothing beyond the four columns was requested or answered.
    pub extra: Option<String>,
}

/// Stamp the trace facts of a proxy row (probe-written; the egress GeoIP
/// columns derived from `ip` stay server-owned, the probe has no mmdb).
/// Called after a successful trace fetch through a pinned listener; a
/// failed fetch journals and touches nothing here.
pub async fn trace_succeeded(
    pool: &DbPool,
    id: i64,
    now: i64,
    facts: &TraceFacts,
) -> crate::Result<()> {
    sqlx::query(
        "UPDATE proxies SET
             egress_ip = ?,
             cf_colo = ?,
             cf_loc = ?,
             cf_warp = ?,
             trace_json = ?,
             updated_at = ?
         WHERE id = ?",
    )
    .bind(facts.ip.as_deref())
    .bind(facts.colo.as_deref())
    .bind(facts.loc.as_deref())
    .bind(facts.warp.as_deref())
    .bind(facts.extra.as_deref())
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stamp the last speed measurement on the proxy row (probe-written; the
/// column pair `speed_mbps`/`speed_at` moves together, so the pipeline
/// can tell a stale number from a fresh one). The column existed reserved
/// since 0001; the writer arrived with migration 0022.
pub async fn speed_succeeded(
    pool: &DbPool,
    id: i64,
    now: i64,
    speed_mbps: f64,
) -> crate::Result<()> {
    sqlx::query(
        "UPDATE proxies SET
             speed_mbps = ?,
             speed_at = ?,
             updated_at = ?
         WHERE id = ?",
    )
    .bind(speed_mbps)
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Apply a failed regular check (proxy was `unknown`, `alive` or `ready`).
///
/// `now` is Unix time in seconds ([`crate::models::now_ts()`]). Increments
/// `fail_count`; when the consecutive-failure limit is reached the proxy
/// moves to `quarantine` and its second chance is scheduled at
/// `quarantined_at + min + U(0..spread)`, the `[12h, 16h)` window of the
/// shipped defaults (`[probe] fail_limit` = 3, `[probe]
/// second_chance_min_hours` = 12, `[probe] second_chance_spread_hours` =
/// 4). The jitter is drawn here, in the core, so the moment is fixed in
/// the DB and survives daemon restarts. A `ready` row that fails (below
/// the limit) is demoted to `alive`: the tunnel-verified tier only lasts
/// while the latest T2 outcome is a success.
///
/// `mark_t2_failed` records the moment on `last_t2_failed_at`. Only
/// T2-side failures pass `true`: a T1 failure keeps the field untouched,
/// because a TCP/TLS miss does not mean the tunnel is dead and T1 has to
/// keep retrying on its own schedule.
///
/// The counter is read and written by the same statement, so two
/// overlapping checks of the same row cannot lose an increment, and the
/// write repeats the `status IN ('unknown', 'alive', 'ready')` guard, so
/// it cannot resurrect a row that left the eligible statuses in between.
/// The returned [`Transition`] reports what was actually written.
pub async fn check_failed(
    pool: &DbPool,
    id: i64,
    now: i64,
    fail_limit: u32,
    second_chance_min_secs: i64,
    second_chance_spread_secs: i64,
    mark_t2_failed: bool,
) -> crate::Result<Transition> {
    let mut transitions = check_failed_batch(
        pool,
        &[id],
        now,
        fail_limit,
        second_chance_min_secs,
        second_chance_spread_secs,
        mark_t2_failed,
    )
    .await?;
    Ok(transitions
        .pop()
        .map(|(_, transition)| transition)
        .unwrap_or(Transition::Unchanged))
}

/// Apply the fail ladder to a batch of rows in one statement: one lock
/// and one commit for the whole batch, and the `CASE` expressions read
/// each row's own `fail_count`, so no counter can be read stale. The
/// per-row semantics are unchanged (the write repeats the
/// `status IN ('unknown', 'alive', 'ready')` guard, and the returned
/// transitions report what was actually written; a row that vanished or
/// left the eligible statuses is not in the list).
///
/// The jitter of the second chance is drawn once for the batch, not once
/// per row, because the statement computes the ladder itself and the
/// spread has to be a bound value: the rows of one batch share their
/// second-chance window.
pub async fn check_failed_batch(
    pool: &DbPool,
    ids: &[i64],
    now: i64,
    fail_limit: u32,
    second_chance_min_secs: i64,
    second_chance_spread_secs: i64,
    mark_t2_failed: bool,
) -> crate::Result<Vec<(i64, Transition)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    // rand 0.10: `random_range` moved from `Rng` to `RngExt`
    use rand::RngExt;

    let jitter = if second_chance_spread_secs > 0 {
        rand::rng().random_range(0..second_chance_spread_secs)
    } else {
        0
    };
    let second_chance_at = now + second_chance_min_secs + jitter;

    // The whole batch is one statement: the ladder is a CASE expression
    // over the row's own `fail_count`, so no statement in between can
    // interleave, and the write repeats the status guard so a row that
    // left the eligible statuses is left alone. Every SET right-hand side
    // reads the old row (SQL semantics), so `fail_count + 1` is the
    // post-failure counter in all of them. `RETURNING id, status` hands
    // back the new status of every touched row, which is how the
    // quarantine decisions are read back
    let mut transitions = Vec::new();
    for chunk in ids.chunks(100) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "UPDATE proxies SET
                 status = CASE
                              WHEN fail_count + 1 >= ? THEN 'quarantine'
                              WHEN status = 'ready' THEN 'alive'
                              ELSE status END,
                 fail_count = fail_count + 1,
                 last_checked_at = ?,
                 quarantined_at = CASE WHEN fail_count + 1 >= ? THEN ? ELSE quarantined_at END,
                 ladder_at = CASE WHEN fail_count + 1 >= ? THEN ? ELSE ladder_at END,
                 ladder_step = CASE WHEN fail_count + 1 >= ? THEN 0 ELSE ladder_step END,
                 last_t2_failed_at = CASE WHEN ? THEN ? ELSE last_t2_failed_at END,
                 updated_at = ?
             WHERE id IN ({placeholders}) AND status IN ('unknown', 'alive', 'ready')
             RETURNING id, status"
        );
        // The binds follow the textual placeholder order: the ladder's
        // limit and the second-chance stamp first, the T2 flag and the
        // timestamps after them, the ids last
        let mut query = sqlx::query_as::<_, (i64, String)>(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(i64::from(fail_limit))
            .bind(now)
            .bind(i64::from(fail_limit))
            .bind(now)
            .bind(i64::from(fail_limit))
            .bind(second_chance_at)
            .bind(i64::from(fail_limit))
            .bind(mark_t2_failed)
            .bind(now)
            .bind(now);
        for id in chunk {
            query = query.bind(id);
        }
        for (id, status) in query.fetch_all(pool).await? {
            transitions.push((
                id,
                if status == "quarantine" {
                    Transition::Quarantined
                } else {
                    Transition::Unchanged
                },
            ));
        }
    }
    Ok(transitions)
}

/// Record a T2 attempt that never happened because the tunnel engine
/// (meow-rs) was down: a ping, config-reload or mid-batch failure, a
/// fault of *our* sidecar rather than a verdict about the proxy. It
/// keeps the two effects a T2 failure legitimately owns, the
/// `last_t2_failed_at` stamp (a T2 verdict is outstanding, so T1 stays
/// suppressed until a real T2 runs, [`check_succeeded`] is the only
/// lifter) and the `ready` → `alive` demote, and deliberately does
/// **not** touch `fail_count` and never quarantines: the shipped
/// `[probe] fail_limit` of 3 would otherwise quarantine a fully healthy
/// proxy after three outage cycles, dropping it out of both T2 selectors
/// and out of `/export/alive` for a fault it did not cause. The outage
/// itself is still visible: the probe journals the attempt, backs the
/// engine off and logs the batch (see the probe's `journal_engine_fault`).
///
/// The status guard is the same one [`check_failed`] uses, a
/// `quarantine`/`removed` row keeps its own schedule. Returns whether
/// the row was in a regular-check state and got stamped, the "report
/// what was actually written" contract of [`check_failed`].
pub async fn check_engine_unavailable(pool: &DbPool, id: i64, now: i64) -> crate::Result<bool> {
    let written = sqlx::query(
        "UPDATE proxies SET
             status = CASE WHEN status = 'ready' THEN 'alive' ELSE status END,
             last_checked_at = ?,
             last_t2_failed_at = ?,
             updated_at = ?
         WHERE id = ? AND status IN ('unknown', 'alive', 'ready')",
    )
    .bind(now)
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(written > 0)
}

/// Stamp a batch of rows as unverified by the engine, in one
/// transaction, instead of one statement per row (an engine outage
/// stamps every due row of the batch).
pub async fn check_engine_unavailable_batch(
    pool: &DbPool,
    ids: &[i64],
    now: i64,
) -> crate::Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    let mut written = 0u64;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for chunk in ids.chunks(100) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "UPDATE proxies SET
                 status = CASE WHEN status = 'ready' THEN 'alive' ELSE status END,
                 last_checked_at = ?,
                 last_t2_failed_at = ?,
                 updated_at = ?
             WHERE id IN ({placeholders}) AND status IN ('unknown', 'alive', 'ready')"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(now)
            .bind(now)
            .bind(now);
        for id in chunk {
            query = query.bind(id);
        }
        written += query.execute(&mut *tx).await?.rows_affected();
    }
    tx.commit().await?;
    Ok(written)
}

/// Apply a failed quarantine check (second chance or a recheck ladder
/// step). The ladder is always scheduled relative to the moment of the
/// failure that triggered it: failing step `k` schedules the next check
/// at `now + delays[k]`, step 0 is the second chance, steps `1..` are
/// the rechecks; failing the last configured step (or an empty `delays`
/// on the second chance) removes the proxy. Delays come from
/// `[probe] recheck_delays_secs` (default 15m / 30m / 1h).
pub async fn quarantine_check_failed(
    pool: &DbPool,
    id: i64,
    now: i64,
    step: i64,
    delays: &[i64],
) -> crate::Result<Transition> {
    let mut transitions = quarantine_check_failed_batch(pool, &[(id, now, step)], delays).await?;
    Ok(transitions
        .pop()
        .map(|(_, transition)| transition)
        .unwrap_or(Transition::Unchanged))
}

/// Advance the quarantine ladder of a batch of rows in one transaction.
/// Each entry is `(id, now, step)`: the row, the moment of the failure
/// and the ladder step it failed at.
pub async fn quarantine_check_failed_batch(
    pool: &DbPool,
    rows: &[(i64, i64, i64)],
    delays: &[i64],
) -> crate::Result<Vec<(i64, Transition)>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut transitions = Vec::with_capacity(rows.len());
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for (id, now, step) in rows {
        let next_delay = delays.get((*step).max(0) as usize).copied();
        let (transition, next_at) = match next_delay {
            Some(delay) => (Transition::Unchanged, now + delay.max(0)),
            None => (Transition::Removed, 0),
        };

        if transition == Transition::Removed {
            let affected = sqlx::query(
                "UPDATE proxies SET
                     status = 'removed',
                     last_checked_at = ?,
                     removed_at = ?,
                     ladder_at = NULL,
                     ladder_step = 0,
                     updated_at = ?
                 WHERE id = ? AND status = 'quarantine'",
            )
            .bind(now)
            .bind(now)
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            // The `status = 'quarantine'` guard: a row that left
            // quarantine matched nothing, and reporting `Removed` would
            // claim a retirement that did not happen (the "report what
            // was actually written" contract [`check_failed`] keeps)
            transitions.push((
                *id,
                if affected > 0 {
                    transition
                } else {
                    Transition::Unchanged
                },
            ));
            continue;
        }

        sqlx::query(
            "UPDATE proxies SET
                 last_checked_at = ?,
                 ladder_at = ?,
                 ladder_step = ?,
                 updated_at = ?
             WHERE id = ? AND status = 'quarantine'",
        )
        .bind(now)
        .bind(next_at)
        .bind(step + 1)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        transitions.push((*id, transition));
    }
    tx.commit().await?;
    Ok(transitions)
}

/// What a fingerprint recompute changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RefingerprintStats {
    pub rewritten: usize,
    /// Rows that described a node another row already described and were
    /// merged into it.
    pub merged: usize,
}

/// The `meta` key that records which fingerprint version the stored rows
/// carry. The recompute runs when it differs from the current one.
pub const FINGERPRINT_VERSION_KEY: &str = "fingerprint_version";

const REFINGERPRINT_BATCH: i64 = 500;

/// Recompute the stored fingerprints after a change of the canonical
/// form. The fingerprint version is part of the pre-image, so a change
/// changes every key: rows written before the change keep keys the
/// ingest no longer produces, and the same node can live in two rows.
///
/// Every row is recomputed from its stored fields; two rows that now
/// describe the same node are merged: the one with the better lifecycle
/// status survives, takes over the links, the state it lacks and the
/// probe history of the other, and the other is deleted, so the node
/// keeps its status, its latency and its history instead of starting
/// over at `unknown`.
///
/// Bounded batches, each in its own short transaction, so the write lock
/// is never held over the whole table. Idempotent: a row whose key
/// already matches its recomputed one is left alone.
pub async fn refingerprint(pool: &DbPool) -> crate::Result<RefingerprintStats> {
    let mut stats = RefingerprintStats::default();
    let mut cursor = 0i64;
    loop {
        let rows = list_for_refingerprint(pool, cursor, REFINGERPRINT_BATCH).await?;
        if rows.is_empty() {
            break;
        }
        cursor = rows.last().map(|row| row.id).unwrap_or(cursor);
        recompute_batch(pool, &rows, &mut stats).await?;
        if (rows.len() as i64) < REFINGERPRINT_BATCH {
            break;
        }
    }
    Ok(stats)
}

/// Bring the stored fingerprints up to the current version: the
/// recompute runs only when the stored rows carry another version. The
/// marker in `meta` names the version the rows were written with, so the
/// pass runs once per version change and not on every start; idempotent,
/// so a start that dies in the middle runs it again on the next start.
pub async fn ensure_fingerprint_version(
    pool: &DbPool,
) -> crate::Result<Option<RefingerprintStats>> {
    let stored = crate::repo::meta_get(pool, FINGERPRINT_VERSION_KEY).await?;
    if stored.as_deref() == Some(crate::fingerprint::FINGERPRINT_VERSION) {
        return Ok(None);
    }
    let stats = refingerprint(pool).await?;
    crate::repo::meta_set(
        pool,
        FINGERPRINT_VERSION_KEY,
        crate::fingerprint::FINGERPRINT_VERSION,
    )
    .await?;
    Ok(Some(stats))
}

/// The rows a recompute pass still has to walk, oldest id first.
async fn list_for_refingerprint(
    pool: &DbPool,
    after_id: i64,
    limit: i64,
) -> crate::Result<Vec<ProxyRow>> {
    let sql = "SELECT * FROM proxies WHERE id > ? ORDER BY id LIMIT ?";
    let rows = sqlx::query_as::<_, ProxyRow>(sql)
        .bind(after_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// Recompute one batch of rows and write the new keys.
async fn recompute_batch(
    pool: &DbPool,
    rows: &[ProxyRow],
    stats: &mut RefingerprintStats,
) -> crate::Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    for row in rows {
        let entry = match row.to_entry() {
            Ok(entry) => entry,
            Err(err) => {
                // A row whose stored fields do not parse cannot be
                // recomputed; its key stays as it is
                tracing::warn!(
                    proxy = row.id,
                    error = %err,
                    "fingerprint recompute: skipping a row that does not parse"
                );
                continue;
            }
        };
        let fingerprint = entry.fingerprint();
        if fingerprint == row.fingerprint {
            continue;
        }
        // The row that already carries the new key, if any: the ingest
        // may have created it after the upgrade
        let clash: Option<(i64, String, Option<i64>)> = sqlx::query_as(
            "SELECT id, status, last_alive_at FROM proxies WHERE fingerprint = ? AND id <> ?",
        )
        .bind(&fingerprint)
        .bind(row.id)
        .fetch_optional(&mut *tx)
        .await?;
        match clash {
            None => {
                sqlx::query("UPDATE proxies SET fingerprint = ? WHERE id = ?")
                    .bind(&fingerprint)
                    .bind(row.id)
                    .execute(&mut *tx)
                    .await?;
                stats.rewritten += 1;
            }
            Some((other_id, other_status, other_alive)) => {
                // The better row survives; the other one is merged into it
                let keep = if status_rank(&other_status, other_alive)
                    > status_rank(&row.status, row.last_alive_at)
                {
                    other_id
                } else {
                    row.id
                };
                let drop = if keep == other_id { row.id } else { other_id };
                merge_rows(&mut tx, keep, drop).await?;
                if keep == row.id {
                    // The survivor was the old row: it takes the new key
                    // now that the row that held it is gone
                    sqlx::query("UPDATE proxies SET fingerprint = ? WHERE id = ?")
                        .bind(&fingerprint)
                        .bind(keep)
                        .execute(&mut *tx)
                        .await?;
                    stats.rewritten += 1;
                }
                stats.merged += 1;
            }
        }
    }
    tx.commit().await?;
    Ok(())
}

/// The state a merge moves from one row of a node to the other: read
/// from the row that goes away, written onto the row that stays, the
/// survivor's own value wins and the dropped row fills the gaps.
#[derive(Debug, sqlx::FromRow)]
struct MergeState {
    latency_ms: Option<i64>,
    last_checked_at: Option<i64>,
    last_alive_at: Option<i64>,
    quarantined_at: Option<i64>,
    removed_at: Option<i64>,
    ladder_at: Option<i64>,
    ladder_step: i64,
    last_t2_failed_at: Option<i64>,
    last_t2_checked_at: Option<i64>,
    fail_count: i64,
    geo_country: Option<String>,
    geo_city: Option<String>,
    geo_asn: Option<String>,
    resolved_ip: Option<String>,
}

/// Merge the `drop` row into the `keep` row: the dropped row's source
/// links move over (most recent sighting of each source kept), the state
/// and the history of the node move with them, and the dropped row goes
/// away. The history belongs to the node, not to the row that happened
/// to store it, so the journal rows are re-pointed at the survivor
/// instead of being deleted with the row that held them.
async fn merge_rows(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    keep: i64,
    drop: i64,
) -> crate::Result<()> {
    sqlx::query(
        "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
         SELECT ?, l.source_id, MAX(l.seen_at)
         FROM proxy_source_links l
         WHERE l.proxy_id IN (?, ?)
         GROUP BY l.source_id
         ON CONFLICT(proxy_id, source_id) DO UPDATE SET
            seen_at = MAX(seen_at, excluded.seen_at)",
    )
    .bind(keep)
    .bind(keep)
    .bind(drop)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM proxy_source_links WHERE proxy_id = ?")
        .bind(drop)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE probe_results SET proxy_id = ? WHERE proxy_id = ?")
        .bind(keep)
        .bind(drop)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE speed_results SET proxy_id = ? WHERE proxy_id = ?")
        .bind(keep)
        .bind(drop)
        .execute(&mut **tx)
        .await?;
    // The state the survivor does not have moves with the journal
    let state: MergeState = sqlx::query_as(
        "SELECT latency_ms, last_checked_at, last_alive_at, quarantined_at,
                removed_at, ladder_at, ladder_step, last_t2_failed_at,
                last_t2_checked_at, fail_count, geo_country, geo_city,
                geo_asn, resolved_ip
         FROM proxies WHERE id = ?",
    )
    .bind(drop)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE proxies SET
            latency_ms = COALESCE(latency_ms, ?),
            last_checked_at = COALESCE(last_checked_at, ?),
            last_alive_at = COALESCE(last_alive_at, ?),
            quarantined_at = COALESCE(quarantined_at, ?),
            removed_at = COALESCE(removed_at, ?),
            ladder_at = COALESCE(ladder_at, ?),
            ladder_step = CASE WHEN ladder_step = 0 THEN ? ELSE ladder_step END,
            last_t2_failed_at = COALESCE(last_t2_failed_at, ?),
            last_t2_checked_at = COALESCE(last_t2_checked_at, ?),
            fail_count = CASE WHEN fail_count = 0 THEN ? ELSE fail_count END,
            geo_country = COALESCE(geo_country, ?),
            geo_city = COALESCE(geo_city, ?),
            geo_asn = COALESCE(geo_asn, ?),
            resolved_ip = COALESCE(resolved_ip, ?)
         WHERE id = ?",
    )
    .bind(state.latency_ms)
    .bind(state.last_checked_at)
    .bind(state.last_alive_at)
    .bind(state.quarantined_at)
    .bind(state.removed_at)
    .bind(state.ladder_at)
    .bind(state.ladder_step)
    .bind(state.last_t2_failed_at)
    .bind(state.last_t2_checked_at)
    .bind(state.fail_count)
    .bind(state.geo_country)
    .bind(state.geo_city)
    .bind(state.geo_asn)
    .bind(state.resolved_ip)
    .bind(keep)
    .execute(&mut **tx)
    .await?;
    // The row itself goes away
    sqlx::query("DELETE FROM proxies WHERE id = ?")
        .bind(drop)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// The lifecycle rank of a status: the row with the higher rank survives
/// a merge of two rows that describe the same node. A row the probe has
/// judged is worth more than a row that never got a verdict (it carries
/// the state of the node); a node the probe retired keeps its verdict
/// across a merge and comes back through the revival paths, not through
/// a merge that happened to meet a fresh row. The most recently alive
/// row wins a tie, then the older row, so the survivor keeps the
/// history.
fn status_rank(status: &str, last_alive_at: Option<i64>) -> (i32, i64) {
    let rank = match status {
        "alive" => 5,
        "ready" => 4,
        "quarantine" => 3,
        "removed" => 2,
        "unknown" => 1,
        _ => 0,
    };
    (rank, last_alive_at.unwrap_or(i64::MIN))
}

#[cfg(test)]
#[path = "proxies_tests.rs"]
mod tests;
