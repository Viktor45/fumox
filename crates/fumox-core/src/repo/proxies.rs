//! Proxy upsert and reconciliation (`proxies`, `proxy_source_links`).
//!
//! Reconciliation runs after every successful source fetch:
//!
//! 1. every parsed entry is upserted by `fingerprint`, mutable fields (name,
//!    params, raw_line, geo) refresh, but the lifecycle state is never
//!    touched: `status`, `fail_count` and the quarantine fields are owned by
//!    the probe state machine, and a reappearing `removed`/`quarantine`
//!    proxy keeps them, the early resurrection rule is deliberately
//!    superseded; the opt-in `[ingest].removed_as_unknown` revival
//!    ([`revive_removed`], called by the server right after
//!    reconciliation) is the only exception);
//! 2. `proxy_source_links.seen_at` is stamped for every proxy still present;
//! 3. links of this source not stamped by the fetch are deleted; a proxy
//!    left without any link by that deletion is marked `removed`. Only
//!    the proxies this pass unlinked: a row that was already link-less
//!    (the admin source-delete path deliberately leaves the statuses it
//!    protects behind, see [`mark_source_orphans_removed`]) is none of this
//!    source's business and stays as it is.
//!
//! Every timestamp this module reads or writes — the `now` parameters,
//! `created_at`/`updated_at`, the lifecycle stamps (`quarantined_at`,
//! `ladder_at`, `removed_at`, `last_t2_failed_at`, `last_checked_at`,
//! `last_alive_at`) and the link `seen_at` — is Unix time in seconds,
//! the [`crate::models::now_ts()`] scale.

use super::BindWhereFilter;
use crate::db::DbPool;
use crate::geo::{GeoFactMask, GeoInfo};
use crate::models::{Param, ProxyEntry, ProxyStatus, Scheme};
use sqlx::FromRow;

/// The geo facts of one proxy, as stored in the `proxies.geo_*` columns.
///
/// Produced by the server at ingest time (and by the startup backfill);
/// `None` fields mean "unknown", never "erase", the upsert keeps existing
/// values when a fresh lookup yields nothing (transient DNS failures must
/// not wipe stored facts).
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
    /// Project a resolved [`GeoInfo`] onto the persisted columns.
    pub fn from_info(info: &GeoInfo) -> Self {
        Self {
            country: info.country_code.clone(),
            city: info.city_name.clone(),
            asn: info.asn.map(crate::geo::asn_text),
        }
    }

    /// Whether the stamp carries no facts at all.
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
    /// Ids of the rows inserted by this pass (a superset of what the caller
    /// may enqueue for priority probing; unsorted, chunked
    /// consumers must not rely on order.
    pub inserted_ids: Vec<i64>,
}

/// Full `proxies` row for reads (admin browser, probe, serving).
///
/// The `Debug` implementation is hand-written and masks `credential` and
/// `raw_line` (the stored feed line repeats them inside the URI): a row
/// lands in log lines and panic messages through its `Debug` form, and
/// the proxy's secret must not ride along. `fingerprint` is safe to
/// print — it is derived from scheme, host and port only.
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
    /// When the most recent T2 attempt failed; NULL means either no T2
    /// attempt yet or a successful T2 since. Filters T1 candidates
    /// ([`select_t1_candidates`]) so a proxy waits out T1 until its next
    /// T2 succeeds.
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
    /// The masked `Debug` form: the credential is elided and the raw
    /// feed line is reduced to its length (the shape is still visible,
    /// the secret is not).
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
            .field("last_t2_failed_at", &self.last_t2_failed_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }

    /// Rebuild a serializable [`ProxyEntry`] from the stored row.
    ///
    /// The database stores parameters as two JSON objects (recognized /
    /// unknown), so the original on-the-wire order is not recoverable; the
    /// entry is still fully serializable.
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
/// proxy with its first writer.
///
/// A row linked to a *different* source keeps the values that source
/// wrote: the display name, the raw feed line and the stored parameter
/// sets are what the operator sees in the panel and in the exported
/// subscription, and two feeds advertising the same server under
/// different names would otherwise flip the row back and forth on every
/// refresh. The row is written once, by the source that got there
/// first, and the other sources keep their link without touching it.
///
/// One bind (the source being reconciled) per use; the placeholder
/// order follows the text order of the statement, so these binds come
/// after the row binds of the chunk.
const FOREIGN_SOURCE_LINK: &str = "EXISTS (SELECT 1 FROM proxy_source_links l
                 WHERE l.proxy_id = proxies.id AND l.source_id != ?)";

/// One multi-row upsert statement per this many entries, so the
/// transaction holds the WAL write lock for few round-trips: a per-row
/// loop kept it long enough for a large refresh to overrun the probe
/// daemon's `busy_timeout` and drop its journals.
///
/// Two ceilings bound this, both of which "optimizing" it upward would
/// hit: 250 * 15 columns = 3750 binds, against SQLite's 32766-variable
/// limit, and a multi-row VALUES is a compound SELECT, against
/// SQLITE_MAX_COMPOUND_SELECT (500 in the bundled build, 256 in some
/// others). The link stamp below uses 500, which is at that ceiling.
const UPSERT_CHUNK: usize = 250;

/// Upsert all entries of one fetch and reconcile links for the source.
/// Runs in a single transaction, and inside it the per-row work is
/// batched into multi-row statements (see the upsert loop): the
/// transaction is what makes the link sweep sound, the batching is what
/// keeps its write-lock span short enough that the probe daemon's
/// concurrent writes survive `busy_timeout` on large feeds.
///
/// `geo` runs parallel to `entries` (indexed access; a shorter slice or a
/// `None` element means "no fresh geo facts", the COALESCE upsert branch
/// then keeps whatever is already stored). A *longer* slice is refused
/// rather than truncated: a caller that filtered the entries but passed
/// the unfiltered stamps back would otherwise store every proxy past the
/// first drop with another host's country and ASN.
///
/// `policy` decides what the refresh may do to the proxies that left
/// the feed ([`crate::ingest::IngestPolicy`]): with the alive-linger
/// policy a proxy that vanished from the feed is nobody's business but
/// the probe's. This pass never retires anything, and it keeps the link
/// on every status the probe still owns (`alive`, `ready`, `unknown`,
/// `quarantine`), so upstream churn cannot end a node that has not
/// failed. The recheck ladder and the priority queue keep working on the
/// `quarantine` lingerer through its own `EXISTS (... link ...)`
/// predicate, and a row that comes back re-stamps its link on the next
/// refresh. With the strict policy and a source that has `drop` rules,
/// the sweep and the unlink run unrestricted: a rule added later has to
/// reach the rows already stored, which is the whole point of the gate.
/// The admin's source deletion path (`mark_source_orphans_removed`) honours the
/// same policy, when the gate is closed, `ready` and `unknown` rows are
/// left alone (`ready` is tunnel-verified, `unknown` has not yet had its
/// first verdict; the click that deleted the source should not retire
/// either); when it is open, every orphan retires.
///
/// `now` (and every stamp the pass writes) is Unix time in seconds
/// ([`crate::models::now_ts()`]). The pass is timed: the duration is
/// logged with the source id, and a `SQLITE_BUSY` escape is logged with
/// both, so a source whose refresh keeps losing the write lock is
/// visible in the log with the time it burned trying.
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
/// `commit` transaction over the whole pass.
async fn reconcile_source_pass(
    pool: &DbPool,
    source_id: &str,
    entries: &[ProxyEntry],
    geo: &[Option<GeoStamp>],
    now: i64,
    policy: crate::ingest::IngestPolicy,
) -> crate::Result<ReconciliationStats> {
    let mut stats = ReconciliationStats::default();
    // BEGIN IMMEDIATE: the first statement grabs the WAL write lock up
    // front instead of upgrading a read transaction mid-flight. A deferred
    // read→write upgrade fails with SQLITE_BUSY_SNAPSHOT (code 517) when
    // another process (probe daemon) committed since our snapshot was
    // taken, busy_timeout does not apply to that upgrade, so it surfaced
    // as "database is locked" on source refreshes. With IMMEDIATE the
    // whole critical section waits inside busy_timeout instead.
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    // `entries` and `geo` are paired by index below. A longer stamp slice
    // than there are entries means the caller filtered one side of the pair
    // and not the other: every stamp from the first extra position on would
    // land on a host that never resolved to it. Refuse rather than persist
    // proxies stamped with another host's country and ASN.
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

    // Pre-existing fingerprints, for insert/update accounting.
    let fingerprints: Vec<String> = entries.iter().map(ProxyEntry::fingerprint).collect();
    let mut existing: std::collections::HashSet<String> = std::collections::HashSet::new();
    for chunk in fingerprints.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!("SELECT fingerprint FROM proxies WHERE fingerprint IN ({placeholders})");
        // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound.
        let mut query = sqlx::query_as::<_, (String,)>(sqlx::AssertSqlSafe(sql.as_str()));
        for fp in chunk {
            query = query.bind(fp);
        }
        let rows: Vec<(String,)> = query.fetch_all(&mut *tx).await?;
        existing.extend(rows.into_iter().map(|(fp,)| fp));
    }

    // Upsert each entry; the ON CONFLICT branch refreshes the mutable
    // identity fields only. Lifecycle fields (status, fail_count, quarantine
    // schedules, removed_at) are deliberately absent: the probe state
    // machine is their sole owner, and a reappearing proxy keeps its state.
    //
    // One multi-row statement per chunk, `UPSERT_CHUNK` entries each
    // (the ceilings that bound the constant live with it).
    //
    // Keyed by fingerprint because RETURNING emits rows in unspecified
    // order, and duplicate fingerprints in one batch must collapse onto
    // the one id.
    let mut ids_by_fingerprint: std::collections::HashMap<String, i64> =
        std::collections::HashMap::with_capacity(entries.len());
    let mut proxy_ids: Vec<i64> = Vec::with_capacity(entries.len());
    let mut seen_in_batch: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (chunk_idx, chunk) in entries.chunks(UPSERT_CHUNK).enumerate() {
        let base = chunk_idx * UPSERT_CHUNK;
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
        // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound.
        let mut query = sqlx::query_as::<_, (i64, String)>(sqlx::AssertSqlSafe(sql.as_str()));
        for (idx, entry) in chunk.iter().enumerate() {
            let fingerprint = fingerprints[base + idx].as_str();
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
        // The guard placeholders sit behind the VALUES list in the
        // statement, so their binds follow the row binds.
        let guard_binds = sql.matches(FOREIGN_SOURCE_LINK).count();
        for _ in 0..guard_binds {
            query = query.bind(source_id);
        }
        let rows: Vec<(i64, String)> = query.fetch_all(&mut *tx).await?;
        for (id, fingerprint) in rows {
            ids_by_fingerprint.insert(fingerprint, id);
        }
    }

    // Rebuild the per-entry id list in entry order and do the
    // insert/update accounting. A fingerprint already in the DB, or
    // already seen earlier in this same batch, counts as an update.
    for fingerprint in &fingerprints {
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

    // The stamp of this pass: `now`, but strictly greater than any
    // `seen_at` this source's links already carry. Two passes of one
    // source inside the same wall-clock second would otherwise stamp the
    // same value, and the sweeps below could not tell the links of the
    // previous pass from the links of this one (they compare
    // `seen_at <> stamp`, not `<`). The read sits inside the
    // `BEGIN IMMEDIATE` transaction, so no concurrent writer can slip a
    // fresher stamp in between.
    let max_seen: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seen_at), 0) FROM proxy_source_links WHERE source_id = ?",
    )
    .bind(source_id)
    .fetch_one(&mut *tx)
    .await?;
    let stamp = now.max(max_seen + 1);

    // Stamp the links of everything still present in this source,
    // batched like the upserts (3 binds per row).
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
        query.execute(&mut *tx).await?;
    }

    // Drop links this fetch no longer saw, then mark orphaned proxies
    // removed (idempotent: proxies already removed keep their removed_at).
    // With the alive-linger policy an alive *or ready* proxy keeps a
    // link the fetch did not re-stamp, it stays linked to the source and
    // keeps running the probe cycle; only the probe's own verdict can end
    // it (`ready` is a live tier too).
    let keep_alive_linger = policy.keep_alive_linger();
    // Stale means "not stamped by this pass": the comparison is against
    // this pass's own strictly-increasing stamp (see the link stamping
    // above), so two passes inside one second still part last pass's
    // links from this pass's.
    let unlinked_sql = if keep_alive_linger {
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
    // The retire sweep runs *before* the links go away and asks the
    // question this pass is actually responsible for: "which proxies
    // does the DELETE below leave with no link at all?" That is a
    // per-proxy answer about this source, not a global one. The
    // unscoped `NOT EXISTS (link)` version swept up every link-less row
    // in the table, including the deliberate residue of the admin
    // source-delete path: `mark_source_orphans_removed` protects `ready` and
    // `unknown` rows under `drop_gate = false` and leaves them link-less
    // on purpose, and the very next reconcile of any *other* source
    // retired them, undoing the operator's choice. The protected rows
    // have no link to this source, so they are not in the candidate set.
    // Both EXISTS share the same arguments: a stale link of this source
    // (about to be deleted) and no link that survives it.
    //
    // Under `drop_gate = false` the sweep is skipped outright: that option
    // means the probe alone retires a proxy, and a proxy that dropped out
    // of the feed has not failed anything. Retiring it here judged it
    // without a verdict. `quarantine` lingers along with the live tiers
    // for the same reason: unlinking it would strand a row in no probe
    // lane, which kills it just as surely as the sweep did, only without
    // the record.
    if !keep_alive_linger {
        const RETIRE_SQL: &str = "UPDATE proxies
             SET status = 'removed', removed_at = ?, updated_at = ?
             WHERE status != 'removed'
               AND EXISTS (SELECT 1 FROM proxy_source_links l
                           WHERE l.proxy_id = proxies.id AND l.source_id = ? AND l.seen_at <> ?)
               AND NOT EXISTS (SELECT 1 FROM proxy_source_links l
                               WHERE l.proxy_id = proxies.id
                                 AND NOT (l.source_id = ? AND l.seen_at <> ?))";
        stats.removed = sqlx::query(RETIRE_SQL)
            .bind(now)
            .bind(now)
            .bind(source_id)
            .bind(now)
            .bind(source_id)
            .bind(now)
            .execute(&mut *tx)
            .await?
            .rows_affected() as usize;
    }

    stats.unlinked = sqlx::query(sqlx::AssertSqlSafe(unlinked_sql))
        .bind(source_id)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected() as usize;

    tx.commit().await?;
    Ok(stats)
}

/// Batch of `(id, host)` rows still missing a fact the loaded databases
/// can supply, ordered by id past `after_id`, keyset pagination.
///
/// Per fact, not per row: a row that resolved a country but no ASN is
/// exactly what a later pass must retry, and the old all-NULL condition
/// locked it out for good. A fact no database can answer (`mask`) is left
/// out of the criterion.
///
/// Rows looked up within [`GEO_RETRY_WINDOW_SECS`] are left out as well:
/// their host was asked recently and did not answer, and asking again
/// before the window passed only takes the budget away from rows that were
/// never tried. `now` is the current time in unix seconds. `removed` rows
/// are never walked: nothing will ever serve their facts.
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
/// asked again.
///
/// Long enough that a hopeless host does not take the backfill budget away
/// from the fresh rows on every pass, short enough that a host that comes
/// back (a name that resolves again, a database that was fixed) is filled
/// within the day. Six hours matches the lifetime of the resolver's own
/// fact cache.
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

/// Store resolved geo facts on one proxy row.
///
/// Only the facts the stamp carries are written: a partial stamp (ASN
/// found, country silent) fills its gap without erasing what the row
/// already knows, the invariant the reconcile upsert keeps too.
///
/// A stored fact clears the attempt counter: the row answered, so it is
/// not a row that has to be asked again in every pass.
pub async fn update_geo(pool: &DbPool, id: i64, geo: &GeoStamp) -> crate::Result<()> {
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
    .execute(pool)
    .await?;
    Ok(())
}

/// Record that a geo lookup for this row failed.
///
/// The row keeps its (missing) facts, but the attempt is remembered, so
/// the backfill leaves it alone until the retry window
/// ([`GEO_RETRY_WINDOW_SECS`]) passed instead of asking again on every
/// pass.
pub async fn mark_geo_attempt(pool: &DbPool, id: i64, now: i64) -> crate::Result<()> {
    sqlx::query(
        "UPDATE proxies
         SET geo_attempts = geo_attempts + 1,
             last_geo_attempt_at = ?
         WHERE id = ?",
    )
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Store the full outcome of an on-demand geo resolution: the facts plus
/// the IP they were resolved from (admin proxy-card action).
///
/// `COALESCE`, exactly like the reconcile upsert: a `None` field means
/// "not known from this lookup", never "erase". The resolver merges the
/// databases with an `any`-hit, so a stamp can be partial where the others
/// are silent. An ASN-only hit (the City record decodes with an empty
/// country, as it does for the Cloudflare `104.16.0.0/12` block) must not
/// wipe a country the ingest path already resolved. `resolved_ip` is
/// always a concrete address from the lookup that just ran and is
/// written as-is.
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
/// it groups by and the counters that used to come from four separate
/// scans of the same table.
#[derive(Debug, Clone, FromRow)]
pub struct StatusAggregateRow {
    /// The status this row groups (`unknown`, `alive`, …).
    pub status: String,
    /// Rows of this status.
    pub count: i64,
    /// Rows of this status that were never checked.
    pub never_checked: i64,
    /// Quarantine rows waiting for their second chance.
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
/// grouped pass.
///
/// The breakdown by status and the scalar counters (quarantine, second
/// chance, never checked, unprobeable, latency) come from the same rows,
/// so the numbers on the dashboard cannot contradict each other the way
/// four independent scans of the same table could.
#[derive(Debug, Clone, Default)]
pub struct StatusAggregates {
    /// The breakdown by status, ordered by status.
    pub counts: Vec<(String, i64)>,
    /// Rows in the table.
    pub total: i64,
    /// Rows in quarantine.
    pub in_quarantine: i64,
    /// Quarantine rows waiting for their second chance.
    pub quarantine_second_chance: i64,
    /// Rows that were never checked (removed rows excluded).
    pub never_checked: i64,
    /// Rows of an unprobeable scheme (removed rows excluded).
    pub unprobeable: i64,
    /// Fastest measured latency of a live proxy (`alive` or `ready`).
    pub latency_min: Option<i64>,
    /// Mean measured latency of a live proxy.
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

/// Read the dashboard's proxy counters in one grouped pass.
///
/// The query groups the table by status and carries the scalar counters
/// as per-group sums, so the whole dashboard reads the table once
/// instead of once per counter. The latency figures cover the same live
/// pool (`alive` and `ready`) the dashboard's other widgets show.
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
    // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound.
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
/// `ready`).
///
/// SQLite has no median builtin: the middle element(s) are picked with a
/// window function over the measured rows and averaged (odd count: one
/// element, even count: the mean of the two middle).
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

/// The coverage aggregate of the preserved probe history: one row per
/// proxy with a flag per tier.
///
/// The journal is read once and grouped, not once per tier and not once
/// per candidate row: the panel's bucket counts, the browser's coverage
/// filter and the browser's per-row flags ask the same question of the
/// same table, and the correlated `EXISTS` subqueries they used to carry
/// ran once per candidate row.
/// Alias of the joined coverage aggregate. The bucket filter and the
/// list query read the same alias, so the WHERE clause and the JOIN it
/// depends on cannot drift apart.
const COVERAGE_ALIAS: &str = "cov";

/// The join that brings the coverage aggregate into the query under the
/// shared alias.
///
/// The list query always carries it (the per-row T1/T2 flags read it);
/// the count query carries it only when the filter constrains the
/// coverage, so an unfiltered count does not pay for a pass over the
/// journal.
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
/// `none`, no journaled attempt at all, `t1_only` / `t2_only`, exactly one
/// of the check tiers has history, `both`, T1 and T2 both do. T1 is
/// `probe_kind IN ('tcp', 'tls')`, T2 is any of the T2 kinds
/// ([`crate::repo::probe::T2_KINDS_SQL`]), so an attempt the engine
/// never verified still counts as a T2 attempt.
///
/// The buckets cover *preserved* history only: `probe_results` rotates after
/// `[retention].probe_results_days`, so a long-unseen proxy may look
/// unverified even though it was checked once, the same view the probe
/// daemon itself has (the T2 recency selector reads the same rows).
/// The order is fixed and missing buckets are zero-filled, so the panel
/// never reshuffles when counts change.
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

// Admin proxy browser
//
// The dynamic list screen: filter clauses are whitelisted fragments
// assembled through the shared [`super::WhereFilter`], every value flows
// through a bind. The count and the page query share one
// [`ProxyListFilter::where_filter`], so their clause sets cannot drift.

/// Which check tiers have preserved history for a proxy, the coverage
/// buckets of the admin proxy browser and the probe overview. T1 is
/// `probe_kind IN ('tcp', 'tls')`, T2 is any of the T2 kinds (an attempt
/// the engine never verified still counts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckCoverage {
    /// No journaled attempt at all.
    None,
    /// A T1 attempt but no T2 attempt.
    T1Only,
    /// A T2 attempt but no T1 attempt.
    T2Only,
    /// Both tiers have at least one attempt.
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
    /// renders as "no filter" (the tolerance the other selects show).
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
    /// aggregate (see [`coverage_aggregate_sql`]). A fixed literal per
    /// variant over the shared alias: caller text never reaches the
    /// SQL.
    ///
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
    /// back to the default, the same tolerance the other selects show.
    pub fn from_param(value: &str) -> Self {
        match value {
            "latency" => Self::Latency,
            "name" => Self::Name,
            _ => Self::Updated,
        }
    }

    /// The `sort` query parameter of this order.
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

    /// The same order, walked backwards: the rows come out in the
    /// opposite sequence, which is how a page before the cursor is
    /// fetched and then turned back into the reading order.
    fn reverse_order_sql(self) -> &'static str {
        match self {
            Self::Updated => "p.updated_at ASC, p.id ASC",
            Self::Latency => "p.latency_ms IS NULL DESC, p.latency_ms DESC, p.id ASC",
            Self::Name => "p.name COLLATE NOCASE DESC, p.id ASC",
        }
    }

    /// Whether `cursor` is a position in this order.
    ///
    /// A cursor of another sort is not a position in this one: the
    /// browser falls back to the first page instead of paging from a
    /// key that means nothing here.
    pub fn accepts_cursor(self, cursor: &ProxyListCursor) -> bool {
        matches!(
            (self, cursor),
            (Self::Updated, ProxyListCursor::Updated { .. })
                | (Self::Latency, ProxyListCursor::Latency { .. })
                | (Self::Name, ProxyListCursor::Name { .. })
        )
    }

    /// The keyset predicate that selects the rows on one side of
    /// `cursor`, with the values the predicate binds.
    ///
    /// The predicate repeats the sort key of the order, so "after the
    /// cursor" means exactly "the rows the next page shows": the
    /// tie-break direction of the order decides which of two equal keys
    /// comes first. `None` when the cursor does not belong to this
    /// order — a cursor of another sort is not a position in this one.
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
                // The measured rows come first, the unmeasured ones last.
                // A cursor inside the measured tier sees the rest of that
                // tier and, past its end, the unmeasured rows; a cursor
                // inside the unmeasured tier sees only the rows behind it
                // in that tier.
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

/// One bound value of a keyset predicate.
///
/// The keyset predicate binds the sort key of the row the page resumes
/// from, and the key is a mix of integers and text (a display name), so
/// the values cannot go through the text-only filter binder.
#[derive(Debug, Clone)]
enum KeysetValue {
    Int(i64),
    Text(String),
}

/// The sort key of one row of the admin proxy browser.
///
/// The browser pages with a keyset cursor: the next page starts after
/// the key of the last row of the current one, so a page costs one index
/// seek instead of a walk over everything it skips.
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
    /// The rows after the cursor: the next page.
    Forward,
    /// The rows before the cursor: the previous page.
    Backward,
}

/// Where one page of the admin proxy browser starts.
#[derive(Debug, Clone)]
pub struct ProxyListPage {
    /// The sort key the page resumes from.
    pub cursor: ProxyListCursor,
    /// Which side of the key the page takes.
    pub direction: ProxyListDirection,
}

/// Filter parameters of the admin proxy browser ([`count_filtered`] /
/// [`list_filtered`]). An empty string or an empty list means "no
/// constraint" for that field.
#[derive(Debug, Clone, Default)]
pub struct ProxyListFilter {
    /// Status whitelist; empty = no status filter.
    pub statuses: Vec<String>,
    /// Exact scheme match.
    pub scheme: String,
    /// Exact ISO country match.
    pub country: String,
    /// Source id, matched through `proxy_source_links`.
    pub source_id: String,
    /// Literal case-insensitive substring match against host and name:
    /// the query is interpolated into a `LIKE %..% ESCAPE '\'` needle
    /// with `%`, `_` and `\` escaped, so the `LIKE` wildcards in the
    /// input mean themselves (`100%` finds `100%`, not `100` + anything).
    pub query: String,
    /// Probe-coverage bucket; `None` = no coverage filter.
    pub coverage: Option<CheckCoverage>,
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
            // Literal substring match: escape the `LIKE` wildcards and
            // the escape character itself, so a `100%` query finds `100%`
            // and a `%` query answers only rows that carry a literal `%`.
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
        wf
    }

    /// The join that brings the coverage aggregate into the query, or
    /// nothing when the filter does not constrain the coverage.
    ///
    /// The aggregate is grouped once and joined, so the filter costs one
    /// pass over the journal instead of two correlated subqueries per
    /// candidate row.
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
/// The page is fetched with a keyset cursor, not with an `OFFSET`: the
/// page resumes from the sort key of a row (`page`), so the database
/// seeks straight to it instead of walking over every row the page
/// skips. The default order (`updated_at`, `id`) is served by
/// `idx_proxies_updated_at`, so the seek is an index scan and not a
/// table walk.
///
/// A page taken *before* the cursor comes out in the reading order even
/// though it is fetched backwards: the rows are reversed before they are
/// returned.
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
                p.updated_at,
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

/// Number of not-yet-retired proxies of a scheme the probe cannot judge
/// at all (tuic/mieru stay `unknown` forever). The dashboard renders it
/// as a sub-line of the "Never checked yet" card, so it counts the same
/// population that card does: retired rows are excluded. The cleanup
/// button moves exactly these rows to `removed`
/// ([`remove_unprobeable_unknown`]); counting them anyway let the
/// sub-line outgrow the headline it annotates (0 never checked, 300
/// unprobeable).
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
    // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound.
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
/// first (proxy card). Unlike [`links_for_proxy`] this resolves the
/// source name through a LEFT JOIN, so a deleted source renders as
/// nameless instead of dropping the link row.
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
/// maps the `p.*` columns onto the nested [`ProxyRow`]).
///
/// `Debug` is hand-written so the nested [`ProxyRow`]'s masking (the
/// credential, the raw feed line) survives the join wrapper.
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

/// Load proxies together with each source they are linked to, for pipeline
/// processing: a proxy linked from several of the selected
/// sources appears once per link, so every source can run its own merged
/// pipeline before the results are merged and deduplicated.
///
/// Rows are ordered by proxy id within each source; the caller imposes the
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

/// The predicate of a proxy that is still served: it has to be linked to
/// a source, and that source has to be enabled.
///
/// A disabled source is one the operator switched off; its proxies must
/// not keep appearing in the export links, and the counters that describe
/// the lists have to count the same rows. The join rides
/// `idx_links_source`, so the check is an index seek per proxy.
const LINKED_TO_ENABLED_SOURCE: &str = "EXISTS (SELECT 1 FROM proxy_source_links l
           JOIN sources s ON s.id = l.source_id
           WHERE l.proxy_id = p.id AND s.enabled = 1)";

/// At most `limit` currently-`alive` proxies still linked to at least one
/// *enabled* source, in stable id order, the backing query of the public
/// «all alive» export link. Fingerprints are unique in the table, so the
/// set is already deduplicated; unlinked rows are excluded just like
/// everywhere else proxies are served.
///
/// The cap is applied in SQL, not by truncating a full read: the export
/// serializes and ships every row it gets, so an unbounded `fetch_all`
/// here is an unbounded render and an unbounded response body on a
/// public, cacheable link. `limit` is a `u32` clamped into `1..=i64::MAX`,
/// so a caller cannot turn it into a negative `LIMIT` (SQLite reads a
/// negative limit as "no limit") or overflow the bind.
///
/// Truncation takes the lowest ids, i.e. the oldest rows, because the
/// order is id-ascending. That is stable across requests but it is *not*
/// health-ordered: a caller that needs a different slice (the admin
/// browser, which pages) must not use this function.
///
/// Strictly `alive`: the tiers do not overlap
///, `ready` rows are served by [`list_ready`] and the ready export link.
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
/// [`revive_removed_never_checked`]). Each statement adds the
/// pieces it owns around this core: `status` (the second
/// [`revive_removed_never_checked`] arm releases frozen `unknown`
/// rows without retouching their status), `removed_at`
/// ([`revive_quarantine`] rows never carry one) and the
/// `updated_at = ?` stamp. Whitespace is cosmetic; SQLite does not care.
const RESET_SET: &str = "fail_count = 0,
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             last_t2_failed_at = NULL";

/// Manual "re-check as new" action from the admin panel:
/// reset the lifecycle to a pristine `unknown`, clearing the fail counter
/// and every quarantine / second-chance / recheck timestamp, and hand the
/// id to the priority queue. The probe daemon stays the sole owner of the
/// state machine, this only puts the proxy back at its starting square.
///
/// `last_t2_failed_at` is part of that starting square (a T2 failure is
/// the only verdict that suppresses T1, and only a later T2 success may
/// lift it): leaving it set would put the row in no probe lane at all.
///
/// The reset only runs on a row a probe lane can actually pick up, which
/// is what the `true` return means. A row without a
/// `proxy_source_links` entry is retired, reconciliation unlinks and
/// retires in one transaction, and every lane filters on the link
/// ([`select_t1_candidates`], [`crate::repo::probe::select_queued_checks`],
/// [`select_t2_candidates`]), so resetting it would hand the operator a
/// success toast for a row that then belongs to no lane: not probed, not
/// served (`list_alive` excludes it too), and not revived by the
/// `removed_as_unknown` path either, which requires the link as well.
/// Worse for a `quarantine` row: the recheck ladder
/// ([`select_due_quarantine`]) is the one lane without a link predicate,
/// so a reset would cancel the last chance that row still had and strand
/// it in `unknown` forever. Refusing keeps the row (and its schedule)
/// intact until a feed brings the proxy back, at which point the revival
/// paths own it. The unprobeable schemes are refused for the same reason:
/// a `tuic`/`mieru` row is in no lane either (hysteria2 is T1-excluded
/// but is the one scheme T2 offers while still `unknown`). A refused row
/// is left completely untouched and the function reports `false`, the
/// "nothing was reset" answer.
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
    // list, every value flows through .bind().
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
/// status" action leaves (`unknown`, `fail_count = 0`, quarantine
/// schedules and `removed_at` cleared), so a later recheck or a source
/// refresh that stops carrying the proxy behaves exactly as if the row had
/// never been removed. Returns the ids of the revived rows, the caller
/// hands them to the priority-probe queue like a fresh insert. Chunked by
/// fingerprint like every other batch statement.
///
/// The link predicate is the point of the revival: the T1 lanes
/// ([`select_t1_candidates`], [`crate::repo::probe::select_queued_checks`])
/// and the T2 sample ([`select_t2_candidates`]) all need a live
/// `proxy_source_links` row, so a link-less row moved back to `unknown`
/// is a row the probe can never look at again. The panel would report
/// it revived and the next reconcile would retire it once more. It is
/// called right after reconciliation re-stamped the links of everything
/// this fetch carried, so the predicate costs nothing there.
///
/// `last_t2_failed_at` goes with the rest of the lifecycle: a revival
/// is an operator decision to re-check the row from scratch (the same
/// one *Reset status* makes), and a row that keeps a stale T2 block is
/// in no lane at all. The T1 sample and the priority queue both filter
/// on `last_t2_failed_at IS NULL`, and the T2 sample wants `alive` or
/// `ready` rows, not a fresh `unknown`.
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
        // sqlx 0.9 SqlSafeStr: placeholder-list format! only; data is bound.
        let mut query = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(sql.as_str())).bind(now);
        for fp in chunk {
            query = query.bind(fp);
        }
        let rows: Vec<(i64,)> = query.fetch_all(pool).await?;
        revived.extend(rows.into_iter().map(|(id,)| id));
    }
    Ok(revived)
}

/// How many rows one revival batch touches.
const REVIVE_BATCH_SIZE: i64 = 1_000;

/// How many revived ids one bulk revival hands back for the priority
/// queue.
///
/// The revival itself touches every matching row; the ids are only the
/// head of that population, and the rows beyond the cap wait for the
/// random T1 sample like any other unchecked row.
pub const REVIVED_ID_CAP: usize = 10_000;

/// The outcome of a bulk revival: how many rows were moved and which of
/// them may be handed to the priority queue.
#[derive(Debug, Default)]
pub struct RevivedRows {
    /// How many rows the revival moved.
    pub revived: u64,
    /// The ids of the revived rows, at most [`REVIVED_ID_CAP`] of them
    /// (the newest ones).
    pub ids: Vec<i64>,
}

/// One revival batch: at most [`REVIVE_BATCH_SIZE`] rows above `cursor`
/// that match `predicate`, moved by `set_clause`.
///
/// The statement is one bounded `UPDATE`: the CTE picks the batch of
/// ids, the update touches only those, and `RETURNING id` hands back
/// what changed. The batch is its own transaction, so the write lock is
/// released before the next one starts.
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
    // The binds follow the textual order of the placeholders: the
    // predicate and the cursor live in the CTE, the `updated_at` stamp
    // in the SET clause.
    let mut query = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(sql.as_str()));
    if let Some(value) = text {
        query = query.bind(value);
    }
    let rows = query.bind(cursor).bind(now).fetch_all(pool).await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Revive every row that matches `predicate`, in bounded batches.
///
/// The batches walk the population in id order, each one its own
/// statement, so a revival of a whole country does not hold the write
/// lock for the whole sweep. The ids of the last batches win the cap:
/// the priority queue prefers the freshest rows.
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
/// the given country back to `unknown`. The SQL is the same shape as
/// [`revive_removed`], but the WHERE filter keys on `geo_country`
/// instead of a fingerprint IN-list, the admin acts on the whole
/// filtered population, no fingerprint enumeration needed. The rows are
/// revived in bounded batches, so a whole-country revival does not hold
/// the write lock for the whole sweep. Returns how many rows were
/// revived and the ids the caller may hand to the priority-probe queue.
/// A row with no source link is left `removed`: no probe lane would ever
/// reach it (see [`revive_removed`]).
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
/// the given autonomous system back to `unknown`.
///
/// `asn` is the AS number in either spelling, `24940` or `AS24940`; it
/// is normalised to the canonical `AS{n}` text the `geo_asn` column
/// stores ([`crate::geo::canonical_asn`]), so both spellings reach the
/// same rows. An input that is not an AS number revives nothing.
/// Returns how many rows were revived and the ids for enqueueing;
/// link-less rows stay `removed` (see [`revive_removed`]).
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
/// The predicate is `last_checked_at IS NULL`: the row's own record of
/// having been checked, which no retention pass ever rotates away. The
/// journal (`probe_results`) cannot answer the question, because the
/// journal *does* rotate: a proxy checked once and then dropped from the
/// preserved history looked "never checked" and was revived on every
/// pass, undoing a verdict the probe had already given.
///
/// 1. `removed` rows the cleanup retired without ever being probed go
///    back to `unknown`.
/// 2. `unknown` rows frozen by the T2 block (`last_t2_failed_at` set)
///    are released. Such a row is in no probe lane at all: the queue
///    drain and the T1 sample both require `last_t2_failed_at IS NULL`,
///    and the T2 selector only offers `alive`/`ready`, so nothing can
///    ever clear the flag. Rows revived before the revival paths learned
///    to clear it (the 2026-09-22..29 window) have been stuck ever
///    since. Clearing the flag is what actually matters here; the
///    lifecycle reset keeps the row pristine.
///
/// Returns how many rows were revived and the ids for enqueueing. The
/// rows are revived in bounded batches, one statement each. Link-less
/// rows are left alone in both halves: no source link means no probe
/// lane can reach them (see [`revive_removed`]).
pub async fn revive_removed_never_checked(pool: &DbPool, now: i64) -> crate::Result<RevivedRows> {
    let revive_set = format!("status = 'unknown', {RESET_SET}, removed_at = NULL, updated_at = ?");
    let removed_predicate = "status = 'removed'
           AND last_checked_at IS NULL
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)";
    let mut outcome = revive_population(pool, &revive_set, removed_predicate, now, None).await?;

    // The frozen-`unknown` arm keeps the row's status (and its absent
    // `removed_at`) and takes only the shared reset core.
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
/// [`quarantine_to_removed`]. The lifecycle fields that
/// `quarantine_to_removed` clears are the same ones `revive_removed`
/// clears, `quarantined_at`, `ladder_at`, `ladder_step`, `fail_count`.
/// `removed_at` stays NULL because quarantined rows never had a
/// `removed_at`. Returns how many rows were revived and the ids for
/// enqueueing; link-less rows stay `quarantine` (see [`revive_removed`]:
/// a revived row with no
/// source link is in no probe lane, the ladder it was on is exactly the
/// one this call drops). `last_t2_failed_at` is cleared like everywhere
/// else a revival happens, for the same reason.
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
    /// Rows the sweep moved to `removed`.
    pub retired: u64,
    /// Rows the sweep left link-less because their status is protected.
    ///
    /// These are the "detached" rows of the admin panel: no source link
    /// means no probe lane can reach them, so they linger until the
    /// operator cleans them up (see [`remove_detached`]).
    pub protected: u64,
}

/// Mark the proxies of one source that lost their last link as
/// `removed` (deleting a source is soft, orphaned
/// proxies are not physically deleted, they transition to `removed`.
/// `removed` is terminal for reconciliation: a proxy that reappears in a
/// fetch keeps its state, the ways back are the admin "reset status"
/// action or purge removed followed by a re-insert). Returns how many
/// proxies were retired and how many were left alone.
///
/// The sweep is restricted to the proxies the source was linked to: it
/// picks them through the link table, so deleting one source does not
/// walk the whole table. A proxy that is still linked to another source
/// keeps its link and stays untouched.
///
/// The rows are selected while the source still exists, because deleting
/// it cascades its links away: the caller runs this first and deletes the
/// source afterwards.
///
/// `protected_statuses` lists the lifecycle states the caller does not
/// want to retire just because their last source link vanished: a row in
/// one of these statuses is left untouched, link-less, until the probe
/// decides for itself. The admin source-delete handler passes
/// `["ready", "unknown"]` when `[ingest].drop_gate = false`, a `ready`
/// proxy was tunnel-verified by hand and an `unknown` one has not yet had
/// its first verdict, so retiring either from a single click would be too
/// aggressive. Pass an empty slice to retire every orphan (the strict
/// policy).
pub async fn mark_source_orphans_removed(
    pool: &DbPool,
    source_id: &str,
    protected_statuses: &[&str],
) -> crate::Result<OrphanSweep> {
    // sqlx's `query` with no bound values still uses a fixed query, the
    // protected-status list only widens the WHERE clause when non-empty
    // (so the no-protection path keeps the original single-statement
    // shape). The slice is built from caller-controlled literals; we
    // expand it into a parameterised `IN (?, ?, …)` list rather than
    // concatenating it into SQL.
    //
    // The ladder bookkeeping goes with the retirement, exactly as it
    // does in every other "move to removed" transition
    // ([`quarantine_to_removed`], [`remove_detached`]): a retired row
    // carries no live recheck schedule any more, and a stale
    // `ladder_at` on a `removed` row describes a ladder that does not
    // exist.
    //
    // The link subquery names the source's own proxies and the NOT EXISTS
    // excludes the source's own link, so a proxy that another source
    // still feeds is not an orphan.
    let mut sql = String::from(
        "UPDATE proxies SET status = 'removed', quarantined_at = NULL, ladder_at = NULL,
                ladder_step = 0, removed_at = ?, updated_at = ?
         WHERE status != 'removed'
           AND id IN (SELECT proxy_id FROM proxy_source_links WHERE source_id = ?)
           AND NOT EXISTS (SELECT 1 FROM proxy_source_links l
                           WHERE l.proxy_id = proxies.id AND l.source_id != ?)",
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

    // The rows the sweep left behind: link-less, not retired, and in one
    // of the protected states. They are counted, not hidden: a link-less
    // row is in no probe lane, so the operator has to know that it is
    // there.
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

/// Number of proxies without any source link ("detached").
///
/// A link-less row is in no probe lane: every lane filters on the link
/// ([`select_t1_candidates`], [`crate::repo::probe::select_queued_checks`],
/// [`select_t2_candidates`]). The panel shows the count, so the operator
/// can see how much of the table no feed reaches any more.
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
/// «cleanup» panel).
///
/// The link-less rows the source-delete path left behind on purpose
/// (see [`mark_orphans_removed`]) have no probe lane and no feed that
/// could bring them back, so this is the path that ends them. Returns
/// how many rows were affected.
pub async fn remove_detached(pool: &DbPool) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(
        "UPDATE proxies SET
             status = 'removed',
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             removed_at = ?,
             updated_at = ?
         WHERE status != 'removed'
           AND id NOT IN (SELECT proxy_id FROM proxy_source_links)",
    )
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// How many rows one purge batch deletes.
const PURGE_BATCH_SIZE: i64 = 1000;

/// The pause between two purge batches.
///
/// The purge holds the WAL write lock for the duration of a batch, and
/// the probe daemon wants that lock for its own state machine. The pause
/// gives it a window between two batches instead of making it wait for
/// the whole sweep.
const PURGE_BATCH_PAUSE: std::time::Duration = std::time::Duration::from_millis(50);

/// Physically delete every `removed` proxy and, via `ON DELETE CASCADE`,
/// its source links and probe/speed history («purge
/// removed»). This is the only hard delete in the system, the bulk
/// cleanup actions above it only transition rows *into* `removed`, and
/// is guarded by a confirmation dialog in the admin UI. Returns the
/// number of deleted proxy rows.
///
/// The delete runs in bounded batches, one transaction each: a single
/// `DELETE` over the whole `removed` population holds the write lock
/// until the last cascade is done, which on a large table is long enough
/// to make the probe daemon's own writes time out. The batch commits
/// release the lock, and the pause between them lets the other writer in
/// before the next batch starts.
pub async fn purge_removed(pool: &DbPool) -> crate::Result<u64> {
    let mut total = 0u64;
    loop {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let affected = sqlx::query(
            "DELETE FROM proxies WHERE id IN (
                 SELECT id FROM proxies WHERE status = 'removed' ORDER BY id LIMIT ?
             )",
        )
        .bind(PURGE_BATCH_SIZE)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        total += affected;
        if affected < PURGE_BATCH_SIZE as u64 {
            break;
        }
        tokio::time::sleep(PURGE_BATCH_PAUSE).await;
    }
    Ok(total)
}

// Bulk cleanup actions: one-click ways to
// move whole groups of proxies into `removed`. They are status transitions,
// never hard deletes, the physical cleanup stays the single «purge
// removed» button, so every action remains reversible via the per-proxy
// «reset status» until purged. Lifecycle fields are cleared to the same
// pristine state as `reset_status` would leave, so a later reset is a
// no-op on those columns.

/// Move every `quarantine` proxy into `removed` (admin «cleanup» panel):
/// a bulk shortcut past the recheck ladder for proxies the admin has
/// already given up on. Returns how many rows were affected.
pub async fn quarantine_to_removed(pool: &DbPool) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(
        "UPDATE proxies SET
             status = 'removed',
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             removed_at = ?,
             updated_at = ?
         WHERE status = 'quarantine'",
    )
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Move every `alive` (or `ready`, the cleanup targets all live tiers,
/// countryless) proxy with no resolved country into
/// `removed` (admin «cleanup» panel). `geo_country IS NULL` means the
/// country was never resolved, failed lookups keep NULL rather than
/// writing an empty string, so this predicate catches exactly the
/// never-resolved rows. Returns how many rows were affected.
pub async fn remove_alive_without_country(pool: &DbPool) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(
        "UPDATE proxies SET
             status = 'removed',
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             removed_at = ?,
             updated_at = ?
         WHERE status IN ('alive', 'ready') AND geo_country IS NULL",
    )
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Move every `alive` (or `ready`, the cleanup targets all live tiers)
/// proxy of the given autonomous system into `removed` (admin «cleanup»
/// panel). `asn` is the AS number in either spelling, `12345` or
/// `AS12345`, and is normalised to the canonical `AS{n}` text the
/// `geo_asn` column stores ([`crate::geo::canonical_asn`]).
/// An input that is not an AS number removes nothing.
/// Returns how many rows were affected.
pub async fn remove_alive_by_asn(pool: &DbPool, asn: &str) -> crate::Result<u64> {
    let Some(canonical) = crate::geo::canonical_asn(asn) else {
        return Ok(0);
    };
    let now = crate::models::now_ts();
    let result = sqlx::query(
        "UPDATE proxies SET
             status = 'removed',
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             removed_at = ?,
             updated_at = ?
         WHERE status IN ('alive', 'ready') AND geo_asn = ?",
    )
    .bind(now)
    .bind(now)
    .bind(canonical)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Move every `alive` (or `ready`, the cleanup targets all live tiers)
/// proxy of the given country into `removed` (admin «cleanup» panel).
/// `code` is an ISO-3166-1 alpha-2 code, e.g. `"DE"`. Returns how many
/// rows were affected.
pub async fn remove_alive_by_country(pool: &DbPool, code: &str) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(
        "UPDATE proxies SET
             status = 'removed',
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             removed_at = ?,
             updated_at = ?
         WHERE status IN ('alive', 'ready') AND geo_country = ?",
    )
    .bind(now)
    .bind(now)
    .bind(code)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Move every `unknown` proxy of an unprobeable scheme into `removed`
/// (admin «cleanup» panel). tuic/mieru cannot be checked at all
/// (T1-unjudgeable), so such rows sit in `unknown` forever unless the admin retires
/// them; probeable schemes are untouched, their `unknown` rows are
/// simply not yet checked. Returns how many rows were affected.
pub async fn remove_unprobeable_unknown(pool: &DbPool) -> crate::Result<u64> {
    let now = crate::models::now_ts();
    let result = sqlx::query(
        "UPDATE proxies SET
             status = 'removed',
             quarantined_at = NULL,
             ladder_at = NULL,
             ladder_step = 0,
             removed_at = ?,
             updated_at = ?
         WHERE status = 'unknown' AND scheme IN ('tuic', 'mieru')",
    )
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// Probe state machine
//
// The probe daemon is the sole driver; every transition is a single atomic
// UPDATE so a crash between "check finished" and "state written" cannot
// corrupt the lifecycle. All scheduling timestamps live in the DB, which
// makes the daemon restart-safe and idempotent.

// The quarantine schedule is a generic ladder: step 0 is the
// second chance inside the `[24h, 48h)` window after quarantining, steps
// `1..=N` are the consecutive rechecks whose delays come from
// `[probe] recheck_delays_secs` (default 15m / 30m / 1h). The failed step
// number travels with the row in `ladder_step`; `ladder_at` holds the
// moment the next check fires. Failing step `k` schedules `delays[k]` ,
// or, past the end of the configured delays, removes the proxy.

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
    /// The entry the stored columns describe.
    ///
    /// The probe needs the parameters to answer two questions about the
    /// node — does it speak TLS, and which name does its handshake present
    /// — and both are answered from the same parameter set the ingest
    /// parsed and the output writers read.
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
/// probe candidate carries.
///
/// The parameters come back from their JSON projection, the same text the
/// ingest wrote; the credential and the raw line are not part of a
/// connectivity check and stay empty.
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

/// The parameters a stored params column holds, as an ordered list.
///
/// The column is a JSON object, so the order is the one the object has;
/// a non-string value is stored as its textual form.
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
    /// successful check reports this — a first verdict on an `unknown`
    /// row just as much as the end of a quarantine — so the name is
    /// deliberately not "revived": a plain `unknown → alive` success is
    /// not a revival and must not be counted as one.
    Succeeded,
    /// The final recheck failed: now `removed`.
    Removed,
}

/// Schemes the T1 connectivity check cannot judge: a TCP/TLS
/// connect to a UDP-only port would quarantine healthy proxies. Shared by
/// the random sample and the priority queue; tuic/mieru are additionally
/// absent from T2 (meow-rs cannot tunnel them).
pub const T1_EXCLUDED_SCHEMES: &[&str] = &["hysteria2", "tuic", "mieru"];

/// The WHERE fragment every T1 lane shares: the row is in one of the
/// lane's statuses (a fixed literal of the caller, never request text),
/// its scheme is T1-probeable ([`T1_EXCLUDED_SCHEMES`]) and it is still
/// linked to a source. The excluded-scheme placeholders bind the
/// [`T1_EXCLUDED_SCHEMES`] values, in order, wherever the fragment sits
/// in the statement.
///
/// The T2-suppression guard (`last_t2_failed_at IS NULL`) is deliberately
/// not part of it: the priority enqueue does not apply that guard, and
/// the two select lanes add it explicitly on top of this fragment (see
/// [`select_t1_candidates`] and `crate::repo::probe::select_queued_checks`).
pub(crate) fn t1_lane_predicate(statuses: &str) -> String {
    let excluded = vec!["?"; T1_EXCLUDED_SCHEMES.len()].join(", ");
    format!(
        "{statuses}
           AND p.scheme NOT IN ({excluded})
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)"
    )
}

/// Schemes meow-rs can actually tunnel (the T2 allowlist). Mirrors
/// `fumox_core::formats::clash::is_supported`, the probe filters the
/// batch by it after
/// the SQL, so the selector must not offer rows that would only be dropped
/// again: under the recency-priority order a perpetually uncheckable row
/// would otherwise sit at the head of the sample forever (starvation).
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
/// knob between per-cycle cost (rows fetched and sorted) and how much of
/// the pool one draw ranges over; 4 keeps the fetch a rounding error next
/// to the checks themselves while the anchor sweep still covers the pool.
const SAMPLE_WINDOW_FACTOR: u32 = 4;

/// A bind value of the shared bounded-window selector: the lane
/// predicates only ever bind timestamps and scheme names.
enum SelectorBind {
    Int(i64),
    Text(&'static str),
}

/// The id of a row the bounded-window sampler fetched.
///
/// The sampler needs it to continue the window *below* the last row it
/// read: the window is a ring segment, so the second leg starts where the
/// first one stopped.
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
/// *eligible* rows' own id range.
///
/// The range is the eligible one, not the table's: a lane that only serves
/// a fraction of the rows must not spend its draw on the ids of the rows
/// it cannot serve. The random source is a parameter so a test can pin
/// the draw; the production call passes the thread RNG.
fn choose_anchor<R: rand::RngExt>(min_id: i64, max_id: i64, rng: &mut R) -> i64 {
    rng.random_range(min_id..=max_id)
}

/// The Fisher–Yates shuffle of the fetched window.
///
/// Every row of the window has the same chance to survive the cut, so the
/// sample is uniform over the window. The random source is a parameter so
/// a test can pin the permutation.
fn shuffle_window<T, R: rand::RngExt>(rows: &mut [T], rng: &mut R) {
    use rand::seq::SliceRandom;
    rows.shuffle(rng);
}

/// One leg of a bounded-window draw: up to `window` eligible rows on one
/// side of `anchor` in id order. The id comparison rides the rowid index,
/// so the leg stops after `window` matches without materializing the rest
/// of the pool: the property `ORDER BY RANDOM() LIMIT ?` lacks (it must
/// visit and temp-sort every matching row before the LIMIT applies).
///
/// The full statement is assembled by the caller (one string per ring
/// leg; the legs differ only in the fixed id-comparison fragment, a
/// literal of this module, never caller text), this helper only binds
/// and runs what it is given.
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
/// the id range they span.
///
/// One aggregate pass over the predicate, so the sampler knows both the
/// size of the pool it draws from and the id space the draw has to
/// cover. The range is the *eligible* one: an anchor drawn over the
/// whole table's id space lands on rows the lane cannot serve, and the
/// rows below the first eligible id are then reachable only from a
/// vanishingly narrow band of anchors.
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
/// The draw has three steps:
///
/// 1. the eligible pool is counted and its id range measured in one
///    aggregate pass ([`eligible_pool_bounds`]);
/// 2. the anchor is drawn uniformly from that id range, and the window is
///    the `SAMPLE_WINDOW_FACTOR * limit` eligible rows that follow it in
///    **id order, wrapping around the end of the range** — the window is
///    a ring segment, so every anchor contributes exactly the same number
///    of rows and every eligible row is covered by the same number of
///    anchors;
/// 3. the window is shuffled and cut to `limit`.
///
/// The ring is what makes the draw fair. A window that stops at the end
/// of the id range covers the lowest ids only from the anchors that sit
/// below them, and the lowest ids are exactly the ones an admin wants
/// re-probed; with the wrap, the bottom of the range is covered by the
/// anchors at the top, and no row of the pool is out of reach.
///
/// Sampling semantics: the marginal per-cycle chance of a row to land in
/// the sample is `limit / eligible-pool` when the eligible rows are
/// evenly spread over the id range, exactly as with a full-pool
/// `ORDER BY RANDOM()`. Where the eligible rows are unevenly spread
/// (a dense block of fresh rows next to a sparse tail of old ones), the
/// anchor is drawn in proportion to the local density, so a row is drawn
/// in proportion to the id span its neighbourhood occupies — the
/// neighbourhood of the same rows, which is what the anchor sweep can
/// reach without a full scan. A pool at or below the window size is
/// fetched whole, which *is* the full-pool shuffle and therefore exactly
/// uniform. What is traded away is independence within a cycle: rows are
/// drawn together with their id neighbours (the keyset-anchor compromise).
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
    // One full statement per ring leg: both legs read ascending (the
    // second starts *below* the first leg's head), they differ only in
    // the id comparison.
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
        // full-pool shuffle the windowed draw replaced.
        fetch_window::<T>(pool, &leg_sql(">="), binds, min_id, window).await?
    } else {
        // The anchor is drawn from the eligible rows' own id range, so
        // the rows the lane cannot serve never widen the draw.
        let anchor = choose_anchor(min_id, max_id, &mut rng);
        let mut window_rows =
            fetch_window::<T>(pool, &leg_sql(">="), binds, anchor, window).await?;
        // The ring continues at the *bottom* of the id range: the first
        // leg ran out of ids at the top, so the next ring successors are
        // the smallest eligible ids. Taking them from the bottom (not
        // from just below the segment's end) is what keeps the segment
        // contiguous in ring order and the two legs disjoint.
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

/// Random sample of probeable proxies for one T1 cycle.
///
/// Eligible: `unknown` or `alive` (quarantine rows follow their own
/// schedule; `removed` is terminal), still linked to at least one source,
/// and not one of the unprobeable schemes ([`T1_EXCLUDED_SCHEMES`]).
///
/// The sample comes from [`select_window_sample`]: a bounded window of the
/// eligible pool, anchored in the eligible rows' own id range and wrapped
/// around the end of it, shuffled down to `limit`, in place of the
/// full-pool `ORDER BY RANDOM()` this used to run on every cycle against
/// the shared SQLite file. Per-cycle inclusion odds are `limit / eligible
/// pool` for an evenly spread pool; what the window trades away is
/// independence between neighboring rows within one cycle (see
/// [`select_window_sample`]).
pub async fn select_t1_candidates(pool: &DbPool, limit: u32) -> crate::Result<Vec<T1Candidate>> {
    // The T2 block is this lane's explicit addition to the shared
    // candidate predicate (see [`t1_lane_predicate`]): a T2 failure
    // suppresses T1 until the next successful T2.
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

/// Batch for a T2 tunnel check through meow-rs: every `alive`
/// **and `ready`** proxy of a T2-supported scheme (T2 re-verifies the
/// tunnel; `ready` must be re-checked or a failed T2 could never demote
/// it), plus `unknown` hysteria2, hysteria2 is
/// excluded from T1 by design (a TCP connect to a QUIC port proves
/// nothing), so T2 is its first and only check; a failure
/// counts through the regular `fail_limit`, it does not quarantine
/// straight away.
///
/// The order is **checked longest ago first**:
/// proxies with no T2 attempt yet come first, then the ones whose last T2
/// check is the oldest, `ORDER BY RANDOM()` could leave a proxy
/// tunnel-unverified for months in a large pool while its `alive` status
/// rested on T1 connectivity alone. The like-for-like counterpart of the
/// T1 priority queue: the first real verdict arrives within one
/// cycle, the rest of the population follows by recency. The moment of
/// the last attempt is the denormalised `last_t2_checked_at` stamp on the
/// proxy row (migration 0014), which the journal write path keeps up to
/// date; `idx_proxies_last_t2_checked_at` answers the order without a
/// sort step. SQLite sorts NULLs first in ascending order, so the
/// never-checked tier comes before everything else, then the oldest last
/// checks. Among peers with the same recency the row order is
/// id-ascending, which spreads the batch across the pool as it cycles
/// through it.
///
/// The stamp is permanent while the journal it was derived from is not:
/// the retention sweep trims `probe_results`, and a proxy whose history
/// was trimmed keeps its stamp instead of falling back into the
/// never-checked tier.
///
/// The caller drops the rows its T1 lanes already gave a verdict in the
/// same cycle before checking the batch: both lanes charge `fail_count`,
/// so a row covered by both quarantines in half the cycles `fail_limit`
/// promises (see the probe daemon's `run_cycle` hand-off).
pub async fn select_t2_candidates(pool: &DbPool, limit: u32) -> crate::Result<Vec<ProxyRow>> {
    // The allowlist is built from `T2_SCHEMES` so the SQL can never drift
    // from the const the mirror test pins (a hardcoded literal used to omit
    // snell/anytls, which silently kept those rows out of every T2 batch).
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

/// the recheck ladder) is due at `now`: every `quarantine` row
/// carries exactly one `ladder_at` (NULL only while a check is in flight),
/// so a single comparison suffices and the failed step travels in
/// `ladder_step`.
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
/// [`T2_REVIVAL_SCHEMES`] schemes, as full rows: the tunnel check needs the
/// credentials and the ladder step that [`DueQuarantine`] omits.
///
/// Drawn through [`select_window_sample`] like its T1-side sibling: a
/// bounded id-anchored window shuffled down to `limit`, so a quarantine
/// backlog cannot push a full-pool random sort into every cycle.
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
    // Fixed literal per target tier, never a bind of caller text.
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

/// Apply a failed regular check (proxy was `unknown`, `alive` or `ready`).
///
/// `now` is Unix time in seconds ([`crate::models::now_ts()`]). Increments
/// `fail_count`; when the consecutive-failure limit is reached the proxy
/// moves to `quarantine` and its second chance is scheduled at
/// `quarantined_at + min + U(0..spread)`, the `[12h, 16h)` window of the
/// shipped defaults (`[probe] fail_limit` = 3, `[probe]
/// second_chance_min_hours` = 12, `[probe] second_chance_spread_hours` =
/// 4). The jitter is drawn here, in the core, so
/// the moment is fixed in the DB and survives daemon restarts.
///
/// A `ready` row that fails (below the limit) is demoted to `alive`:
/// the tunnel-verified tier only lasts
/// while the latest T2 outcome is a success, the next successful T2
/// promotes it back.
///
/// `mark_t2_failed` records the moment on `last_t2_failed_at`. Only
/// T2-side failures pass `true`: a T1 failure keeps the field untouched,
/// because a TCP/TLS miss does not mean the tunnel is dead and T1 has to
/// keep retrying on its own schedule. Set by [`check_failed`] callers
/// that handle T2 outcomes (see [`crate::repo::probe`] / the probe
/// daemon's `journal_and_fail`).
///
/// The counter is read and written by the same statement (the ladder is
/// a `CASE` expression over the row's own `fail_count`), so two
/// overlapping checks of the same row cannot lose an increment; and the
/// write repeats the `status IN ('unknown', 'alive', 'ready')` guard, so
/// it cannot resurrect a row that left the eligible statuses in between
/// (a `removed` row driven back into `quarantine` with a second chance
/// scheduled, undoing a terminal retirement). The guard makes the write a
/// no-op on a row that is no longer ours to touch, and the returned
/// [`Transition`] then reports what was actually written.
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

/// Apply the fail ladder to a batch of rows in one statement.
///
/// The per-row version opens a statement per row, and a batch of failed
/// tunnels meant a hundred round trips: every one of them took the write
/// lock, read a counter and wrote it back. This version writes the whole
/// batch with one `UPDATE` whose `CASE` expressions read the row's own
/// `fail_count`, so the batch costs one lock and one commit and no
/// counter can be read stale.
///
/// The per-row semantics are unchanged: the counter is read and written
/// by the same expression, the write repeats the `status IN ('unknown',
/// 'alive', 'ready')` guard, and the returned transitions report what
/// was actually written; a row that vanished or left the eligible
/// statuses is not in the list.
///
/// One thing did change: the jitter of the second chance is drawn once
/// for the batch, not once per row, because the statement computes the
/// ladder itself and the spread has to be a bound value. The rows of one
/// batch therefore share their second-chance window.
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
    // rand 0.10: `random_range` moved from `Rng` to `RngExt`.
    use rand::RngExt;

    // The jitter of the second chance is drawn once for the batch: the
    // statement computes the ladder from each row's own counter, so the
    // spread has to be a bound value and not a per-row computation. The
    // rows of one batch therefore share their second-chance window.
    let jitter = if second_chance_spread_secs > 0 {
        rand::rng().random_range(0..second_chance_spread_secs)
    } else {
        0
    };
    let second_chance_at = now + second_chance_min_secs + jitter;

    // The whole batch is one statement: the ladder is a CASE expression
    // over the row's own `fail_count`, so the counter is read and
    // written by the same expression and no statement in between can
    // interleave. The write repeats the `status IN ('unknown', 'alive',
    // 'ready')` guard, so a row that left the eligible statuses is left
    // alone.
    //
    // Every right-hand side of the SET clauses reads the *old* row (SQL
    // semantics, and SQLite follows them), so `fail_count + 1` is the
    // counter the row would have after this failure in all of them.
    //
    // `RETURNING id, status` hands back the new status of every row the
    // statement touched, which is how the quarantine decisions are read
    // back: a row that came out as `quarantine` was quarantined by this
    // call, a row that is still `alive` was only demoted from `ready`.
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
        // The binds follow the textual order of the placeholders: the
        // ladder's limit and the second-chance stamp come first, the
        // T2 flag and the timestamps after them, the ids last.
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
/// (meow-rs) was down: a ping, config-reload or mid-batch failure, i.e. a
/// fault of *our* sidecar rather than a verdict about the proxy.
///
/// It keeps the two effects a T2 failure legitimately owns, the
/// `last_t2_failed_at` stamp (a T2 verdict is outstanding, so T1 stays
/// suppressed until a real T2 runs, [`check_succeeded`] is the only
/// lifter) and the `ready` → `alive` demote (the tunnel-verified tier only
/// lasts while the latest T2 was a success). It deliberately does **not**
/// touch `fail_count` and never quarantines: the shipped `[probe]
/// fail_limit` of 3 would otherwise quarantine a fully healthy proxy
/// after three outage cycles, dropping it out of both T2 selectors and
/// out of `/export/alive` for a fault it did not cause. The outage itself
/// is still visible: the probe journals the attempt, backs the engine off
/// and logs the batch (see the probe's `journal_engine_fault`).
///
/// The write is a single statement, so no read-modify-write transaction is
/// needed (nothing is computed from the current row). The status guard is
/// the same one [`check_failed`] uses, a `quarantine`/`removed` row keeps
/// its own schedule.
///
/// Returns whether the row was in a regular-check state and got stamped;
/// `false` means it had left those states (quarantined or removed by
/// somebody else) and was left alone, exactly the "report what was
/// actually written" contract of [`check_failed`].
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

/// Stamp a batch of rows as unverified by the engine, in one transaction.
///
/// The per-row version is one statement per row, and an engine outage
/// stamps every due row of the batch: a hundred rows meant a hundred
/// round trips before the cycle could move on.
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

/// Apply a failed quarantine check (second chance or a recheck ladder step).
///
/// The ladder is always scheduled relative to the moment of the failure that
/// triggered it: failing step `k` schedules the next
/// check at `now + delays[k]`, step 0 is the second chance, steps `1..`
/// are the rechecks. Failing the last configured step (or an empty
/// `delays` on the second chance) removes the proxy.
/// The delays come from `[probe] recheck_delays_secs` (default
/// 15m / 30m / 1h).
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
///
/// Each entry is `(id, now, step)`: the row, the moment of the failure and
/// the ladder step it failed at. The per-row version is one statement per
/// row, and a batch of failed revival checks settled them one after the
/// other.
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
            // quarantine (or never was in it) matched nothing, and
            // reporting `Removed` would claim a retirement that did not
            // happen — the same "report what was actually written"
            // contract [`check_failed`] keeps.
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
    /// Rows whose key was rewritten.
    pub rewritten: usize,
    /// Rows that described a node another row already described and were
    /// merged into it.
    pub merged: usize,
}

/// The `meta` key that records which fingerprint version the stored rows
/// carry. The recompute runs when it differs from the current one.
pub const FINGERPRINT_VERSION_KEY: &str = "fingerprint_version";

/// How many rows one recompute batch pulls and rewrites.
const REFINGERPRINT_BATCH: i64 = 500;

/// Recompute the stored fingerprints after a change of the canonical form.
///
/// The fingerprint version is part of the pre-image, so a change of the
/// canonical form changes every key: the rows written before the change
/// keep keys the ingest no longer produces, and the same node can live in
/// two rows — the old one and the new one the ingest created.
///
/// Every row is recomputed from its stored fields, so its key is the key
/// the ingest computes for the same node. Two rows that now describe the
/// same node are merged: the one with the better lifecycle status
/// survives, takes over the links, the state it lacks and the probe
/// history of the other, and the other is deleted. The node keeps its
/// status, its latency and its probe history instead of starting over at
/// `unknown`.
///
/// The rows are walked in bounded batches, each in its own short
/// transaction, so the write lock is never held over the whole table and
/// the probe daemon keeps working while the pass runs.
///
/// The pass is idempotent: a row whose key already matches its recomputed
/// one is left alone, so a second run costs a read and nothing else.
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

/// Bring the stored fingerprints up to the current version.
///
/// The version is part of the pre-image, so a change of the canonical form
/// changes every key: the rows written before the change keep keys the
/// ingest no longer produces, and the same node can live in two rows — the
/// old one and the new one the ingest created.
///
/// The recompute runs only when the stored rows carry another version. The
/// marker in `meta` names the version the rows were written with, so the
/// pass runs once per version change and not on every start. The pass is
/// idempotent, so a start that dies in the middle of it runs it again on
/// the next start.
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
                // recomputed; its key stays as it is.
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
        // may have created it after the upgrade.
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
                // The better row survives; the other one is merged into it.
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
                    // now that the row that held it is gone.
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

/// The state a merge moves from one row of a node to the other.
///
/// The fields are read from the row that goes away and written onto the
/// row that stays, field by field: the survivor keeps its own value and
/// the dropped row fills the gaps.
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
/// links move over, the state and the history of the node move with them,
/// and the dropped row goes away.
///
/// The history belongs to the node, not to the row that happened to store
/// it: two rows that describe one node share one journal, so the journal
/// rows move to the survivor instead of being deleted with the row that
/// held them. The state moves the same way — the survivor's own value
/// wins and the dropped row fills the gaps — so a node that was probed
/// before keeps its latency, its last check, its T2 stamps and its geo
/// facts even when the row that carried them is the one that goes away.
async fn merge_rows(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    keep: i64,
    drop: i64,
) -> crate::Result<()> {
    // The links move first: the surviving row takes over the sources the
    // dropped row was seen in, and keeps the most recent sighting of each.
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
    // The journal of the node follows it: the history rows are re-pointed
    // at the survivor, not deleted with the row that held them.
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
    // The state the survivor does not have moves with the journal.
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
    // The row itself goes away.
    sqlx::query("DELETE FROM proxies WHERE id = ?")
        .bind(drop)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// The lifecycle rank of a status: the row with the higher rank survives a
/// merge of two rows that describe the same node.
///
/// A row the probe has judged is worth more than a row that never got a
/// verdict: the judged row carries the state of the node, and a merge
/// that preferred the unjudged row would throw that verdict away and
/// hand the node back as a first-timer. A node the probe retired keeps
/// its verdict across a merge; it comes back through the paths that
/// exist for that (the ingest revives a retired node the feed still
/// carries, the panel revives a retired population), not through a merge
/// that happened to meet a fresh row. The most recently alive row wins a
/// tie, and the older row wins a tie beyond that, so the survivor keeps
/// the history.
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
