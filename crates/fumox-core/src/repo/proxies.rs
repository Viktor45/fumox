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
//!    protects behind, see [`mark_orphans_removed`]) is none of this
//!    source's business and stays as it is.

use super::BindWhereFilter;
use crate::db::DbPool;
use crate::geo::GeoInfo;
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
            asn: info.asn.map(|asn| format!("AS{asn}")),
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
#[derive(Debug, Clone, FromRow)]
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
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub geo_asn: Option<String>,
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

impl ProxyRow {
    /// Rebuild a serializable [`ProxyEntry`] from the stored row.
    ///
    /// The database stores parameters as two JSON objects (recognized /
    /// unknown), so the original on-the-wire order is not recoverable; the
    /// entry is still fully serializable. `raw_path` is not persisted (no
    /// schema column) and resets to empty.
    pub fn to_entry(&self) -> crate::Result<ProxyEntry> {
        let mut params: Vec<Param> = Vec::new();
        for (column, known) in [(&self.params, true), (&self.unknown_params, false)] {
            if let Some(text) = column {
                let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(text)
                    .map_err(|e| crate::Error::Parse(format!("corrupt proxy params JSON: {e}")))?;
                for (key, value) in map {
                    params.push(Param {
                        key,
                        value: value.as_str().unwrap_or_default().to_string(),
                        known,
                    });
                }
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
            raw_path: String::new(),
            raw_line: self.raw_line.clone().unwrap_or_default(),
        })
    }
}

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
/// `keep_alive_linger`: when `[ingest].drop_gate` is `false` (the
/// default), a proxy that vanished from the feed is nobody's business but
/// the probe's. This pass never retires anything, and it keeps the link
/// on every status the probe still owns (`alive`, `ready`, `unknown`,
/// `quarantine`), so upstream churn cannot end a node that has not
/// failed. The recheck ladder and the priority queue keep working on the
/// `quarantine` lingerer through its own `EXISTS (... link ...)`
/// predicate, and a row that comes back re-stamps its link on the next
/// refresh. When `drop_gate` is `true` and the source has `drop` rules,
/// the sweep and the unlink run unrestricted: a rule added later has to
/// reach the rows already stored, which is the whole point of the gate.
/// The admin's source deletion path (`mark_orphans_removed`) honours the
/// same flag, when it is `false`, `ready` and `unknown` rows are left
/// alone (`ready` is tunnel-verified, `unknown` has not yet had its
/// first verdict; the click that deleted the source should not retire
/// either); when it is `true`, every orphan retires.
pub async fn reconcile_source(
    pool: &DbPool,
    source_id: &str,
    entries: &[ProxyEntry],
    geo: &[Option<GeoStamp>],
    now: i64,
    keep_alive_linger: bool,
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
    // One multi-row statement per `UPSERT_CHUNK` entries, so the
    // transaction holds the WAL write lock for few round-trips: a per-row
    // loop kept it long enough for a large refresh to overrun the probe
    // daemon's `busy_timeout` and drop its journals.
    //
    // Two ceilings bound this, both of which "optimizing" it upward would
    // hit: 250 * 14 columns = 3500 binds, against SQLite's 32766-variable
    // limit, and a multi-row VALUES is a compound SELECT, against
    // SQLITE_MAX_COMPOUND_SELECT (500 in the bundled build, 256 in some
    // others). The link stamp below uses 500, which is at that ceiling.
    const UPSERT_CHUNK: usize = 250;
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
            vec!["(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"; chunk.len()].join(", ");
        let sql = format!(
            "INSERT INTO proxies
                (fingerprint, scheme, name, host, port, credential,
                 params, unknown_params, raw_line,
                 geo_country, geo_city, geo_asn, created_at, updated_at)
             VALUES {placeholders}
             ON CONFLICT(fingerprint) DO UPDATE SET
                name = excluded.name,
                params = excluded.params,
                unknown_params = excluded.unknown_params,
                raw_line = excluded.raw_line,
                geo_country = COALESCE(excluded.geo_country, proxies.geo_country),
                geo_city = COALESCE(excluded.geo_city, proxies.geo_city),
                geo_asn = COALESCE(excluded.geo_asn, proxies.geo_asn),
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
                .bind(geostamp.country)
                .bind(geostamp.city)
                .bind(geostamp.asn)
                .bind(now)
                .bind(now);
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
            query = query.bind(id).bind(source_id).bind(now);
        }
        query.execute(&mut *tx).await?;
    }

    // Drop links this fetch no longer saw, then mark orphaned proxies
    // removed (idempotent: proxies already removed keep their removed_at).
    // With `keep_alive_linger` an alive *or ready* proxy keeps a link the
    // fetch did not re-stamp, it stays linked to the source and keeps
    // running the probe cycle; only the probe's own verdict can end it
    // (`ready` is a live tier too).
    let unlinked_sql = if keep_alive_linger {
        "DELETE FROM proxy_source_links
         WHERE source_id = ?
           AND seen_at < ?
           AND proxy_id NOT IN (SELECT id FROM proxies
                                WHERE status IN ('alive', 'ready', 'unknown', 'quarantine'))"
    } else {
        "DELETE FROM proxy_source_links WHERE source_id = ? AND seen_at < ?"
    };
    // The retire sweep runs *before* the links go away and asks the
    // question this pass is actually responsible for: "which proxies
    // does the DELETE below leave with no link at all?" That is a
    // per-proxy answer about this source, not a global one. The
    // unscoped `NOT EXISTS (link)` version swept up every link-less row
    // in the table, including the deliberate residue of the admin
    // source-delete path: `mark_orphans_removed` protects `ready` and
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
                           WHERE l.proxy_id = proxies.id AND l.source_id = ? AND l.seen_at < ?)
               AND NOT EXISTS (SELECT 1 FROM proxy_source_links l
                               WHERE l.proxy_id = proxies.id
                                 AND NOT (l.source_id = ? AND l.seen_at < ?))";
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

/// Batch of `(id, host)` rows that carry no geo facts at all (all three
/// `geo_*` columns NULL), ordered by id past `after_id`, keyset pagination,
/// so rows the resolver cannot answer are skipped without reappearing.
pub async fn list_missing_geo(
    pool: &DbPool,
    after_id: i64,
    limit: i64,
) -> crate::Result<Vec<(i64, String)>> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, host FROM proxies
         WHERE id > ? AND geo_country IS NULL AND geo_city IS NULL AND geo_asn IS NULL
         ORDER BY id LIMIT ?",
    )
    .bind(after_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// How many rows still have every geo column NULL. The backfill summary
/// reports this: rows the resolver cannot answer stay NULL and are retried
/// on the next start, so the count is the honest "still missing" figure.
pub async fn count_missing_geo(pool: &DbPool) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxies
         WHERE geo_country IS NULL AND geo_city IS NULL AND geo_asn IS NULL",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Store resolved geo facts on one proxy row.
pub async fn update_geo(pool: &DbPool, id: i64, geo: &GeoStamp) -> crate::Result<()> {
    sqlx::query("UPDATE proxies SET geo_country = ?, geo_city = ?, geo_asn = ? WHERE id = ?")
        .bind(&geo.country)
        .bind(&geo.city)
        .bind(&geo.asn)
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

/// Check-coverage buckets of the whole population (probe overview panel):
/// `none`, no journaled attempt at all, `t1_only` / `t2_only`, exactly one
/// of the check tiers has history, `both`, T1 and T2 both do. T1 is
/// `probe_kind IN ('tcp', 'tls')`, T2 is `probe_kind = 't2'`.
///
/// The buckets cover *preserved* history only: `probe_results` rotates after
/// `[retention].probe_results_days`, so a long-unseen proxy may look
/// unverified even though it was checked once, the same view the probe
/// daemon itself has (the T2 recency selector reads the same rows).
/// The order is fixed and missing buckets are zero-filled, so the panel
/// never reshuffles when counts change.
pub async fn count_by_check_coverage(pool: &DbPool) -> crate::Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT bucket, COUNT(*) FROM (
             SELECT CASE
                 WHEN t1.e IS NOT NULL AND t2.e IS NOT NULL THEN 'both'
                 WHEN t1.e IS NOT NULL THEN 't1_only'
                 WHEN t2.e IS NOT NULL THEN 't2_only'
                 ELSE 'none'
             END AS bucket
             FROM proxies p
             LEFT JOIN (SELECT DISTINCT proxy_id, 1 AS e FROM probe_results
                        WHERE probe_kind IN ('tcp', 'tls')) t1 ON t1.proxy_id = p.id
             LEFT JOIN (SELECT DISTINCT proxy_id, 1 AS e FROM probe_results
                        WHERE probe_kind = 't2') t2 ON t2.proxy_id = p.id
         ) GROUP BY bucket",
    )
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
/// `probe_kind IN ('tcp', 'tls')`, T2 is `probe_kind = 't2'`.
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

    /// The EXISTS-based WHERE fragment of the bucket over `proxies p`.
    /// A fixed literal per variant: caller text never reaches the SQL.
    fn exists_clause(self) -> &'static str {
        match self {
            Self::None => "NOT EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id)",
            Self::T1Only => {
                "EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id \
                 AND r.probe_kind IN ('tcp', 'tls')) \
                 AND NOT EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id \
                 AND r.probe_kind = 't2')"
            }
            Self::T2Only => {
                "EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id \
                 AND r.probe_kind = 't2') \
                 AND NOT EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id \
                 AND r.probe_kind IN ('tcp', 'tls'))"
            }
            Self::Both => {
                "EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id \
                 AND r.probe_kind IN ('tcp', 'tls')) \
                 AND EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id \
                 AND r.probe_kind = 't2')"
            }
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

    fn order_sql(self) -> &'static str {
        match self {
            Self::Updated => "p.updated_at DESC, p.id DESC",
            Self::Latency => "p.latency_ms IS NULL ASC, p.latency_ms ASC, p.id DESC",
            Self::Name => "p.name COLLATE NOCASE ASC, p.id DESC",
        }
    }
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
    /// Substring match against host and name (`LIKE %q%`).
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
            let needle = format!("%{}%", self.query);
            wf = wf
                .text("(p.host LIKE ? OR p.name LIKE ?)", needle.clone())
                .text_value(needle);
        }
        if let Some(coverage) = self.coverage {
            wf = wf.clause(coverage.exists_clause());
        }
        wf
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
    /// Whether the preserved probe history carries any T1 attempt.
    pub t1_checked: bool,
    /// Whether the preserved probe history carries any T2 attempt.
    pub t2_checked: bool,
}

/// Count the rows the admin proxy browser would show for `filter` — the
/// same clause set [`list_filtered`] applies.
pub async fn count_filtered(pool: &DbPool, filter: &ProxyListFilter) -> crate::Result<i64> {
    let wf = filter.where_filter();
    let sql = format!("SELECT COUNT(*) FROM proxies p{}", wf.sql());
    let count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
        .bind_where_filter(wf.values())
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// One page of the admin proxy browser for `filter`, ordered by `order`.
/// `offset` is the plain SQL OFFSET; the caller clamps it (page arithmetic
/// saturates in the server layer).
pub async fn list_filtered(
    pool: &DbPool,
    filter: &ProxyListFilter,
    order: ProxyListOrder,
    limit: i64,
    offset: i64,
) -> crate::Result<Vec<ProxyListRow>> {
    let wf = filter.where_filter();
    let sql = format!(
        "SELECT p.id, p.scheme, p.name, p.host, p.port, p.status, p.latency_ms, p.geo_country,
                EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id
                        AND r.probe_kind IN ('tcp', 'tls')) AS t1_checked,
                EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = p.id
                        AND r.probe_kind = 't2') AS t2_checked
         FROM proxies p{}
         ORDER BY {}
         LIMIT ? OFFSET ?",
        wf.sql(),
        order.order_sql(),
    );
    let rows = sqlx::query_as::<_, ProxyListRow>(sqlx::AssertSqlSafe(sql))
        .bind_where_filter(wf.values())
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
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
#[derive(Debug, Clone, FromRow)]
pub struct ProxyWithSource {
    pub source_id: String,
    #[sqlx(flatten)]
    pub proxy: ProxyRow,
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

/// At most `limit` currently-`alive` proxies still linked to at least one
/// source, in stable id order, the backing query of the public «all alive»
/// export link. Fingerprints are unique in the table, so the set is
/// already deduplicated; unlinked rows are excluded just like everywhere
/// else proxies are served.
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
    let rows: Vec<ProxyRow> = sqlx::query_as(
        "SELECT p.* FROM proxies p
         WHERE p.status = 'alive'
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
         ORDER BY p.id
         LIMIT ?",
    )
    .bind(i64::from(limit).clamp(1, i64::MAX))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// At most `limit` currently-`ready` proxies (tunnel-verified tier) still
/// linked to at least one source, the verified twin of [`list_alive`],
/// backing the public `/export/ready/{token}` link. Same cap semantics,
/// same stable truncation.
pub async fn list_ready(pool: &DbPool, limit: u32) -> crate::Result<Vec<ProxyRow>> {
    let rows: Vec<ProxyRow> = sqlx::query_as(
        "SELECT p.* FROM proxies p
         WHERE p.status = 'ready'
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
         ORDER BY p.id
         LIMIT ?",
    )
    .bind(i64::from(limit).clamp(1, i64::MAX))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Number of proxies [`list_alive`] would return (admin screen badge).
pub async fn count_alive(pool: &DbPool) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxies p
         WHERE p.status = 'alive'
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Number of proxies [`list_ready`] would return (admin screen badge).
pub async fn count_ready(pool: &DbPool) -> crate::Result<i64> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxies p
         WHERE p.status = 'ready'
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// The lifecycle fields every pristine reset clears, shared verbatim by
/// [`reset_status`] and the `revive_*` statements so a new lifecycle
/// column cannot be reset in one path and missed in another (the miss is
/// what strands a row in no probe lane: a stale `last_t2_failed_at`
/// suppresses T1 and only a later T2 success lifts it, see
/// [`revive_removed_without_probe_history`]). Each statement adds the
/// pieces it owns around this core: `status` (the second
/// [`revive_removed_without_probe_history`] arm releases frozen `unknown`
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

/// Bulk revival (admin *Revival* panel): bring every `removed` proxy of
/// the given country back to `unknown`. The SQL is the same shape as
/// [`revive_removed`], but the WHERE filter keys on `geo_country`
/// instead of a fingerprint IN-list, the admin acts on the whole
/// filtered population in one statement, no fingerprint enumeration
/// needed. Returns the revived ids so the caller can hand them to the
/// priority-probe queue. A row with no source link is left `removed`:
/// no probe lane would ever reach it (see [`revive_removed`]).
pub async fn revive_removed_by_country(
    pool: &DbPool,
    code: &str,
    now: i64,
) -> crate::Result<Vec<i64>> {
    let sql = format!(
        "UPDATE proxies SET
             status = 'unknown',
             {RESET_SET},
             removed_at = NULL,
             updated_at = ?
         WHERE status = 'removed' AND geo_country = ?
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)
         RETURNING id"
    );
    // sqlx 0.9 SqlSafeStr: format! interpolation of RESET_SET only; data is bound.
    let rows: Vec<(i64,)> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(now)
        .bind(code)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Bulk revival (admin *Revival* panel): bring every `removed` proxy of
/// the given autonomous system back to `unknown`. `asn` is the bare
/// number (`"24940"` or `"AS24940"`), the canonical `AS{n}` form is
/// what `geo_asn` stores, so we build it once here. Returns the
/// revived ids for enqueueing; link-less rows stay `removed` (see
/// [`revive_removed`]).
pub async fn revive_removed_by_asn(pool: &DbPool, asn: &str, now: i64) -> crate::Result<Vec<i64>> {
    let sql = format!(
        "UPDATE proxies SET
             status = 'unknown',
             {RESET_SET},
             removed_at = NULL,
             updated_at = ?
         WHERE status = 'removed' AND geo_asn = ?
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)
         RETURNING id"
    );
    // sqlx 0.9 SqlSafeStr: format! interpolation of RESET_SET only; data is bound.
    let rows: Vec<(i64,)> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(now)
        .bind(format!("AS{asn}"))
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Bulk revival (admin *Revival* panel): every proxy that never received
/// a probe verdict, in either of the two states such a row can be stuck
/// in, comes back into the rotation.
///
/// The `NOT EXISTS` predicate is the historical record: any row in
/// `probe_results` for the proxy means the probe at least got to it,
/// which is a stronger signal than the source ever did.
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
/// Returns every revived id for enqueueing. Link-less rows are left
/// alone in both halves: no source link means no probe lane can reach
/// them (see [`revive_removed`]).
pub async fn revive_removed_without_probe_history(
    pool: &DbPool,
    now: i64,
) -> crate::Result<Vec<i64>> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let removed_sql = format!(
        "UPDATE proxies SET
             status = 'unknown',
             {RESET_SET},
             removed_at = NULL,
             updated_at = ?
         WHERE status = 'removed'
           AND NOT EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = proxies.id)
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)
         RETURNING id"
    );
    let mut ids: Vec<i64> = sqlx::query_as(sqlx::AssertSqlSafe(removed_sql.as_str()))
        .bind(now)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|(id,)| id)
        .collect();

    // The frozen-`unknown` arm keeps the row's status (and its absent
    // `removed_at`) and takes only the shared reset core.
    let frozen_sql = format!(
        "UPDATE proxies SET
             {RESET_SET},
             updated_at = ?
         WHERE status = 'unknown'
           AND last_t2_failed_at IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM probe_results r WHERE r.proxy_id = proxies.id)
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)
         RETURNING id"
    );
    ids.extend(
        sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(frozen_sql.as_str()))
            .bind(now)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|(id,)| id),
    );

    tx.commit().await?;
    Ok(ids)
}

/// Bulk revival (admin *Revival* panel): bring every `quarantine` proxy
/// back to `unknown`, skipping the recheck ladder. Symmetric to
/// [`quarantine_to_removed`]. The lifecycle fields that
/// `quarantine_to_removed` clears are the same ones `revive_removed`
/// clears, `quarantined_at`, `ladder_at`, `ladder_step`, `fail_count`.
/// `removed_at` stays NULL because quarantined rows never had a
/// `removed_at`. Returns the revived ids for enqueueing; link-less rows
/// stay `quarantine` (see [`revive_removed`]: a revived row with no
/// source link is in no probe lane, the ladder it was on is exactly the
/// one this call drops). `last_t2_failed_at` is cleared like everywhere
/// else a revival happens, for the same reason.
pub async fn revive_quarantine(pool: &DbPool, now: i64) -> crate::Result<Vec<i64>> {
    let sql = format!(
        "UPDATE proxies SET
             status = 'unknown',
             {RESET_SET},
             updated_at = ?
         WHERE status = 'quarantine'
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)
         RETURNING id"
    );
    // sqlx 0.9 SqlSafeStr: format! interpolation of RESET_SET only; data is bound.
    let rows: Vec<(i64,)> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(now)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
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

/// Mark proxies that lost their last source link as `removed`
/// (deleting a source is soft, orphaned
/// proxies are not physically deleted, they transition to `removed`.
/// `removed` is terminal for reconciliation: a proxy that reappears in a
/// fetch keeps its state, the ways back are the admin "reset status"
/// action or purge removed followed by a re-insert). Returns how many
/// proxies were affected.
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
pub async fn mark_orphans_removed(
    pool: &DbPool,
    protected_statuses: &[&str],
) -> crate::Result<u64> {
    // sqlx's `query` with no bound values still uses a fixed query, the
    // protected-status list only widens the WHERE clause when non-empty
    // (so the no-protection path keeps the original single-statement
    // shape). The slice is built from caller-controlled literals; we
    // expand it into a parameterised `IN (?, ?, …)` list rather than
    // concatenating it into SQL.
    let mut sql = String::from(
        "UPDATE proxies SET status = 'removed', removed_at = ?, updated_at = ?
         WHERE status != 'removed'
           AND id NOT IN (SELECT proxy_id FROM proxy_source_links)",
    );
    if !protected_statuses.is_empty() {
        let placeholders = vec!["?"; protected_statuses.len()].join(", ");
        sql.push_str(&format!(" AND status NOT IN ({placeholders})"));
    }
    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(crate::models::now_ts())
        .bind(crate::models::now_ts());
    for status in protected_statuses {
        query = query.bind(*status);
    }
    let result = query.execute(pool).await?;
    Ok(result.rows_affected())
}

/// Physically delete every `removed` proxy and, via `ON DELETE CASCADE`,
/// its source links and probe/speed history («purge
/// removed»). This is the only hard delete in the system, the bulk
/// cleanup actions above it only transition rows *into* `removed`, and
/// is guarded by a confirmation dialog in the admin UI. Returns the
/// number of deleted proxy rows.
pub async fn purge_removed(pool: &DbPool) -> crate::Result<u64> {
    let result = sqlx::query("DELETE FROM proxies WHERE status = 'removed'")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
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
/// panel). `asn` is the bare AS number, `"12345"`, not `"AS12345"`, and
/// is stored/compared in the canonical `AS{n}` text format of `geo_asn`.
/// Returns how many rows were affected.
pub async fn remove_alive_by_asn(pool: &DbPool, asn: &str) -> crate::Result<u64> {
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
    .bind(format!("AS{asn}"))
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

/// Result of applying a check outcome to the lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Still `unknown`/`alive`; the fail counter was bumped (or reset).
    Unchanged,
    /// The consecutive-failure limit was reached: now `quarantine` with a
    /// second chance scheduled.
    Quarantined,
    /// A quarantine check succeeded: back to `alive` with a clean slate.
    Revived,
    /// The final recheck failed: now `removed`.
    Removed,
}

/// Schemes the T1 connectivity check cannot judge: a TCP/TLS
/// connect to a UDP-only port would quarantine healthy proxies. Shared by
/// the random sample and the priority queue; tuic/mieru are additionally
/// absent from T2 (meow-rs cannot tunnel them).
pub const T1_EXCLUDED_SCHEMES: &[&str] = &["hysteria2", "tuic", "mieru"];

/// Schemes meow-rs can actually tunnel (the T2 allowlist). Mirrors
/// `fumox_probe::clash::is_supported`, probe filters the batch by it after
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

/// Schemes whose quarantined rows revive through the T2 tunnel check — a TCP
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

/// One leg of a bounded-window draw: up to `window` eligible rows on one
/// side of `anchor` in id order. The id comparison rides the rowid index,
/// so the leg stops after `window` matches without materializing the rest
/// of the pool — the property `ORDER BY RANDOM() LIMIT ?` lacks (it must
/// visit and temp-sort every matching row before the LIMIT applies). The
/// comparison and order fragments are fixed literals of this module
/// (`>=`, `<`, `ASC`, `DESC`), never caller text.
async fn fetch_window_leg<T>(
    pool: &DbPool,
    select_list: &str,
    predicate: &str,
    binds: &[SelectorBind],
    comparison: &str,
    order: &str,
    anchor: i64,
    window: i64,
) -> crate::Result<Vec<T>>
where
    T: for<'r> FromRow<'r, sqlx::sqlite::SqliteRow> + Send + Unpin,
{
    let sql = format!(
        "SELECT {select_list}
         FROM proxies p
         WHERE {predicate} AND p.id {comparison} ?
         ORDER BY p.id {order}
         LIMIT ?"
    );
    let mut query = sqlx::query_as::<_, T>(sqlx::AssertSqlSafe(sql.as_str()));
    for bind in binds {
        query = match bind {
            SelectorBind::Int(value) => query.bind(*value),
            SelectorBind::Text(scheme) => query.bind(*scheme),
        };
    }
    Ok(query.bind(anchor).bind(window).fetch_all(pool).await?)
}

/// Draw `limit` rows at random from a *bounded window* of the eligible
/// pool instead of shuffling the pool itself: anchor at a uniformly random
/// `id`, read the first `SAMPLE_WINDOW_FACTOR * limit` eligible rows
/// upward in id order, wrap once below the anchor when the head of the id
/// space came up short (a fresh or sparse tail, or an anchor past the last
/// eligible row), Fisher–Yates-shuffle the fetched window and cut it to
/// `limit`. The two legs are disjoint (`id >= anchor` vs `id < anchor`)
/// and together form one contiguous ring segment around the anchor, so
/// the cut is a uniform draw from the window and the DESC wrap keeps the
/// segment ring-contiguous instead of pinning it to the bottom of the
/// table.
///
/// Sampling semantics: the marginal per-cycle chance of a row to land in
/// the sample stays `limit / eligible-pool`, exactly as with a full-pool
/// `ORDER BY RANDOM()`, and a pool at or below the window size is fetched
/// whole, which *is* that full-pool shuffle. What is traded away is
/// independence within a cycle: rows are drawn together with their id
/// neighbors (the keyset-anchor compromise), and a locally denser
/// eligible region gets a proportionally smaller per-cycle draw while the
/// uniform anchor sweep keeps long-run coverage even.
async fn select_window_sample<T>(
    pool: &DbPool,
    select_list: &str,
    predicate: &str,
    binds: &[SelectorBind],
    limit: u32,
) -> crate::Result<Vec<T>>
where
    T: for<'r> FromRow<'r, sqlx::sqlite::SqliteRow> + Send + Unpin,
{
    use rand::RngExt;
    use rand::seq::SliceRandom;

    if limit == 0 {
        return Ok(Vec::new());
    }
    let window = i64::from(limit) * i64::from(SAMPLE_WINDOW_FACTOR);
    // Uniform anchor over the id space; `MAX(id)` is a single b-tree seek.
    // Ids are roughly insertion-ordered, so the anchor sweep visits the
    // whole population over time; gaps left by removed rows just shift
    // the window start to the next surviving row.
    let (max_id,): (i64,) = sqlx::query_as("SELECT COALESCE(MAX(id), 0) FROM proxies")
        .fetch_one(pool)
        .await?;
    let anchor = if max_id == 0 {
        0
    } else {
        rand::rng().random_range(0..=max_id)
    };

    let mut rows = fetch_window_leg::<T>(
        pool,
        select_list,
        predicate,
        binds,
        ">=",
        "ASC",
        anchor,
        window,
    )
    .await?;
    if rows.len() < limit as usize && anchor > 0 {
        rows.extend(
            fetch_window_leg::<T>(
                pool,
                select_list,
                predicate,
                binds,
                "<",
                "DESC",
                anchor,
                window,
            )
            .await?,
        );
    }
    rows.shuffle(&mut rand::rng());
    rows.truncate(limit as usize);
    Ok(rows)
}

/// Random sample of probeable proxies for one T1 cycle.
///
/// Eligible: `unknown` or `alive` (quarantine rows follow their own
/// schedule; `removed` is terminal), still linked to at least one source,
/// and not one of the unprobeable schemes ([`T1_EXCLUDED_SCHEMES`]).
///
/// The sample comes from [`select_window_sample`]: a bounded id-anchored
/// window of the eligible pool, shuffled down to `limit`, in place of the
/// full-pool `ORDER BY RANDOM()` this used to run on every cycle against
/// the shared SQLite file. Per-cycle inclusion odds are unchanged
/// (`limit / eligible pool`); what the window trades away is independence
/// between neighboring rows within one cycle (see [`select_window_sample`]).
pub async fn select_t1_candidates(pool: &DbPool, limit: u32) -> crate::Result<Vec<T1Candidate>> {
    let excluded = vec!["?"; T1_EXCLUDED_SCHEMES.len()].join(", ");
    let predicate = format!(
        "p.status IN ('unknown', 'alive')
           AND p.scheme NOT IN ({excluded})
           AND p.last_t2_failed_at IS NULL
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)"
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
/// cycle, the rest of the population follows by recency. The history
/// lookup goes through `idx_probe_t2_last` (partial index, migration 0006);
/// SQLite sorts NULLs first in ascending order, so the single `MAX`
/// expression yields both tiers, never-checked before everything else,
/// then the oldest last checks. Among peers with the same recency the row
/// order is id-ascending, which spreads the batch across the pool as it
/// cycles through it.
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
         ORDER BY (SELECT MAX(r.checked_at) FROM probe_results r
                   WHERE r.proxy_id = p.id AND r.probe_kind = 't2') ASC,
                  p.id ASC
         LIMIT ?"
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
/// Rows of the [`T2_REVIVAL_SCHEMES`] schemes are not offered here — their
/// lane is [`select_due_quarantine_t2`], so a due row is never charged by
/// both lanes in one cycle.
///
/// The due rows are drawn through [`select_window_sample`] (bounded
/// id-anchored window, shuffled down to `limit`): the due pool is usually
/// small, but a backlog outpacing the cycle must not push a full-pool
/// random sort into every cycle.
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
/// [`T2_REVIVAL_SCHEMES`] schemes, as full rows — the tunnel check needs the
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
        Transition::Revived
    } else {
        Transition::Unchanged
    })
}

/// Apply a failed regular check (proxy was `unknown`, `alive` or `ready`).
///
/// Increments `fail_count`; when the consecutive-failure limit is reached
/// the proxy moves to `quarantine` and its second chance is scheduled at
/// `quarantined_at + min + U(0..spread)`, the `[24h, 48h)` window by
/// default. The jitter is drawn here, in the core, so
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
/// The read of `fail_count` and the write that acts on it run in one
/// `BEGIN IMMEDIATE` transaction, and both writes repeat the
/// `status IN ('unknown', 'alive', 'ready')` guard of the read. The
/// counter is read-modified-write by nature, so splitting it into two
/// pool-level statements loses an increment whenever two checks of the
/// same row overlap; and the unguarded write would resurrect a row that
/// left the eligible statuses in between (a `removed` row driven back
/// into `quarantine` with a second chance scheduled, undoing a terminal
/// retirement). The transaction makes the pair atomic, the guard makes
/// the write a no-op on a row that is no longer ours to touch, and the
/// returned [`Transition`] then reports what was actually written.
pub async fn check_failed(
    pool: &DbPool,
    id: i64,
    now: i64,
    fail_limit: u32,
    second_chance_min_secs: i64,
    second_chance_spread_secs: i64,
    mark_t2_failed: bool,
) -> crate::Result<Transition> {
    // rand 0.10: `random_range` moved from `Rng` to `RngExt`.
    use rand::RngExt;

    // BEGIN IMMEDIATE: the read has to be inside the write transaction,
    // a deferred one would fail the read→write upgrade with
    // SQLITE_BUSY_SNAPSHOT, which busy_timeout does not cover (see
    // `reconcile_source`).
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT fail_count FROM proxies WHERE id = ? AND status IN ('unknown', 'alive', 'ready')",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((fail_count,)) = row else {
        // Row vanished or left the regular-check states concurrently
        // (quarantined by another worker, removed by reconciliation).
        return Ok(Transition::Unchanged);
    };

    let new_count = fail_count + 1;
    let (transition, written) = if new_count >= i64::from(fail_limit) {
        let jitter = if second_chance_spread_secs > 0 {
            rand::rng().random_range(0..second_chance_spread_secs)
        } else {
            0
        };
        let second_chance_at = now + second_chance_min_secs + jitter;
        let written = sqlx::query(
            "UPDATE proxies SET
                 status = 'quarantine',
                 fail_count = ?,
                 last_checked_at = ?,
                 quarantined_at = ?,
                 ladder_at = ?,
                 ladder_step = 0,
                 last_t2_failed_at = CASE WHEN ? THEN ? ELSE last_t2_failed_at END,
                 updated_at = ?
             WHERE id = ? AND status IN ('unknown', 'alive', 'ready')",
        )
        .bind(new_count)
        .bind(now)
        .bind(now)
        .bind(second_chance_at)
        .bind(mark_t2_failed)
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        (Transition::Quarantined, written)
    } else {
        let written = sqlx::query(
            "UPDATE proxies SET
                 status = CASE WHEN status = 'ready' THEN 'alive' ELSE status END,
                 fail_count = ?,
                 last_checked_at = ?,
                 last_t2_failed_at = CASE WHEN ? THEN ? ELSE last_t2_failed_at END,
                 updated_at = ?
             WHERE id = ? AND status IN ('unknown', 'alive', 'ready')",
        )
        .bind(new_count)
        .bind(now)
        .bind(mark_t2_failed)
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        (Transition::Unchanged, written)
    };
    tx.commit().await?;

    // The guard refused the write (the row left the eligible statuses
    // after all): report what happened, not what was attempted.
    Ok(if written > 0 {
        transition
    } else {
        Transition::Unchanged
    })
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
/// touch `fail_count` and never quarantines: the shipped `fail_limit` of 2
/// would otherwise quarantine a fully healthy proxy after two outage
/// cycles, dropping it out of both T2 selectors and out of
/// `/export/alive` for a fault it did not cause. The outage itself is
/// still visible: the probe journals the attempt, backs the engine off and
/// logs the batch (see the probe's `journal_engine_fault`).
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
    let next_delay = delays.get(step.max(0) as usize).copied();
    let (transition, next_at) = match next_delay {
        Some(delay) => (Transition::Unchanged, now + delay.max(0)),
        None => (Transition::Removed, 0),
    };

    if transition == Transition::Removed {
        sqlx::query(
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
        .execute(pool)
        .await?;
        return Ok(Transition::Removed);
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
    .execute(pool)
    .await?;
    Ok(transition)
}

#[cfg(test)]
#[path = "proxies_tests.rs"]
mod tests;
