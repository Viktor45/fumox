//! Proxy upsert and reconciliation (`proxies`, `proxy_source_links`).
//!
//! Reconciliation runs after every successful source fetch (DATABASE.md
//! «Reconciliation»):
//!
//! 1. every parsed entry is upserted by `fingerprint` — mutable fields (name,
//!    params, raw_line, geo) refresh, but the lifecycle state is never
//!    touched: `status`, `fail_count` and the quarantine fields are owned by
//!    the probe state machine, and a reappearing `removed`/`quarantine`
//!    proxy keeps them (owner decision 2026-08-31, superseding the DATABASE
//!    v0.4 resurrection rule);
//! 2. `proxy_source_links.seen_at` is stamped for every proxy still present;
//! 3. links of this source not stamped by the fetch are deleted; a proxy
//!    with no remaining links is marked `removed`.

use crate::db::DbPool;
use crate::geo::GeoInfo;
use crate::models::{Param, ProxyEntry, Scheme};
use sqlx::FromRow;

/// The geo facts of one proxy, as stored in the `proxies.geo_*` columns.
///
/// Produced by the server at ingest time (and by the startup backfill);
/// `None` fields mean "unknown", never "erase" — the upsert keeps existing
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
    /// may enqueue for priority probing — SPEC §8.3); unsorted, chunked
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
    pub second_chance_at: Option<i64>,
    pub recheck_15m_at: Option<i64>,
    pub recheck_30m_at: Option<i64>,
    pub recheck_1h_at: Option<i64>,
    pub removed_at: Option<i64>,
    pub latency_ms: Option<i64>,
    pub speed_mbps: Option<f64>,
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
/// Runs in a single transaction.
///
/// `geo` runs parallel to `entries` (indexed access; a shorter slice or a
/// `None` element means "no fresh geo facts" — the COALESCE upsert branch
/// then keeps whatever is already stored).
pub async fn reconcile_source(
    pool: &DbPool,
    source_id: &str,
    entries: &[ProxyEntry],
    geo: &[Option<GeoStamp>],
    now: i64,
) -> crate::Result<ReconciliationStats> {
    let mut stats = ReconciliationStats::default();
    // BEGIN IMMEDIATE: the first statement grabs the WAL write lock up
    // front instead of upgrading a read transaction mid-flight. A deferred
    // read→write upgrade fails with SQLITE_BUSY_SNAPSHOT (code 517) when
    // another process (probe daemon) committed since our snapshot was
    // taken — busy_timeout does not apply to that upgrade, so it surfaced
    // as "database is locked" on source refreshes. With IMMEDIATE the
    // whole critical section waits inside busy_timeout instead.
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    // Pre-existing fingerprints, for insert/update accounting.
    let fingerprints: Vec<String> = entries.iter().map(ProxyEntry::fingerprint).collect();
    let mut existing: std::collections::HashSet<String> = std::collections::HashSet::new();
    for chunk in fingerprints.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!("SELECT fingerprint FROM proxies WHERE fingerprint IN ({placeholders})");
        let mut query = sqlx::query_as::<_, (String,)>(&sql);
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
    let mut proxy_ids: Vec<i64> = Vec::with_capacity(entries.len());
    let mut seen_in_batch: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (idx, (entry, fingerprint)) in entries.iter().zip(&fingerprints).enumerate() {
        let params_json =
            super::json_to_text(&serde_json::Value::Object(entry.known_params_json()))?;
        let unknown_json =
            super::json_to_text(&serde_json::Value::Object(entry.unknown_params_json()))?;
        let geo = geo
            .get(idx)
            .and_then(|stamp| stamp.as_ref())
            .cloned()
            .unwrap_or_default();
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies
                (fingerprint, scheme, name, host, port, credential,
                 params, unknown_params, raw_line,
                 geo_country, geo_city, geo_asn, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(fingerprint) DO UPDATE SET
                name = excluded.name,
                params = excluded.params,
                unknown_params = excluded.unknown_params,
                raw_line = excluded.raw_line,
                geo_country = COALESCE(excluded.geo_country, proxies.geo_country),
                geo_city = COALESCE(excluded.geo_city, proxies.geo_city),
                geo_asn = COALESCE(excluded.geo_asn, proxies.geo_asn),
                updated_at = excluded.updated_at
             RETURNING id",
        )
        .bind(fingerprint)
        .bind(entry.scheme.as_str())
        .bind(&entry.name)
        .bind(&entry.host)
        .bind(entry.port)
        .bind(&entry.credential)
        .bind(&params_json)
        .bind(&unknown_json)
        .bind(&entry.raw_line)
        .bind(&geo.country)
        .bind(&geo.city)
        .bind(&geo.asn)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        proxy_ids.push(id);
        // A fingerprint already in the DB, or already upserted earlier in
        // this same batch, counts as an update.
        if existing.contains(fingerprint.as_str()) || !seen_in_batch.insert(fingerprint.as_str()) {
            stats.updated += 1;
        } else {
            stats.inserted += 1;
            stats.inserted_ids.push(id);
        }
    }

    // Stamp the links of everything still present in this source.
    for id in &proxy_ids {
        sqlx::query(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at)
             VALUES (?, ?, ?)
             ON CONFLICT(proxy_id, source_id) DO UPDATE SET seen_at = excluded.seen_at",
        )
        .bind(id)
        .bind(source_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    // Drop links this fetch no longer saw, then mark orphaned proxies
    // removed (idempotent: proxies already removed keep their removed_at).
    stats.unlinked =
        sqlx::query("DELETE FROM proxy_source_links WHERE source_id = ? AND seen_at < ?")
            .bind(source_id)
            .bind(now)
            .execute(&mut *tx)
            .await?
            .rows_affected() as usize;

    stats.removed = sqlx::query(
        "UPDATE proxies
         SET status = 'removed', removed_at = ?, updated_at = ?
         WHERE status != 'removed'
           AND NOT EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = proxies.id)",
    )
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected() as usize;

    tx.commit().await?;
    Ok(stats)
}

/// Batch of `(id, host)` rows that carry no geo facts at all (all three
/// `geo_*` columns NULL), ordered by id past `after_id` — keyset pagination,
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
pub async fn update_geo_full(
    pool: &DbPool,
    id: i64,
    geo: &GeoStamp,
    resolved_ip: &str,
) -> crate::Result<()> {
    sqlx::query(
        "UPDATE proxies SET geo_country = ?, geo_city = ?, geo_asn = ?, resolved_ip = ?
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

/// Load the deduplicated proxy set reachable from a list of sources, excluding
/// the given lifecycle statuses (health-filter, SPEC §8.5).
///
/// A proxy linked from several of the selected sources is returned once.
/// Ordering is stable (by id) so callers can apply their own `sort.by`.
pub async fn list_for_sources(
    pool: &DbPool,
    source_ids: &[String],
    exclude_statuses: &[crate::models::ProxyStatus],
) -> crate::Result<Vec<ProxyRow>> {
    if source_ids.is_empty() {
        return Ok(Vec::new());
    }
    let src_ph = vec!["?"; source_ids.len()].join(", ");
    // Never exclude by an empty NOT IN list — build a harmless always-false
    // placeholder set when nothing is excluded.
    let excluded: Vec<&str> = exclude_statuses
        .iter()
        .map(|status| status.as_str())
        .collect();
    let stat_ph = if excluded.is_empty() {
        "''".to_string()
    } else {
        vec!["?"; excluded.len()].join(", ")
    };
    let sql = format!(
        "SELECT p.* FROM proxies p
         WHERE p.id IN (
             SELECT l.proxy_id FROM proxy_source_links l WHERE l.source_id IN ({src_ph})
         )
         AND p.status NOT IN ({stat_ph})
         ORDER BY p.id"
    );
    let mut query = sqlx::query_as::<_, ProxyRow>(&sql);
    for id in source_ids {
        query = query.bind(id);
    }
    if !excluded.is_empty() {
        for status in &excluded {
            query = query.bind(status);
        }
    }
    let rows = query.fetch_all(pool).await?;
    // A proxy linked from multiple selected sources appears once thanks to
    // the IN-subquery, but guard defensively just in case.
    let mut seen = std::collections::HashSet::new();
    Ok(rows.into_iter().filter(|row| seen.insert(row.id)).collect())
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
/// processing (SPEC §5): a proxy linked from several of the selected
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
    let mut query = sqlx::query_as::<_, ProxyWithSource>(&sql);
    for id in source_ids {
        query = query.bind(id);
    }
    Ok(query.fetch_all(pool).await?)
}

/// Every currently-`alive` proxy still linked to at least one source, in
/// stable id order — the backing query of the public «all alive» export
/// link (SPEC §10.4). Fingerprints are unique in the table, so the set is
/// already deduplicated; unlinked rows are excluded just like everywhere
/// else proxies are served.
pub async fn list_alive(pool: &DbPool) -> crate::Result<Vec<ProxyRow>> {
    let rows: Vec<ProxyRow> = sqlx::query_as(
        "SELECT p.* FROM proxies p
         WHERE p.status = 'alive'
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
         ORDER BY p.id",
    )
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

/// Manual "re-check as new" action from the admin panel (ADMIN_PLAN §8):
/// reset the lifecycle to a pristine `unknown`, clearing the fail counter
/// and every quarantine / second-chance / recheck timestamp. The probe
/// daemon stays the sole owner of the state machine — this only puts the
/// proxy back at its starting square.
pub async fn reset_status(pool: &DbPool, id: i64) -> crate::Result<bool> {
    let result = sqlx::query(
        "UPDATE proxies SET
             status = 'unknown',
             fail_count = 0,
             quarantined_at = NULL,
             second_chance_at = NULL,
             recheck_15m_at = NULL,
             recheck_30m_at = NULL,
             recheck_1h_at = NULL,
             removed_at = NULL,
             updated_at = ?
         WHERE id = ?",
    )
    .bind(crate::models::now_ts())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
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
/// (ADMIN_PLAN §13.1 decision 9: deleting a source is soft — orphaned
/// proxies are not physically deleted, they transition to `removed`.
/// `removed` is terminal for reconciliation: a proxy that reappears in a
/// fetch keeps its state — the ways back are the admin "reset status"
/// action or purge removed followed by a re-insert). Returns how many
/// proxies were affected.
pub async fn mark_orphans_removed(pool: &DbPool) -> crate::Result<u64> {
    let result = sqlx::query(
        "UPDATE proxies SET status = 'removed', removed_at = ?, updated_at = ?
         WHERE status != 'removed'
           AND id NOT IN (SELECT proxy_id FROM proxy_source_links)",
    )
    .bind(crate::models::now_ts())
    .bind(crate::models::now_ts())
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Physically delete every `removed` proxy and, via `ON DELETE CASCADE`,
/// its source links and probe/speed history (ADMIN_PLAN §13.16 «purge
/// removed»). This is the only hard delete in the system and is guarded by
/// a confirmation dialog in the admin UI. Returns the number of deleted
/// proxy rows.
pub async fn purge_removed(pool: &DbPool) -> crate::Result<u64> {
    let result = sqlx::query("DELETE FROM proxies WHERE status = 'removed'")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------
// Probe state machine (SPEC §8.3, §8.3a, §8.4)
//
// The probe daemon is the sole driver; every transition is a single atomic
// UPDATE so a crash between "check finished" and "state written" cannot
// corrupt the lifecycle. All scheduling timestamps live in the DB, which
// makes the daemon restart-safe and idempotent.
// ---------------------------------------------------------------------------

/// Recheck ladder steps after a failed second chance (SPEC §8.3a), seconds.
pub const RECHECK_15M_SECS: i64 = 15 * 60;
pub const RECHECK_30M_SECS: i64 = 30 * 60;
pub const RECHECK_1H_SECS: i64 = 60 * 60;

/// Which scheduled quarantine check is due for a row (SPEC §8.3a ladder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineStage {
    /// The initial second chance inside the `[24h, 48h)` window.
    SecondChance,
    /// First recheck, 15 minutes after the second chance failed.
    Recheck15m,
    /// Second recheck, 30 minutes after the previous failure.
    Recheck30m,
    /// Final recheck, 1 hour after the previous failure; failing it removes
    /// the proxy.
    Recheck1h,
}

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
    /// Which scheduled check fired, derived from which `*_at` column matched.
    pub stage: String,
}

impl DueQuarantine {
    pub fn stage(&self) -> QuarantineStage {
        match self.stage.as_str() {
            "recheck_15m" => QuarantineStage::Recheck15m,
            "recheck_30m" => QuarantineStage::Recheck30m,
            "recheck_1h" => QuarantineStage::Recheck1h,
            _ => QuarantineStage::SecondChance,
        }
    }
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

/// Schemes the T1 connectivity check cannot judge (SPEC §8.5): a TCP/TLS
/// connect to a UDP-only port would quarantine healthy proxies. Shared by
/// the random sample and the priority queue; tuic/mieru are additionally
/// absent from T2 (meow-rs cannot tunnel them).
pub const T1_EXCLUDED_SCHEMES: &[&str] = &["hysteria2", "tuic", "mieru"];

/// Random sample of probeable proxies for one T1 cycle (SPEC §8.3: random
/// sampling spreads load and avoids bursts).
///
/// Eligible: `unknown` or `alive` (quarantine rows follow their own
/// schedule; `removed` is terminal), still linked to at least one source,
/// and not one of the unprobeable schemes ([`T1_EXCLUDED_SCHEMES`]).
/// `ORDER BY RANDOM()` keeps the sample unbiased without client-side
/// shuffling.
pub async fn select_t1_candidates(pool: &DbPool, limit: u32) -> crate::Result<Vec<T1Candidate>> {
    let excluded = vec!["?"; T1_EXCLUDED_SCHEMES.len()].join(", ");
    let sql = format!(
        "SELECT p.id, p.scheme, p.host, p.port, p.params
         FROM proxies p
         WHERE p.status IN ('unknown', 'alive')
           AND p.scheme NOT IN ({excluded})
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
         ORDER BY RANDOM()
         LIMIT ?"
    );
    let mut query = sqlx::query_as::<_, T1Candidate>(&sql);
    for scheme in T1_EXCLUDED_SCHEMES {
        query = query.bind(scheme);
    }
    query = query.bind(i64::from(limit));
    Ok(query.fetch_all(pool).await?)
}

/// Random sample of `alive` proxies eligible for a T2 tunnel check through
/// meow-rs (SPEC §8.2). T2 verifies real tunnel + credentials, so only
/// proxies that already passed T1 are sampled. tuic/mieru are excluded —
/// meow-rs cannot tunnel them (SPEC §8.5); hysteria2 is included (QUIC is
/// fine at T2, it only skips T1).
pub async fn select_t2_candidates(pool: &DbPool, limit: u32) -> crate::Result<Vec<ProxyRow>> {
    let rows: Vec<ProxyRow> = sqlx::query_as(
        "SELECT p.*
         FROM proxies p
         WHERE p.status = 'alive'
           AND p.scheme NOT IN ('tuic', 'mieru')
           AND EXISTS (SELECT 1 FROM proxy_source_links l WHERE l.proxy_id = p.id)
         ORDER BY RANDOM()
         LIMIT ?",
    )
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
/// the recheck ladder steps) is due at `now` (SPEC §8.3a).
///
/// Exactly one of the schedule columns is non-NULL at any time — each
/// transition clears the previous schedule before writing the next — so the
/// four branches are mutually exclusive and the derived stage is unambiguous.
pub async fn select_due_quarantine(
    pool: &DbPool,
    now: i64,
    limit: u32,
) -> crate::Result<Vec<DueQuarantine>> {
    let rows: Vec<DueQuarantine> = sqlx::query_as(
        "SELECT id, scheme, host, port, params,
                CASE
                    WHEN recheck_1h_at IS NOT NULL THEN 'recheck_1h'
                    WHEN recheck_30m_at IS NOT NULL THEN 'recheck_30m'
                    WHEN recheck_15m_at IS NOT NULL THEN 'recheck_15m'
                    ELSE 'second_chance'
                END AS stage
         FROM proxies
         WHERE status = 'quarantine'
           AND (
               (second_chance_at IS NOT NULL AND second_chance_at <= ?)
               OR (recheck_15m_at IS NOT NULL AND recheck_15m_at <= ?)
               OR (recheck_30m_at IS NOT NULL AND recheck_30m_at <= ?)
               OR (recheck_1h_at IS NOT NULL AND recheck_1h_at <= ?)
           )
         ORDER BY RANDOM()
         LIMIT ?",
    )
    .bind(now)
    .bind(now)
    .bind(now)
    .bind(now)
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Apply a successful check: the proxy is `alive`, every
/// quarantine/recheck timestamp cleared, `last_alive_at` stamped and the
/// measured latency stored. Covers `unknown → alive` (first success,
/// SPEC §8.4) and quarantine revival (SPEC §8.3a step 3/4) alike.
///
/// `reset_fail_count` implements the strict T2 priority (owner decision
/// 2026-08-29, SPEC §8.3): a T1 success must not wipe the fail counter
/// accumulated from T2 failures — the tunnel verdict stands until T2 itself
/// confirms the proxy or the quarantine ladder takes over. T2 successes and
/// second-chance revivals reset the counter unconditionally; a T1 success
/// resets it only when the last failed attempt was not a T2 one (the caller
/// asks [`crate::repo::probe::last_failed_kind`]).
///
/// `status != 'removed'` keeps a success from reviving a removed proxy:
/// `removed` is terminal — only the admin "reset status" action (or purge
/// removed followed by a re-insert from a fetch) returns a proxy to service.
pub async fn check_succeeded(
    pool: &DbPool,
    id: i64,
    now: i64,
    latency_ms: Option<i64>,
    reset_fail_count: bool,
) -> crate::Result<Transition> {
    let result = sqlx::query(
        "UPDATE proxies SET
             status = 'alive',
             fail_count = CASE WHEN ? THEN 0 ELSE fail_count END,
             last_checked_at = ?,
             last_alive_at = ?,
             latency_ms = COALESCE(?, latency_ms),
             quarantined_at = NULL,
             second_chance_at = NULL,
             recheck_15m_at = NULL,
             recheck_30m_at = NULL,
             recheck_1h_at = NULL,
             updated_at = ?
         WHERE id = ? AND status != 'removed'",
    )
    .bind(reset_fail_count)
    .bind(now)
    .bind(now)
    .bind(latency_ms)
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

/// Apply a failed regular check (proxy was `unknown` or `alive`).
///
/// Increments `fail_count`; when the consecutive-failure limit is reached
/// the proxy moves to `quarantine` and its second chance is scheduled at
/// `quarantined_at + min + U(0..spread)` — the `[24h, 48h)` window by
/// default (SPEC §8.3a step 2). The jitter is drawn here, in the core, so
/// the moment is fixed in the DB and survives daemon restarts.
pub async fn check_failed(
    pool: &DbPool,
    id: i64,
    now: i64,
    fail_limit: u32,
    second_chance_min_secs: i64,
    second_chance_spread_secs: i64,
) -> crate::Result<Transition> {
    use rand::Rng;

    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT fail_count FROM proxies WHERE id = ? AND status IN ('unknown', 'alive')",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some((fail_count,)) = row else {
        // Row vanished or left the regular-check states concurrently
        // (quarantined by another worker, removed by reconciliation).
        return Ok(Transition::Unchanged);
    };

    let new_count = fail_count + 1;
    if new_count >= i64::from(fail_limit) {
        let jitter = if second_chance_spread_secs > 0 {
            rand::rng().random_range(0..second_chance_spread_secs)
        } else {
            0
        };
        let second_chance_at = now + second_chance_min_secs + jitter;
        sqlx::query(
            "UPDATE proxies SET
                 status = 'quarantine',
                 fail_count = ?,
                 last_checked_at = ?,
                 quarantined_at = ?,
                 second_chance_at = ?,
                 updated_at = ?
             WHERE id = ?",
        )
        .bind(new_count)
        .bind(now)
        .bind(now)
        .bind(second_chance_at)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(Transition::Quarantined)
    } else {
        sqlx::query(
            "UPDATE proxies SET fail_count = ?, last_checked_at = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(new_count)
        .bind(now)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
        Ok(Transition::Unchanged)
    }
}

/// Apply a failed quarantine check (second chance or a recheck ladder step).
///
/// The ladder is always scheduled relative to the moment of the failure that
/// triggered it (SPEC §8.3a step 4): +15m after the second chance, +30m
/// after the first recheck, +1h after the second. Failing the third recheck
/// removes the proxy (SPEC §8.3a step 5).
pub async fn quarantine_check_failed(
    pool: &DbPool,
    id: i64,
    now: i64,
    stage: QuarantineStage,
) -> crate::Result<Transition> {
    let (transition, next_at, next_column) = match stage {
        QuarantineStage::SecondChance => (
            Transition::Unchanged,
            now + RECHECK_15M_SECS,
            "recheck_15m_at",
        ),
        QuarantineStage::Recheck15m => (
            Transition::Unchanged,
            now + RECHECK_30M_SECS,
            "recheck_30m_at",
        ),
        QuarantineStage::Recheck30m => (
            Transition::Unchanged,
            now + RECHECK_1H_SECS,
            "recheck_1h_at",
        ),
        QuarantineStage::Recheck1h => (Transition::Removed, 0, ""),
    };

    if transition == Transition::Removed {
        sqlx::query(
            "UPDATE proxies SET
                 status = 'removed',
                 last_checked_at = ?,
                 removed_at = ?,
                 second_chance_at = NULL,
                 recheck_15m_at = NULL,
                 recheck_30m_at = NULL,
                 recheck_1h_at = NULL,
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

    // Column name comes from the fixed match above, never from user input.
    let sql = format!(
        "UPDATE proxies SET
             last_checked_at = ?,
             second_chance_at = NULL,
             recheck_15m_at = NULL,
             recheck_30m_at = NULL,
             recheck_1h_at = NULL,
             {next_column} = ?,
             updated_at = ?
         WHERE id = ? AND status = 'quarantine'"
    );
    sqlx::query(&sql)
        .bind(now)
        .bind(next_at)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(transition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Scheme;
    use crate::models::{Encoding, Source};
    use crate::repo::sources as sources_repo;
    use crate::repo::tests::temp_pool;

    fn entry(name: &str, host: &str, port: u16) -> ProxyEntry {
        ProxyEntry {
            scheme: Scheme::Vless,
            name: name.to_string(),
            host: host.to_string(),
            port,
            credential: "uuid-1".to_string(),
            params: vec![Param {
                key: "security".to_string(),
                value: "reality".to_string(),
                known: true,
            }],
            raw_path: String::new(),
            raw_line: format!("vless://uuid-1@{host}:{port}#{name}"),
        }
    }

    async fn make_source(pool: &DbPool, id: &str) {
        let now = crate::models::now_ts();
        sources_repo::create(
            pool,
            &Source {
                id: id.to_string(),
                slug: None,
                name: id.into(),
                url: "https://example.com".into(),
                enabled: true,
                encoding: Encoding::Auto,
                input_format: None,
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
            },
        )
        .await
        .unwrap();
    }

    async fn status_of(pool: &DbPool, entry: &ProxyEntry) -> (String, i64) {
        let row = get_by_fingerprint(pool, &entry.fingerprint())
            .await
            .unwrap()
            .unwrap();
        (row.status, row.fail_count)
    }

    #[tokio::test]
    async fn inserts_new_proxies_as_unknown() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let entries = vec![
            entry("one", "h1.example.com", 443),
            entry("two", "h2.example.com", 8443),
        ];
        let stats = reconcile_source(&pool, "srcA0000000", &entries, &[], 1000)
            .await
            .unwrap();
        assert_eq!(stats.inserted, 2);
        assert_eq!(stats.inserted_ids.len(), 2);
        assert_eq!(stats.updated, 0);
        for e in &entries {
            assert_eq!(status_of(&pool, e).await, ("unknown".into(), 0));
        }

        // A refetch updates instead of inserting — no new ids are reported.
        let stats = reconcile_source(&pool, "srcA0000000", &entries, &[], 2000)
            .await
            .unwrap();
        assert_eq!(stats.updated, 2);
        assert!(stats.inserted_ids.is_empty());
    }

    #[tokio::test]
    async fn refetch_updates_name_and_keeps_probe_state() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let original = entry("old-name", "h1.example.com", 443);
        reconcile_source(
            &pool,
            "srcA0000000",
            std::slice::from_ref(&original),
            &[],
            1000,
        )
        .await
        .unwrap();

        // Simulate probe state accumulated since the first fetch.
        let fp = original.fingerprint();
        sqlx::query("UPDATE proxies SET status = 'alive', fail_count = 0, last_alive_at = 1500 WHERE fingerprint = ?")
            .bind(&fp)
            .execute(&pool)
            .await
            .unwrap();

        let renamed = entry("new-name", "h1.example.com", 443);
        let stats = reconcile_source(
            &pool,
            "srcA0000000",
            std::slice::from_ref(&renamed),
            &[],
            2000,
        )
        .await
        .unwrap();
        assert_eq!(stats.updated, 1);
        assert_eq!(stats.inserted, 0);

        let row = get_by_fingerprint(&pool, &fp).await.unwrap().unwrap();
        assert_eq!(row.name, "new-name");
        assert_eq!(row.status, "alive"); // probe state preserved
        assert_eq!(row.last_alive_at, Some(1500));
    }

    #[tokio::test]
    async fn disappearance_removes_proxy() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let kept = entry("kept", "h1.example.com", 443);
        let gone = entry("gone", "h2.example.com", 443);
        reconcile_source(
            &pool,
            "srcA0000000",
            &[kept.clone(), gone.clone()],
            &[],
            1000,
        )
        .await
        .unwrap();

        let stats = reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&kept), &[], 2000)
            .await
            .unwrap();
        assert_eq!(stats.unlinked, 1);
        assert_eq!(stats.removed, 1);
        assert_eq!(status_of(&pool, &gone).await.0, "removed");
        let gone_row = get_by_fingerprint(&pool, &gone.fingerprint())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(gone_row.removed_at, Some(2000));
        assert_eq!(status_of(&pool, &kept).await.0, "unknown");
    }

    #[tokio::test]
    async fn reappearing_removed_proxy_stays_removed() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let e = entry("x", "h1.example.com", 443);
        reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&e), &[], 1000)
            .await
            .unwrap();
        reconcile_source(&pool, "srcA0000000", &[], &[], 2000)
            .await
            .unwrap();
        assert_eq!(status_of(&pool, &e).await.0, "removed");

        // Reappearing in a live source does NOT reset the lifecycle
        // (owner decision 2026-08-31): `removed` is terminal for
        // reconciliation; only mutable fields refresh.
        let stats = reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&e), &[], 3000)
            .await
            .unwrap();
        assert_eq!(stats.updated, 1);
        let (status, fail_count) = status_of(&pool, &e).await;
        assert_eq!(status, "removed");
        assert_eq!(fail_count, 0);
        let row = get_by_fingerprint(&pool, &e.fingerprint())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.removed_at, Some(2000));
        assert_eq!(row.quarantined_at, None);
    }

    #[tokio::test]
    async fn reappearing_quarantined_proxy_keeps_ladder() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let e = entry("x", "h1.example.com", 443);
        reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&e), &[], 1000)
            .await
            .unwrap();

        let fp = e.fingerprint();
        sqlx::query(
            "UPDATE proxies SET status = 'quarantine', fail_count = 3,
                quarantined_at = 1500, second_chance_at = 9000,
                recheck_15m_at = 2400, recheck_30m_at = 3300, recheck_1h_at = 5100
             WHERE fingerprint = ?",
        )
        .bind(&fp)
        .execute(&pool)
        .await
        .unwrap();

        // Reappearance must not touch the state machine: the quarantine
        // ladder keeps running on its stored schedule.
        reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&e), &[], 2000)
            .await
            .unwrap();
        let row = get_by_fingerprint(&pool, &fp).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        assert_eq!(row.fail_count, 3);
        assert_eq!(row.quarantined_at, Some(1500));
        assert_eq!(row.second_chance_at, Some(9000));
        assert_eq!(row.recheck_15m_at, Some(2400));
        assert_eq!(row.recheck_30m_at, Some(3300));
        assert_eq!(row.recheck_1h_at, Some(5100));
    }

    #[tokio::test]
    async fn shared_proxy_survives_until_last_source_lets_go() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        make_source(&pool, "srcB0000000").await;
        let shared = entry("shared", "h1.example.com", 443);

        reconcile_source(
            &pool,
            "srcA0000000",
            std::slice::from_ref(&shared),
            &[],
            1000,
        )
        .await
        .unwrap();
        reconcile_source(
            &pool,
            "srcB0000000",
            std::slice::from_ref(&shared),
            &[],
            1100,
        )
        .await
        .unwrap();
        // One proxy row, two links.
        let row = get_by_fingerprint(&pool, &shared.fingerprint())
            .await
            .unwrap()
            .unwrap();
        let links: Vec<(String,)> =
            sqlx::query_as("SELECT source_id FROM proxy_source_links WHERE proxy_id = ?")
                .bind(row.id)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(links.len(), 2);

        // Dropping from source A only: still linked via B.
        let stats = reconcile_source(&pool, "srcA0000000", &[], &[], 2000)
            .await
            .unwrap();
        assert_eq!(stats.unlinked, 1);
        assert_eq!(stats.removed, 0);
        assert_eq!(status_of(&pool, &shared).await.0, "unknown");

        // Dropping from B as well: now it is removed.
        let stats = reconcile_source(&pool, "srcB0000000", &[], &[], 3000)
            .await
            .unwrap();
        assert_eq!(stats.removed, 1);
        assert_eq!(status_of(&pool, &shared).await.0, "removed");
    }

    #[tokio::test]
    async fn duplicate_entries_in_one_batch_collapse() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let a = entry("name-A", "h1.example.com", 443);
        let b = entry("name-B", "h1.example.com", 443); // same fingerprint
        let stats = reconcile_source(&pool, "srcA0000000", &[a, b], &[], 1000)
            .await
            .unwrap();
        assert_eq!(stats.inserted, 1);
        assert_eq!(stats.updated, 1);
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn row_converts_back_to_entry() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let e = entry("conv", "h1.example.com", 443);
        reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&e), &[], 1000)
            .await
            .unwrap();
        let row = get_by_fingerprint(&pool, &e.fingerprint())
            .await
            .unwrap()
            .unwrap();
        let back = row.to_entry().unwrap();
        assert_eq!(back.scheme, e.scheme);
        assert_eq!(back.name, e.name);
        assert_eq!(back.host, e.host);
        assert_eq!(back.port, e.port);
        assert_eq!(back.credential, e.credential);
        assert_eq!(back.param("security"), Some("reality"));
        // Same fingerprint even after the DB round trip.
        assert_eq!(back.fingerprint(), e.fingerprint());
    }

    #[tokio::test]
    async fn list_for_sources_filters_and_dedups() {
        use crate::models::ProxyStatus;
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        make_source(&pool, "srcB0000000").await;

        let shared = entry("shared", "h1.example.com", 443);
        let only_a = entry("only-a", "h2.example.com", 443);
        let quarantined = entry("sick", "h3.example.com", 443);

        reconcile_source(
            &pool,
            "srcA0000000",
            &[shared.clone(), only_a.clone(), quarantined.clone()],
            &[],
            1000,
        )
        .await
        .unwrap();
        reconcile_source(
            &pool,
            "srcB0000000",
            std::slice::from_ref(&shared),
            &[],
            1100,
        )
        .await
        .unwrap();

        // Put one proxy into quarantine.
        sqlx::query("UPDATE proxies SET status = 'quarantine' WHERE fingerprint = ?")
            .bind(quarantined.fingerprint())
            .execute(&pool)
            .await
            .unwrap();

        let ids = vec!["srcA0000000".to_string(), "srcB0000000".to_string()];
        let rows = list_for_sources(
            &pool,
            &ids,
            &[ProxyStatus::Quarantine, ProxyStatus::Removed],
        )
        .await
        .unwrap();
        // shared (deduped across both sources) + only_a; quarantined excluded.
        assert_eq!(rows.len(), 2);
        let hosts: Vec<&str> = rows.iter().map(|r| r.host.as_str()).collect();
        assert!(hosts.contains(&"h1.example.com"));
        assert!(hosts.contains(&"h2.example.com"));
        assert!(!hosts.contains(&"h3.example.com"));

        // Excluding nothing returns all three.
        let all = list_for_sources(&pool, &ids, &[]).await.unwrap();
        assert_eq!(all.len(), 3);

        // Empty source list short-circuits.
        let none = list_for_sources(&pool, &[], &[ProxyStatus::Removed])
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn list_alive_and_count_cover_linked_alive_only() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let alive = entry("alive", "h1.example.com", 443);
        let never_checked = entry("never", "h2.example.com", 443);
        let quarantined = entry("quar", "h3.example.com", 443);
        let removed = entry("gone", "h4.example.com", 443);
        reconcile_source(
            &pool,
            "srcA0000000",
            &[
                alive.clone(),
                never_checked.clone(),
                quarantined.clone(),
                removed.clone(),
            ],
            &[],
            1000,
        )
        .await
        .unwrap();
        for (proxy, status) in [
            (&alive, "alive"),
            (&quarantined, "quarantine"),
            (&removed, "removed"),
        ] {
            sqlx::query("UPDATE proxies SET status = ? WHERE fingerprint = ?")
                .bind(status)
                .bind(proxy.fingerprint())
                .execute(&pool)
                .await
                .unwrap();
        }

        assert_eq!(count_alive(&pool).await.unwrap(), 1);
        let hosts: Vec<String> = list_alive(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.host)
            .collect();
        assert_eq!(hosts, vec!["h1.example.com".to_string()]);

        // Losing the last source link takes even an alive row out of the
        // export, exactly like every other serving path.
        sqlx::query("DELETE FROM proxy_source_links")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(count_alive(&pool).await.unwrap(), 0);
        assert!(list_alive(&pool).await.unwrap().is_empty());
    }

    // ------------------------------------------------------------------
    // Probe state machine (SPEC §8.3, §8.3a)
    // ------------------------------------------------------------------

    /// Insert a bare proxy row with the given scheme and link it to a source
    /// so it is eligible for probing.
    async fn seed_proxy(pool: &DbPool, scheme: &str, host: &str) -> i64 {
        // Idempotent: several seeds share one source.
        sqlx::query(
            "INSERT OR IGNORE INTO sources (id, name, url, enabled, encoding, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcP0000000', 'probe-src', 'https://example.com', 1, 'auto', 3600, 1, 1)",
        )
        .execute(pool)
        .await
        .unwrap();
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, created_at, updated_at)
             VALUES (?, ?, 'n', ?, 443, 'c', 1, 1)
             RETURNING id",
        )
        .bind(format!("fp-{host}-{scheme}"))
        .bind(scheme)
        .bind(host)
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, 'srcP0000000', 1)")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn first_success_moves_unknown_to_alive() {
        let pool = temp_pool().await;
        let id = seed_proxy(&pool, "vless", "h1.example.com").await;

        let transition = check_succeeded(&pool, id, 5000, Some(42), true)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Revived);

        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        assert_eq!(row.fail_count, 0);
        assert_eq!(row.last_alive_at, Some(5000));
        assert_eq!(row.last_checked_at, Some(5000));
        assert_eq!(row.latency_ms, Some(42));
    }

    #[tokio::test]
    async fn success_without_reset_keeps_fail_count_and_removed_stays_removed() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let e = entry("t2-failed", "h1.example.com", 443);
        reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&e), &[], 1000)
            .await
            .unwrap();
        let (id,): (i64,) = sqlx::query_as("SELECT id FROM proxies WHERE fingerprint = ?")
            .bind(e.fingerprint())
            .fetch_one(&pool)
            .await
            .unwrap();
        // Failures already accumulated — e.g. two failed tunnel checks.
        sqlx::query("UPDATE proxies SET status = 'alive', fail_count = 2 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();

        // A T1-style success WITHOUT reset keeps the T2-accumulated counter
        // (strict T2 priority) and keeps the proxy alive.
        let transition = check_succeeded(&pool, id, 2000, Some(30), false)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Revived);
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        assert_eq!(row.fail_count, 2);

        // With reset the counter is wiped.
        check_succeeded(&pool, id, 3000, Some(31), true)
            .await
            .unwrap();
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.fail_count, 0);

        // A removed proxy is terminal: a success cannot revive it.
        sqlx::query("UPDATE proxies SET status = 'removed', fail_count = 1 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let transition = check_succeeded(&pool, id, 4000, Some(32), true)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Unchanged);
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "removed");
    }

    #[tokio::test]
    async fn failures_below_limit_only_bump_counter() {
        let pool = temp_pool().await;
        let id = seed_proxy(&pool, "vless", "h1.example.com").await;

        for step in 1..3i64 {
            let transition = check_failed(&pool, id, 1000 + step, 3, 86_400, 86_400)
                .await
                .unwrap();
            assert_eq!(transition, Transition::Unchanged);
            let row = get_by_id(&pool, id).await.unwrap().unwrap();
            assert_eq!(row.status, "unknown");
            assert_eq!(row.fail_count, step);
            assert_eq!(row.quarantined_at, None);
        }
    }

    #[tokio::test]
    async fn reaching_fail_limit_quarantines_with_jittered_second_chance() {
        let pool = temp_pool().await;
        let id = seed_proxy(&pool, "vless", "h1.example.com").await;
        let now = 100_000i64;

        check_failed(&pool, id, now - 10, 3, 86_400, 86_400)
            .await
            .unwrap();
        check_failed(&pool, id, now - 5, 3, 86_400, 86_400)
            .await
            .unwrap();
        let transition = check_failed(&pool, id, now, 3, 86_400, 86_400)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Quarantined);

        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        assert_eq!(row.fail_count, 3);
        assert_eq!(row.quarantined_at, Some(now));
        // second_chance_at ∈ [now + 24h, now + 48h)
        let sc = row.second_chance_at.unwrap();
        assert!(sc >= now + 86_400, "second chance too early: {sc}");
        assert!(sc < now + 2 * 86_400, "second chance too late: {sc}");
        assert_eq!(row.removed_at, None);
    }

    #[tokio::test]
    async fn second_chance_success_revives_with_clean_slate() {
        let pool = temp_pool().await;
        let id = seed_proxy(&pool, "vless", "h1.example.com").await;
        for t in [10, 20, 30] {
            check_failed(&pool, id, t, 3, 86_400, 0).await.unwrap();
        }
        assert_eq!(
            get_by_id(&pool, id).await.unwrap().unwrap().status,
            "quarantine"
        );

        let transition = check_succeeded(&pool, id, 90_000, Some(10), true)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Revived);
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        assert_eq!(row.fail_count, 0);
        assert_eq!(row.quarantined_at, None);
        assert_eq!(row.second_chance_at, None);
        assert_eq!(row.last_alive_at, Some(90_000));
    }

    #[tokio::test]
    async fn failed_ladder_walks_15m_30m_1h_then_removes() {
        let pool = temp_pool().await;
        let id = seed_proxy(&pool, "vless", "h1.example.com").await;
        for t in [10, 20, 30] {
            check_failed(&pool, id, t, 3, 86_400, 0).await.unwrap();
        }

        // Second chance fails → recheck in 15 minutes from the failure.
        let t = 90_000i64;
        let transition = quarantine_check_failed(&pool, id, t, QuarantineStage::SecondChance)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Unchanged);
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.second_chance_at, None);
        assert_eq!(row.recheck_15m_at, Some(t + RECHECK_15M_SECS));

        // First recheck fails → +30m from this failure.
        let t = t + RECHECK_15M_SECS;
        quarantine_check_failed(&pool, id, t, QuarantineStage::Recheck15m)
            .await
            .unwrap();
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.recheck_15m_at, None);
        assert_eq!(row.recheck_30m_at, Some(t + RECHECK_30M_SECS));

        // Second recheck fails → +1h from this failure.
        let t = t + RECHECK_30M_SECS;
        quarantine_check_failed(&pool, id, t, QuarantineStage::Recheck30m)
            .await
            .unwrap();
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.recheck_30m_at, None);
        assert_eq!(row.recheck_1h_at, Some(t + RECHECK_1H_SECS));

        // Final recheck fails → removed.
        let t = t + RECHECK_1H_SECS;
        let transition = quarantine_check_failed(&pool, id, t, QuarantineStage::Recheck1h)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Removed);
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "removed");
        assert_eq!(row.removed_at, Some(t));
        assert_eq!(row.recheck_1h_at, None);
    }

    #[tokio::test]
    async fn recheck_success_at_any_step_revives() {
        let pool = temp_pool().await;
        let id = seed_proxy(&pool, "vless", "h1.example.com").await;
        for t in [10, 20, 30] {
            check_failed(&pool, id, t, 3, 86_400, 0).await.unwrap();
        }
        quarantine_check_failed(&pool, id, 90_000, QuarantineStage::SecondChance)
            .await
            .unwrap();

        // The 15-minute recheck succeeds → alive again.
        let transition = check_succeeded(&pool, id, 90_000 + RECHECK_15M_SECS, None, true)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Revived);
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "alive");
        assert_eq!(row.recheck_15m_at, None);
    }

    #[tokio::test]
    async fn due_quarantine_selection_respects_schedule_and_stage() {
        let pool = temp_pool().await;
        let early = seed_proxy(&pool, "vless", "early.example.com").await;
        let late = seed_proxy(&pool, "vless", "late.example.com").await;
        let ladder = seed_proxy(&pool, "vless", "ladder.example.com").await;

        // early: second chance already due; late: still sleeping.
        sqlx::query(
            "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, second_chance_at = ? WHERE id = ?",
        )
        .bind(1_000i64)
        .bind(early)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, second_chance_at = ? WHERE id = ?",
        )
        .bind(999_999i64)
        .bind(late)
        .execute(&pool)
        .await
        .unwrap();
        // ladder: mid-ladder with a due 30-minute recheck.
        sqlx::query(
            "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, recheck_30m_at = ? WHERE id = ?",
        )
        .bind(2_000i64)
        .bind(ladder)
        .execute(&pool)
        .await
        .unwrap();

        let due = select_due_quarantine(&pool, 5_000, 100).await.unwrap();
        let ids: Vec<i64> = due.iter().map(|d| d.id).collect();
        assert!(ids.contains(&early));
        assert!(ids.contains(&ladder));
        assert!(!ids.contains(&late));

        let stages: std::collections::HashMap<i64, QuarantineStage> =
            due.into_iter().map(|d| (d.id, d.stage())).collect();
        assert_eq!(stages[&early], QuarantineStage::SecondChance);
        assert_eq!(stages[&ladder], QuarantineStage::Recheck30m);
    }

    #[tokio::test]
    async fn t1_candidates_skip_unprobeable_unlinked_and_quarantined() {
        let pool = temp_pool().await;
        let vless = seed_proxy(&pool, "vless", "v.example.com").await;
        let hysteria2 = seed_proxy(&pool, "hysteria2", "hy.example.com").await;
        let tuic = seed_proxy(&pool, "tuic", "tu.example.com").await;
        let mieru = seed_proxy(&pool, "mieru", "mi.example.com").await;
        let quarantined = seed_proxy(&pool, "trojan", "q.example.com").await;
        let unlinked = seed_proxy(&pool, "ss", "u.example.com").await;

        sqlx::query("UPDATE proxies SET status = 'quarantine' WHERE id = ?")
            .bind(quarantined)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM proxy_source_links WHERE proxy_id = ?")
            .bind(unlinked)
            .execute(&pool)
            .await
            .unwrap();

        let candidates = select_t1_candidates(&pool, 100).await.unwrap();
        let ids: Vec<i64> = candidates.iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![vless]);
        for excluded in [hysteria2, tuic, mieru, quarantined, unlinked] {
            assert!(!ids.contains(&excluded));
        }
    }

    #[tokio::test]
    async fn full_lifecycle_is_restart_safe() {
        // The whole machine is driven by DB columns only: simulate a daemon
        // restart by re-reading state between every step — no in-memory
        // carryover is required to advance the lifecycle.
        let pool = temp_pool().await;
        let id = seed_proxy(&pool, "vless", "h1.example.com").await;

        for t in [10, 20, 30] {
            check_failed(&pool, id, t, 3, 86_400, 0).await.unwrap();
        }
        // "Restart": derive everything from the row itself.
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        let sc = row.second_chance_at.unwrap();

        // Nothing is due before the scheduled moment.
        assert!(
            select_due_quarantine(&pool, sc - 1, 100)
                .await
                .unwrap()
                .is_empty()
        );
        // At the moment it becomes due exactly one check fires.
        let due = select_due_quarantine(&pool, sc, 100).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].stage(), QuarantineStage::SecondChance);

        // Fail it, restart again, and the ladder continues from the DB.
        quarantine_check_failed(&pool, id, sc, QuarantineStage::SecondChance)
            .await
            .unwrap();
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        let next = row.recheck_15m_at.unwrap();
        let due = select_due_quarantine(&pool, next, 100).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].stage(), QuarantineStage::Recheck15m);
    }

    #[tokio::test]
    async fn t2_sample_offers_only_t1_passed_proxies() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let alive = entry("alive", "h1.example.com", 443);
        let never_checked = entry("never", "h2.example.com", 443);
        let quarantined = entry("quar", "h3.example.com", 443);
        let removed = entry("gone", "h4.example.com", 443);
        // tuic cannot pass T1 by design — even an "alive" one must not be
        // offered to T2 (meow-rs cannot tunnel it, SPEC §8.5).
        let mut alive_unprobeable = entry("tuic", "h5.example.com", 443);
        alive_unprobeable.scheme = Scheme::Tuic;
        let all = vec![
            alive.clone(),
            never_checked.clone(),
            quarantined.clone(),
            removed.clone(),
            alive_unprobeable.clone(),
        ];
        reconcile_source(&pool, "srcA0000000", &all, &[], 1000)
            .await
            .unwrap();

        for (proxy, status) in [
            (&alive, "alive"),
            (&never_checked, "unknown"),
            (&quarantined, "quarantine"),
            (&removed, "removed"),
            (&alive_unprobeable, "alive"),
        ] {
            sqlx::query("UPDATE proxies SET status = ? WHERE fingerprint = ?")
                .bind(status)
                .bind(proxy.fingerprint())
                .execute(&pool)
                .await
                .unwrap();
        }

        let candidates = select_t2_candidates(&pool, 100).await.unwrap();
        let hosts: Vec<&str> = candidates.iter().map(|row| row.host.as_str()).collect();
        assert_eq!(hosts, vec!["h1.example.com"]);
    }

    #[tokio::test]
    async fn reconcile_stores_geo_and_keeps_it_when_fresh_lookup_empty() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let e = entry("geo", "h1.example.com", 443);
        let stamp = GeoStamp {
            country: Some("DE".into()),
            city: Some("Frankfurt".into()),
            asn: Some("AS24940".into()),
        };
        reconcile_source(
            &pool,
            "srcA0000000",
            std::slice::from_ref(&e),
            &[Some(stamp)],
            1000,
        )
        .await
        .unwrap();
        let row = get_by_fingerprint(&pool, &e.fingerprint())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.geo_country.as_deref(), Some("DE"));
        assert_eq!(row.geo_city.as_deref(), Some("Frankfurt"));
        assert_eq!(row.geo_asn.as_deref(), Some("AS24940"));

        // Refetch with an inactive resolver (all-None stamps): stored facts
        // are preserved, never wiped by a missing lookup.
        reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&e), &[], 2000)
            .await
            .unwrap();
        let row = get_by_fingerprint(&pool, &e.fingerprint())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.geo_country.as_deref(), Some("DE"));
        assert_eq!(row.geo_city.as_deref(), Some("Frankfurt"));
        assert_eq!(row.geo_asn.as_deref(), Some("AS24940"));
    }

    #[tokio::test]
    async fn missing_geo_listing_and_update() {
        let pool = temp_pool().await;
        make_source(&pool, "srcA0000000").await;
        let e = entry("geo", "h1.example.com", 443);
        reconcile_source(&pool, "srcA0000000", std::slice::from_ref(&e), &[], 1000)
            .await
            .unwrap();

        let missing = list_missing_geo(&pool, 0, 500).await.unwrap();
        let id = missing
            .iter()
            .find(|(_, host)| host == "h1.example.com")
            .expect("row without geo must be listed")
            .0;

        let stamp = GeoStamp {
            country: Some("US".into()),
            city: None,
            asn: None,
        };
        update_geo(&pool, id, &stamp).await.unwrap();
        let row = get_by_fingerprint(&pool, &e.fingerprint())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.geo_country.as_deref(), Some("US"));
        assert_eq!(row.geo_city, None);

        // The row has country data now, so it no longer counts as missing.
        let missing = list_missing_geo(&pool, 0, 500).await.unwrap();
        assert!(missing.iter().all(|(known, _)| known != &id));
    }
}
