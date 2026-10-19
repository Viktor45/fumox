//! Backfill of the `proxies.geo_*` columns.
//!
//! Ingestion resolves geo facts for every proxy it upserts, but a row can
//! still end up without them: it entered the database before a geo
//! database was available (or while the server ran with
//! `[geo].enabled = false`), or its host lookup failed once and the stamp
//! it got back was partial. This module walks such rows, oldest id first,
//! resolves each host and stores what came back.
//!
//! The criterion is per fact (see [`proxies::list_missing_geo`]), so a row
//! holding a country but no ASN gets another chance instead of being
//! retired as "already filled". A fact no loaded database can answer is
//! never asked for.
//!
//! Host lookups run with the same bounded concurrency as the ingest path
//! and the whole pass is bounded by a wall-clock budget, so a hopeless set
//! cannot hammer the resolver. Rows the resolver cannot answer and rows
//! the budget did not reach stay missing, retried by the next pass: the
//! startup one ([`backfill_missing_geo_within_budget`]) and the periodic
//! one the scheduler runs.

use fumox_core::db::DbPool;
use fumox_core::geo::{GeoFactMask, GeoInfo, GeoResolver};
use fumox_core::repo::proxies::{self, GeoStamp};
use std::sync::Arc;
use std::time::Duration;

/// How many rows to pull from the database per pass.
const BATCH: i64 = 500;

/// Ceiling on concurrent host lookups inside one backfill pass, the same
/// shape ingest uses (`GEO_LOOKUP_CONCURRENCY` there): every unseen
/// domain host costs up to `[geo].dns_timeout` (5 s by default) when DNS
/// hangs, so the lookups run concurrently instead of one await per row.
const GEO_LOOKUP_CONCURRENCY: usize = 32;

/// Wall-clock budget for one backfill pass, mirroring the geo download
/// startup budget (`[geo].startup_download_budget_secs`, 60 s by default —
/// the same bound `main` applies to `geo_download`). `main` passes the
/// configured value straight through [`backfill_missing_geo_within_budget`];
/// this default only backs [`backfill_missing_geo`], the config-less shape
/// the tests drive. Past the budget the pass stops issuing lookups and the
/// rows it did not reach stay NULL for the next start.
#[cfg(test)]
const DEFAULT_STARTUP_BUDGET: Duration = Duration::from_secs(60);

/// Fill geo facts for every proxy row that has none, bounded by
/// [`DEFAULT_STARTUP_BUDGET`] (the tests' config-less shape; `main` calls
/// [`backfill_missing_geo_within_budget`] with the configured budget).
/// Never blocks startup: call sites spawn it as a background task.
#[cfg(test)]
pub async fn backfill_missing_geo(pool: DbPool, geo: Arc<GeoResolver>) {
    backfill_missing_geo_within_budget(pool, geo, DEFAULT_STARTUP_BUDGET).await;
}

/// [`backfill_missing_geo`] with an explicit wall-clock budget, for
/// callers holding the config (pass
/// `config.geo.startup_download_budget()`).
pub async fn backfill_missing_geo_within_budget(
    pool: DbPool,
    geo: Arc<GeoResolver>,
    budget: Duration,
) {
    if !geo.is_active() {
        tracing::debug!("geo resolver inactive, skipping geo backfill");
        return;
    }
    let mask = geo.fact_mask();
    let started = std::time::Instant::now();
    let updated = run_backfill(geo.as_ref(), &pool, budget, mask).await;
    // Rows the resolver could not answer (or the budget did not reach) stay
    // missing; the summary names how many, so a directory without a usable
    // database is visible instead of only the rows that happened to
    // resolve.
    let remaining = proxies::count_missing_geo(&pool, mask).await.ok();
    if updated > 0 || remaining != Some(0) {
        tracing::info!(
            updated,
            remaining = ?remaining,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "geo backfill complete"
        );
    } else {
        tracing::debug!("geo backfill: nothing to fill");
    }
}

/// The one [`GeoResolver`] call the backfill makes. The real resolver
/// implements it as-is; the seam exists so the lookup *shape* (concurrent,
/// capped, budget-bounded, id-ordered) can be observed without a MaxMind
/// database and a slow DNS server on the test machine, like the seam
/// ingest resolves its stamps through.
trait GeoLookup {
    /// Resolve one host, `None` when nothing is known about it.
    fn resolve_host(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = Option<Arc<GeoInfo>>> + Send;
}

impl GeoLookup for GeoResolver {
    fn resolve_host(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = Option<Arc<GeoInfo>>> + Send {
        self.resolve(host)
    }
}

/// Walk every row missing a fact this installation can still fill, oldest
/// id first: at most [`GEO_LOOKUP_CONCURRENCY`] lookups in flight, no
/// lookups once `budget` has elapsed. Returns how many rows it filled.
async fn run_backfill<G: GeoLookup>(
    geo: &G,
    pool: &DbPool,
    budget: Duration,
    mask: GeoFactMask,
) -> usize {
    let deadline = std::time::Instant::now() + budget;
    let mut cursor = 0i64;
    let mut updated = 0usize;
    loop {
        if std::time::Instant::now() >= deadline {
            tracing::warn!(
                budget_secs = budget.as_secs(),
                updated,
                "geo backfill: budget elapsed before every row missing a fact was \
                 examined; the rest stay missing and are retried by the next pass"
            );
            break;
        }
        let rows = match proxies::list_missing_geo(pool, cursor, BATCH, mask).await {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!(error = %err, "geo backfill: cannot list rows");
                return updated;
            }
        };
        if rows.is_empty() {
            break;
        }
        use futures_util::StreamExt;
        // `buffered` (not `buffer_unordered`) keeps the id order the
        // cursor pagination walks, holding at most `GEO_LOOKUP_CONCURRENCY`
        // lookups in flight; once the budget elapses the queued lookups
        // short-circuit instead of piling onto the resolver.
        let stamps = futures_util::stream::iter(
            rows.iter()
                .map(|(_, host)| async move {
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    geo.resolve_host(host)
                        .await
                        .map(|info| GeoStamp::from_info(&info))
                })
                .collect::<Vec<_>>(),
        )
        .buffered(GEO_LOOKUP_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
        for ((id, _), stamp) in rows.iter().zip(stamps) {
            cursor = (*id).max(cursor);
            let Some(stamp) = stamp else {
                continue; // unresolvable or past budget: stays NULL, retried next start
            };
            if stamp.is_empty() {
                continue;
            }
            if let Err(err) = proxies::update_geo(pool, *id, &stamp).await {
                tracing::warn!(proxy = id, error = %err, "geo backfill: update failed");
            } else {
                updated += 1;
            }
        }
        if (rows.len() as i64) < BATCH {
            break;
        }
    }
    updated
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::config::{DatabaseConfig, GeoConfig};
    use fumox_core::models::{ProxyEntry, Scheme, Source};
    use fumox_core::repo::proxies::ProxyRow;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn temp_pool() -> DbPool {
        let dir = std::env::temp_dir().join(format!(
            "fumox-geo-backfill-{}",
            fumox_core::models::new_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        };
        let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        pool
    }

    /// GeoLite2-City from the workspace `config/` directory (gitignored ,
    /// the test skips itself when the file is absent, like the geo tests).
    fn geo_resolver() -> Option<Arc<GeoResolver>> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/GeoLite2-City.mmdb");
        if !path.exists() {
            return None;
        }
        let cfg = GeoConfig {
            enabled: true,
            db_dir: path.parent().unwrap().to_path_buf(),
            ..Default::default()
        };
        let resolver = GeoResolver::new(&cfg);
        resolver.is_active().then(|| Arc::new(resolver))
    }

    fn source(id: &str) -> Source {
        let now = fumox_core::models::now_ts();
        Source {
            id: id.into(),
            slug: None,
            name: "s".into(),
            url: "https://example.com".into(),
            enabled: true,
            encoding: Default::default(),
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
        }
    }

    fn entry(host: &str) -> ProxyEntry {
        ProxyEntry {
            scheme: Scheme::Trojan,
            name: format!("n-{host}"),
            host: host.into(),
            port: 443,
            credential: "pw".into(),
            params: Vec::new(),
            raw_path: String::new(),
            raw_line: String::new(),
        }
    }

    async fn fetch_row(pool: &DbPool, host: &str) -> ProxyRow {
        sqlx::query_as::<_, ProxyRow>("SELECT * FROM proxies WHERE host = ?")
            .bind(host)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Seed `count` proxy rows with no geo facts, each under its own
    /// source (hosts carry the tag, so pools stay collision-free).
    async fn seed_missing_rows(pool: &DbPool, count: usize, tag: u8) {
        let src = source(&format!("srcBackfillSeed{tag}"));
        fumox_core::repo::sources::create(pool, &src).await.unwrap();
        let entries: Vec<ProxyEntry> = (0..count)
            .map(|i| entry(&format!("198.51.{tag}.{i}")))
            .collect();
        proxies::reconcile_source(
            pool,
            &src.id,
            &entries,
            &[],
            fumox_core::models::now_ts(),
            false,
        )
        .await
        .unwrap();
    }

    /// Shared in-flight stats for the fake resolver.
    #[derive(Default)]
    struct LookupStats {
        in_flight: AtomicUsize,
        peak: AtomicUsize,
    }

    /// Fake resolver standing in for [`GeoResolver`]: records how many
    /// lookups overlapped and takes a fixed real delay per host, so the
    /// lookup *shape* is observable without a MaxMind database, like
    /// ingest's `GeoLookup` seam. It answers every fact the [`BOTH_FACTS`]
    /// mask asks for, so a filled row really leaves the missing set.
    struct FakeGeo {
        delay: Duration,
        stats: Arc<LookupStats>,
    }

    /// Both facts filled: what a complete City + ASN installation sees.
    const BOTH_FACTS: GeoFactMask = GeoFactMask {
        country: true,
        asn: true,
    };

    impl GeoLookup for FakeGeo {
        fn resolve_host(
            &self,
            _host: &str,
        ) -> impl std::future::Future<Output = Option<Arc<GeoInfo>>> + Send {
            let delay = self.delay;
            let stats = Arc::clone(&self.stats);
            async move {
                let now = stats.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                stats.peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                stats.in_flight.fetch_sub(1, Ordering::SeqCst);
                Some(Arc::new(GeoInfo {
                    country_code: Some("US".into()),
                    asn: Some(15169),
                    ..Default::default()
                }))
            }
        }
    }

    /// Rows ingested without geo (empty stamp slice, as an inactive resolver
    /// produces) start with NULL columns; the backfill fills them. Skipped
    /// without the mmdb file (CI runs without it).
    #[tokio::test]
    async fn backfill_fills_rows_ingested_without_geo() {
        let Some(geo) = geo_resolver() else {
            eprintln!("skipping: config/GeoLite2-City.mmdb not present");
            return;
        };
        let pool = temp_pool().await;
        let src = source("srcBackfill01");
        fumox_core::repo::sources::create(&pool, &src)
            .await
            .unwrap();
        let entries = vec![entry("8.8.8.8"), entry("8.8.4.4")];
        proxies::reconcile_source(
            &pool,
            &src.id,
            &entries,
            &[],
            fumox_core::models::now_ts(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(fetch_row(&pool, "8.8.8.8").await.geo_country, None);

        backfill_missing_geo(pool.clone(), geo.clone()).await;

        let first = fetch_row(&pool, "8.8.8.8").await;
        let second = fetch_row(&pool, "8.8.4.4").await;
        assert_eq!(first.geo_country.as_deref(), Some("US"));
        assert!(second.geo_country.is_some());

        // A second run is a no-op: the rows no longer count as missing.
        backfill_missing_geo(pool.clone(), geo).await;
    }

    /// A row that carries a country but no ASN counted as filled under the
    /// old all-NULL criterion and was never walked again, so its ASN
    /// stayed NULL for good. It must get a second chance.
    #[tokio::test]
    async fn backfill_fills_the_asn_of_a_row_that_already_has_a_country() {
        let pool = temp_pool().await;
        seed_missing_rows(&pool, 1, 3).await;
        let row = fetch_row(&pool, "198.51.3.0").await;
        proxies::update_geo(
            &pool,
            row.id,
            &GeoStamp {
                country: Some("US".into()),
                city: None,
                asn: None,
            },
        )
        .await
        .unwrap();
        assert!(fetch_row(&pool, "198.51.3.0").await.geo_asn.is_none());

        let geo = FakeGeo {
            delay: Duration::from_millis(1),
            stats: Arc::new(LookupStats::default()),
        };
        let updated = run_backfill(&geo, &pool, Duration::from_secs(60), BOTH_FACTS).await;

        assert_eq!(updated, 1);
        let filled = fetch_row(&pool, "198.51.3.0").await;
        assert_eq!(filled.geo_asn.as_deref(), Some("AS15169"));
        assert_eq!(
            filled.geo_country.as_deref(),
            Some("US"),
            "a partial stamp must not erase the stored country"
        );
        assert_eq!(
            proxies::count_missing_geo(&pool, BOTH_FACTS).await.unwrap(),
            0
        );
    }

    /// A fact no loaded database could answer is not chased: an ASN-only
    /// install must not re-walk the table over a column nothing will fill.
    #[tokio::test]
    async fn a_fact_no_database_can_answer_is_not_walked() {
        /// Stands in for an installation that opened `GeoLite2-ASN.mmdb`
        /// only: it cannot answer a country at all.
        struct AsnOnlyGeo;

        impl GeoLookup for AsnOnlyGeo {
            async fn resolve_host(&self, _host: &str) -> Option<Arc<GeoInfo>> {
                Some(Arc::new(GeoInfo {
                    asn: Some(15169),
                    ..Default::default()
                }))
            }
        }

        let pool = temp_pool().await;
        seed_missing_rows(&pool, 1, 4).await;
        let asn_only = GeoFactMask {
            country: false,
            asn: true,
        };

        let updated = run_backfill(&AsnOnlyGeo, &pool, Duration::from_secs(60), asn_only).await;

        assert_eq!(updated, 1);
        let row = fetch_row(&pool, "198.51.4.0").await;
        assert_eq!(row.geo_asn.as_deref(), Some("AS15169"));
        assert_eq!(row.geo_country, None);
        assert_eq!(
            proxies::count_missing_geo(&pool, asn_only).await.unwrap(),
            0,
            "the installation is complete as far as it can be"
        );
        assert_eq!(
            proxies::count_missing_geo(&pool, BOTH_FACTS).await.unwrap(),
            1,
            "an installation that could also resolve the country would still see it"
        );
    }

    /// Without a database the backfill is a no-op that must not touch rows.
    #[tokio::test]
    async fn backfill_without_resolver_is_noop() {
        let pool = temp_pool().await;
        let src = source("srcBackfill02");
        fumox_core::repo::sources::create(&pool, &src)
            .await
            .unwrap();
        let entries = vec![entry("8.8.8.8")];
        proxies::reconcile_source(
            &pool,
            &src.id,
            &entries,
            &[],
            fumox_core::models::now_ts(),
            false,
        )
        .await
        .unwrap();
        let inactive = Arc::new(GeoResolver::new(&GeoConfig {
            enabled: false,
            ..Default::default()
        }));
        backfill_missing_geo(pool.clone(), inactive).await;
        assert_eq!(fetch_row(&pool, "8.8.8.8").await.geo_country, None);
    }

    /// The backfill resolves a batch's hosts concurrently, capped at
    /// `GEO_LOOKUP_CONCURRENCY` in flight (the same shape ingest uses),
    /// not one sequential await per row.
    #[tokio::test]
    async fn backfill_resolves_batch_with_capped_concurrency() {
        let pool = temp_pool().await;
        seed_missing_rows(&pool, 100, 1).await;
        let stats = Arc::new(LookupStats::default());
        let geo = FakeGeo {
            delay: Duration::from_millis(5),
            stats: Arc::clone(&stats),
        };

        let updated = run_backfill(&geo, &pool, Duration::from_secs(60), BOTH_FACTS).await;

        assert_eq!(updated, 100);
        let peak = stats.peak.load(Ordering::SeqCst);
        assert!(peak > 1, "lookups must overlap, peak was {peak}");
        assert!(
            peak <= GEO_LOOKUP_CONCURRENCY,
            "peak {peak} exceeded the cap"
        );
        assert_eq!(
            proxies::count_missing_geo(&pool, BOTH_FACTS).await.unwrap(),
            0
        );
    }

    /// The startup budget stops the pass: rows the budget did not reach
    /// stay NULL (retried next start) instead of stretching the pass into
    /// an unbounded lookup grind.
    #[tokio::test]
    async fn backfill_stops_issuing_lookups_once_budget_elapses() {
        let pool = temp_pool().await;
        seed_missing_rows(&pool, 400, 2).await;
        let stats = Arc::new(LookupStats::default());
        let geo = FakeGeo {
            delay: Duration::from_millis(50),
            stats: Arc::clone(&stats),
        };

        let started = std::time::Instant::now();
        let updated = run_backfill(&geo, &pool, Duration::from_millis(300), BOTH_FACTS).await;
        let elapsed = started.elapsed();

        // Every fake lookup takes ≥50 ms and at most 32 run at once, so
        // the 300 ms budget can complete at most 32 × (300 / 50 + 1) = 224
        // of the 400 rows, no matter how loaded the machine is.
        assert!(updated > 0, "the first lookup wave must land in the budget");
        assert!(
            updated < 400,
            "the budget must cut the pass short, updated {updated}"
        );
        assert_eq!(
            proxies::count_missing_geo(&pool, BOTH_FACTS).await.unwrap(),
            (400 - updated) as i64
        );
        assert!(elapsed < Duration::from_secs(10), "pass ran {elapsed:?}");
    }
}
