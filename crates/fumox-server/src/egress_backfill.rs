//! Backfill of the `proxies.egress_*` geo columns.
//!
//! The probe stamps `egress_ip` from the Cloudflare trace, but the mmdb
//! files live on the server only (the `fumox-geo` volume never reaches the
//! probe), so the egress country and AS are the server's fact to derive.
//! This module walks the rows holding an egress address but no egress geo
//! (see [`proxies::list_missing_egress_geo`]), resolves the address through
//! the same [`GeoResolver`] the ingest path uses — an address literal, no
//! DNS — and stores what came back.
//!
//! The walk is the [`crate::geo_backfill`] shape on a different fact set:
//! oldest id first, bounded concurrency, a wall-clock budget, a retry
//! window for rows nothing knows, and a fact mask so an ASN-only install
//! never re-walks a column nothing can fill.

use fumox_core::db::DbPool;
use fumox_core::geo::{GEO_LOOKUP_CONCURRENCY, GeoFactMask, GeoInfo, GeoResolver};
use fumox_core::repo::proxies::{self, EgressGeoStamp};
use std::sync::Arc;
use std::time::Duration;

/// How many rows to pull from the database per pass.
const BATCH: i64 = 500;

/// Fill the egress geo facts for every proxy row that carries an egress
/// address but none, bounded by `budget`. Never blocks startup: call sites
/// spawn it as a background task.
pub async fn backfill_missing_egress_geo_within_budget(
    pool: DbPool,
    geo: Arc<GeoResolver>,
    budget: Duration,
) {
    if !geo.is_active() {
        tracing::debug!("geo resolver inactive, skipping egress geo backfill");
        return;
    }
    egress_pass(geo.as_ref(), &pool, geo.fact_mask(), budget).await;
}

/// [`backfill_missing_egress_geo_within_budget`] around any [`GeoLookup`]
/// with an explicit fact mask: the shared tail of the pass. The tests
/// drive it with fake resolvers, so the lookup shape and the second-pass
/// no-op are observable without a MaxMind database on the machine.
async fn egress_pass<G: GeoLookup>(geo: &G, pool: &DbPool, mask: GeoFactMask, budget: Duration) {
    let started = std::time::Instant::now();
    let updated = run_egress_backfill(geo, pool, budget, mask).await;
    let remaining = match proxies::count_missing_egress_geo(pool, mask).await {
        Ok(count) => Some(count),
        Err(err) => {
            tracing::warn!(error = %err, "egress geo backfill: cannot count remaining rows");
            None
        }
    };
    if updated > 0 || remaining != Some(0) {
        tracing::info!(
            updated,
            remaining = ?remaining,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "egress geo backfill pass finished"
        );
    } else {
        tracing::debug!("egress geo backfill: nothing to fill");
    }
}

/// The one [`GeoResolver`] call the egress backfill makes, over the same
/// seam the geo backfill resolves its hosts through: the lookup *shape*
/// (concurrent, capped, budget-bounded, id-ordered) is observable in tests
/// without a MaxMind database.
trait GeoLookup {
    /// Resolve one address literal, `None` when nothing is known about it.
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

/// Walk every row missing an egress fact this installation can still fill,
/// oldest id first: at most [`GEO_LOOKUP_CONCURRENCY`] lookups in flight,
/// no lookups once `budget` has elapsed. Returns how many rows it filled.
async fn run_egress_backfill<G: GeoLookup>(
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
                "egress geo backfill: budget elapsed before every row missing a fact was \
                 examined; the rest stay missing and are retried by the next pass"
            );
            break;
        }
        let rows =
            match proxies::list_missing_egress_geo(pool, cursor, BATCH + 1, mask, now()).await {
                Ok(rows) if rows.is_empty() => break,
                Ok(rows) => rows,
                Err(err) => {
                    tracing::warn!(error = %err, "egress geo backfill: cannot list rows");
                    break;
                }
            };
        let has_more = rows.len() as i64 > BATCH;
        let page: Vec<(i64, String)> = rows.into_iter().take(BATCH as usize).collect();
        let stamps = resolve_page(geo, &page, deadline).await;
        let mut tx = match pool.begin().await {
            Ok(tx) => tx,
            Err(err) => {
                tracing::warn!(error = %err, "egress geo backfill: cannot open the batch transaction");
                break;
            }
        };
        for ((id, _), stamp) in page.iter().zip(&stamps) {
            cursor = (*id).max(cursor);
            match stamp {
                // Past the budget: the row was not looked up, so it is not
                // marked; it stays missing and the next pass tries it
                Lookup::Skipped => {}
                // The resolver answered, but it knows nothing about this
                // address: remember the attempt so the next pass leaves the
                // row alone for a while
                Lookup::NoFacts => {
                    if let Err(err) = proxies::mark_egress_geo_attempt_tx(&mut tx, *id, now()).await
                    {
                        tracing::warn!(proxy = id, error = %err, "egress geo backfill: cannot record the attempt");
                    }
                }
                Lookup::Facts(stamp) => {
                    if let Err(err) = proxies::update_egress_geo_tx(&mut tx, *id, stamp).await {
                        tracing::warn!(proxy = id, error = %err, "egress geo backfill: update failed");
                    } else {
                        updated += 1;
                    }
                }
            }
        }
        if let Err(err) = tx.commit().await {
            tracing::warn!(error = %err, "egress geo backfill: cannot commit the batch");
        }
        if !has_more {
            break;
        }
    }
    updated
}

/// Resolve every egress address of a page, oldest id first: at most
/// [`GEO_LOOKUP_CONCURRENCY`] lookups in flight, and once `deadline` has
/// elapsed the queued lookups short-circuit to [`Lookup::Skipped`] instead
/// of piling onto the resolver.
async fn resolve_page<G: GeoLookup>(
    geo: &G,
    rows: &[(i64, String)],
    deadline: std::time::Instant,
) -> Vec<Lookup> {
    use futures_util::StreamExt;
    // `buffered` (not `buffer_unordered`) keeps the id order the
    // cursor pagination walks, holding at most `GEO_LOOKUP_CONCURRENCY`
    // lookups in flight
    futures_util::stream::iter(
        rows.iter()
            .map(|(_, ip)| async move {
                if std::time::Instant::now() >= deadline {
                    return Lookup::Skipped;
                }
                match geo.resolve_host(ip).await {
                    None => Lookup::NoFacts,
                    Some(info) => {
                        let stamp = EgressGeoStamp::from_info(&info);
                        if stamp.is_empty() {
                            Lookup::NoFacts
                        } else {
                            Lookup::Facts(stamp)
                        }
                    }
                }
            })
            .collect::<Vec<_>>(),
    )
    .buffered(GEO_LOOKUP_CONCURRENCY)
    .collect::<Vec<_>>()
    .await
}

/// What one lookup of a batch produced.
enum Lookup {
    /// The budget elapsed before the lookup ran.
    Skipped,
    /// The resolver knows nothing about this address.
    NoFacts,
    /// The resolver produced these facts.
    Facts(EgressGeoStamp),
}

/// The current time in unix seconds, the unit of the stored timestamps.
fn now() -> i64 {
    fumox_core::models::now_ts()
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
            "fumox-egress-backfill-{}",
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

    fn source(id: &str) -> Source {
        Source::fixture(id, fumox_core::models::now_ts())
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
            canonical: None,
        }
    }

    async fn fetch_row(pool: &DbPool, host: &str) -> ProxyRow {
        sqlx::query_as::<_, ProxyRow>("SELECT * FROM proxies WHERE host = ?")
            .bind(host)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Seed `count` proxy rows, then stamp the probe's trace facts onto
    /// them directly (the way the daemon would): an egress address but no
    /// egress geo yet.
    async fn seed_rows_with_egress_ip(pool: &DbPool, count: usize, tag: u8) {
        let src = source(&format!("srcEgressSeed{tag}"));
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
            fumox_core::ingest::IngestPolicy::refresh(true, true),
        )
        .await
        .unwrap();
        for i in 0..count {
            let row = fetch_row(pool, &format!("198.51.{tag}.{i}")).await;
            sqlx::query("UPDATE proxies SET egress_ip = ? WHERE id = ?")
                .bind(format!("203.0.{tag}.{i}"))
                .bind(row.id)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    /// Fake resolver: every address is Google's, so the stamp is complete.
    struct FakeGeo {
        calls: AtomicUsize,
        facts: bool,
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
            self.calls.fetch_add(1, Ordering::SeqCst);
            let facts = self.facts;
            async move {
                if !facts {
                    return None;
                }
                Some(Arc::new(GeoInfo {
                    country_code: Some("US".into()),
                    asn: Some(15169),
                    asn_org: Some("Google LLC".into()),
                    ..Default::default()
                }))
            }
        }
    }

    /// A row with an egress address but no egress geo facts is filled by
    /// the walk; a second pass is a no-op that does not disturb the facts.
    #[tokio::test]
    async fn egress_backfill_fills_rows_holding_an_egress_address() {
        let pool = temp_pool().await;
        seed_rows_with_egress_ip(&pool, 2, 1).await;
        assert_eq!(fetch_row(&pool, "198.51.1.0").await.egress_country, None);

        let geo = FakeGeo {
            calls: AtomicUsize::new(0),
            facts: true,
        };
        let updated = run_egress_backfill(&geo, &pool, Duration::from_secs(60), BOTH_FACTS).await;
        assert_eq!(updated, 2);

        let first = fetch_row(&pool, "198.51.1.0").await;
        assert_eq!(first.egress_country.as_deref(), Some("US"));
        assert_eq!(first.egress_asn.as_deref(), Some("AS15169"));
        assert_eq!(first.egress_asn_org.as_deref(), Some("Google LLC"));

        // The second pass is a no-op: the rows no longer count as missing
        assert_eq!(
            proxies::count_missing_egress_geo(&pool, BOTH_FACTS)
                .await
                .unwrap(),
            0
        );
        let again = run_egress_backfill(&geo, &pool, Duration::from_secs(60), BOTH_FACTS).await;
        assert_eq!(again, 0);
        assert_eq!(geo.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            fetch_row(&pool, "198.51.1.0")
                .await
                .egress_country
                .as_deref(),
            Some("US"),
            "the second pass must not disturb the stored facts"
        );
    }

    /// A row without an egress address is never walked: the probe has not
    /// traced it yet, there is nothing to resolve.
    #[tokio::test]
    async fn rows_without_an_egress_address_are_not_walked() {
        let pool = temp_pool().await;
        let src = source("srcEgressNoIp");
        fumox_core::repo::sources::create(&pool, &src)
            .await
            .unwrap();
        proxies::reconcile_source(
            &pool,
            &src.id,
            &[entry("8.8.8.8")],
            &[],
            fumox_core::models::now_ts(),
            fumox_core::ingest::IngestPolicy::refresh(true, true),
        )
        .await
        .unwrap();

        let geo = FakeGeo {
            calls: AtomicUsize::new(0),
            facts: true,
        };
        let updated = run_egress_backfill(&geo, &pool, Duration::from_secs(60), BOTH_FACTS).await;
        assert_eq!(updated, 0);
        assert_eq!(geo.calls.load(Ordering::SeqCst), 0);
    }

    /// An address nothing knows is marked and left alone by the next pass,
    /// and the "still missing" count does not hide it.
    #[tokio::test]
    async fn a_hopeless_egress_address_is_marked_and_skipped_next_pass() {
        let pool = temp_pool().await;
        seed_rows_with_egress_ip(&pool, 2, 2).await;
        let geo = FakeGeo {
            calls: AtomicUsize::new(0),
            facts: false,
        };

        let updated = run_egress_backfill(&geo, &pool, Duration::from_secs(60), BOTH_FACTS).await;
        assert_eq!(updated, 0);
        assert_eq!(geo.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            proxies::count_missing_egress_geo(&pool, BOTH_FACTS)
                .await
                .unwrap(),
            2
        );

        // The second pass leaves the marked rows alone
        run_egress_backfill(&geo, &pool, Duration::from_secs(60), BOTH_FACTS).await;
        assert_eq!(
            geo.calls.load(Ordering::SeqCst),
            2,
            "a marked row must not be looked up again within the retry window"
        );
    }

    /// An ASN-only install walks the rows its mask can still fill and
    /// leaves the country column to an installation that has the City
    /// database; a partial stamp must not erase a stored fact.
    #[tokio::test]
    async fn an_asn_only_install_fills_its_own_fact_only() {
        let pool = temp_pool().await;
        seed_rows_with_egress_ip(&pool, 1, 3).await;
        let row = fetch_row(&pool, "198.51.3.0").await;
        // The country was established by an earlier pass with a City
        // database that has since been removed
        sqlx::query("UPDATE proxies SET egress_country = 'US' WHERE id = ?")
            .bind(row.id)
            .execute(&pool)
            .await
            .unwrap();

        let asn_only = GeoFactMask {
            country: false,
            asn: true,
        };
        let geo = FakeGeo {
            calls: AtomicUsize::new(0),
            facts: true,
        };
        let updated = run_egress_backfill(&geo, &pool, Duration::from_secs(60), asn_only).await;
        assert_eq!(updated, 1);

        let filled = fetch_row(&pool, "198.51.3.0").await;
        assert_eq!(filled.egress_country.as_deref(), Some("US"));
        assert_eq!(filled.egress_asn.as_deref(), Some("AS15169"));
        assert_eq!(
            proxies::count_missing_egress_geo(&pool, asn_only)
                .await
                .unwrap(),
            0,
            "the installation is complete as far as it can be"
        );
    }

    /// A resolver that cannot even start (no databases) is a no-op that
    /// must not touch rows — the public entry returns early.
    #[tokio::test]
    async fn egress_backfill_without_resolver_is_noop() {
        let pool = temp_pool().await;
        seed_rows_with_egress_ip(&pool, 1, 4).await;
        let inactive = Arc::new(GeoResolver::new(&GeoConfig {
            enabled: false,
            ..Default::default()
        }));
        backfill_missing_egress_geo_within_budget(pool.clone(), inactive, Duration::from_secs(60))
            .await;
        assert_eq!(fetch_row(&pool, "198.51.4.0").await.egress_country, None);
    }
}
