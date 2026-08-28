//! One-shot startup backfill of the `proxies.geo_*` columns (SPEC §6).
//!
//! Ingestion resolves geo facts for every proxy it upserts, but rows that
//! entered the database before a geo database was available (or while the
//! server ran with `[geo].enabled = false`) have all three columns NULL.
//! On every start — after the resolver has been built — this module walks
//! those rows once, oldest id first, resolves each host and stores the
//! facts. Rows the resolver cannot answer (DNS dead, no data in the
//! database) are left NULL; the next server start tries again.

use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use fumox_core::repo::proxies::{self, GeoStamp};
use std::sync::Arc;

/// How many rows to pull from the database per pass.
const BATCH: i64 = 500;

/// Fill geo facts for every proxy row that has none. Never blocks startup:
/// call sites spawn it as a background task.
pub async fn backfill_missing_geo(pool: DbPool, geo: Arc<GeoResolver>) {
    if !geo.is_active() {
        tracing::debug!("geo resolver inactive — skipping geo backfill");
        return;
    }
    let mut cursor = 0i64;
    let mut updated = 0usize;
    let started = std::time::Instant::now();
    loop {
        let rows = match proxies::list_missing_geo(&pool, cursor, BATCH).await {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!(error = %err, "geo backfill: cannot list rows");
                return;
            }
        };
        if rows.is_empty() {
            break;
        }
        for (id, host) in &rows {
            cursor = (*id).max(cursor);
            let Some(stamp) = geo
                .resolve(host)
                .await
                .map(|info| GeoStamp::from_info(&info))
            else {
                continue; // unresolvable — stays NULL, retried next start
            };
            if stamp.is_empty() {
                continue;
            }
            if let Err(err) = proxies::update_geo(&pool, *id, &stamp).await {
                tracing::warn!(proxy = id, error = %err, "geo backfill: update failed");
            } else {
                updated += 1;
            }
        }
        if (rows.len() as i64) < BATCH {
            break;
        }
    }
    if updated > 0 {
        tracing::info!(
            updated,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "geo backfill complete"
        );
    } else {
        tracing::debug!("geo backfill: nothing to fill");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::config::{DatabaseConfig, GeoConfig};
    use fumox_core::models::{ProxyEntry, Scheme, Source};
    use fumox_core::repo::proxies::ProxyRow;

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

    /// GeoLite2-Country from the workspace `config/` directory (gitignored —
    /// the test skips itself when the file is absent, like the geo tests).
    fn country_resolver() -> Option<Arc<GeoResolver>> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/GeoLite2-Country.mmdb");
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

    /// Rows ingested without geo (empty stamp slice, as an inactive resolver
    /// produces) start with NULL columns; the backfill fills them. Skipped
    /// without the mmdb file (CI runs without it).
    #[tokio::test]
    async fn backfill_fills_rows_ingested_without_geo() {
        let Some(geo) = country_resolver() else {
            eprintln!("skipping: config/GeoLite2-Country.mmdb not present");
            return;
        };
        let pool = temp_pool().await;
        let src = source("srcBackfill01");
        fumox_core::repo::sources::create(&pool, &src)
            .await
            .unwrap();
        let entries = vec![entry("8.8.8.8"), entry("8.8.4.4")];
        proxies::reconcile_source(&pool, &src.id, &entries, &[], fumox_core::models::now_ts())
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

    /// Without a database the backfill is a no-op that must not touch rows.
    #[tokio::test]
    async fn backfill_without_resolver_is_noop() {
        let pool = temp_pool().await;
        let src = source("srcBackfill02");
        fumox_core::repo::sources::create(&pool, &src)
            .await
            .unwrap();
        let entries = vec![entry("8.8.8.8")];
        proxies::reconcile_source(&pool, &src.id, &entries, &[], fumox_core::models::now_ts())
            .await
            .unwrap();
        let inactive = Arc::new(GeoResolver::new(&GeoConfig {
            enabled: false,
            ..Default::default()
        }));
        backfill_missing_geo(pool.clone(), inactive).await;
        assert_eq!(fetch_row(&pool, "8.8.8.8").await.geo_country, None);
    }
}
