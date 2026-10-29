use super::*;
use crate::ingest::IngestPolicy;
use crate::models::ProxyStatus;
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

/// Insert a probe attempt row for the proxy of `entry`.
async fn probe_attempt(pool: &DbPool, entry: &ProxyEntry, kind: &str) {
    let row = get_by_fingerprint(pool, &entry.fingerprint())
        .await
        .unwrap()
        .unwrap();
    sqlx::query(
        "INSERT INTO probe_results (proxy_id, checked_at, ok, latency_ms, error, probe_kind)
             VALUES (?, 1, 1, 10, NULL, ?)",
    )
    .bind(row.id)
    .bind(kind)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn coverage_buckets_partition_the_population() {
    let (_dir, pool) = temp_pool().await;

    // An empty database still yields every bucket, zero-filled and in
    // the fixed panel order.
    assert_eq!(
        count_by_check_coverage(&pool)
            .await
            .unwrap()
            .iter()
            .map(|(bucket, count)| (bucket.as_str(), *count))
            .collect::<Vec<_>>(),
        vec![("none", 0), ("t1_only", 0), ("t2_only", 0), ("both", 0)]
    );

    // One proxy per bucket: untouched, tcp-only, t2-only, tcp + t2.
    make_source(&pool, "srcA0000000").await;
    let untouched = entry("untouched", "h0.example.com", 443);
    let tcp_only = entry("tcp-only", "h1.example.com", 443);
    let t2_only = entry("t2-only", "h2.example.com", 443);
    let both = entry("both", "h3.example.com", 443);
    for e in [&untouched, &tcp_only, &t2_only, &both] {
        reconcile_source(
            &pool,
            "srcA0000000",
            std::slice::from_ref(e),
            &[],
            1000,
            IngestPolicy::refresh(true, true),
        )
        .await
        .unwrap();
    }
    probe_attempt(&pool, &tcp_only, "tcp").await;
    probe_attempt(&pool, &t2_only, "t2").await;
    probe_attempt(&pool, &both, "tls").await;
    probe_attempt(&pool, &both, "t2").await;

    assert_eq!(
        count_by_check_coverage(&pool)
            .await
            .unwrap()
            .iter()
            .map(|(bucket, count)| (bucket.as_str(), *count))
            .collect::<Vec<_>>(),
        vec![("none", 1), ("t1_only", 1), ("t2_only", 1), ("both", 1)]
    );

    // A second T1 kind on a tcp-only proxy must not move it anywhere:
    // the buckets count presence, not attempts.
    probe_attempt(&pool, &tcp_only, "tls").await;
    assert_eq!(
        count_by_check_coverage(&pool)
            .await
            .unwrap()
            .iter()
            .map(|(bucket, count)| (bucket.as_str(), *count))
            .collect::<Vec<_>>(),
        vec![("none", 1), ("t1_only", 1), ("t2_only", 1), ("both", 1)]
    );
}

/// An attempt the tunnel engine never verified is still a T2 attempt:
/// the row exists, so the coverage buckets and the admin browser count
/// it, and the recency queue moves past the proxy instead of serving it
/// again and again.
#[tokio::test]
async fn an_unverified_t2_attempt_counts_as_a_t2_attempt() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let unverified = entry("unverified", "h9.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&unverified),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    // No attempt at all: the proxy is in the `none` bucket.
    assert_eq!(coverage_of(&pool).await, ("none".to_string(), 1));

    // An attempt the engine never verified: still a T2 attempt.
    let row = get_by_fingerprint(&pool, &unverified.fingerprint())
        .await
        .unwrap()
        .unwrap();
    journal_result(
        &pool,
        row.id,
        1000,
        false,
        crate::repo::probe::T2_UNVERIFIED_KIND,
    )
    .await;
    assert_eq!(coverage_of(&pool).await, ("t2_only".to_string(), 1));

    // The admin browser flags the proxy as T2-checked as well.
    let (t2_checked,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM probe_results r
         WHERE r.proxy_id = ? AND r.probe_kind IN ('t2', 't2_unverified')",
    )
    .bind(row.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(t2_checked, 1, "the unverified attempt is a T2 attempt");
}

/// The bucket of the only proxy of the pool, as (bucket, count).
async fn coverage_of(pool: &DbPool) -> (String, i64) {
    let buckets = count_by_check_coverage(pool).await.unwrap();
    let (name, count) = buckets
        .into_iter()
        .find(|(_, count)| *count > 0)
        .expect("a bucket");
    (name, count)
}

/// The recency queue must move past a proxy whose T2 attempt never ran:
/// an unverified attempt is still an attempt, so the proxy is not
/// served again in the very next cycle.
#[tokio::test]
async fn an_unverified_attempt_advances_the_t2_recency_queue() {
    let (_dir, pool) = temp_pool().await;
    let a = seed_proxy(&pool, "vless", "rec-a.example.com").await;
    let b = seed_proxy(&pool, "trojan", "rec-b.example.com").await;
    sqlx::query("UPDATE proxies SET status = 'alive'")
        .execute(&pool)
        .await
        .unwrap();

    // Without any attempt the queue is served by id.
    let rows = select_t2_candidates(&pool, 10).await.unwrap();
    assert_eq!(
        rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![a, b]
    );

    // An unverified attempt is an attempt: the proxy moves to the back
    // of the queue.
    journal_result(
        &pool,
        a,
        1000,
        false,
        crate::repo::probe::T2_UNVERIFIED_KIND,
    )
    .await;

    let rows = select_t2_candidates(&pool, 10).await.unwrap();
    assert_eq!(
        rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![b, a]
    );
}

#[tokio::test]
async fn inserts_new_proxies_as_unknown() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let entries = vec![
        entry("one", "h1.example.com", 443),
        entry("two", "h2.example.com", 8443),
    ];
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(stats.inserted, 2);
    assert_eq!(stats.inserted_ids.len(), 2);
    assert_eq!(stats.updated, 0);
    for e in &entries {
        assert_eq!(status_of(&pool, e).await, ("unknown".into(), 0));
    }

    // A refetch updates instead of inserting, no new ids are reported.
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(stats.updated, 2);
    assert!(stats.inserted_ids.is_empty());
}

/// A feed larger than one upsert chunk drives the batched multi-row
/// statements end to end: the chunk boundaries must not lose or
/// duplicate rows, and duplicate fingerprints must still collapse onto
/// one row whether the repeat lands inside its own chunk (the
/// second values-row conflicts with the first row of the same
/// statement) or in a later one (it conflicts with a row this
/// transaction wrote earlier). The per-row loop this replaced could
/// not fail these assertions by construction; the batched form can
/// (bad placeholder count, mis-sized RETURNING map, conflated ids).
#[tokio::test]
async fn reconcile_batches_large_feeds_with_duplicate_fingerprints() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    // 600 unique entries: two full chunks of 250 plus a partial third.
    let mut entries: Vec<ProxyEntry> = (0..600)
        .map(|i| entry(&format!("p{i}"), &format!("h{i}.example.com"), 443))
        .collect();
    // Same-chunk duplicate: right after the first chunk's last entry.
    entries.insert(251, entries[250].clone());
    // Cross-chunk duplicate: position 601 lands in the third chunk,
    // the original sits in the first.
    entries.push(entries[0].clone());
    let unique = 600;
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(stats.inserted, unique);
    assert_eq!(stats.updated, 2, "both repeats count as updates");
    assert_eq!(stats.inserted_ids.len(), unique);
    assert_eq!(stats.removed, 0);

    let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, unique as i64);
    // Every unique proxy carries a link even though two fingerprints
    // were stamped twice: the ON CONFLICT branch folds the repeats.
    let (links,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxy_source_links")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(links, unique as i64);

    // A refetch updates every entry (repeats included) and the sweep
    // finds nothing to retire.
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(stats.updated, entries.len());
    assert_eq!(stats.inserted, 0);
    assert_eq!(stats.removed, 0);
    assert_eq!(stats.unlinked, 0);
}

/// A stamp slice longer than the entry list means the caller filtered
/// the entries and handed back the unfiltered stamps: pairing them by
/// index would stamp each proxy with a neighbouring host's country and
/// ASN. Reconcile must refuse and write nothing.
#[tokio::test]
async fn reconcile_refuses_more_geo_stamps_than_entries() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let entries = vec![entry("one", "h1.example.com", 443)];
    let stamps = vec![
        Some(GeoStamp {
            asn: Some("AS100".into()),
            ..Default::default()
        }),
        Some(GeoStamp {
            asn: Some("AS200".into()),
            ..Default::default()
        }),
    ];
    let err = reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &stamps,
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .expect_err("a longer stamp slice must be refused");
    assert!(
        err.to_string().contains("stamp count"),
        "unexpected error: {err}"
    );
    // Nothing was written: a refused reconcile leaves no half-stamped row.
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM proxies")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

/// The paired happy path: entries and stamps of equal length each land
/// on their own row, which is the invariant the drop-filtered ingest
/// path depends on.
#[tokio::test]
async fn reconcile_stamps_each_entry_with_its_own_geo() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let entries = vec![entry("one", "1.1.1.1", 443), entry("two", "2.2.2.2", 443)];
    let stamps = vec![
        Some(GeoStamp {
            country: Some("AA".into()),
            asn: Some("AS100".into()),
            ..Default::default()
        }),
        Some(GeoStamp {
            country: Some("BB".into()),
            asn: Some("AS200".into()),
            ..Default::default()
        }),
    ];
    reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &stamps,
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    for (e, country, asn) in [(&entries[0], "AA", "AS100"), (&entries[1], "BB", "AS200")] {
        let (c, a): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT geo_country, geo_asn FROM proxies WHERE host = ?")
                .bind(&e.host)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(c.as_deref(), Some(country), "country for {}", e.host);
        assert_eq!(a.as_deref(), Some(asn), "asn for {}", e.host);
    }
}

/// The path segment of a parsed URI survives the round trip through the
/// database: a node served from the store keeps the path it was parsed
/// with, so a client that reads the path from the URI segment connects to
/// the endpoint the feed named.
#[tokio::test]
async fn reconcile_keeps_the_raw_path_of_an_entry() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let mut with_path = entry("one", "h1.example.com", 443);
    with_path.raw_path = "/ws".to_string();
    reconcile_source(
        &pool,
        "srcA0000000",
        &[with_path.clone()],
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let row = get_by_fingerprint(&pool, &with_path.fingerprint())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.raw_path.as_deref(), Some("/ws"));
    assert_eq!(row.to_entry().unwrap().raw_path, "/ws");
}

/// Two feeds advertising the same server under different names share
/// one row, and the row keeps the name of the feed that got there
/// first: the panel and the exported subscription show a stable name
/// instead of one that flips on every refresh.
#[tokio::test]
async fn reconcile_keeps_the_first_source_values_of_a_shared_proxy() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    make_source(&pool, "srcB0000000").await;

    let from_a = entry("name-from-a", "shared.example.com", 443);
    let mut from_b = entry("name-from-b", "shared.example.com", 443);
    from_b.raw_line = "vless://uuid-1@shared.example.com:443#name-from-b".to_string();
    assert_eq!(from_a.fingerprint(), from_b.fingerprint());

    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&from_a),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    reconcile_source(
        &pool,
        "srcB0000000",
        std::slice::from_ref(&from_b),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let row = get_by_fingerprint(&pool, &from_a.fingerprint())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.name, "name-from-a");
    assert_eq!(row.raw_line.as_deref(), Some(from_a.raw_line.as_str()));

    // Both sources are linked: the second one does not take the row over.
    let links: Vec<(String,)> = sqlx::query_as(
        "SELECT source_id FROM proxy_source_links WHERE proxy_id = ? ORDER BY source_id",
    )
    .bind(row.id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        links,
        vec![("srcA0000000".to_string(),), ("srcB0000000".to_string(),)]
    );
}

/// The other order gives the same answer: whoever reconciles first owns
/// the row, and the latecomer leaves its own values alone.
#[tokio::test]
async fn reconcile_keeps_the_first_source_values_regardless_of_the_order() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    make_source(&pool, "srcB0000000").await;

    let from_b = entry("name-from-b", "shared.example.com", 443);
    let from_a = entry("name-from-a", "shared.example.com", 443);

    reconcile_source(
        &pool,
        "srcB0000000",
        std::slice::from_ref(&from_b),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&from_a),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let row = get_by_fingerprint(&pool, &from_b.fingerprint())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.name, "name-from-b");
}

/// A proxy that only one source carries keeps following that source:
/// the guard only speaks for rows another source also claims.
#[tokio::test]
async fn reconcile_updates_a_proxy_that_only_one_source_carries() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;

    let first = entry("first-name", "solo.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&first),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let renamed = entry("second-name", "solo.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&renamed),
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let row = get_by_fingerprint(&pool, &first.fingerprint())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.name, "second-name");
}

#[tokio::test]
async fn revive_removed_resets_terminal_rows_and_reconcile_keeps_them() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let entries = vec![entry("one", "h1.example.com", 443)];
    reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    let fp = entries[0].fingerprint();
    sqlx::query(
        "UPDATE proxies SET status = 'removed', fail_count = 3,
                 removed_at = 1500, ladder_at = 1600, ladder_step = 2
             WHERE fingerprint = ?",
    )
    .bind(&fp)
    .execute(&pool)
    .await
    .unwrap();

    // Reconciliation itself never touches the terminal state.
    reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&pool, &entries[0]).await, ("removed".into(), 3));

    // The opt-in revival resets the pristine state and returns the id.
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM proxies WHERE fingerprint = ?")
        .bind(&fp)
        .fetch_one(&pool)
        .await
        .unwrap();
    let ids = revive_removed(&pool, std::slice::from_ref(&fp), 3000)
        .await
        .unwrap();
    assert_eq!(ids, vec![id]);
    assert_eq!(status_of(&pool, &entries[0]).await, ("unknown".into(), 0));
    let (removed_at, quarantined_at, ladder_at, ladder_step): (
        Option<i64>,
        Option<i64>,
        Option<i64>,
        i64,
    ) = sqlx::query_as(
        "SELECT removed_at, quarantined_at, ladder_at, ladder_step
             FROM proxies WHERE fingerprint = ?",
    )
    .bind(&fp)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (removed_at, quarantined_at, ladder_at, ladder_step),
        (None, None, None, 0)
    );

    // Idempotent: a second pass is a no-op for the now-`unknown` row,
    // and a fingerprint with no `removed` row never matches.
    let ids = revive_removed(&pool, &[fp, "no-such-fingerprint0000000".to_string()], 4000)
        .await
        .unwrap();
    assert!(ids.is_empty());
}

#[tokio::test]
async fn refetch_updates_name_and_keeps_probe_state() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let original = entry("old-name", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&original),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
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
        IngestPolicy::refresh(true, true),
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
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let kept = entry("kept", "h1.example.com", 443);
    let gone = entry("gone", "h2.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        &[kept.clone(), gone.clone()],
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&kept),
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
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
async fn alive_linger_keeps_link_and_serves_while_alive() {
    //: a probe-verified proxy that vanished from the feed
    // keeps its link, the probe alone decides when it leaves.
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("linger", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    // Probe confirms it alive.
    sqlx::query("UPDATE proxies SET status = 'alive', fail_count = 0 WHERE fingerprint = ?")
        .bind(e.fingerprint())
        .execute(&pool)
        .await
        .unwrap();

    // The feed no longer carries it; linger keeps the link.
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        2000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(stats.unlinked, 0, "the alive proxy keeps its link");
    assert_eq!(stats.removed, 0);
    assert_eq!(status_of(&pool, &e).await.0, "alive");

    // Still served: the link survives, so list_with_source finds it.
    let rows = list_with_source(&pool, &["srcA0000000".to_string()])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);

    // Reappearance: the link is re-stamped, status kept.
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        3000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(stats.updated, 1);
    assert_eq!(status_of(&pool, &e).await.0, "alive");
}

#[tokio::test]
async fn quarantined_linger_survives_the_next_refresh() {
    // `drop_gate = false` means the probe alone retires a proxy. A node
    // that merely dropped out of the feed has failed nothing, so
    // reconcile neither unlinks it nor moves it to `removed`; the
    // recheck ladder keeps working on it through its own link
    // predicate and the next refresh that sees it re-stamps the link.
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("dying", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE proxies SET status = 'quarantine', quarantined_at = 1500 WHERE fingerprint = ?",
    )
    .bind(e.fingerprint())
    .execute(&pool)
    .await
    .unwrap();

    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        2000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(stats.unlinked, 0, "quarantine lingers like the live tiers");
    assert_eq!(stats.removed, 0, "reconcile must not retire anything");
    assert_eq!(status_of(&pool, &e).await.0, "quarantine");
    let (links,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM proxy_source_links l
             JOIN proxies p ON p.id = l.proxy_id WHERE p.fingerprint = ?",
    )
    .bind(e.fingerprint())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(links, 1, "the link must survive, or no lane can reach it");
}

/// The gate itself still works: with `keep_alive_linger = false`
/// (`drop_gate = true` on a source with drop rules) the sweep is not
/// skipped, so a proxy that vanished from the feed is unlinked and
/// retired as before.
#[tokio::test]
async fn drop_gate_still_retires_proxies_that_left_the_feed() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("gone", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE proxies SET status = 'quarantine' WHERE fingerprint = ?")
        .bind(e.fingerprint())
        .execute(&pool)
        .await
        .unwrap();

    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(stats.unlinked, 1);
    assert_eq!(stats.removed, 1);
    assert_eq!(status_of(&pool, &e).await.0, "removed");
}

#[tokio::test]
async fn unknown_lingers_until_next_seen_or_quarantined() {
    // The probe queue gets the `unknown` row before the next refresh
    // can drop it: with linger protection, a one-cycle miss in the
    // feed must not retire a row the probe never had time to check.
    // The link survives, the row stays `unknown`, and a later refresh
    // that re-lists the proxy re-stamps the link cleanly.
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("transient", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&pool, &e).await.0, "unknown");

    // Source drops the proxy on the next refresh (entry omitted).
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        2000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(stats.unlinked, 0, "unknown rows linger like alive/ready");
    assert_eq!(stats.removed, 0);
    assert_eq!(status_of(&pool, &e).await.0, "unknown");

    // The reappearance stamps the link back; status is preserved.
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        3000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(stats.updated, 1);
    assert_eq!(status_of(&pool, &e).await.0, "unknown");

    // And the quarantine transition keeps the linger: under
    // `drop_gate = false` the probe owns the lifecycle end to end, the
    // ladder is what retires the row, not a feed that stopped
    // mentioning it.
    sqlx::query("UPDATE proxies SET status = 'quarantine' WHERE fingerprint = ?")
        .bind(e.fingerprint())
        .execute(&pool)
        .await
        .unwrap();
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        4000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(stats.unlinked, 0, "quarantine lingers too");
    assert_eq!(stats.removed, 0);
    assert_eq!(status_of(&pool, &e).await.0, "quarantine");
}

#[tokio::test]
async fn linger_is_per_proxy_not_per_batch() {
    // One alive, one already-removed row vanish together: only the
    // live one keeps its link in the same reconcile pass. The filter
    // is evaluated per row, so a dead neighbour cannot drag a live
    // proxy out with it.
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let alive = entry("alive", "h1.example.com", 443);
    let dying = entry("dying", "h2.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        &[alive.clone(), dying.clone()],
        &[],
        1000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    for (e, status) in [(&alive, "alive"), (&dying, "removed")] {
        sqlx::query("UPDATE proxies SET status = ? WHERE fingerprint = ?")
            .bind(status)
            .bind(e.fingerprint())
            .execute(&pool)
            .await
            .unwrap();
    }

    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        2000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(stats.unlinked, 1, "only the terminal row loses its link");
    assert_eq!(stats.removed, 0, "the terminal row is already removed");
    assert_eq!(status_of(&pool, &alive).await.0, "alive");
    assert_eq!(status_of(&pool, &dying).await.0, "removed");
}

#[tokio::test]
async fn multi_source_linger_stays_linked_to_the_other_source() {
    // A lingering proxy is per-source: it stays while linked anywhere.
    // (Both sources linger here; the point is removal needs ALL links
    // gone, dropping one source's link must not remove the row.)
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    make_source(&pool, "srcB0000000").await;
    let e = entry("shared", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    reconcile_source(
        &pool,
        "srcB0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE proxies SET status = 'alive' WHERE fingerprint = ?")
        .bind(e.fingerprint())
        .execute(&pool)
        .await
        .unwrap();

    // Source B drops it, source B does not linger (drop-rules gate):
    // the row stays alive thanks to A's link.
    reconcile_source(
        &pool,
        "srcB0000000",
        &[],
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&pool, &e).await.0, "alive");
}

#[tokio::test]
async fn reappearing_removed_proxy_stays_removed() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("x", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&pool, &e).await.0, "removed");

    // Reappearing in a live source does NOT reset the lifecycle
    //: `removed` is terminal for
    // reconciliation; only mutable fields refresh.
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        3000,
        IngestPolicy::refresh(true, true),
    )
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
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("x", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let fp = e.fingerprint();
    sqlx::query(
        "UPDATE proxies SET status = 'quarantine', fail_count = 3,
                quarantined_at = 1500, ladder_at = 9000, ladder_step = 2
             WHERE fingerprint = ?",
    )
    .bind(&fp)
    .execute(&pool)
    .await
    .unwrap();

    // Reappearance must not touch the state machine: the quarantine
    // ladder keeps running on its stored schedule.
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    let row = get_by_fingerprint(&pool, &fp).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
    assert_eq!(row.fail_count, 3);
    assert_eq!(row.quarantined_at, Some(1500));
    assert_eq!(row.ladder_at, Some(9000));
    assert_eq!(row.ladder_step, 2);
}

#[tokio::test]
async fn shared_proxy_survives_until_last_source_lets_go() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    make_source(&pool, "srcB0000000").await;
    let shared = entry("shared", "h1.example.com", 443);

    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&shared),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    reconcile_source(
        &pool,
        "srcB0000000",
        std::slice::from_ref(&shared),
        &[],
        1100,
        IngestPolicy::refresh(true, true),
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
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        2000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(stats.unlinked, 1);
    assert_eq!(stats.removed, 0);
    assert_eq!(status_of(&pool, &shared).await.0, "unknown");

    // Dropping from B as well: now it is removed.
    let stats = reconcile_source(
        &pool,
        "srcB0000000",
        &[],
        &[],
        3000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    assert_eq!(stats.removed, 1);
    assert_eq!(status_of(&pool, &shared).await.0, "removed");
}

/// The end-of-pass sweep answers one question: which proxies does
/// *this* pass leave without a link? A row that was already
/// link-less before the pass started is none of this source's
/// business, and that is exactly the residue the admin source
/// delete leaves behind under `drop_gate = false`, where
/// `mark_orphans_removed` protects `ready` and `unknown` rows on
/// purpose. Reconciling an unrelated source afterwards must not
/// retire them.
#[tokio::test]
async fn reconcile_of_another_source_leaves_protected_orphans_alone() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcD0000000").await;
    let doomed_ready = entry("doomed-ready", "dr.example.com", 443);
    let doomed_unknown = entry("doomed-unknown", "du.example.com", 443);
    reconcile_source(
        &pool,
        "srcD0000000",
        &[doomed_ready.clone(), doomed_unknown.clone()],
        &[],
        1_000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE proxies SET status = 'ready' WHERE fingerprint = ?")
        .bind(doomed_ready.fingerprint())
        .execute(&pool)
        .await
        .unwrap();

    // The source is deleted: the click protects the verified and the
    // not-yet-checked row, both stay behind without a link.
    assert!(sources_repo::delete(&pool, "srcD0000000").await.unwrap());
    assert_eq!(
        mark_orphans_removed(&pool, &["ready", "unknown"])
            .await
            .unwrap()
            .retired,
        0
    );

    // An unrelated source is reconciled. Its own pass must not touch
    // the two rows the delete left behind.
    make_source(&pool, "srcD0000001").await;
    let survivor = entry("survivor", "sv.example.com", 443);
    let stats = reconcile_source(
        &pool,
        "srcD0000001",
        std::slice::from_ref(&survivor),
        &[],
        2_000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();

    assert_eq!(stats.removed, 0, "the pass retires only its own orphans");
    assert_eq!(status_of(&pool, &doomed_ready).await.0, "ready");
    assert_eq!(status_of(&pool, &doomed_unknown).await.0, "unknown");
    assert_eq!(status_of(&pool, &survivor).await.0, "unknown");
}

#[tokio::test]
async fn duplicate_entries_in_one_batch_collapse() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let a = entry("name-A", "h1.example.com", 443);
    let b = entry("name-B", "h1.example.com", 443); // same fingerprint
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[a, b],
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
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
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("conv", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
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
async fn list_alive_and_count_cover_linked_alive_only() {
    let (_dir, pool) = temp_pool().await;
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
        IngestPolicy::refresh(true, true),
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
    let hosts: Vec<String> = list_alive(&pool, 1_000)
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
    assert!(list_alive(&pool, 1_000).await.unwrap().is_empty());
}

/// The export backing query is bounded in SQL: it is the public
/// «all alive» link, and it serializes and ships every row it
/// returns, so an unbounded `fetch_all` there is an unbounded render
/// and an unbounded response body. The cap truncates the stable
/// id-ascending order, so it is deterministic, and the badge count
/// (`count_alive`) deliberately stays the full tier: the operator
/// must be able to see that the export is smaller than the tier.
#[tokio::test]
async fn list_alive_and_list_ready_apply_the_sql_cap() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let entries: Vec<_> = (0..6)
        .map(|i| entry(&format!("cap{i}"), &format!("cap{i}.example.com"), 443))
        .collect();
    reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    for (i, e) in entries.iter().enumerate() {
        let status = if i < 3 { "alive" } else { "ready" };
        sqlx::query("UPDATE proxies SET status = ? WHERE fingerprint = ?")
            .bind(status)
            .bind(e.fingerprint())
            .execute(&pool)
            .await
            .unwrap();
    }
    assert_eq!(count_alive(&pool).await.unwrap(), 3);
    assert_eq!(count_ready(&pool).await.unwrap(), 3);

    // Under the cap the tier comes back whole.
    assert_eq!(list_alive(&pool, 10).await.unwrap().len(), 3);
    assert_eq!(list_ready(&pool, 10).await.unwrap().len(), 3);

    // At the cap it is truncated to the lowest ids, deterministically
    // across two reads.
    let capped: Vec<i64> = list_alive(&pool, 2)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    let all: Vec<i64> = list_alive(&pool, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(capped, all[..2].to_vec());
    assert_eq!(
        list_alive(&pool, 2).await.unwrap().len(),
        2,
        "the cap is stable, not a random slice"
    );

    // A cap of 0 must not become "no limit" (SQLite reads a negative
    // LIMIT as unbounded); it clamps up to one row.
    assert_eq!(list_alive(&pool, 0).await.unwrap().len(), 1);
    // An absurd cap does not overflow the bind.
    assert_eq!(list_alive(&pool, u32::MAX).await.unwrap().len(), 3);

    // The ready tier is capped the same way: the export link and the
    // badge share the tier, so the truncation must not differ between
    // them.
    let ready_capped: Vec<i64> = list_ready(&pool, 2)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    let ready_all: Vec<i64> = list_ready(&pool, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(ready_capped, ready_all[..2].to_vec());
    assert_eq!(list_ready(&pool, 0).await.unwrap().len(), 1);
    assert_eq!(list_ready(&pool, u32::MAX).await.unwrap().len(), 3);
    // The badge stays the full tier: the operator must be able to see
    // that the export is smaller than the tier.
    assert_eq!(count_ready(&pool).await.unwrap(), 3);
}

/// Admin *Reset status* is "check this proxy again from scratch", and
/// a from-scratch row carries no T2 block: both T1 lanes (the random
/// sample and the priority queue) filter on
/// `last_t2_failed_at IS NULL` and the T2 sample only offers
/// `alive`/`ready` rows, so a reset row that kept the stamp would
/// belong to no probe lane at all. The id is also queued for
/// priority checking, the handoff the bulk revival paths give their
/// callers (this function's caller only learns that the row exists).
#[tokio::test]
async fn reset_status_clears_the_t2_block_and_queues_a_check() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "reset.example.com").await;
    sqlx::query(
        "UPDATE proxies SET status = 'removed', fail_count = 7, removed_at = 900,
                  quarantined_at = 800, last_t2_failed_at = 700 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    assert!(reset_status(&pool, id).await.unwrap());

    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "unknown");
    assert_eq!(row.fail_count, 0);
    assert_eq!(row.quarantined_at, None);
    assert_eq!(row.removed_at, None);
    assert_eq!(
        row.last_t2_failed_at, None,
        "a reset row must not stay behind a stale T2 block"
    );

    // The row is reachable by the probe again: both T1 lanes see it.
    let queued: Vec<i64> = crate::repo::probe::select_queued_checks(&pool, 10)
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(queued, vec![id], "the reset row is queued for a check");
    let sampled: Vec<i64> = select_t1_candidates(&pool, 100)
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert!(sampled.contains(&id));

    // A missing id changes nothing and queues nothing.
    assert!(!reset_status(&pool, id + 1_000).await.unwrap());
    let (pending,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM probe_requests")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 1);
}

/// A reset that no probe lane can pick up must not report success and
/// must not half-apply. Two shapes reach the operator's button: a
/// reconcile-retired row (retired and unlinked in one transaction) and
/// a row whose scheme no lane judges (`tuic`, `mieru`; hysteria2 is
/// T1-excluded but T2 offers it while `unknown`). Before the guard such
/// a reset wrote the whole lifecycle and then enqueued nothing, so the
/// operator got a success toast and a row in no lane at all.
#[tokio::test]
async fn reset_status_refuses_a_row_no_probe_lane_can_reach() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;

    // Retired and unlinked, the normal shape of a reconcile-retired
    // row, carrying the T2 block the previous fix clears.
    let (unlinked,): (i64,) = sqlx::query_as(
        "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential,
                                  status, fail_count, removed_at, last_t2_failed_at,
                                  created_at, updated_at)
             VALUES ('fp-unlinked', 'vless', 'n', 'retired.example.com', 443, 'c',
                     'removed', 3, 900, 700, 1, 1)
             RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    // Linked, but a scheme neither T1 nor T2 will ever check.
    let (tuic,): (i64,) = sqlx::query_as(
        "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential,
                                  status, fail_count, removed_at, last_t2_failed_at,
                                  created_at, updated_at)
             VALUES ('fp-tuic', 'tuic', 'n', 'tuic.example.com', 443, 'c',
                     'removed', 4, 901, 701, 1, 1)
             RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, 'srcA0000000', 1)")
            .bind(tuic)
            .execute(&pool)
            .await
            .unwrap();

    for id in [unlinked, tuic] {
        assert!(
            !reset_status(&pool, id).await.unwrap(),
            "id {id}: a row no lane can reach must not be reported as reset"
        );
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "removed", "id {id}: left untouched");
        assert_eq!(row.fail_count, 3 + i64::from(id == tuic), "id {id}");
        assert_eq!(row.removed_at, Some(900 + i64::from(id == tuic)), "id {id}");
        assert_eq!(
            row.last_t2_failed_at,
            Some(700 + i64::from(id == tuic)),
            "id {id}: the T2 block stays, the row is where it was"
        );
    }

    // Nothing was queued, so no lane offers either id either.
    let (pending,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM probe_requests")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
    for id in [unlinked, tuic] {
        assert!(
            !select_t1_candidates(&pool, 100)
                .await
                .unwrap()
                .iter()
                .any(|c| c.id == id),
            "id {id} must stay out of the T1 sample"
        );
        assert!(
            !select_t2_candidates(&pool, 100)
                .await
                .unwrap()
                .iter()
                .any(|r| r.id == id),
            "id {id} must stay out of the T2 sample"
        );
    }
}

/// A linked `hysteria2` row is reachable, so a reset of it must
/// succeed: hysteria2 is excluded from the T1 sample, but the T2 sample
/// offers it while it is still `unknown`. A reset that refused it would
/// leave the row exactly where it was, and a reset that cleared the T2
/// block but reported failure would send the operator looking for a
/// failure that did not happen.
#[tokio::test]
async fn reset_status_accepts_a_linked_hysteria2_row() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "hysteria2", "hy.example.com").await;
    sqlx::query(
        "UPDATE proxies SET status = 'unknown', fail_count = 2, last_t2_failed_at = 700 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    assert!(reset_status(&pool, id).await.unwrap());

    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "unknown");
    assert_eq!(row.fail_count, 0);
    assert_eq!(
        row.last_t2_failed_at, None,
        "a reset row must not stay behind a stale T2 block"
    );

    // The row stays in the T2 sample: it is the one lane that judges it.
    let t2_ids: Vec<i64> = select_t2_candidates(&pool, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(
        t2_ids.contains(&id),
        "the reset hysteria2 row must stay reachable for the T2 sample"
    );
}

// Probe state machine.

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
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "h1.example.com").await;

    let transition = check_succeeded(&pool, id, 5000, Some(42), true, ProxyStatus::Alive)
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
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("t2-failed", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM proxies WHERE fingerprint = ?")
        .bind(e.fingerprint())
        .fetch_one(&pool)
        .await
        .unwrap();
    // Failures already accumulated, e.g. two failed tunnel checks.
    sqlx::query("UPDATE proxies SET status = 'alive', fail_count = 2 WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    // A T1-style success WITHOUT reset keeps the T2-accumulated counter
    // (strict T2 priority) and keeps the proxy alive.
    let transition = check_succeeded(&pool, id, 2000, Some(30), false, ProxyStatus::Alive)
        .await
        .unwrap();
    assert_eq!(transition, Transition::Revived);
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert_eq!(row.fail_count, 2);

    // With reset the counter is wiped.
    check_succeeded(&pool, id, 3000, Some(31), true, ProxyStatus::Alive)
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
    let transition = check_succeeded(&pool, id, 4000, Some(32), true, ProxyStatus::Alive)
        .await
        .unwrap();
    assert_eq!(transition, Transition::Unchanged);
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "removed");
}

/// The `ready` tier: a successful T2
/// promotes to `ready`; a below-limit failure demotes back to `alive`;
/// a T1 success never touches a `ready` row.
#[tokio::test]
async fn ready_tier_lifecycle() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "h1.example.com").await;

    // T1 success → alive (the plain tier).
    check_succeeded(&pool, id, 1000, Some(20), true, ProxyStatus::Alive)
        .await
        .unwrap();

    // T2 success → ready (the tunnel-verified tier).
    check_succeeded(&pool, id, 2000, Some(42), true, ProxyStatus::Ready)
        .await
        .unwrap();
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");
    assert_eq!(row.fail_count, 0);

    // A later T1 success must NOT demote the verified row (CASE keeps
    // ready), only a failed T2 outcome may.
    check_succeeded(&pool, id, 3000, Some(21), true, ProxyStatus::Alive)
        .await
        .unwrap();
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");
    assert_eq!(row.latency_ms, Some(21), "the T1 latency is stored");

    // A failed T2 (below the limit) demotes to alive.
    let transition = check_failed(&pool, id, 4000, 3, 86_400, 0, false)
        .await
        .unwrap();
    assert_eq!(transition, Transition::Unchanged);
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert_eq!(row.fail_count, 1);

    // The next T2 success promotes back.
    check_succeeded(&pool, id, 5000, Some(45), true, ProxyStatus::Ready)
        .await
        .unwrap();
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");

    // The verified row is served by the ready export and by no other
    // one: the two tiers are disjoint, and a `ready` row is not also
    // counted as `alive`.
    let alive_ids: Vec<i64> = list_alive(&pool, 1_000)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    let ready_ids: Vec<i64> = list_ready(&pool, 1_000)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(
        ready_ids.contains(&id),
        "the verified row is served as ready"
    );
    assert!(
        !alive_ids.contains(&id),
        "the verified row is not served as alive"
    );
    assert!(
        alive_ids.iter().all(|other| !ready_ids.contains(other)),
        "the alive and ready tiers must not overlap"
    );

    // Reaching the fail limit from ready quarantines like from alive.
    for _ in 0..2 {
        check_failed(&pool, id, 6000, 2, 86_400, 0, false)
            .await
            .unwrap();
    }
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
    assert_eq!(row.fail_count, 2);

    // A quarantined row is served by neither tier.
    let alive_rows = list_alive(&pool, 1_000).await.unwrap();
    let ready_rows = list_ready(&pool, 1_000).await.unwrap();
    assert!(alive_rows.iter().all(|r| r.id != id));
    assert!(ready_rows.iter().all(|r| r.id != id));
}

/// Linger protects `ready` exactly like `alive`: a tunnel-verified
/// proxy that vanished from the feed keeps its link.
#[tokio::test]
async fn linger_protects_ready() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("verified-linger", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM proxies WHERE fingerprint = ?")
        .bind(e.fingerprint())
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET status = 'ready' WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    // The feed no longer carries it; linger keeps the link.
    let stats = reconcile_source(
        &pool,
        "srcA0000000",
        &[],
        &[],
        2000,
        IngestPolicy::from_drop_gate(false),
    )
    .await
    .unwrap();
    assert_eq!(stats.unlinked, 0, "the ready proxy keeps its link");
    assert_eq!(stats.removed, 0);
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");
}

#[tokio::test]
async fn failures_below_limit_only_bump_counter() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "h1.example.com").await;

    for step in 1..3i64 {
        let transition = check_failed(&pool, id, 1000 + step, 3, 86_400, 86_400, false)
            .await
            .unwrap();
        assert_eq!(transition, Transition::Unchanged);
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "unknown");
        assert_eq!(row.fail_count, step);
        assert_eq!(row.quarantined_at, None);
    }
}

/// `check_failed` reads `fail_count` and writes back `fail_count + 1`:
/// a read-modify-write, so the read and the write have to be one
/// atomic step. Two checks of the same row in flight at once (the
/// probe can pick the same proxy up in two lanes, and the admin
/// actions write to the same table) must both count: split into a
/// read statement and a write statement, the second one writes back
/// the value it read before the first bump landed and the failure is
/// lost.
///
/// The contention is forced, not hoped for: one connection holds the
/// write lock inside an open transaction that bumps the counter, and
/// the second failure is issued while that transaction is still open,
/// so its statement waits for the lock. A split implementation would
/// read the pre-transaction value on the waiting connection and write
/// back 1, losing the first bump; the single atomic statement reads
/// the committed value and writes 2.
#[tokio::test]
async fn check_failed_counts_every_overlapping_check() {
    let (_dir, pool) = temp_pool().await;
    for round in 0..5 {
        let id = seed_proxy(&pool, "vless", &format!("race{round}.example.com")).await;

        let mut locked = pool.acquire().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *locked)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE proxies SET fail_count = fail_count + 1, last_checked_at = ? WHERE id = ?",
        )
        .bind(1_000)
        .bind(id)
        .execute(&mut *locked)
        .await
        .unwrap();

        // The second failure is issued while the first transaction is
        // still open: it waits for the write lock.
        let waiting = tokio::spawn({
            let pool = pool.clone();
            async move { check_failed(&pool, id, 1_000, 100, 86_400, 0, false).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        sqlx::query("COMMIT").execute(&mut *locked).await.unwrap();
        drop(locked);

        assert_eq!(waiting.await.unwrap().unwrap(), Transition::Unchanged);

        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(
            row.fail_count, 2,
            "round {round}: two overlapping failures must both be counted"
        );
        assert_eq!(row.status, "unknown");
    }
}

#[tokio::test]
async fn reaching_fail_limit_quarantines_with_jittered_second_chance() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "h1.example.com").await;
    let now = 100_000i64;

    check_failed(&pool, id, now - 10, 3, 86_400, 86_400, false)
        .await
        .unwrap();
    check_failed(&pool, id, now - 5, 3, 86_400, 86_400, false)
        .await
        .unwrap();
    let transition = check_failed(&pool, id, now, 3, 86_400, 86_400, false)
        .await
        .unwrap();
    assert_eq!(transition, Transition::Quarantined);

    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
    assert_eq!(row.fail_count, 3);
    assert_eq!(row.quarantined_at, Some(now));
    // ladder_at ∈ [now + 24h, now + 48h), waiting on step 0.
    let sc = row.ladder_at.unwrap();
    assert!(sc >= now + 86_400, "second chance too early: {sc}");
    assert!(sc < now + 2 * 86_400, "second chance too late: {sc}");
    assert_eq!(row.ladder_step, 0);
    assert_eq!(row.removed_at, None);
}

/// An engine outage (meow-rs down) is a fault of the sidecar, not a
/// verdict about the proxy: it must stamp the outstanding T2 verdict
/// and demote a `ready` row, but never touch the fail counter and
/// never quarantine. Repeated past the shipped `fail_limit` of 2, the
/// row would otherwise drop out of both T2 selectors and out of
/// `/export/alive` for an outage it did not cause.
#[tokio::test]
async fn engine_outage_stamps_t2_without_charging_the_fail_budget() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "outage.example.com").await;
    // Tunnel-verified, one genuine T2 failure already on the counter.
    check_succeeded(&pool, id, 1_000, Some(42), true, ProxyStatus::Ready)
        .await
        .unwrap();
    check_failed(&pool, id, 2_000, 3, 86_400, 0, true)
        .await
        .unwrap();
    check_succeeded(&pool, id, 3_000, Some(43), true, ProxyStatus::Ready)
        .await
        .unwrap();
    let before = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(before.status, "ready");
    assert_eq!(before.fail_count, 0);

    // Three outage cycles, i.e. past the shipped fail_limit of 2.
    for cycle in 1..=3 {
        assert!(
            check_engine_unavailable(&pool, id, 10_000 * cycle)
                .await
                .unwrap()
        );
    }
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.fail_count, 0,
        "an engine outage must not charge the proxy's fail budget"
    );
    assert_eq!(
        row.status, "alive",
        "a T2 verdict is outstanding, so the ready tier must not survive the outage"
    );
    assert_eq!(
        row.last_t2_failed_at,
        Some(30_000),
        "the outstanding T2 verdict is stamped (T1 stays suppressed)"
    );
    assert_eq!(row.quarantined_at, None);
    assert_eq!(row.ladder_at, None, "no second chance is scheduled");

    // A genuine T2 failure after the outage still counts from zero.
    assert_eq!(
        check_failed(&pool, id, 40_000, 2, 86_400, 0, true)
            .await
            .unwrap(),
        Transition::Unchanged
    );
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.fail_count, 1);
    assert_eq!(row.status, "alive");
}

/// The status guard is the one `check_failed` uses: a quarantined or
/// removed row keeps its own schedule and the call reports that
/// nothing was written.
#[tokio::test]
async fn engine_outage_leaves_quarantined_and_removed_rows_alone() {
    let (_dir, pool) = temp_pool().await;
    for (host, status) in [
        ("outage-quar.example.com", "quarantine"),
        ("outage-gone.example.com", "removed"),
    ] {
        let id = seed_proxy(&pool, "vless", host).await;
        sqlx::query("UPDATE proxies SET status = ? WHERE id = ?")
            .bind(status)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !check_engine_unavailable(&pool, id, 5_000).await.unwrap(),
            "a {status} row must not be stamped"
        );
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, status);
        assert_eq!(row.last_t2_failed_at, None);
    }
}

#[tokio::test]
async fn second_chance_success_revives_with_clean_slate() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "h1.example.com").await;
    for t in [10, 20, 30] {
        check_failed(&pool, id, t, 3, 86_400, 0, false)
            .await
            .unwrap();
    }
    assert_eq!(
        get_by_id(&pool, id).await.unwrap().unwrap().status,
        "quarantine"
    );

    // The revival is a T1-style check → plain alive (the next
    // successful T2 promotes to ready).
    let transition = check_succeeded(&pool, id, 90_000, Some(10), true, ProxyStatus::Alive)
        .await
        .unwrap();
    assert_eq!(transition, Transition::Revived);
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert_eq!(row.fail_count, 0);
    assert_eq!(row.quarantined_at, None);
    assert_eq!(row.ladder_at, None);
    assert_eq!(row.ladder_step, 0);
    assert_eq!(row.last_alive_at, Some(90_000));
}

#[tokio::test]
async fn failed_ladder_walks_15m_30m_1h_then_removes() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "h1.example.com").await;
    for t in [10, 20, 30] {
        check_failed(&pool, id, t, 3, 86_400, 0, false)
            .await
            .unwrap();
    }
    // The default ladder: three rechecks after the second chance.
    let delays = [900i64, 1800, 3600];

    // Second chance (step 0) fails → recheck in 15 minutes from the
    // failure, now on step 1.
    let t = 90_000i64;
    let transition = quarantine_check_failed(&pool, id, t, 0, &delays)
        .await
        .unwrap();
    assert_eq!(transition, Transition::Unchanged);
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.ladder_at, Some(t + delays[0]));
    assert_eq!(row.ladder_step, 1);

    // First recheck fails → +30m from this failure, step 2.
    let t = t + delays[0];
    quarantine_check_failed(&pool, id, t, 1, &delays)
        .await
        .unwrap();
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.ladder_at, Some(t + delays[1]));
    assert_eq!(row.ladder_step, 2);

    // Second recheck fails → +1h from this failure, step 3.
    let t = t + delays[1];
    quarantine_check_failed(&pool, id, t, 2, &delays)
        .await
        .unwrap();
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.ladder_at, Some(t + delays[2]));
    assert_eq!(row.ladder_step, 3);

    // Final recheck fails → past the end of the delays: removed.
    let t = t + delays[2];
    let transition = quarantine_check_failed(&pool, id, t, 3, &delays)
        .await
        .unwrap();
    assert_eq!(transition, Transition::Removed);
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "removed");
    assert_eq!(row.removed_at, Some(t));
    assert_eq!(row.ladder_at, None);
}

/// The ladder length follows `recheck_delays_secs`: an empty list
/// removes right after the failed second chance, a single entry after
/// one recheck, a longer list simply extends the walk.
#[tokio::test]
async fn ladder_length_follows_configured_delays() {
    let (_dir, pool) = temp_pool().await;

    // Empty ladder: the failed second chance removes immediately.
    let id = seed_proxy(&pool, "vless", "empty.example.com").await;
    for t in [10, 20, 30] {
        check_failed(&pool, id, t, 3, 86_400, 0, false)
            .await
            .unwrap();
    }
    let transition = quarantine_check_failed(&pool, id, 100, 0, &[])
        .await
        .unwrap();
    assert_eq!(transition, Transition::Removed);
    assert_eq!(
        get_by_id(&pool, id).await.unwrap().unwrap().status,
        "removed"
    );

    // One recheck: second chance → recheck → removed.
    let id = seed_proxy(&pool, "vless", "one.example.com").await;
    for t in [10, 20, 30] {
        check_failed(&pool, id, t, 3, 86_400, 0, false)
            .await
            .unwrap();
    }
    assert_eq!(
        quarantine_check_failed(&pool, id, 100, 0, &[600])
            .await
            .unwrap(),
        Transition::Unchanged
    );
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!((row.ladder_at, row.ladder_step), (Some(700), 1));
    assert_eq!(
        quarantine_check_failed(&pool, id, 700, 1, &[600])
            .await
            .unwrap(),
        Transition::Removed
    );

    // Four rechecks: the walk goes through step 4 before removal.
    let id = seed_proxy(&pool, "vless", "four.example.com").await;
    for t in [10, 20, 30] {
        check_failed(&pool, id, t, 3, 86_400, 0, false)
            .await
            .unwrap();
    }
    let delays = [60i64; 4];
    for step in 0..4i64 {
        assert_eq!(
            quarantine_check_failed(&pool, id, 1000 + step, step, &delays)
                .await
                .unwrap(),
            Transition::Unchanged
        );
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.ladder_step, step + 1);
    }
    assert_eq!(
        quarantine_check_failed(&pool, id, 2000, 4, &delays)
            .await
            .unwrap(),
        Transition::Removed
    );
}

#[tokio::test]
async fn recheck_success_at_any_step_revives() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "h1.example.com").await;
    for t in [10, 20, 30] {
        check_failed(&pool, id, t, 3, 86_400, 0, false)
            .await
            .unwrap();
    }
    quarantine_check_failed(&pool, id, 90_000, 0, &[900])
        .await
        .unwrap();

    // The first recheck succeeds → alive again (a T1-style revival;
    // the next successful T2 promotes to ready).
    let transition = check_succeeded(&pool, id, 90_000 + 900, None, true, ProxyStatus::Alive)
        .await
        .unwrap();
    assert_eq!(transition, Transition::Revived);
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert_eq!(row.ladder_at, None);
}

#[tokio::test]
async fn due_quarantine_selection_respects_schedule_and_step() {
    let (_dir, pool) = temp_pool().await;
    let early = seed_proxy(&pool, "vless", "early.example.com").await;
    let late = seed_proxy(&pool, "vless", "late.example.com").await;
    let ladder = seed_proxy(&pool, "vless", "ladder.example.com").await;

    // early: second chance already due; late: still sleeping.
    sqlx::query(
            "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, ladder_at = ?, ladder_step = 0 WHERE id = ?",
        )
        .bind(1_000i64)
        .bind(early)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
            "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, ladder_at = ?, ladder_step = 0 WHERE id = ?",
        )
        .bind(999_999i64)
        .bind(late)
        .execute(&pool)
        .await
        .unwrap();
    // ladder: mid-ladder with a due second recheck.
    sqlx::query(
            "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, ladder_at = ?, ladder_step = 2 WHERE id = ?",
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

    let steps: std::collections::HashMap<i64, i64> =
        due.into_iter().map(|d| (d.id, d.ladder_step)).collect();
    assert_eq!(steps[&early], 0);
    assert_eq!(steps[&ladder], 2);
}

/// Quarantine dues split by revival lane: [`T2_REVIVAL_SCHEMES`] rows come
/// back only from [`select_due_quarantine_t2`], everything else only from
/// [`select_due_quarantine`]: a due row must not be charged by both lanes.
#[tokio::test]
async fn quarantine_dues_split_by_revival_kind() {
    let (_dir, pool) = temp_pool().await;
    let vless = seed_proxy(&pool, "vless", "v.example.com").await;
    let hysteria2 = seed_proxy(&pool, "hysteria2", "hy.example.com").await;
    let tuic = seed_proxy(&pool, "tuic", "tu.example.com").await;
    for id in [vless, hysteria2, tuic] {
        sqlx::query(
                "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, ladder_at = 100, ladder_step = 0 WHERE id = ?",
            )
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }

    let mut t1_ids: Vec<i64> = select_due_quarantine(&pool, 5_000, 100)
        .await
        .unwrap()
        .iter()
        .map(|d| d.id)
        .collect();
    t1_ids.sort();
    assert_eq!(t1_ids, vec![vless, tuic]);

    // Full rows: the revival check needs credentials and the ladder step.
    let t2_due = select_due_quarantine_t2(&pool, 5_000, 100).await.unwrap();
    let t2_ids: Vec<i64> = t2_due.iter().map(|row| row.id).collect();
    assert_eq!(t2_ids, vec![hysteria2]);
    assert_eq!(t2_due[0].scheme, "hysteria2");
    assert_eq!(t2_due[0].ladder_step, 0);

    // Not yet due: nothing comes back from either lane.
    assert!(
        select_due_quarantine(&pool, 50, 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        select_due_quarantine_t2(&pool, 50, 100)
            .await
            .unwrap()
            .is_empty()
    );
}

/// `T2_REVIVAL_SCHEMES` must equal the intersection of [`T1_EXCLUDED_SCHEMES`]
/// and [`T2_SCHEMES`]: a scheme entering or leaving either set updates this
/// const in the same change.
#[test]
fn t2_revival_schemes_intersect_t1_excluded_with_t2_supported() {
    let revival: Vec<&str> = T1_EXCLUDED_SCHEMES
        .iter()
        .filter(|scheme| T2_SCHEMES.contains(scheme))
        .copied()
        .collect();
    assert_eq!(T2_REVIVAL_SCHEMES, revival.as_slice());
    assert_eq!(T2_REVIVAL_SCHEMES, ["hysteria2"]);
}

#[tokio::test]
async fn t1_candidates_skip_unprobeable_unlinked_and_quarantined() {
    let (_dir, pool) = temp_pool().await;
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

/// A `last_t2_failed_at` stamp excludes the proxy from the T1 sample:
/// the only path back to T1 is a successful T2.
#[tokio::test]
async fn t1_candidates_skip_proxies_with_recent_t2_failure() {
    let (_dir, pool) = temp_pool().await;
    let clean = seed_proxy(&pool, "vless", "clean.example.com").await;
    let blocked = seed_proxy(&pool, "vless", "blocked.example.com").await;

    // Mark only `blocked` as recently T2-failed.
    sqlx::query("UPDATE proxies SET last_t2_failed_at = 5_000 WHERE id = ?")
        .bind(blocked)
        .execute(&pool)
        .await
        .unwrap();

    let ids: Vec<i64> = select_t1_candidates(&pool, 100)
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(ids, vec![clean]);
}

/// A T1-side failure must not stamp `last_t2_failed_at`: a closed
/// TCP/TLS port does not mean the tunnel is dead, and T1 needs to keep
/// retrying on its own schedule. Only T2 callers pass `true`.
#[tokio::test]
async fn t1_failure_does_not_set_t2_block() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "t1fail.example.com").await;

    // fail_limit=100 so a single T1 fail does not move us to quarantine
    // and the row stays in the T1 candidate set.
    check_failed(&pool, id, 1_000, 100, 86_400, 0, false)
        .await
        .unwrap();

    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert!(
        row.last_t2_failed_at.is_none(),
        "T1 failure must not stamp last_t2_failed_at, got {:?}",
        row.last_t2_failed_at
    );
}

/// The symmetric side of the suppression flag, as migration 0007
/// states it: "T1 checks for the proxy are skipped **until the next
/// successful T2** clears the flag", only a T2 success lifts it. A
/// plain TCP/TLS success says nothing about the tunnel, so it must
/// leave `last_t2_failed_at` alone and the row out of the T1 sample;
/// the T2 recency selector is the only way back.
#[tokio::test]
async fn t2_block_clears_on_next_t2_success_only() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "unblock.example.com").await;

    sqlx::query("UPDATE proxies SET last_t2_failed_at = 1_000 WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    let blocked_ids: Vec<i64> = select_t1_candidates(&pool, 100)
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert!(!blocked_ids.contains(&id));

    // A T1 success: the row is `alive` again, the block stays.
    check_succeeded(&pool, id, 2_000, Some(10), false, ProxyStatus::Alive)
        .await
        .unwrap();

    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert_eq!(
        row.last_t2_failed_at,
        Some(1_000),
        "a T1 success must not clear last_t2_failed_at"
    );
    let still_blocked: Vec<i64> = select_t1_candidates(&pool, 100)
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert!(
        !still_blocked.contains(&id),
        "a T1-success row under a T2 block stays out of the T1 sample"
    );

    // The T2 success the probe writes for a passing tunnel check
    // (`status_to = ready`) is what lifts the block.
    check_succeeded(&pool, id, 3_000, Some(20), true, ProxyStatus::Ready)
        .await
        .unwrap();

    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");
    assert!(
        row.last_t2_failed_at.is_none(),
        "a T2 success must clear last_t2_failed_at, got {:?}",
        row.last_t2_failed_at
    );
}

#[tokio::test]
async fn full_lifecycle_is_restart_safe() {
    // The whole machine is driven by DB columns only: simulate a daemon
    // restart by re-reading state between every step, no in-memory
    // carryover is required to advance the lifecycle.
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "h1.example.com").await;

    for t in [10, 20, 30] {
        check_failed(&pool, id, t, 3, 86_400, 0, false)
            .await
            .unwrap();
    }
    // "Restart": derive everything from the row itself.
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
    let sc = row.ladder_at.unwrap();

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
    assert_eq!(due[0].ladder_step, 0);

    // Fail it, restart again, and the ladder continues from the DB.
    quarantine_check_failed(&pool, id, sc, 0, &[900, 1800, 3600])
        .await
        .unwrap();
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    let next = row.ladder_at.unwrap();
    assert_eq!(row.ladder_step, 1);
    let due = select_due_quarantine(&pool, next, 100).await.unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].ladder_step, 1);
}

#[tokio::test]
async fn t2_sample_offers_only_t1_passed_proxies() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let alive = entry("alive", "h1.example.com", 443);
    let never_checked = entry("never", "h2.example.com", 443);
    let quarantined = entry("quar", "h3.example.com", 443);
    let removed = entry("gone", "h4.example.com", 443);
    // tuic cannot pass T1 by design, even an "alive" one must not be
    // offered to T2 (meow-rs cannot tunnel it). naive passes
    // that old NOT IN guard but has no mihomo counterpart either: the
    // allowlist must keep it out too, or under the recency order it
    // would occupy the head of every batch (starvation).
    let mut alive_unprobeable = entry("tuic", "h5.example.com", 443);
    alive_unprobeable.scheme = Scheme::Tuic;
    let mut alive_naive = entry("naive", "h7.example.com", 443);
    alive_naive.scheme = Scheme::Naive;
    // hysteria2 skips T1 entirely (a TCP connect proves nothing on
    // QUIC): an `unknown` one goes straight to the T2 batch.
    let mut fresh_hysteria2 = entry("hy2", "h6.example.com", 443);
    fresh_hysteria2.scheme = Scheme::Hysteria2;
    let all = vec![
        alive.clone(),
        never_checked.clone(),
        quarantined.clone(),
        removed.clone(),
        alive_unprobeable.clone(),
        fresh_hysteria2.clone(),
        alive_naive.clone(),
    ];
    reconcile_source(
        &pool,
        "srcA0000000",
        &all,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    for (proxy, status) in [
        (&alive, "alive"),
        (&never_checked, "unknown"),
        (&quarantined, "quarantine"),
        (&removed, "removed"),
        (&alive_unprobeable, "alive"),
        (&fresh_hysteria2, "unknown"),
        (&alive_naive, "alive"),
    ] {
        sqlx::query("UPDATE proxies SET status = ? WHERE fingerprint = ?")
            .bind(status)
            .bind(proxy.fingerprint())
            .execute(&pool)
            .await
            .unwrap();
    }

    let mut candidates = select_t2_candidates(&pool, 100).await.unwrap();
    candidates.sort_by(|a, b| a.host.cmp(&b.host));
    let hosts: Vec<&str> = candidates.iter().map(|row| row.host.as_str()).collect();
    assert_eq!(hosts, vec!["h1.example.com", "h6.example.com"]);
}

/// Journal one probe result through the production write path, so the
/// denormalised T2 recency stamp follows the journal the way it does in
/// the probe daemon.
async fn journal_result(pool: &DbPool, id: i64, at: i64, ok: bool, kind: &str) {
    crate::repo::probe::insert(
        pool,
        &crate::repo::probe::ProbeResultEntry {
            proxy_id: id,
            checked_at: at,
            ok,
            latency_ms: None,
            error: None,
            probe_kind: kind,
        },
    )
    .await
    .unwrap();
}

/// The T2 batch is recency-prioritized:
/// never-checked proxies first, then the ones whose last T2 check is
/// the oldest, a large pool must not keep a proxy tunnel-unverified
/// for months while its `alive` rests on T1 connectivity alone.
#[tokio::test]
async fn t2_sample_prioritizes_never_checked_then_oldest_last_check() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    // Five alive proxies: two never T2-checked, three checked at
    // increasing timestamps.
    let all = vec![
        entry("fresh-a", "a.example.com", 443),
        entry("fresh-b", "b.example.com", 443),
        entry("stale", "s.example.com", 443),
        entry("mid", "m.example.com", 443),
        entry("recent", "r.example.com", 443),
    ];
    reconcile_source(
        &pool,
        "srcA0000000",
        &all,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    let id_of = async |fp: &str| get_by_fingerprint(&pool, fp).await.unwrap().unwrap().id;
    let stale_id = id_of(&entry("stale", "s.example.com", 443).fingerprint()).await;
    let mid_id = id_of(&entry("mid", "m.example.com", 443).fingerprint()).await;
    let recent_id = id_of(&entry("recent", "r.example.com", 443).fingerprint()).await;
    for (id, at) in [(stale_id, 100), (mid_id, 200), (recent_id, 300)] {
        journal_result(&pool, id, at, true, "t2").await;
    }
    // T1 history must not disturb the T2 recency: `stale` also has a
    // fresh tcp row, yet its last t2 is still the oldest.
    journal_result(&pool, stale_id, 9_999, true, "tcp").await;
    sqlx::query("UPDATE proxies SET status = 'alive' WHERE status = 'unknown'")
        .execute(&pool)
        .await
        .unwrap();

    let candidates = select_t2_candidates(&pool, 100).await.unwrap();
    let hosts: Vec<&str> = candidates.iter().map(|row| row.host.as_str()).collect();
    // Never-checked first, then the oldest last check upward; ties
    // between the two never-checked rows break by id, which follows
    // insertion order here (a, b).
    assert_eq!(
        hosts,
        vec![
            "a.example.com",
            "b.example.com",
            "s.example.com",
            "m.example.com",
            "r.example.com",
        ]
    );

    // A limit cuts from the tail: the freshest-recently-checked row
    // waits for a later batch, the head of the order is unchanged.
    let head = select_t2_candidates(&pool, 3).await.unwrap();
    let hosts: Vec<&str> = head.iter().map(|row| row.host.as_str()).collect();
    assert_eq!(
        hosts,
        vec!["a.example.com", "b.example.com", "s.example.com"]
    );
}

/// The recency stamp lives on the proxy row, not in the journal: the
/// T2 batch must not walk the history to learn when a proxy was last
/// tunnel-checked. The stamp is written by the journal write path, only
/// for the T2 tier, and it never moves backwards.
#[tokio::test]
async fn the_t2_recency_stamp_follows_the_journal() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let all = vec![
        entry("a", "a.example.com", 443),
        entry("b", "b.example.com", 443),
    ];
    reconcile_source(
        &pool,
        "srcA0000000",
        &all,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    let id_of = async |fp: &str| get_by_fingerprint(&pool, fp).await.unwrap().unwrap().id;
    let a = id_of(&entry("a", "a.example.com", 443).fingerprint()).await;
    let b = id_of(&entry("b", "b.example.com", 443).fingerprint()).await;
    sqlx::query("UPDATE proxies SET status = 'alive'")
        .execute(&pool)
        .await
        .unwrap();

    let stamp_of = async |id: i64| -> Option<i64> {
        sqlx::query_scalar("SELECT last_t2_checked_at FROM proxies WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
    };

    // A T1 attempt says nothing about the tunnel: no stamp.
    journal_result(&pool, a, 500, true, "tcp").await;
    assert_eq!(stamp_of(a).await, None, "a T1 attempt stamps nothing");

    // A T2 attempt stamps the moment of the attempt.
    journal_result(&pool, a, 1000, true, "t2").await;
    assert_eq!(stamp_of(a).await, Some(1000));
    assert_eq!(stamp_of(b).await, None, "the other row is untouched");

    // An unverified attempt is an attempt too: the recency queue has to
    // move past the row.
    journal_result(
        &pool,
        b,
        1200,
        false,
        crate::repo::probe::T2_UNVERIFIED_KIND,
    )
    .await;
    assert_eq!(stamp_of(b).await, Some(1200));

    // A replayed older attempt must not make the row look older.
    journal_result(&pool, a, 700, true, "t2").await;
    assert_eq!(stamp_of(a).await, Some(1000), "the stamp never goes back");

    // A newer attempt moves it forward.
    journal_result(&pool, a, 2000, true, "t2").await;
    assert_eq!(stamp_of(a).await, Some(2000));
}

/// The stamp is a permanent fact about the proxy, not about the journal
/// it was derived from: the retention sweep trims `probe_results`, and a
/// proxy whose history was trimmed must not fall back into the
/// never-checked tier and be served as a first-timer forever.
#[tokio::test]
async fn the_t2_recency_stamp_survives_the_history_sweep() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let all = vec![
        entry("a", "a.example.com", 443),
        entry("b", "b.example.com", 443),
    ];
    reconcile_source(
        &pool,
        "srcA0000000",
        &all,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    let id_of = async |fp: &str| get_by_fingerprint(&pool, fp).await.unwrap().unwrap().id;
    let a = id_of(&entry("a", "a.example.com", 443).fingerprint()).await;
    let b = id_of(&entry("b", "b.example.com", 443).fingerprint()).await;
    sqlx::query("UPDATE proxies SET status = 'alive'")
        .execute(&pool)
        .await
        .unwrap();

    journal_result(&pool, a, 1000, true, "t2").await;

    // The journal is swept: the row that was checked has no history left.
    let purged = crate::repo::probe::purge_before(&pool, 2_000)
        .await
        .unwrap();
    assert_eq!(purged, 1);
    let (left,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM probe_results")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0, "the history is gone");

    // The checked row stays behind the never-checked one: its stamp
    // outlived the journal it came from.
    let candidates = select_t2_candidates(&pool, 10).await.unwrap();
    assert_eq!(
        candidates.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![b, a],
        "a swept history must not turn the row back into a first-timer"
    );
}

/// The SQL allowlist must mirror what meow-rs can actually tunnel
/// (`fumox_core::formats::clash::is_supported`, the mapping the probe
/// builds its T2 batch with). A
/// divergence would either drop rows the SQL offered, under the
/// recency order a perpetually uncheckable row (e.g. naive) would
/// starve the whole batch, or skip schemes meow-rs handles fine.
#[tokio::test]
async fn t2_scheme_allowlist_mirrors_meow_support() {
    use crate::models::Scheme;
    // The mapping lives in fumox-core::formats::clash; the SQL allowlist
    // cannot depend on the mapping, so assert the exact expected set
    // instead: adding a scheme there (or removing one) must update
    // T2_SCHEMES in the same change.
    let meow_supported: Vec<&str> = Scheme::all()
        .iter()
        .filter(|scheme| !matches!(scheme, Scheme::Tuic | Scheme::Mieru | Scheme::Naive))
        .map(|scheme| scheme.as_str())
        .collect();
    assert_eq!(T2_SCHEMES, meow_supported.as_slice());

    // And the selector must actually offer that set: the IN-list was
    // once a hardcoded six-scheme literal that omitted snell/anytls,
    // so those rows could never receive a T2 verdict and never leave
    // `alive` for `ready`.
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let mk = |scheme: Scheme, host: &str| ProxyEntry {
        scheme,
        name: host.to_string(),
        host: host.to_string(),
        port: 443,
        credential: "c1".to_string(),
        params: Vec::new(),
        raw_path: String::new(),
        raw_line: String::new(),
    };
    let entries = vec![
        mk(Scheme::Snell, "snell.example.com"),
        mk(Scheme::AnyTls, "anytls.example.com"),
        mk(Scheme::Naive, "naive.example.com"),
    ];
    reconcile_source(
        &pool,
        "srcA0000000",
        &entries,
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE proxies SET status = 'alive'")
        .execute(&pool)
        .await
        .unwrap();
    let candidates = select_t2_candidates(&pool, 100).await.unwrap();
    let schemes: Vec<&str> = candidates.iter().map(|row| row.scheme.as_str()).collect();
    assert!(schemes.contains(&"snell"), "candidates: {schemes:?}");
    assert!(schemes.contains(&"anytls"), "candidates: {schemes:?}");
    assert!(!schemes.contains(&"naive"), "candidates: {schemes:?}");
}

/// The bounded-window T1 draw must keep the old full-pool shuffle's
/// contract: the quota is filled every cycle with distinct rows, and the
/// random anchor sweep gives every row of the pool the same marginal
/// per-cycle chance (`limit / pool`), so the whole population is covered
/// over time. The pool here sits well above the draw window
/// (`SAMPLE_WINDOW_FACTOR * limit`), so every call takes the bounded path.
#[tokio::test]
async fn t1_windowed_sample_fills_quota_and_covers_the_pool() {
    let (_dir, pool) = temp_pool().await;
    let total = 80usize;
    let limit = 5u32;
    assert!(
        total as i64 > i64::from(limit) * i64::from(SAMPLE_WINDOW_FACTOR) * 3,
        "premise: the pool must sit well above the draw window"
    );
    for i in 0..total {
        seed_proxy(&pool, "vless", &format!("w{i}.example.com")).await;
    }

    let mut seen = std::collections::HashSet::new();
    for _ in 0..400 {
        let drawn = select_t1_candidates(&pool, limit).await.unwrap();
        assert_eq!(drawn.len(), limit as usize, "quota filled every cycle");
        let batch: std::collections::HashSet<i64> = drawn.iter().map(|c| c.id).collect();
        assert_eq!(batch.len(), limit as usize, "no duplicate within a draw");
        seen.extend(batch);
    }
    assert_eq!(
        seen.len(),
        total,
        "the anchor sweep must eventually sample every row"
    );
}

/// Below the window size the bounded draw fetches the whole eligible pool,
/// which is exactly the full-pool `ORDER BY RANDOM()` it replaced, so
/// eligibility semantics must match it exactly: only `unknown`/`alive`,
/// linked, T1-probeable rows come back, however many ineligible rows
/// surround them.
#[tokio::test]
async fn t1_windowed_sample_matches_full_pool_eligibility_below_the_window() {
    let (_dir, pool) = temp_pool().await;
    let mut eligible = Vec::new();
    for i in 0..3 {
        eligible.push(seed_proxy(&pool, "vless", &format!("keep{i}.example.com")).await);
    }
    for i in 0..10 {
        let id = seed_proxy(&pool, "vless", &format!("removed{i}.example.com")).await;
        sqlx::query("UPDATE proxies SET status = 'removed' WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    for i in 0..10 {
        let id = seed_proxy(&pool, "vless", &format!("quar{i}.example.com")).await;
        sqlx::query("UPDATE proxies SET status = 'quarantine' WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    for i in 0..5 {
        // Ineligible by scheme alone (T1 cannot judge a QUIC port).
        seed_proxy(&pool, "tuic", &format!("tuic{i}.example.com")).await;
    }
    let unlinked = seed_proxy(&pool, "ss", "unlinked.example.com").await;
    sqlx::query("DELETE FROM proxy_source_links WHERE proxy_id = ?")
        .bind(unlinked)
        .execute(&pool)
        .await
        .unwrap();

    // limit 10 → window 40, above the whole row count: full-pool draw.
    let mut drawn: Vec<i64> = select_t1_candidates(&pool, 10)
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    drawn.sort_unstable();
    let mut expected = eligible.clone();
    expected.sort_unstable();
    assert_eq!(drawn, expected);
}

/// The quarantine lane gets the same bounded-window contract: quota filled
/// with distinct rows from a due pool larger than the window, full
/// coverage over the anchor sweep, and not-yet-due rows never offered.
#[tokio::test]
async fn quarantine_windowed_sample_fills_quota_and_covers_the_pool() {
    let (_dir, pool) = temp_pool().await;
    let total = 56usize;
    let limit = 4u32;
    assert!(
        total as i64 > i64::from(limit) * i64::from(SAMPLE_WINDOW_FACTOR) * 3,
        "premise: the due pool must sit well above the draw window"
    );
    for i in 0..total {
        let id = seed_proxy(&pool, "vless", &format!("dq{i}.example.com")).await;
        sqlx::query(
            "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, ladder_at = 100, ladder_step = 0
             WHERE id = ?",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    }
    // Sleeping past the horizon: never due, never drawn.
    let sleeping = seed_proxy(&pool, "vless", "sleeping.example.com").await;
    sqlx::query(
        "UPDATE proxies SET status = 'quarantine', quarantined_at = 0, ladder_at = 999_999, ladder_step = 0
         WHERE id = ?",
    )
    .bind(sleeping)
    .execute(&pool)
    .await
    .unwrap();

    let mut seen = std::collections::HashSet::new();
    for _ in 0..400 {
        let due = select_due_quarantine(&pool, 5_000, limit).await.unwrap();
        assert_eq!(due.len(), limit as usize, "quota filled every cycle");
        let batch: std::collections::HashSet<i64> = due.iter().map(|d| d.id).collect();
        assert_eq!(batch.len(), limit as usize, "no duplicate within a draw");
        assert!(!batch.contains(&sleeping), "not-due rows stay out");
        seen.extend(batch);
    }
    assert_eq!(
        seen.len(),
        total,
        "the anchor sweep must eventually draw every due row"
    );
}

/// The window draw is built from two core helpers, and both are pinned
/// by a seeded RNG: the anchor is drawn inside the eligible rows' own id
/// range, and the shuffle that cuts the window must never lose or
/// duplicate a row, whatever the seed, and it must actually reorder (two
/// seeds agreeing on a 32-row permutation is a 1-in-32! coincidence).
///
/// The test drives the helpers themselves, not the `rand` crate: a
/// shuffle of the standard library says nothing about the sampler that
/// uses it.
#[test]
fn the_window_draw_helpers_are_pinned_by_the_seed() {
    use rand::SeedableRng;

    let base: Vec<usize> = (0..32).collect();
    let mut distinct = std::collections::HashSet::new();
    for seed in 0..16u64 {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        // The anchor stays inside the eligible range, the only range
        // the draw is allowed to spend its luck on.
        let anchor = choose_anchor(10, 20, &mut rng);
        assert!(
            (10..=20).contains(&anchor),
            "seed {seed}: the anchor {anchor} left the eligible range"
        );

        let mut rows = base.clone();
        shuffle_window(&mut rows, &mut rng);
        let mut sorted = rows.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted, base,
            "seed {seed}: the shuffle lost or duplicated rows"
        );
        distinct.insert(rows);
    }
    assert!(
        distinct.len() > 1,
        "different seeds must shuffle differently"
    );
}

#[tokio::test]
async fn reconcile_stores_geo_and_keeps_it_when_fresh_lookup_empty() {
    let (_dir, pool) = temp_pool().await;
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
        IngestPolicy::refresh(true, true),
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
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        2000,
        IngestPolicy::refresh(true, true),
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
}

/// The listing is per fact, so a row holding a country but no ASN is
/// walked again; `update_geo` then fills the ASN without erasing the
/// country.
#[tokio::test]
async fn missing_geo_listing_and_update() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("geo", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let now = 1_000_000i64;
    let both = GeoFactMask {
        country: true,
        asn: true,
    };
    let missing = list_missing_geo(&pool, 0, 500, both, now).await.unwrap();
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

    // The country landed, the ASN did not: the row stays in the listing.
    let missing = list_missing_geo(&pool, 0, 500, both, now).await.unwrap();
    assert!(
        missing.iter().any(|(walked, _)| walked == &id),
        "a row missing only its ASN must still be walked"
    );
    assert_eq!(count_missing_geo(&pool, both).await.unwrap(), 1);

    // A City-only install cannot answer the ASN and must not chase it.
    let city_only = GeoFactMask {
        country: true,
        asn: false,
    };
    assert!(
        list_missing_geo(&pool, 0, 500, city_only, now)
            .await
            .unwrap()
            .iter()
            .all(|(walked, _)| walked != &id),
        "a fact no database can answer is not chased"
    );
    assert_eq!(count_missing_geo(&pool, city_only).await.unwrap(), 0);

    // The ASN arrives later and the partial stamp leaves the country be.
    update_geo(
        &pool,
        id,
        &GeoStamp {
            country: None,
            city: None,
            asn: Some("AS15169".into()),
        },
    )
    .await
    .unwrap();
    let row = get_by_fingerprint(&pool, &e.fingerprint())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.geo_asn.as_deref(), Some("AS15169"));
    assert_eq!(row.geo_country.as_deref(), Some("US"));
    assert_eq!(count_missing_geo(&pool, both).await.unwrap(), 0);
    assert!(
        list_missing_geo(&pool, 0, 500, both, now)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A row whose lookup failed is left out of the listing until the retry
/// window passed: a hopeless host must not take the backfill budget away
/// from the rows that were never tried.
#[tokio::test]
async fn a_recently_attempted_row_is_not_walked_again() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("geo-retry", "h3.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let both = GeoFactMask {
        country: true,
        asn: true,
    };
    let now = 1_000_000i64;
    let id = list_missing_geo(&pool, 0, 500, both, now)
        .await
        .unwrap()
        .first()
        .expect("row without geo must be listed")
        .0;

    mark_geo_attempt(&pool, id, now).await.unwrap();
    let row = get_by_fingerprint(&pool, &e.fingerprint())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.geo_attempts, 1);
    assert_eq!(row.last_geo_attempt_at, Some(now));

    assert!(
        list_missing_geo(&pool, 0, 500, both, now)
            .await
            .unwrap()
            .is_empty(),
        "a row that was just tried must not be walked again"
    );
    // The backlog is still real, the count does not hide it.
    assert_eq!(count_missing_geo(&pool, both).await.unwrap(), 1);

    // Once the retry window passed the row is walked again.
    let later = now + GEO_RETRY_WINDOW_SECS + 1;
    assert_eq!(
        list_missing_geo(&pool, 0, 500, both, later)
            .await
            .unwrap()
            .len(),
        1
    );

    // A successful lookup clears the marker.
    update_geo(
        &pool,
        id,
        &GeoStamp {
            country: Some("US".into()),
            city: None,
            asn: Some("AS15169".into()),
        },
    )
    .await
    .unwrap();
    let row = get_by_fingerprint(&pool, &e.fingerprint())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.geo_attempts, 0);
    assert_eq!(row.last_geo_attempt_at, None);
}

/// No database at all: nothing is obtainable, so nothing is walked.
#[tokio::test]
async fn an_empty_fact_mask_walks_nothing() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("geo-none", "h2.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();

    let now = 1_000_000i64;
    assert!(
        list_missing_geo(&pool, 0, 500, GeoFactMask::default(), now)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        count_missing_geo(&pool, GeoFactMask::default())
            .await
            .unwrap(),
        0
    );
}

/// The admin card refresh resolves a host and writes the whole stamp
/// back. The resolver merges the databases with an `any`-hit, so one
/// stamp can be partial where the others are silent. An ASN-only hit
/// (the City record decodes with an empty country, as it does for the
/// Cloudflare `104.16.0.0/12` block) must not erase the country the
/// ingest path already resolved, same invariant the reconcile upsert
/// keeps.
#[tokio::test]
async fn update_geo_full_keeps_stored_facts_a_partial_stamp_cannot_replace() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    let e = entry("geo-card", "h1.example.com", 443);
    reconcile_source(
        &pool,
        "srcA0000000",
        std::slice::from_ref(&e),
        &[Some(GeoStamp {
            country: Some("US".into()),
            city: Some("New York".into()),
            asn: None,
        })],
        1000,
        IngestPolicy::refresh(true, true),
    )
    .await
    .unwrap();
    let id = get_by_fingerprint(&pool, &e.fingerprint())
        .await
        .unwrap()
        .unwrap()
        .id;

    update_geo_full(
        &pool,
        id,
        &GeoStamp {
            country: None,
            city: None,
            asn: Some("AS13335".into()),
        },
        "104.16.0.1",
    )
    .await
    .unwrap();
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.geo_country.as_deref(),
        Some("US"),
        "an ASN-only stamp must not wipe the stored country"
    );
    assert_eq!(row.geo_city.as_deref(), Some("New York"));
    assert_eq!(row.geo_asn.as_deref(), Some("AS13335"));
    assert_eq!(row.resolved_ip.as_deref(), Some("104.16.0.1"));

    // A stamp that does carry the fields still overwrites them.
    update_geo_full(
        &pool,
        id,
        &GeoStamp {
            country: Some("DE".into()),
            city: Some("Frankfurt".into()),
            asn: Some("AS24940".into()),
        },
        "1.2.3.4",
    )
    .await
    .unwrap();
    let row = get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.geo_country.as_deref(), Some("DE"));
    assert_eq!(row.geo_city.as_deref(), Some("Frankfurt"));
    assert_eq!(row.geo_asn.as_deref(), Some("AS24940"));
    assert_eq!(row.resolved_ip.as_deref(), Some("1.2.3.4"));
}

// Bulk cleanup transitions: each action
// must move exactly its target group into `removed`, clear the
// quarantine/ladder bookkeeping and leave everything else untouched.

/// Minimal raw insert, the bulk helpers filter on columns the
/// reconciliation path never populates (geo_asn, unprobeable schemes),
/// so tests seed rows directly.
async fn bulk_test_row(
    pool: &DbPool,
    fingerprint: &str,
    scheme: &str,
    status: &str,
    geo_country: Option<&str>,
    geo_asn: Option<&str>,
) -> i64 {
    let now = crate::models::now_ts();
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO proxies
                 (fingerprint, scheme, name, host, port, credential, params,
                  unknown_params, raw_line, geo_country, geo_asn,
                  status, fail_count, quarantined_at, ladder_step, created_at, updated_at)
             VALUES (?, ?, ?, ?, 443, '', '{}', '{}', '', ?, ?, ?, 0, NULL, 0, ?, ?)
             RETURNING id",
    )
    .bind(fingerprint)
    .bind(scheme)
    .bind(fingerprint)
    .bind(format!("{fingerprint}.example.com"))
    .bind(geo_country)
    .bind(geo_asn)
    .bind(status)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await
    .unwrap();
    id
}

/// Link a bulk fixture row to a source. The revival paths require a
/// live link (a row without one is in no probe lane), so revival
/// tests have to give their targets one.
async fn link_row(pool: &DbPool, proxy_id: i64, source_id: &str) {
    sqlx::query("INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, ?, 1)")
        .bind(proxy_id)
        .bind(source_id)
        .execute(pool)
        .await
        .unwrap();
}

/// The sampled state of a bulk fixture row: the status, the three
/// lifecycle timestamps and the two lifecycle counters. The counters are
/// part of the sample because a transition that retires a row has to
/// clear the whole ladder, not only its timestamps.
async fn bulk_status_of(
    pool: &DbPool,
    id: i64,
) -> (String, Option<i64>, Option<i64>, Option<i64>, i64, i64) {
    sqlx::query_as(
        "SELECT status, quarantined_at, ladder_at, removed_at, ladder_step, fail_count
         FROM proxies WHERE id = ?",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn quarantine_to_removed_moves_only_quarantined() {
    let (_dir, pool) = temp_pool().await;
    let q = bulk_test_row(&pool, "bulk-q1", "vless", "quarantine", Some("DE"), None).await;
    let alive = bulk_test_row(&pool, "bulk-a1", "vless", "alive", Some("DE"), None).await;

    // The stamp is "now", and "now" moves: the call is bracketed
    // instead of compared against a second reading of the clock.
    let before = crate::models::now_ts();
    assert_eq!(quarantine_to_removed(&pool).await.unwrap(), 1);
    let after = crate::models::now_ts();

    let (status, quarantined_at, ladder_at, removed_at, ladder_step, fail_count) =
        bulk_status_of(&pool, q).await;
    assert_eq!(status, "removed");
    assert_eq!(quarantined_at, None);
    assert_eq!(ladder_at, None);
    assert_eq!(ladder_step, 0);
    assert_eq!(fail_count, 0);
    let removed_at = removed_at.expect("the retired row stamps removed_at");
    assert!(
        (before..=after).contains(&removed_at),
        "removed_at {removed_at} is outside the call window {before}..={after}"
    );

    assert_eq!(
        bulk_status_of(&pool, alive).await,
        ("alive".into(), None, None, None, 0, 0)
    );
}

#[tokio::test]
async fn quarantine_to_removed_clears_ladder_and_quarantine_fields() {
    let (_dir, pool) = temp_pool().await;
    let id = bulk_test_row(&pool, "bulk-q2", "vless", "quarantine", Some("DE"), None).await;
    let now = crate::models::now_ts();
    sqlx::query(
        "UPDATE proxies SET fail_count = 3, quarantined_at = ?, ladder_at = ?,
             ladder_step = 2, last_checked_at = ? WHERE id = ?",
    )
    .bind(now)
    .bind(now + 100)
    .bind(now)
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    quarantine_to_removed(&pool).await.unwrap();
    let (status, quarantined_at, ladder_at, removed_at, ladder_step, fail_count) =
        bulk_status_of(&pool, id).await;
    assert_eq!(status, "removed");
    assert_eq!(quarantined_at, None);
    assert_eq!(ladder_at, None);
    assert!(removed_at.is_some());
    assert_eq!(ladder_step, 0, "the recheck ladder is over");
    assert_eq!(
        fail_count, 3,
        "the retirement does not touch the counter; the revival paths reset it"
    );
}

#[tokio::test]
async fn remove_alive_without_country_targets_only_alive_without_geo() {
    let (_dir, pool) = temp_pool().await;
    let no_country = bulk_test_row(&pool, "bulk-nc1", "vless", "alive", None, None).await;
    let with_country = bulk_test_row(&pool, "bulk-nc2", "vless", "alive", Some("US"), None).await;
    let q_no_country = bulk_test_row(&pool, "bulk-nc3", "vless", "quarantine", None, None).await;
    let unknown_no_country = bulk_test_row(&pool, "bulk-nc4", "vless", "unknown", None, None).await;

    assert_eq!(remove_alive_without_country(&pool).await.unwrap(), 1);
    assert_eq!(bulk_status_of(&pool, no_country).await.0, "removed");
    assert_eq!(bulk_status_of(&pool, with_country).await.0, "alive");
    assert_eq!(bulk_status_of(&pool, q_no_country).await.0, "quarantine");
    assert_eq!(bulk_status_of(&pool, unknown_no_country).await.0, "unknown");
}

#[tokio::test]
async fn remove_alive_by_asn_matches_canonical_as_prefix() {
    let (_dir, pool) = temp_pool().await;
    // The ASN is accepted in both spellings, each round on its own
    // fixtures: the operator types "AS24940" or "24940" and both must
    // hit the same rows.
    for (round, spelling) in ["24940", "AS24940"].into_iter().enumerate() {
        let target = bulk_test_row(
            &pool,
            &format!("bulk-as1-{round}"),
            "vless",
            "alive",
            Some("DE"),
            Some("AS24940"),
        )
        .await;
        let other_asn = bulk_test_row(
            &pool,
            &format!("bulk-as2-{round}"),
            "vless",
            "alive",
            Some("DE"),
            Some("AS13335"),
        )
        .await;
        let quarantined_same = bulk_test_row(
            &pool,
            &format!("bulk-as3-{round}"),
            "vless",
            "quarantine",
            Some("DE"),
            Some("AS24940"),
        )
        .await;

        assert_eq!(
            remove_alive_by_asn(&pool, spelling).await.unwrap(),
            1,
            "{spelling}: only the matching alive row is retired"
        );
        assert_eq!(bulk_status_of(&pool, target).await.0, "removed");
        assert_eq!(bulk_status_of(&pool, other_asn).await.0, "alive");
        assert_eq!(
            bulk_status_of(&pool, quarantined_same).await.0,
            "quarantine"
        );
    }
}

#[tokio::test]
async fn remove_alive_by_country_targets_matching_alive_rows() {
    let (_dir, pool) = temp_pool().await;
    let de_alive = bulk_test_row(&pool, "bulk-c1", "vless", "alive", Some("DE"), None).await;
    let de_quarantine =
        bulk_test_row(&pool, "bulk-c2", "vless", "quarantine", Some("DE"), None).await;
    let us_alive = bulk_test_row(&pool, "bulk-c3", "vless", "alive", Some("US"), None).await;

    assert_eq!(remove_alive_by_country(&pool, "DE").await.unwrap(), 1);
    assert_eq!(bulk_status_of(&pool, de_alive).await.0, "removed");
    assert_eq!(bulk_status_of(&pool, de_quarantine).await.0, "quarantine");
    assert_eq!(bulk_status_of(&pool, us_alive).await.0, "alive");
}

#[tokio::test]
async fn remove_unprobeable_unknown_retires_only_tuic_and_mieru() {
    let (_dir, pool) = temp_pool().await;
    let tuic = bulk_test_row(&pool, "bulk-u1", "tuic", "unknown", None, None).await;
    let mieru = bulk_test_row(&pool, "bulk-u2", "mieru", "unknown", None, None).await;
    let vless_unknown = bulk_test_row(&pool, "bulk-u3", "vless", "unknown", None, None).await;
    let tuic_alive = bulk_test_row(&pool, "bulk-u4", "tuic", "alive", None, None).await;

    assert_eq!(remove_unprobeable_unknown(&pool).await.unwrap(), 2);
    assert_eq!(bulk_status_of(&pool, tuic).await.0, "removed");
    assert_eq!(bulk_status_of(&pool, mieru).await.0, "removed");
    assert_eq!(bulk_status_of(&pool, vless_unknown).await.0, "unknown");
    assert_eq!(bulk_status_of(&pool, tuic_alive).await.0, "alive");
}

/// `mark_orphans_removed` with no protected statuses is the strict
/// policy: every link-less proxy retires, no matter the tier, this is
/// what `drop_gate = true` asks for from the admin source-delete path.
#[tokio::test]
async fn mark_orphans_removed_retires_every_status_by_default() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcO0000000").await;

    let ready = bulk_test_row(&pool, "orphan-ready", "vless", "ready", None, None).await;
    let alive = bulk_test_row(&pool, "orphan-alive", "vless", "alive", None, None).await;
    let unknown = bulk_test_row(&pool, "orphan-unknown", "vless", "unknown", None, None).await;
    let quarantined = bulk_test_row(
        &pool,
        "orphan-quarantine",
        "vless",
        "quarantine",
        None,
        None,
    )
    .await;
    // The rows start linked and lose the link, exactly what happens
    // after a source delete: the sweep only acts on rows with no
    // remaining links.
    for id in [ready, alive, unknown, quarantined] {
        link_row(&pool, id, "srcO0000000").await;
    }
    sqlx::query("DELETE FROM proxy_source_links")
        .execute(&pool)
        .await
        .unwrap();

    // The fixtures carry a live ladder: a retired row must not keep a
    // recheck schedule that describes a ladder nobody walks any more.
    let now = crate::models::now_ts();
    for id in [ready, alive, unknown, quarantined] {
        sqlx::query(
            "UPDATE proxies SET quarantined_at = ?, ladder_at = ?, ladder_step = 2,
                    fail_count = 3 WHERE id = ?",
        )
        .bind(now)
        .bind(now + 100)
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    }

    let sweep = mark_orphans_removed(&pool, &[]).await.unwrap();
    assert_eq!(
        sweep.retired, 4,
        "every orphan must retire under strict policy"
    );
    assert_eq!(
        sweep.protected, 0,
        "the strict policy protects nothing, so nothing is left detached"
    );
    for (label, id) in [
        ("ready", ready),
        ("alive", alive),
        ("unknown", unknown),
        ("quarantine", quarantined),
    ] {
        let (status, quarantined_at, ladder_at, removed_at, ladder_step, fail_count) =
            bulk_status_of(&pool, id).await;
        assert_eq!(status, "removed", "{label} proxy must retire");
        assert!(
            removed_at.unwrap_or(0) > 0,
            "{label} proxy must stamp removed_at"
        );
        assert_eq!(
            quarantined_at, None,
            "{label} proxy loses its quarantine stamp"
        );
        assert_eq!(ladder_at, None, "{label} proxy loses its recheck schedule");
        assert_eq!(ladder_step, 0, "{label} proxy loses its ladder step");
        assert_eq!(
            fail_count, 3,
            "{label} proxy keeps its counter; the revival paths reset it"
        );
    }
}

/// When the caller protects statuses (admin source-delete path with
/// `drop_gate = false` passes `["ready", "unknown"]`), link-less rows
/// in those statuses are left untouched, the probe remains the only
/// authority on their lifecycle, and the priority queue the only
/// authority on a not-yet-verified row. Already-`removed` rows stay
/// untouched regardless of the protected list (idempotency).
#[tokio::test]
async fn mark_orphans_removed_protects_listed_statuses() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcO0000001").await;

    let ready = bulk_test_row(&pool, "protect-ready", "vless", "ready", None, None).await;
    let alive = bulk_test_row(&pool, "protect-alive", "vless", "alive", None, None).await;
    let unknown = bulk_test_row(&pool, "protect-unknown", "vless", "unknown", None, None).await;
    // Already-removed row: keeps its removed_at untouched, the
    // protected list does not revive it.
    let already = bulk_test_row(&pool, "protect-gone", "vless", "removed", None, None).await;
    // The rows start linked and lose the link, exactly what happens
    // after a source delete.
    for id in [ready, alive, unknown, already] {
        link_row(&pool, id, "srcO0000001").await;
    }
    sqlx::query("DELETE FROM proxy_source_links")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET removed_at = 1234 WHERE id = ?")
        .bind(already)
        .execute(&pool)
        .await
        .unwrap();

    // The admin source-delete conservative mode passes both
    // `ready` (tunnel-verified, the probe is its only authority) and
    // `unknown` (not yet checked, the priority queue is its only
    // authority). Both must survive the click.
    let sweep = mark_orphans_removed(&pool, &["ready", "unknown"])
        .await
        .unwrap();
    assert_eq!(
        sweep.retired, 1,
        "only the non-protected orphan (alive) retires; ready and unknown are spared"
    );
    assert_eq!(
        sweep.protected, 2,
        "the protected orphans are counted, not hidden: they are the detached rows"
    );
    assert_eq!(
        bulk_status_of(&pool, ready).await.0,
        "ready",
        "a protected ready proxy keeps its tier"
    );
    assert_eq!(
        bulk_status_of(&pool, unknown).await.0,
        "unknown",
        "a protected unknown proxy keeps its status, the priority queue stays the only authority"
    );
    assert_eq!(bulk_status_of(&pool, alive).await.0, "removed");
    assert_eq!(bulk_status_of(&pool, already).await.0, "removed");
    let (_status, _q, _l, removed_at, _step, _fails) = bulk_status_of(&pool, already).await;
    assert_eq!(
        removed_at,
        Some(1234),
        "an already-removed row is not re-stamped"
    );
}

/// Empty protected-status slice is the strict path; a non-empty slice
/// with multiple statuses protects every row in any of them.
#[tokio::test]
async fn mark_orphans_removed_accepts_multiple_protected_statuses() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcO0000002").await;

    let ready = bulk_test_row(&pool, "multi-ready", "vless", "ready", None, None).await;
    let alive = bulk_test_row(&pool, "multi-alive", "vless", "alive", None, None).await;
    let unknown = bulk_test_row(&pool, "multi-unknown", "vless", "unknown", None, None).await;
    // The rows start linked and lose the link, exactly what happens
    // after a source delete.
    for id in [ready, alive, unknown] {
        link_row(&pool, id, "srcO0000002").await;
    }
    sqlx::query("DELETE FROM proxy_source_links")
        .execute(&pool)
        .await
        .unwrap();

    let sweep = mark_orphans_removed(&pool, &["ready", "alive"])
        .await
        .unwrap();
    assert_eq!(sweep.retired, 1, "only the non-protected orphan retires");
    assert_eq!(sweep.protected, 2);
    assert_eq!(bulk_status_of(&pool, ready).await.0, "ready");
    assert_eq!(bulk_status_of(&pool, alive).await.0, "alive");
    assert_eq!(bulk_status_of(&pool, unknown).await.0, "removed");
}

/// The detached rows — the ones without a source link — are counted,
/// marked in the browser and retired by the cleanup path. A link-less
/// row is in no probe lane, so nothing else would ever end it.
#[tokio::test]
async fn the_detached_rows_are_counted_marked_and_cleanable() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcO0000003").await;

    let linked = bulk_test_row(&pool, "detach-linked", "vless", "alive", None, None).await;
    let detached = bulk_test_row(&pool, "detach-loose", "vless", "alive", None, None).await;
    let gone = bulk_test_row(&pool, "detach-gone", "vless", "removed", None, None).await;
    link_row(&pool, linked, "srcO0000003").await;

    assert_eq!(count_detached(&pool).await.unwrap(), 1);

    let rows = list_filtered(
        &pool,
        &ProxyListFilter::default(),
        ProxyListOrder::Updated,
        50,
        None,
    )
    .await
    .unwrap();
    let detached_flag = |id: i64| rows.iter().find(|row| row.id == id).unwrap().detached;
    assert!(!detached_flag(linked), "a linked row is not detached");
    assert!(detached_flag(detached), "a link-less row is detached");
    assert!(
        !detached_flag(gone),
        "an already-removed row is not counted as detached"
    );

    assert_eq!(remove_detached(&pool).await.unwrap(), 1);
    assert_eq!(bulk_status_of(&pool, detached).await.0, "removed");
    assert_eq!(count_detached(&pool).await.unwrap(), 0);
    assert_eq!(bulk_status_of(&pool, linked).await.0, "alive");
}

/// `revive_removed_by_country` resets matching `removed` rows back to
/// `unknown` and clears every lifecycle field, symmetric to
/// `remove_alive_by_country`. Rows outside the country stay `removed`.
#[tokio::test]
async fn revive_removed_by_country_returns_unknown_and_clears_lifecycle() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcR0000000").await;
    let de = bulk_test_row(&pool, "revive-de", "vless", "removed", Some("DE"), None).await;
    let us = bulk_test_row(&pool, "revive-us", "vless", "removed", Some("US"), None).await;
    link_row(&pool, de, "srcR0000000").await;
    link_row(&pool, us, "srcR0000000").await;
    let now = crate::models::now_ts();
    // Stamp a non-zero ladder / quarantine / fail_count on DE to
    // confirm the revival clears them.
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 2,
                  fail_count = 5, removed_at = 300 WHERE id = ?",
    )
    .bind(de)
    .execute(&pool)
    .await
    .unwrap();

    let outcome = revive_removed_by_country(&pool, "DE", now).await.unwrap();
    assert_eq!(
        outcome.ids,
        vec![de],
        "only the DE row revives; US stays removed"
    );
    assert_eq!(outcome.revived, 1, "one row was revived");

    let (status, q, l, removed_at, ladder_step, fail_count) = bulk_status_of(&pool, de).await;
    assert_eq!(status, "unknown");
    assert_eq!(q, None, "quarantined_at must be cleared");
    assert_eq!(l, None, "ladder_at must be cleared");
    assert_eq!(removed_at, None, "removed_at must be cleared");
    assert_eq!(ladder_step, 0, "the ladder step must be cleared");
    assert_eq!(fail_count, 0, "the fail budget must be cleared");
    assert_eq!(bulk_status_of(&pool, us).await.0, "removed");
}

/// `revive_removed_by_country` only acts on `status = 'removed'`;
/// every other tier is left untouched even when the country matches.
#[tokio::test]
async fn revive_removed_by_country_ignores_other_statuses() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcR0000001").await;
    let alive = bulk_test_row(&pool, "revive-alive", "vless", "alive", Some("DE"), None).await;
    let q = bulk_test_row(&pool, "revive-q", "vless", "quarantine", Some("DE"), None).await;
    let unknown = bulk_test_row(
        &pool,
        "revive-unknown",
        "vless",
        "unknown",
        Some("DE"),
        None,
    )
    .await;
    let now = crate::models::now_ts();

    let outcome = revive_removed_by_country(&pool, "DE", now).await.unwrap();
    assert!(
        outcome.ids.is_empty(),
        "no row matches status='removed' + DE"
    );
    assert_eq!(outcome.revived, 0);
    assert_eq!(bulk_status_of(&pool, alive).await.0, "alive");
    assert_eq!(bulk_status_of(&pool, q).await.0, "quarantine");
    assert_eq!(bulk_status_of(&pool, unknown).await.0, "unknown");
}

/// `revive_removed_by_asn` accepts both `24940` and `AS24940`,
/// matches the canonical `AS24940` form stored in `geo_asn`, and
/// leaves rows of other ASes alone.
#[tokio::test]
async fn revive_removed_by_asn_matches_canonical_prefix() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcR0000002").await;
    // One fixture per spelling: both spellings canonicalise to the
    // stored `AS…` form, and each call has to hit its own row and
    // nothing else.
    let bare = bulk_test_row(&pool, "revive-asn-bare", "vless", "removed", None, None).await;
    let prefixed =
        bulk_test_row(&pool, "revive-asn-prefixed", "vless", "removed", None, None).await;
    let no = bulk_test_row(&pool, "revive-asn-no", "vless", "removed", None, None).await;
    for id in [bare, prefixed, no] {
        link_row(&pool, id, "srcR0000002").await;
    }
    sqlx::query("UPDATE proxies SET geo_asn = 'AS24940' WHERE id = ?")
        .bind(bare)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET geo_asn = 'AS13335' WHERE id = ?")
        .bind(prefixed)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET geo_asn = 'AS16509' WHERE id = ?")
        .bind(no)
        .execute(&pool)
        .await
        .unwrap();
    let now = crate::models::now_ts();

    // The bare number works.
    let outcome = revive_removed_by_asn(&pool, "24940", now).await.unwrap();
    assert_eq!(outcome.ids, vec![bare], "the bare number canonicalises");
    assert_eq!(outcome.revived, 1);
    assert_eq!(bulk_status_of(&pool, bare).await.0, "unknown");

    // The AS-prefix works as well.
    let outcome = revive_removed_by_asn(&pool, "AS13335", now).await.unwrap();
    assert_eq!(outcome.ids, vec![prefixed], "the AS-prefix works as well");
    assert_eq!(outcome.revived, 1);
    assert_eq!(bulk_status_of(&pool, prefixed).await.0, "unknown");
    assert_eq!(bulk_status_of(&pool, no).await.0, "removed");
}

/// `revive_removed_never_checked` only revives `removed` rows the probe
/// never reached, a row that was checked once (even if the check failed)
/// stays removed.
///
/// The marker is the row's own `last_checked_at`, not a journal entry:
/// the journal rotates, so a proxy checked long ago and dropped from the
/// preserved history would look "never checked" and be revived on every
/// pass.
#[tokio::test]
async fn revive_removed_never_checked_targets_only_never_checked_rows() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcR0000003").await;
    let lonely = bulk_test_row(&pool, "revive-lonely", "vless", "removed", None, None).await;
    let tried = bulk_test_row(&pool, "revive-tried", "vless", "removed", None, None).await;
    link_row(&pool, lonely, "srcR0000003").await;
    link_row(&pool, tried, "srcR0000003").await;
    // The probe reached the row once; its journal entry is long gone
    // (the retention pass removed it), the row still knows.
    sqlx::query("UPDATE proxies SET last_checked_at = 1 WHERE id = ?")
        .bind(tried)
        .execute(&pool)
        .await
        .unwrap();
    let now = crate::models::now_ts();

    let outcome = revive_removed_never_checked(&pool, now).await.unwrap();
    assert_eq!(outcome.ids, vec![lonely]);
    assert_eq!(outcome.revived, 1);
    assert_eq!(bulk_status_of(&pool, lonely).await.0, "unknown");
    assert_eq!(bulk_status_of(&pool, tried).await.0, "removed");
}

/// The same button must also release `unknown` rows frozen by the T2
/// block. With `last_t2_failed_at` set they satisfy no probe lane at
/// all (queue drain and T1 sample require it NULL, the T2 selector
/// only offers `alive`/`ready`), so they are never checked and never
/// can clear the flag on their own. A row that *was* checked is left
/// alone: the panel is for rows that never got a verdict.
#[tokio::test]
async fn revive_never_checked_releases_t2_frozen_unknown_rows() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcR0000003").await;
    let frozen = bulk_test_row(&pool, "revive-frozen", "vless", "unknown", None, None).await;
    let clear = bulk_test_row(&pool, "revive-clear", "vless", "unknown", None, None).await;
    let frozen_with_history =
        bulk_test_row(&pool, "revive-frozen-hist", "vless", "unknown", None, None).await;
    let unlinked = bulk_test_row(
        &pool,
        "revive-frozen-nolink",
        "vless",
        "unknown",
        None,
        None,
    )
    .await;
    for id in [frozen, clear, frozen_with_history] {
        link_row(&pool, id, "srcR0000003").await;
    }
    // frozen + frozen_with_history + unlinked carry the T2 block; clear
    // does not. The unlinked row differs from the frozen one in the
    // source link and in nothing else, so the assertion below really
    // tests the link and not the block.
    for id in [frozen, frozen_with_history, unlinked] {
        sqlx::query("UPDATE proxies SET last_t2_failed_at = 1700, fail_count = 3 WHERE id = ?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE proxies SET last_checked_at = 1700 WHERE id = ?")
        .bind(frozen_with_history)
        .execute(&pool)
        .await
        .unwrap();

    let outcome = revive_removed_never_checked(&pool, 2000).await.unwrap();
    let ids = &outcome.ids;

    assert!(ids.contains(&frozen), "the frozen row must be released");
    let (flag, fails): (Option<i64>, i64) =
        sqlx::query_as("SELECT last_t2_failed_at, fail_count FROM proxies WHERE id = ?")
            .bind(frozen)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(flag, None, "the T2 block must be cleared");
    assert_eq!(fails, 0, "the row goes back pristine");

    assert!(!ids.contains(&clear), "an unblocked row needs no revival");
    assert!(
        !ids.contains(&frozen_with_history),
        "a row the probe already checked is not never-checked"
    );
    assert!(
        !ids.contains(&unlinked),
        "no source link means no probe lane can reach the row"
    );
}

/// `revive_quarantine` moves every quarantined row back to `unknown`
/// and clears `quarantined_at` / `ladder_at` / `ladder_step` /
/// `fail_count`. The recheck-ladder schedule is dropped, the probe
/// picks the row up via the priority queue (the caller enqueues
/// the returned ids) and runs T1 from scratch.
#[tokio::test]
async fn revive_quarantine_returns_unknown_and_clears_ladder_fields() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcR0000004").await;
    let q = bulk_test_row(
        &pool,
        "revive-q-only",
        "vless",
        "quarantine",
        Some("DE"),
        None,
    )
    .await;
    link_row(&pool, q, "srcR0000004").await;
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 1500, ladder_at = 1700, ladder_step = 2,
                  fail_count = 4 WHERE id = ?",
    )
    .bind(q)
    .execute(&pool)
    .await
    .unwrap();
    let now = crate::models::now_ts();

    let outcome = revive_quarantine(&pool, now).await.unwrap();
    assert_eq!(outcome.ids, vec![q]);
    assert_eq!(outcome.revived, 1);
    let (status, quarantined_at, ladder_at, removed_at, ladder_step, fail_count) =
        bulk_status_of(&pool, q).await;
    assert_eq!(status, "unknown");
    assert_eq!(quarantined_at, None);
    assert_eq!(ladder_at, None);
    assert_eq!(
        removed_at, None,
        "removed_at was never set on a quarantine row"
    );
    assert_eq!(ladder_step, 0, "the ladder step must be cleared");
    assert_eq!(fail_count, 0, "the fail budget must be cleared");
}

/// `revive_quarantine` only acts on `status = 'quarantine'`; every
/// other tier (including `removed` itself) stays put.
#[tokio::test]
async fn revive_quarantine_leaves_alive_and_removed_alone() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcR0000005").await;
    let alive = bulk_test_row(&pool, "revive-alive-skip", "vless", "alive", None, None).await;
    let removed = bulk_test_row(&pool, "revive-removed-skip", "vless", "removed", None, None).await;
    let unknown = bulk_test_row(&pool, "revive-unknown-skip", "vless", "unknown", None, None).await;
    let now = crate::models::now_ts();

    let outcome = revive_quarantine(&pool, now).await.unwrap();
    assert!(outcome.ids.is_empty());
    assert_eq!(outcome.revived, 0);
    assert_eq!(bulk_status_of(&pool, alive).await.0, "alive");
    assert_eq!(bulk_status_of(&pool, removed).await.0, "removed");
    assert_eq!(bulk_status_of(&pool, unknown).await.0, "unknown");
}

/// The T1 lanes (random sample and priority queue) and the T2 sample
/// all require a live `proxy_source_links` row. A revival that
/// ignored that would hand the panel a "revived N rows" toast for
/// rows no probe can reach: the request is queued, skipped at
/// drain, and the next reconcile retires the row again. All five
/// revival statements therefore require the link, including
/// `revive_quarantine`, where the ladder is the only lane that ever
/// saw a link-less row and reviving drops it.
#[tokio::test]
async fn bulk_revival_skips_rows_without_a_source_link() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcR0000006").await;
    let now = crate::models::now_ts();

    // One target per panel, all linked, each the only row its own
    // filter matches (the country, the AS and the "no probe history"
    // filters overlap otherwise).
    let by_country = bulk_test_row(&pool, "revive-c", "vless", "removed", Some("DE"), None).await;
    let by_asn = bulk_test_row(
        &pool,
        "revive-a",
        "vless",
        "removed",
        Some("US"),
        Some("AS24940"),
    )
    .await;
    let by_history = bulk_test_row(&pool, "revive-h", "vless", "removed", Some("FR"), None).await;
    let from_quarantine = bulk_test_row(
        &pool,
        "revive-q",
        "vless",
        "quarantine",
        Some("DE"),
        Some("AS24940"),
    )
    .await;
    for id in [by_country, by_asn, by_history, from_quarantine] {
        link_row(&pool, id, "srcR0000006").await;
    }
    // All four carry a stale T2 block, a revived row must not keep it:
    // the T1 lanes filter on `last_t2_failed_at IS NULL`.
    sqlx::query("UPDATE proxies SET last_t2_failed_at = 1_000 WHERE id IN (?, ?, ?, ?)")
        .bind(by_country)
        .bind(by_asn)
        .bind(by_history)
        .bind(from_quarantine)
        .execute(&pool)
        .await
        .unwrap();

    // The same population without a link to any source: in range of
    // every filter above, reachable by no probe lane.
    let orphan_removed = bulk_test_row(
        &pool,
        "revive-orphan-removed",
        "vless",
        "removed",
        Some("DE"),
        Some("AS24940"),
    )
    .await;
    let orphan_quarantine = bulk_test_row(
        &pool,
        "revive-orphan-quarantine",
        "vless",
        "quarantine",
        Some("DE"),
        Some("AS24940"),
    )
    .await;
    sqlx::query("UPDATE proxies SET last_t2_failed_at = 1_000 WHERE id IN (?, ?)")
        .bind(orphan_removed)
        .bind(orphan_quarantine)
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(
        revive_removed_by_country(&pool, "DE", now)
            .await
            .unwrap()
            .ids,
        vec![by_country]
    );
    assert_eq!(
        revive_removed_by_asn(&pool, "24940", now)
            .await
            .unwrap()
            .ids,
        vec![by_asn]
    );
    assert_eq!(
        revive_removed_never_checked(&pool, now).await.unwrap().ids,
        vec![by_history]
    );
    assert!(
        revive_removed(&pool, &["revive-orphan-removed".to_string()], now)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        revive_quarantine(&pool, now).await.unwrap().ids,
        vec![from_quarantine]
    );

    assert_eq!(bulk_status_of(&pool, orphan_removed).await.0, "removed");
    assert_eq!(
        bulk_status_of(&pool, orphan_quarantine).await.0,
        "quarantine",
        "an unlinked quarantined row keeps its ladder instead of being revived into a lane that cannot see it"
    );

    // The revived rows are back on a T1 lane, the untouched ones keep
    // the block they had.
    for id in [by_country, by_asn, by_history, from_quarantine] {
        let row = get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "unknown");
        assert_eq!(row.last_t2_failed_at, None, "revival clears the T2 block");
    }
    let (blocked,): (Option<i64>,) =
        sqlx::query_as("SELECT last_t2_failed_at FROM proxies WHERE id = ?")
            .bind(orphan_removed)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(blocked, Some(1_000));
}

/// Empty quarantine → no due rows.
#[tokio::test]
async fn count_due_quarantine_returns_zero_when_empty() {
    let (_dir, pool) = temp_pool().await;
    let now = crate::models::now_ts();
    let n = count_due_quarantine(&pool, now).await.unwrap();
    assert_eq!(n, 0);
}

/// `count_due_quarantine` only counts rows whose `ladder_at` has
/// passed, both NULL-ladder (in-flight) and future-ladder rows
/// stay out of the count.
#[tokio::test]
async fn count_due_quarantine_counts_only_due() {
    let (_dir, pool) = temp_pool().await;
    let now = crate::models::now_ts();
    let due = bulk_test_row(&pool, "due-c1", "vless", "quarantine", None, None).await;
    let due2 = bulk_test_row(&pool, "due-c2", "vless", "quarantine", None, None).await;
    let future = bulk_test_row(&pool, "due-c3", "vless", "quarantine", None, None).await;
    let null_ladder = bulk_test_row(&pool, "due-c4", "vless", "quarantine", None, None).await;

    sqlx::query("UPDATE proxies SET quarantined_at = ?, ladder_at = ? WHERE id = ?")
        .bind(now - 3600)
        .bind(now - 1)
        .bind(due)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET quarantined_at = ?, ladder_at = ? WHERE id = ?")
        .bind(now - 7200)
        .bind(now - 60)
        .bind(due2)
        .execute(&pool)
        .await
        .unwrap();
    // future: ladder_at is in the future
    sqlx::query("UPDATE proxies SET quarantined_at = ?, ladder_at = ? WHERE id = ?")
        .bind(now - 3600)
        .bind(now + 3600)
        .bind(future)
        .execute(&pool)
        .await
        .unwrap();
    // null_ladder: keeps ladder_at NULL (the bulk insert sets it to NULL
    // for non-quarantine; for quarantine it's whatever default, verify)
    let (ladder_at,): (Option<i64>,) = sqlx::query_as("SELECT ladder_at FROM proxies WHERE id = ?")
        .bind(null_ladder)
        .fetch_one(&pool)
        .await
        .unwrap();
    // Force NULL ladder_at so the row is excluded.
    if ladder_at.is_some() {
        sqlx::query("UPDATE proxies SET ladder_at = NULL WHERE id = ?")
            .bind(null_ladder)
            .execute(&pool)
            .await
            .unwrap();
    }

    let n = count_due_quarantine(&pool, now).await.unwrap();
    assert_eq!(n, 2, "only `due` and `due2` have ladder_at <= now");
}

/// Empty quarantine → `None` (the banner uses this to skip the
/// staleness factor without a SQL error).
#[tokio::test]
async fn oldest_quarantined_at_returns_none_when_empty() {
    let (_dir, pool) = temp_pool().await;
    let v = oldest_quarantined_at(&pool).await.unwrap();
    assert!(v.is_none());
}

/// `oldest_quarantined_at` returns the minimum `quarantined_at` and
/// ignores non-quarantine rows.
#[tokio::test]
async fn oldest_quarantined_at_returns_min() {
    let (_dir, pool) = temp_pool().await;
    let now = crate::models::now_ts();
    let q1 = bulk_test_row(&pool, "old-q1", "vless", "quarantine", None, None).await;
    let q2 = bulk_test_row(&pool, "old-q2", "vless", "quarantine", None, None).await;
    let alive = bulk_test_row(&pool, "old-alive", "vless", "alive", None, None).await;
    // q1 oldest, q2 newer, alive with even older quarantined_at must be ignored.
    sqlx::query("UPDATE proxies SET quarantined_at = ? WHERE id = ?")
        .bind(now - 30 * 86_400)
        .bind(q1)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET quarantined_at = ? WHERE id = ?")
        .bind(now - 7 * 86_400)
        .bind(q2)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET quarantined_at = ? WHERE id = ?")
        .bind(now - 365 * 86_400)
        .bind(alive)
        .execute(&pool)
        .await
        .unwrap();

    let v = oldest_quarantined_at(&pool).await.unwrap();
    assert_eq!(v, Some(now - 30 * 86_400));
}

// Admin proxy browser

/// Fixture for the admin proxy browser: four proxies with distinct
/// schemes, countries, statuses, links and probe history. Returns
/// `(id, letter)` in insertion order.
async fn admin_list_fixture(pool: &DbPool) -> Vec<(i64, &'static str)> {
    make_source(pool, "srcA0000000").await;
    make_source(pool, "srcB0000000").await;
    let mut ids = Vec::new();
    for (letter, scheme, country, status) in [
        ("a", "vless", Some("US"), "unknown"),
        ("b", "trojan", Some("DE"), "alive"),
        ("c", "tuic", None, "unknown"),
        ("d", "vless", Some("US"), "removed"),
    ] {
        let id = bulk_test_row(
            pool,
            &format!("fp-admin-{letter}"),
            scheme,
            status,
            country,
            None,
        )
        .await;
        ids.push((id, letter));
    }
    // Links: a+b on srcA, c on srcB, d unlinked.
    for (id, letter) in &ids {
        match *letter {
            "a" | "b" => link_row(pool, *id, "srcA0000000").await,
            "c" => link_row(pool, *id, "srcB0000000").await,
            _ => {}
        }
    }
    // Preserved history: a = T1+T2, b = T1 only, c = none, d = T2 only.
    let by_letter: std::collections::HashMap<&str, i64> =
        ids.iter().map(|(id, letter)| (*letter, *id)).collect();
    for (letter, kinds) in [
        ("a", &["tcp", "t2"][..]),
        ("b", &["tcp"][..]),
        ("d", &["t2"][..]),
    ] {
        for kind in kinds {
            sqlx::query(
                    "INSERT INTO probe_results (proxy_id, checked_at, ok, latency_ms, error, probe_kind)
                     VALUES (?, 1, 1, 10, NULL, ?)",
                )
                .bind(by_letter[letter])
                .bind(kind)
                .execute(pool)
                .await
                .unwrap();
        }
    }
    ids
}

/// The count and the rows of one filter, asserted together: the two
/// queries share one clause set, and a filter that constrains only one
/// of them would show a total that does not match the page.
async fn filtered_ids(pool: &DbPool, filter: &ProxyListFilter) -> (i64, Vec<i64>) {
    let total = count_filtered(pool, filter).await.unwrap();
    let rows = list_filtered(pool, filter, ProxyListOrder::Updated, 50, None)
        .await
        .unwrap();
    let mut ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    assert_eq!(
        total,
        ids.len() as i64,
        "the count and the page of one filter must agree"
    );
    (total, ids)
}

/// The count and the page of the admin browser apply exactly the same
/// filter clauses, and every filter column constrains the rows it is
/// supposed to.
#[tokio::test]
async fn admin_list_filter_count_and_rows_match() {
    let (_dir, pool) = temp_pool().await;
    let ids = admin_list_fixture(&pool).await;
    let id_of = |letter: &str| ids.iter().find(|(_, l)| *l == letter).unwrap().0;
    let expected = |letters: &[&str]| -> Vec<i64> {
        let mut out: Vec<i64> = letters.iter().map(|l| id_of(l)).collect();
        out.sort_unstable();
        out
    };

    // Unfiltered: everything, and count and rows agree.
    let filter = ProxyListFilter::default();
    let (total, rows) = filtered_ids(&pool, &filter).await;
    assert_eq!(total, 4);
    assert_eq!(rows, expected(&["a", "b", "c", "d"]));

    // Status whitelist.
    let filter = ProxyListFilter {
        statuses: vec!["alive".into()],
        ..Default::default()
    };
    let (total, rows) = filtered_ids(&pool, &filter).await;
    assert_eq!(total, 1);
    assert_eq!(rows, expected(&["b"]));

    // Exact scheme and exact country.
    let filter = ProxyListFilter {
        scheme: "vless".into(),
        country: "US".into(),
        ..Default::default()
    };
    let (total, rows) = filtered_ids(&pool, &filter).await;
    assert_eq!(total, 2, "a and d are vless in the US");
    assert_eq!(rows, expected(&["a", "d"]));

    // Source filter through the link table.
    let filter = ProxyListFilter {
        source_id: "srcA0000000".into(),
        ..Default::default()
    };
    let (total, rows) = filtered_ids(&pool, &filter).await;
    assert_eq!(total, 2, "a and b are linked to srcA");
    assert_eq!(rows, expected(&["a", "b"]));

    // Substring over host and name (both carry the fingerprint here).
    let filter = ProxyListFilter {
        query: "fp-admin-a.example".into(),
        ..Default::default()
    };
    let (total, rows) = filtered_ids(&pool, &filter).await;
    assert_eq!(total, 1);
    assert_eq!(rows, expected(&["a"]));
    let filter = ProxyListFilter {
        query: "fp-admin-b".into(),
        ..Default::default()
    };
    let (total, rows) = filtered_ids(&pool, &filter).await;
    assert_eq!(total, 1, "b matches on host and name");
    assert_eq!(rows, expected(&["b"]));

    // Coverage buckets.
    for (bucket, expected_letter) in [
        (CheckCoverage::T1Only, "b"),
        (CheckCoverage::T2Only, "d"),
        (CheckCoverage::Both, "a"),
        (CheckCoverage::None, "c"),
    ] {
        let filter = ProxyListFilter {
            coverage: Some(bucket),
            ..Default::default()
        };
        let (total, rows) = filtered_ids(&pool, &filter).await;
        assert_eq!(total, 1, "coverage bucket {}", bucket.as_str());
        assert_eq!(
            rows,
            expected(&[expected_letter]),
            "coverage bucket {}",
            bucket.as_str()
        );
    }

    // The rows carry the coverage flags the "Checks" cell renders.
    let rows = list_filtered(
        &pool,
        &ProxyListFilter::default(),
        ProxyListOrder::Updated,
        50,
        None,
    )
    .await
    .unwrap();
    let flags: std::collections::HashMap<i64, (bool, bool)> = rows
        .into_iter()
        .map(|r| (r.id, (r.t1_checked, r.t2_checked)))
        .collect();
    assert_eq!(flags[&id_of("a")], (true, true));
    assert_eq!(flags[&id_of("b")], (true, false));
    assert_eq!(flags[&id_of("c")], (false, false));
    assert_eq!(flags[&id_of("d")], (false, true));

    // Purge-dialog count: unfiltered terminal rows.
    assert_eq!(count_removed(&pool).await.unwrap(), 1);
    // Country dropdown: distinct stored codes, ascending.
    assert_eq!(distinct_countries(&pool).await.unwrap(), vec!["DE", "US"]);
}

/// The three sort orders of the admin browser and the LIMIT/OFFSET
/// pagination; ties break by id DESC in `Updated` order.
#[tokio::test]
async fn admin_list_orders_and_pages() {
    let (_dir, pool) = temp_pool().await;
    let ids = admin_list_fixture(&pool).await;
    let id_of = |letter: &str| ids.iter().find(|(_, l)| *l == letter).unwrap().0;
    // Distinct recency and latency so both orders are deterministic.
    // b and c share their timestamp: the tie must break by id DESC, and
    // a page boundary must not cut a tied pair in half.
    let recency = [("a", 100), ("b", 300), ("c", 300), ("d", 400)];
    let latency = [
        ("a", Some(100)),
        ("b", Some(50)),
        ("c", None),
        ("d", Some(80)),
    ];
    for (letter, updated_at) in recency {
        sqlx::query("UPDATE proxies SET updated_at = ? WHERE id = ?")
            .bind(updated_at)
            .bind(id_of(letter))
            .execute(&pool)
            .await
            .unwrap();
    }
    for (letter, latency) in latency {
        sqlx::query("UPDATE proxies SET latency_ms = ? WHERE id = ?")
            .bind(latency)
            .bind(id_of(letter))
            .execute(&pool)
            .await
            .unwrap();
    }
    // Mixed-case names, so the name order has to fold the case to
    // order them the way an operator reads them.
    for (letter, name) in [
        ("a", "Alpha"),
        ("b", "beta"),
        ("c", "Gamma"),
        ("d", "delta"),
    ] {
        sqlx::query("UPDATE proxies SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id_of(letter))
            .execute(&pool)
            .await
            .unwrap();
    }

    // Updated: newest first, ties by id DESC (c before b).
    let rows = list_filtered(
        &pool,
        &ProxyListFilter::default(),
        ProxyListOrder::Updated,
        50,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![id_of("d"), id_of("c"), id_of("b"), id_of("a")]
    );
    // Latency: measured ascending, unmeasured last.
    let rows = list_filtered(
        &pool,
        &ProxyListFilter::default(),
        ProxyListOrder::Latency,
        50,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![id_of("b"), id_of("d"), id_of("a"), id_of("c")]
    );
    // Name: case-insensitive ascending (the fixture names are mixed
    // case, so a plain byte order would put "Gamma" and "Alpha" in the
    // wrong places).
    let rows = list_filtered(
        &pool,
        &ProxyListFilter::default(),
        ProxyListOrder::Name,
        50,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![id_of("a"), id_of("b"), id_of("d"), id_of("c")]
    );

    // Keyset pagination: the second page resumes after the last row of
    // the first one, so the two pages cover every row exactly once.
    let first_page = list_page(&pool, ProxyListOrder::Updated, 2, None).await;
    let first_ids: Vec<i64> = first_page.iter().map(|r| r.id).collect();
    assert_eq!(first_ids, vec![id_of("d"), id_of("c")]);
    let second_page = list_page(
        &pool,
        ProxyListOrder::Updated,
        2,
        Some(&first_page[1].cursor(ProxyListOrder::Updated)),
    )
    .await;
    let second_ids: Vec<i64> = second_page.iter().map(|r| r.id).collect();
    assert_eq!(second_ids, vec![id_of("b"), id_of("a")]);
    // The two pages cover every row exactly once: a tied pair must not
    // show up on both pages and must not be skipped between them.
    assert!(
        !first_ids.iter().any(|id| second_ids.contains(id)),
        "the pages overlap"
    );
    let mut all: Vec<i64> = first_ids.iter().chain(second_ids.iter()).copied().collect();
    all.sort_unstable();
    let mut every: Vec<i64> = ids.iter().map(|(id, _)| *id).collect();
    every.sort_unstable();
    assert_eq!(all, every, "the pages leave a gap");

    // The page before the first one is empty: past the end of the order
    // there is nothing to walk back to.
    let rows = list_page_backward(
        &pool,
        ProxyListOrder::Updated,
        2,
        &first_page[0].cursor(ProxyListOrder::Updated),
    )
    .await;
    assert!(rows.is_empty());

    // The page before the second one is the first one again, and it comes
    // out in the reading order even though it is fetched backwards.
    let rows = list_page_backward(
        &pool,
        ProxyListOrder::Updated,
        2,
        &second_page[0].cursor(ProxyListOrder::Updated),
    )
    .await;
    let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![id_of("d"), id_of("c")]);
}

/// One page of the admin list, taken after `cursor` (or the first page
/// when there is none).
async fn list_page(
    pool: &DbPool,
    order: ProxyListOrder,
    limit: i64,
    cursor: Option<&ProxyListCursor>,
) -> Vec<ProxyListRow> {
    let page = cursor.map(|cursor| ProxyListPage {
        cursor: cursor.clone(),
        direction: ProxyListDirection::Forward,
    });
    list_filtered(
        pool,
        &ProxyListFilter::default(),
        order,
        limit,
        page.as_ref(),
    )
    .await
    .unwrap()
}

/// The page of the admin list *before* `cursor`.
async fn list_page_backward(
    pool: &DbPool,
    order: ProxyListOrder,
    limit: i64,
    cursor: &ProxyListCursor,
) -> Vec<ProxyListRow> {
    let page = ProxyListPage {
        cursor: cursor.clone(),
        direction: ProxyListDirection::Backward,
    };
    list_filtered(pool, &ProxyListFilter::default(), order, limit, Some(&page))
        .await
        .unwrap()
}

/// `from_bucket`/`from_param` are the whitelists: a garbage value is
/// refused rather than guessed into a filter.
#[test]
fn admin_list_param_parsing_refuses_garbage() {
    assert_eq!(
        CheckCoverage::from_bucket("t1_only"),
        Some(CheckCoverage::T1Only)
    );
    assert_eq!(
        CheckCoverage::from_bucket("T1_ONLY"),
        None,
        "the handler lowercases, the whitelist does not"
    );
    assert_eq!(CheckCoverage::from_bucket("everything"), None);
    assert_eq!(
        ProxyListOrder::from_param("latency"),
        ProxyListOrder::Latency
    );
    assert_eq!(ProxyListOrder::from_param("name"), ProxyListOrder::Name);
    assert_eq!(
        ProxyListOrder::from_param("updated"),
        ProxyListOrder::Updated
    );
    assert_eq!(ProxyListOrder::from_param("bogus"), ProxyListOrder::Updated);
}

/// The "unprobeable (tuic/mieru)" sub-line is rendered under the
/// "Never checked yet" headline, which counts `status != 'removed'`.
/// The cleanup button moves exactly these rows to `removed`, so
/// counting them anyway made the sub-line outgrow the number it
/// annotates: 0 never checked, 300 unprobeable.
#[tokio::test]
async fn count_unprobeable_excludes_rows_the_cleanup_button_retired() {
    let (_dir, pool) = temp_pool().await;
    for i in 0..5 {
        bulk_test_row(
            &pool,
            &format!("fp-tuic-{i}"),
            "tuic",
            "unknown",
            None,
            None,
        )
        .await;
    }
    // A probeable scheme is never part of the sub-line.
    bulk_test_row(&pool, "fp-vless", "vless", "unknown", None, None).await;

    assert_eq!(count_unprobeable(&pool).await.unwrap(), 5);

    let retired = remove_unprobeable_unknown(&pool).await.unwrap();
    assert_eq!(retired, 5);
    // The headline the sub-line sits under is now 0 too, so the two
    // can no longer disagree.
    let never_checked: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(last_checked_at IS NULL), 0) FROM proxies
                                WHERE status != 'removed'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(never_checked, 1, "only the vless row is left unchecked");
    assert_eq!(count_unprobeable(&pool).await.unwrap(), 0);
}

/// The quarantine queue lists quarantined rows by nearest scheduled
/// check, capped, and never shows other statuses.
#[tokio::test]
async fn quarantine_queue_orders_by_nearest_check() {
    let (_dir, pool) = temp_pool().await;
    let now = crate::models::now_ts();
    let q1 = bulk_test_row(&pool, "fp-q1", "vless", "quarantine", None, None).await;
    let q2 = bulk_test_row(&pool, "fp-q2", "vless", "quarantine", None, None).await;
    let q3 = bulk_test_row(&pool, "fp-q3", "vless", "quarantine", None, None).await;
    let alive = bulk_test_row(&pool, "fp-qa", "vless", "alive", None, None).await;
    // q2 is due first, then q3, then q1.
    sqlx::query("UPDATE proxies SET ladder_at = ? WHERE id = ?")
        .bind(now + 300)
        .bind(q1)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET ladder_at = ? WHERE id = ?")
        .bind(now + 100)
        .bind(q2)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE proxies SET ladder_at = ? WHERE id = ?")
        .bind(now + 200)
        .bind(q3)
        .execute(&pool)
        .await
        .unwrap();

    let rows = list_quarantine_queue(&pool, 2).await.unwrap();
    assert_eq!(rows.iter().map(|r| r.id).collect::<Vec<_>>(), vec![q2, q3]);

    let rows = list_quarantine_queue(&pool, 50).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert!(!rows.iter().any(|r| r.id == alive));
}

/// The proxy card resolves source display names through the link
/// table, newest seen first. (A link row itself cannot outlive its
/// source (the FK cascades) but the LEFT JOIN keeps the card robust
/// to a dangling name regardless.)
#[tokio::test]
async fn proxy_card_links_resolve_source_names() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcA0000000").await;
    make_source(&pool, "srcB0000000").await;
    let id = bulk_test_row(&pool, "fp-links", "vless", "alive", None, None).await;
    link_row(&pool, id, "srcA0000000").await;
    link_row(&pool, id, "srcB0000000").await;
    sqlx::query("UPDATE proxy_source_links SET seen_at = 2 WHERE source_id = 'srcB0000000'")
        .execute(&pool)
        .await
        .unwrap();

    let rows = links_with_source_name(&pool, id).await.unwrap();
    assert_eq!(rows.len(), 2);
    // Newest seen first, each with the source's display name.
    assert_eq!(rows[0].source_id, "srcB0000000");
    assert_eq!(rows[0].name.as_deref(), Some("srcB0000000"));
    assert_eq!(rows[0].seen_at, 2);
    assert_eq!(rows[1].source_id, "srcA0000000");
    assert_eq!(rows[1].name.as_deref(), Some("srcA0000000"));
}

/// Insert a proxy row with a hand-made fingerprint, the shape a row
/// written before the canonical form changed has: a key the ingest no
/// longer produces and the fields the recompute reads.
async fn insert_legacy_row(
    pool: &DbPool,
    fingerprint: &str,
    params: &str,
    status: &str,
    source_id: &str,
) -> i64 {
    let now = crate::models::now_ts();
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential,
                              params, unknown_params, status, created_at, updated_at)
         VALUES (?, 'vless', 'n', 'h.example.com', 443, 'uuid-1', ?, NULL, ?, ?, ?)
         RETURNING id",
    )
    .bind(fingerprint)
    .bind(params)
    .bind(status)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, ?, ?)")
        .bind(id)
        .bind(source_id)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
    id
}

/// The key the canonical form gives a vless node with that SNI.
fn canonical_key_of(sni: &str) -> String {
    let entry = ProxyEntry {
        scheme: Scheme::Vless,
        name: "n".into(),
        host: "h.example.com".into(),
        port: 443,
        credential: "uuid-1".into(),
        params: vec![Param {
            key: "sni".into(),
            value: sni.into(),
            known: true,
        }],
        raw_path: String::new(),
        raw_line: String::new(),
    };
    entry.fingerprint()
}

#[tokio::test]
async fn two_rows_that_describe_the_same_node_are_merged() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcMergeA").await;
    make_source(&pool, "srcMergeB").await;

    // Two keys under the old canonical form, one node under the new one:
    // the Clash spelling `servername` and the URI spelling `sni`.
    let alive = insert_legacy_row(
        &pool,
        "old-alive",
        r#"{"sni":"a.example.com"}"#,
        "alive",
        "srcMergeA",
    )
    .await;
    insert_legacy_row(
        &pool,
        "old-other",
        r#"{"servername":"a.example.com"}"#,
        "unknown",
        "srcMergeB",
    )
    .await;

    let stats = refingerprint(&pool).await.unwrap();
    assert_eq!(stats.merged, 1);
    assert_eq!(stats.rewritten, 1);

    // One row is left, and it is the one the probe had verified.
    let rows: Vec<ProxyRow> = sqlx::query_as("SELECT * FROM proxies")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, alive);
    assert_eq!(rows[0].status, "alive");
    assert_eq!(rows[0].fingerprint, canonical_key_of("a.example.com"));

    // Both sources are still linked to the surviving row.
    let links: Vec<(String,)> = sqlx::query_as(
        "SELECT source_id FROM proxy_source_links WHERE proxy_id = ? ORDER BY source_id",
    )
    .bind(alive)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        links,
        vec![("srcMergeA".to_string(),), ("srcMergeB".to_string(),)]
    );
}

#[tokio::test]
async fn a_row_that_already_carries_the_key_is_left_alone() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcUnchanged").await;
    let id = insert_legacy_row(
        &pool,
        &canonical_key_of("a.example.com"),
        r#"{"sni":"a.example.com"}"#,
        "unknown",
        "srcUnchanged",
    )
    .await;

    let stats = refingerprint(&pool).await.unwrap();
    assert_eq!(stats.rewritten, 0);
    assert_eq!(stats.merged, 0);
    let row: ProxyRow = sqlx::query_as("SELECT * FROM proxies WHERE id = ?")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.fingerprint, canonical_key_of("a.example.com"));
}

#[tokio::test]
async fn the_recompute_is_idempotent() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcIdempotent").await;
    insert_legacy_row(
        &pool,
        "old-one",
        r#"{"sni":"a.example.com"}"#,
        "unknown",
        "srcIdempotent",
    )
    .await;

    let first = refingerprint(&pool).await.unwrap();
    assert_eq!(first.rewritten, 1);
    // A second pass finds every key already computed and changes nothing.
    let second = refingerprint(&pool).await.unwrap();
    assert_eq!(second.rewritten, 0);
    assert_eq!(second.merged, 0);
}

#[tokio::test]
async fn a_row_the_ingest_already_recomputed_is_not_duplicated() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcIngest").await;
    // The old row, still under its old key.
    let legacy = insert_legacy_row(
        &pool,
        "old-row",
        r#"{"sni":"a.example.com"}"#,
        "unknown",
        "srcIngest",
    )
    .await;
    // The row the ingest created after the upgrade, already under the new
    // key: the same node, twice.
    let fresh = insert_legacy_row(
        &pool,
        &canonical_key_of("a.example.com"),
        r#"{"sni":"a.example.com"}"#,
        "alive",
        "srcIngest",
    )
    .await;

    let stats = refingerprint(&pool).await.unwrap();
    assert_eq!(stats.merged, 1);
    let rows: Vec<ProxyRow> = sqlx::query_as("SELECT * FROM proxies")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    // The verified row survives: the old row had no verdict of its own.
    assert_eq!(rows[0].id, fresh);
    assert_ne!(rows[0].id, legacy);
    assert_eq!(rows[0].status, "alive");
}

#[tokio::test]
async fn the_version_marker_gates_the_recompute() {
    let (_dir, pool) = temp_pool().await;
    make_source(&pool, "srcMarker").await;
    insert_legacy_row(
        &pool,
        "old-row",
        r#"{"sni":"a.example.com"}"#,
        "unknown",
        "srcMarker",
    )
    .await;

    // The rows carry no version yet: the recompute runs and the marker
    // names the version they now carry.
    let stats = ensure_fingerprint_version(&pool).await.unwrap().unwrap();
    assert_eq!(stats.rewritten, 1);
    assert_eq!(
        crate::repo::meta_get(&pool, FINGERPRINT_VERSION_KEY)
            .await
            .unwrap()
            .as_deref(),
        Some(crate::fingerprint::FINGERPRINT_VERSION)
    );

    // The rows carry the current version now: the next start does no work.
    assert!(ensure_fingerprint_version(&pool).await.unwrap().is_none());

    // Another version: the recompute runs again.
    crate::repo::meta_set(&pool, FINGERPRINT_VERSION_KEY, "fp1")
        .await
        .unwrap();
    let stats = ensure_fingerprint_version(&pool).await.unwrap().unwrap();
    assert_eq!(stats.rewritten, 0);
    assert_eq!(stats.merged, 0);
}
