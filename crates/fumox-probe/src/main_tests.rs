use super::*;
use axum::extract::Path;
use axum::routing::{get, put};
use axum::{Json, Router};

#[test]
fn zero_retention_window_is_clamped_to_one_day() {
    assert_eq!(
        retention::cutoff(100_000, 0),
        100_000 - 86_400,
        "the shared clamp keeps a zero window at one day"
    );
    assert_eq!(retention::cutoff(100_000, 7), 100_000 - 7 * 86_400);
}

/// Hardening: with
/// the default policy the daemon must refuse to *dial* loopback feed
/// targets, but the refusal itself is now a journaled failed check
/// (the fail ladder runs), so a blocked proxy cannot clog the queues
/// forever. A live loopback listener stays untouched, and the blocked
/// proxy collects a failure record instead of silence.
#[tokio::test]
async fn private_targets_are_not_dialed_by_default() {
    let (_dir, pool) = temp_pool().await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live_port = listener.local_addr().unwrap().port();
    let hit = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hit_clone = hit.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(ok) => ok,
                Err(_) => break,
            };
            hit_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            drop(socket);
        }
    });
    let id = seed_proxy(&pool, "vless", "127.0.0.1", live_port, "unknown").await;

    // The shipped default is the one the test is about: the daemon must
    // not dial a private target unless the operator says so.
    assert!(
        !fumox_core::config::ProbeConfig::default().allow_private_targets,
        "the shipped default must refuse private targets"
    );
    // The test config turns the guard on for the loopback listeners the
    // other tests use, so it is turned off again here.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(1, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    // The listener saw no connection.
    assert_eq!(hit.load(std::sync::atomic::Ordering::Relaxed), 0);
    // The refusal is journaled as a failed check...
    let (attempts, error, kind): (i64, String, String) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(MAX(error), ''), COALESCE(MAX(probe_kind), '')
             FROM probe_results WHERE proxy_id = ? AND ok = 0",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(attempts, 1, "the vet refusal must be journaled");
    assert!(
        error.contains("blocked by the private-address policy"),
        "{error}"
    );
    assert_eq!(kind, "tcp");
    // ...and the fail ladder ran: fail_limit reached → quarantine.
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
    assert_eq!(row.fail_count, 1);
    assert!(row.ladder_at.is_some());
}

/// Concurrent vetting must hand the verdicts back in the input order
/// (the lanes zip them onto their candidates) and must apply the same
/// per-address policy the serial pass did. IP literals keep the test
/// off DNS.
#[tokio::test]
async fn vet_hosts_preserves_order_and_policy() {
    let (_dir, pool) = temp_pool().await;
    let hosts = vec![
        "192.168.7.7".to_string(),
        "169.254.169.254".to_string(),
        "127.0.0.1".to_string(),
    ];

    // Guard on: every verdict is a refusal with the host's own reason,
    // in order.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(Context::new(config.clone(), pool.clone()).expect("test context"));
    let verdicts = vet_hosts(&ctx, &hosts, &CycleVet::default()).await;
    let reasons: Vec<&str> = verdicts
        .iter()
        .map(|verdict| verdict.as_ref().expect_err("must be refused"))
        .map(String::as_str)
        .collect();
    assert!(reasons[0].contains("RFC1918"), "{}", reasons[0]);
    assert!(reasons[1].contains("link-local"), "{}", reasons[1]);
    assert!(reasons[2].contains("loopback"), "{}", reasons[2]);

    // Guard off: the same list vets in order.
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool).expect("test context"));
    let verdicts = vet_hosts(&ctx, &hosts, &CycleVet::default()).await;
    let vetted: Vec<std::net::IpAddr> = verdicts
        .into_iter()
        .map(|verdict| verdict.expect("must be allowed")[0])
        .collect();
    assert_eq!(
        vetted,
        hosts
            .iter()
            .map(|host| host.parse::<std::net::IpAddr>().unwrap())
            .collect::<Vec<_>>()
    );
}

/// The T2 counterpart: a vet-refused T2
/// candidate is journaled as a failed `t2` check even when meow-rs is
/// completely down, the journal row is what un-sticks the head of the
/// recency queue (the selector orders by the last t2 attempt).
#[tokio::test]
async fn t2_vet_block_is_journaled_even_without_meow() {
    let (_dir, pool) = temp_pool().await;

    // A private host that would never pass the gate. The proxy is
    // `ready`, so the T1 sample never draws it (T1 takes
    // `unknown`/`alive`) and the vet refusal is the cycle's only
    // verdict for it: charged exactly once to the fail ladder.
    let id = seed_proxy(&pool, "vless", "127.0.0.1", 1, "ready").await;

    // meow-rs is unreachable on a closed port.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    // The failed t2 row exists, exactly what keeps the recency
    // selector moving past blocked rows.
    let (t2_rows, error): (i64, String) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(MAX(error), '') FROM probe_results
             WHERE proxy_id = ? AND ok = 0 AND probe_kind = 't2'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(t2_rows, 1, "the T2 refusal must be journaled as t2");
    assert!(
        error.contains("blocked by the private-address policy"),
        "{error}"
    );
    // Charged once (the T1 lane was never involved), the failed
    // `ready` tier demotes and the T2 block is stamped.
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert_eq!(row.fail_count, 1);
    assert!(row.last_t2_failed_at.is_some());
    let (tcp_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND probe_kind = 'tcp'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        tcp_rows, 0,
        "a `ready` row is out of the T1 sample's population"
    );
}

/// Engine failure (engine-failure branch 1): meow answers
/// /version but rejects the config reload, every proxy of the batch
/// gets a journaled failed t2 check (outage reason) and the recency
/// queue head cannot pin during the outage. The outage is *not*
/// charged to the proxies.
#[tokio::test]
async fn t2_engine_failure_at_reload_fails_the_batch() {
    let (_dir, pool) = temp_pool().await;

    // Mock meow-rs: /version alive, /configs broken.
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route(
            "/configs",
            put(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message":"reload failed"})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Two due proxies, `ready` so the T1 sample never draws them and
    // the reload outage is the only thing that touches them.
    let a = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let b = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "ready").await;
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let mut config = test_config(3, &meow_addr, config_path.clone());
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx.clone()).await.unwrap();

    for id in [a, b] {
        let (kind, error): (String, String) = sqlx::query_as(
            "SELECT probe_kind, COALESCE(error, '') FROM probe_results
                 WHERE proxy_id = ? AND ok = 0 ORDER BY id DESC LIMIT 1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            kind, "t2_unverified",
            "the reload outage must be journaled as unverified, not as a proxy verdict"
        );
        assert!(error.contains("meow-rs unavailable"), "id {id}: {error}");
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        // The engine outage stamps the outstanding T2 verdict but
        // leaves the proxy's own fail budget alone.
        assert_eq!(row.fail_count, 0, "id {id}");
        assert!(
            row.last_t2_failed_at.is_some(),
            "id {id}: the outstanding T2 verdict must be stamped"
        );
        // The `ready` tier does not outlive an outage.
        assert_eq!(row.status, "alive", "id {id}");
    }

    // The meow backoff is armed: a second immediate cycle sleeps
    // silently instead of re-failing the pool (checked against the
    // same ctx, whose retry gate now points into the future).
    assert!(
        fumox_core::models::now_ts() < ctx.meow_retry_at.load(std::sync::atomic::Ordering::Relaxed),
        "the reload outage must arm the meow backoff"
    );
}

/// The regression this whole split exists for: a meow-rs outage must
/// not charge the proxies it skipped. With the shipped
/// `fail_limit = 2` two outage cycles used to quarantine a proxy
/// that had never failed a single check, dropping it out of both T2
/// selectors and out of `/export/alive` for a fault of the sidecar.
///
/// The proxies here are healthy: the `alive` one points at a live TCP
/// listener, so the T1 sample really dials it and it really passes, and
/// the `ready` one sits in the tunnel-verified tier. meow-rs is
/// unreachable, so every cycle takes the ping-outage branch. After two
/// cycles both must still be in service: the row the T1 lane judged keeps
/// its T1 verdict, the row the T2 lane owed a verdict carries the
/// outage stamp (the `ready` tier does not survive an outage), and
/// neither fail counter moved.
#[tokio::test]
async fn meow_outage_never_quarantines_a_healthy_proxy() {
    let (_dir, pool) = temp_pool().await;

    // A live listener so T1 passes and the only failure the proxy can
    // collect is one the engine owes it.
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match tcp.accept().await {
                Ok(ok) => ok,
                Err(_) => break,
            };
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = socket.shutdown().await;
            });
        }
    });
    // The `alive` row is the one the T1 sample draws, so the TCP check
    // really runs against the listener.
    let alive = seed_proxy(&pool, "vless", "127.0.0.1", tcp_port, "alive").await;
    // The `ready` row is never drawn by T1, it only carries the
    // tunnel-verified tier the outage has to demote.
    let ready = seed_proxy(&pool, "trojan", "127.0.0.1", tcp_port, "ready").await;

    // The shipped fail_limit of 2, and meow-rs on a closed port.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let mut config = test_config(2, "127.0.0.1:1", config_path);
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    for cycle in 1..=2 {
        // The backoff gate would otherwise skip T2 on the second
        // cycle; clear it so both cycles really reach the outage
        // branch (the backoff itself is asserted in the reload test).
        ctx.meow_retry_at.store(0, Ordering::Relaxed);
        run_cycle(ctx.clone()).await.unwrap();

        // The `alive` row: the T1 sample really dials it, the dial
        // succeeds, and the outage leaves the row the T1 lane just
        // judged alone.
        let row = proxies::get_by_id(&pool, alive).await.unwrap().unwrap();
        assert_ne!(
            row.status, "quarantine",
            "cycle {cycle}: an engine outage must not quarantine a healthy proxy"
        );
        assert_eq!(
            row.fail_count, 0,
            "cycle {cycle}: the outage must not charge the proxy's fail budget"
        );
        assert_eq!(
            row.quarantined_at, None,
            "cycle {cycle}: no second chance may be scheduled"
        );
        let (tcp_verdicts,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM probe_results
                 WHERE proxy_id = ? AND probe_kind = 'tcp' AND ok = 1",
        )
        .bind(alive)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            tcp_verdicts >= 1,
            "cycle {cycle}: the T1 sample must really dial the alive row"
        );

        // The `ready` row: the outage stamps the outstanding T2 verdict
        // and demotes the tunnel-verified tier, without charging it.
        let row = proxies::get_by_id(&pool, ready).await.unwrap().unwrap();
        assert_ne!(
            row.status, "quarantine",
            "cycle {cycle}: an engine outage must not quarantine a healthy proxy"
        );
        assert_eq!(
            row.fail_count, 0,
            "cycle {cycle}: the outage must not charge the proxy's fail budget"
        );
        assert_eq!(
            row.quarantined_at, None,
            "cycle {cycle}: no second chance may be scheduled"
        );
        assert!(
            row.last_t2_failed_at.is_some(),
            "cycle {cycle}: the outstanding T2 verdict must be stamped"
        );
        assert_eq!(
            row.status, "alive",
            "cycle {cycle}: the ready tier must not outlive an engine outage"
        );
    }
}

/// Engine failure (engine-failure branch 2): meow dies
/// mid-batch, the pre-flight ping succeeded (so `reload_config` and
/// the fan-out began), but every delay request and the follow-up
/// `/version` ping now fail. The connected-engine check therefore
/// reports `engine_alive = false` for every task, the consecutive
/// counter crosses the threshold on the first task to record a
/// failure, and the rest of the tasks see the abort flag and journal
/// an aborted-failure record without further meow calls.
#[tokio::test]
async fn t2_engine_failure_mid_batch_aborts_the_rest() {
    let (_dir, pool) = temp_pool().await;

    // The pre-flight ping calls /version first, so the handler returns
    // 200 on that call and 500 on every subsequent one. This
    // models "engine crashed after the pre-flight passed".
    let version_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let version_calls_inner = version_calls.clone();
    let delay_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let delay_calls_inner = delay_calls.clone();
    let app = Router::new()
        .route(
            "/version",
            get(move || {
                let version_calls = version_calls_inner.clone();
                async move {
                    let n = version_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n == 0 {
                        (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({"version":"mock"})),
                        )
                    } else {
                        (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"message":"engine crashed"})),
                        )
                    }
                }
            }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(move || {
                let delay_calls = delay_calls_inner.clone();
                async move {
                    delay_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"message":"engine exploded"})),
                    )
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Four proxies, `ready` so the T1 sample never draws them and the
    // mid-batch outage is the only thing that touches them: with
    // threshold=3 the first three tasks record a failure
    // (engine_alive = false) and the third one flips the abort flag.
    // The fourth task, whichever side of the is_aborted() check
    // it lands on, gets either a "mid-batch" record or an "aborted:"
    // record, both are engine-outage texts.
    //
    // One check at a time, so the order is deterministic: the fourth
    // task starts after the third one flipped the flag.
    let a = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let b = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "ready").await;
    let c = seed_proxy(&pool, "vmess", "127.0.0.1", 443, "ready").await;
    let d = seed_proxy(&pool, "ss", "127.0.0.1", 443, "ready").await;
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let mut config = test_config(3, &meow_addr, config_path);
    config.probe.allow_private_targets = true;
    config.probe.concurrency = 1;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    // Every proxy of the batch carries a journaled t2 failure:
    // either the mid-batch reason (the task that crossed the
    // threshold) or the aborted marker (a task that arrived after
    // the flag was set). Both are engine-outage texts.
    let mut aborted = 0;
    let mut mid_batch = 0;
    for id in [a, b, c, d] {
        let (error,): (String,) = sqlx::query_as(
            "SELECT COALESCE(error, '') FROM probe_results
                 WHERE proxy_id = ? AND ok = 0 AND probe_kind = 't2_unverified'",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            error.contains("meow-rs unavailable mid-batch")
                || error.contains("aborted: meow-rs became unavailable"),
            "id {id}: {error}"
        );
        if error.starts_with("aborted:") {
            aborted += 1;
        } else {
            mid_batch += 1;
        }
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        // An engine outage, mid-batch or aborted, stamps the
        // outstanding T2 verdict without spending the proxy's fail
        // budget, and no T1 dial ran for a `ready` row.
        assert_eq!(row.fail_count, 0, "id {id}");
        assert!(
            row.last_t2_failed_at.is_some(),
            "id {id}: the outstanding T2 verdict must be stamped"
        );
    }
    // With concurrency 1 the split is deterministic: the first three
    // tasks reached the engine and tripped the threshold, the fourth
    // one found the abort flag already set.
    assert_eq!(mid_batch, 3, "the first three tasks crossed the threshold");
    assert_eq!(
        aborted, 1,
        "the task behind the flag never reached the engine"
    );

    // L-088: the aborted task must not have reached the engine. Three
    // tasks asked for a delay, each of them twice (the retry absorbs a
    // transient failure), so six delay requests and no more.
    assert_eq!(
        delay_calls.load(Ordering::SeqCst),
        6,
        "the aborted task must not send a delay request"
    );
    // The /version pings: one pre-flight ping before the fan-out and
    // one liveness ping per task that reached the engine. The aborted
    // task adds none.
    assert_eq!(
        version_calls.load(Ordering::SeqCst),
        4,
        "the /version budget is one pre-flight ping plus one per failed task"
    );
}

/// The cycle counters must not fold an engine-wide outage into
/// `t2_checked`: with meow-rs down before the batch starts, every due
/// proxy is journaled unverified and reported as aborted, and no row is
/// claimed as a real check.
#[tokio::test]
async fn t2_outage_counters_report_aborted_not_checked() {
    let (_dir, pool) = temp_pool().await;
    for _ in 0..3 {
        seed_proxy(&pool, "vless", "127.0.0.1", 443, "alive").await;
    }

    // meow-rs is unreachable on a closed port.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    let cycle = test_cycle(&ctx.config);
    let outcome = probe_t2_batch(ctx, &[], cycle).await.unwrap();
    assert_eq!(outcome.checked, 0, "an outage produces no real checks");
    assert_eq!(outcome.aborted, 3, "every due proxy is aborted unverified");
    assert_eq!(outcome.skipped, 0);

    // All three were journaled as unverified attempts, so the recency
    // queue moves past them despite the outage.
    let (rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM probe_results WHERE ok = 0 AND probe_kind = 't2_unverified'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 3);
}

/// The healthy-path counterpart: real engine contacts land in
/// `checked`, nothing else moves.
#[tokio::test]
async fn t2_live_engine_counters_count_real_checks() {
    let (_dir, pool) = temp_pool().await;

    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::OK,
                    Json(serde_json::json!({"delay": 42})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    seed_proxy(&pool, "vless", "127.0.0.1", 443, "alive").await;
    seed_proxy(&pool, "trojan", "127.0.0.1", 443, "alive").await;

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let mut config = test_config(3, &meow_addr, config_path);
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    let cycle = test_cycle(&ctx.config);
    let outcome = probe_t2_batch(ctx, &[], cycle).await.unwrap();
    assert_eq!(outcome.checked, 2);
    assert_eq!(outcome.aborted, 0);
    assert_eq!(outcome.skipped, 0);
}

/// Per-request blip below the escalation threshold: every delay check
/// fails with 5xx, but /version keeps answering 200, the engine is
/// alive, the proxy names are just bad. The blip counter therefore
/// never crosses the threshold, the batch keeps running, and every
/// proxy gets a "meow-rs transient error" record instead of an
/// "aborted:" one.
#[tokio::test]
async fn t2_per_request_blip_with_alive_engine_does_not_abort() {
    let (_dir, pool) = temp_pool().await;

    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message":"proxy not found"})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // `ready` rows: T2 candidates the T1 sample never draws, so the
    // batch of two really runs through the engine. Two is below the
    // blip threshold (three), so the run never escalates.
    let a = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let b = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "ready").await;
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let mut config = test_config(3, &meow_addr, config_path);
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    // L-090: the counters are the point of the test. A check that ran
    // against a live engine and did not succeed is *checked*, not
    // aborted: only a task that never reached the engine is aborted.
    let cycle = test_cycle(&ctx.config);
    let outcome = probe_t2_batch(ctx.clone(), &[], cycle).await.unwrap();
    assert_eq!(outcome.checked, 2, "both checks really ran");
    assert_eq!(
        outcome.aborted, 0,
        "a blip below the threshold is not an abort"
    );
    assert_eq!(outcome.skipped, 0);

    // Neither proxy crossed the blip threshold: /version answered 200
    // for every probe, so the run of blips never grew long enough and
    // the counter never advanced to the escalation. No backoff was
    // engaged either, meow_retry_at stays at 0.
    for id in [a, b] {
        let (error,): (String,) = sqlx::query_as(
            "SELECT COALESCE(error, '') FROM probe_results
                 WHERE proxy_id = ? AND ok = 0 AND probe_kind = 't2_unverified'",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            error.contains("meow-rs transient error"),
            "alive engine, bad delay → transient error text; got {error}"
        );
        assert!(
            !error.contains("aborted:") && !error.contains("mid-batch"),
            "alive engine must never escalate to abort; got {error}"
        );
        // The blip is a fault of the engine, not a verdict about the
        // proxy: the fail budget is untouched.
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.fail_count, 0, "id {id}");
    }
    let (retry_at,): (i64,) =
        sqlx::query_as("SELECT COALESCE(value, '0') FROM meta WHERE key = 'meow_retry_at'")
            .fetch_one(&pool)
            .await
            .unwrap_or((0,));
    assert_eq!(
        retry_at, 0,
        "no backoff engaged when the engine is alive and only delay checks fail"
    );
}

/// A *run* of blips is a broken test path, not a run of unlucky
/// requests: once the blip threshold is crossed the batch is treated as
/// an engine fault. The meow backoff is armed and no proxy is charged.
#[tokio::test]
async fn a_run_of_blips_escalates_to_an_engine_fault() {
    let (_dir, pool) = temp_pool().await;

    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message":"proxy not found"})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Four blipping proxies: the third one crosses the threshold.
    let mut ids = Vec::new();
    for scheme in ["vless", "trojan", "vmess", "ss"] {
        ids.push(seed_proxy(&pool, scheme, "127.0.0.1", 443, "ready").await);
    }
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let mut config = test_config(3, &meow_addr, config_path);
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    // The four checks really ran against the live engine: a check that
    // ran and did not succeed is *checked*, not aborted. The run of
    // blips backs the engine off, it does not undo the checks that
    // already happened.
    let cycle = test_cycle(&ctx.config);
    let outcome = probe_t2_batch(ctx.clone(), &[], cycle).await.unwrap();
    assert_eq!(outcome.checked, 4, "all four checks really ran");
    assert_eq!(outcome.aborted, 0, "no task was stopped before the engine");

    // The escalation armed the meow backoff: the engine is not
    // hammered again on the next cycle.
    assert!(
        fumox_core::models::now_ts() < ctx.meow_retry_at.load(std::sync::atomic::Ordering::Relaxed),
        "a run of blips must arm the meow backoff"
    );

    for id in ids {
        let (kind, error): (String, String) = sqlx::query_as(
            "SELECT probe_kind, COALESCE(error, '') FROM probe_results
                 WHERE proxy_id = ? AND ok = 0 ORDER BY id DESC LIMIT 1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            kind, "t2_unverified",
            "id {id}: a blip is an engine fault, not a proxy verdict"
        );
        assert!(
            error.contains("meow-rs transient error")
                || error.contains("aborted: meow-rs failed consecutive delay checks"),
            "id {id}: {error}"
        );
        // The proxies are not charged for the engine's broken test path.
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.fail_count, 0, "id {id}");
    }
}

/// The retry absorbs a single transient 5xx on a per-proxy basis:
/// the first delay request 5xxes, the second succeeds, so the task
/// reports `Ok` and never touches the abort counter. The batch
/// keeps running for the rest of the proxies.
#[tokio::test]
async fn t2_retry_recovers_a_flaky_proxy() {
    let (_dir, pool) = temp_pool().await;

    // Delay handler: first call per name returns 500, second returns 200.
    let delay_calls: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let delay_calls_inner = delay_calls.clone();
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(move |Path(name): Path<String>| {
                let delay_calls = delay_calls_inner.clone();
                async move {
                    let mut guard = delay_calls.lock().unwrap();
                    let n = guard.entry(name.clone()).or_insert(0);
                    *n += 1;
                    let attempt = *n;
                    drop(guard);
                    if attempt == 1 {
                        (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"message":"blip"})),
                        )
                    } else {
                        (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({"delay": 42})),
                        )
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // One flaky proxy; the second proxy is there to confirm the
    // batch keeps running and reports a clean Ok. Both are `ready`:
    // T2 candidates the T1 sample never draws.
    let flaky = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let stable = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "ready").await;
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let mut config = test_config(3, &meow_addr, config_path);
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    // The flaky proxy survived: the retry absorbed the first 5xx and
    // the second attempt returned Ok. The row becomes `ready`.
    let row = proxies::get_by_id(&pool, flaky).await.unwrap().unwrap();
    assert_eq!(
        row.status, "ready",
        "retry should have rescued the flaky proxy from a transient blip"
    );
    let (ok_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND ok = 1")
            .bind(flaky)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(ok_count, 1, "exactly one successful T2 for the flaky proxy");

    // The stable proxy was not touched by the abort counter at all.
    let row = proxies::get_by_id(&pool, stable).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");
}

/// The `ready` tier is demoted by every failed T2 outcome (owner
/// decision, 2026-09-10), here, by the meow outage itself: the proxy
/// was due a tunnel check, the engine was down, so the verification
/// no longer holds.
#[tokio::test]
async fn ready_is_demoted_by_engine_outage() {
    let (_dir, pool) = temp_pool().await;

    let id = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;

    // No meow-rs at all: the ping fails and the batch (this proxy)
    // gets journaled engine failures.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.status, "alive",
        "an unverified-by-outage proxy loses the ready tier"
    );
    let (error,): (String,) = sqlx::query_as(
        "SELECT COALESCE(error, '') FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2_unverified' AND ok = 0",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(error.contains("meow-rs unavailable"), "{error}");
}

/// A vet-refused T2 target loses the ready tier as well: the check it
/// was due could not run, and (as everywhere) the refusal is a failed
/// check on the ladder.
#[tokio::test]
async fn ready_is_demoted_by_vet_block() {
    let (_dir, pool) = temp_pool().await;

    let id = seed_proxy(&pool, "vless", "127.0.0.1", 1, "ready").await;

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.status, "alive",
        "the vet refusal demotes the ready tier"
    );
    let (kind, error): (String, String) = sqlx::query_as(
        "SELECT probe_kind, COALESCE(error, '') FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2' AND ok = 0",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kind, "t2");
    assert!(
        error.contains("blocked by the private-address policy"),
        "{error}"
    );
}

/// Fresh migrated SQLite in a scoped temp directory: keep the returned
/// guard in scope (`let (_dir, pool) = temp_pool().await`) and the whole
/// directory is removed when it drops.
async fn temp_pool() -> (fumox_core::tempdir_lite::TempDir, DbPool) {
    let dir = fumox_core::tempdir_lite::TempDir::new("probe");
    let cfg = fumox_core::config::DatabaseConfig {
        path: dir.path().join("test.db"),
        ..Default::default()
    };
    let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
    fumox_core::db::migrate(&pool).await.unwrap();
    (dir, pool)
}

/// Seed a linked proxy row; returns its id.
async fn seed_proxy(pool: &DbPool, scheme: &str, host: &str, port: u16, status: &str) -> i64 {
    sqlx::query(
            "INSERT OR IGNORE INTO sources (id, name, url, enabled, encoding, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcT0000000', 'probe-test', 'https://example.com', 1, 'auto', 3600, 1, 1)",
        )
        .execute(pool)
        .await
        .unwrap();
    let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES (?, ?, 'n', ?, ?, 'c', ?, 1, 1)
             RETURNING id",
        )
        .bind(format!("fp-{}", fumox_core::models::new_id()))
        .bind(scheme)
        .bind(host)
        .bind(i64::from(port))
        .bind(status)
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query(
            "INSERT INTO proxy_source_links (proxy_id, source_id, seen_at) VALUES (?, 'srcT0000000', 1)",
        )
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    id
}

/// The shared state of one cycle, for the tests that drive a single lane.
fn test_cycle(config: &AppConfig) -> Arc<Cycle> {
    Arc::new(Cycle::new(config))
}

fn test_config(fail_limit: u32, meow_addr: &str, meow_config: PathBuf) -> AppConfig {
    AppConfig {
        probe: fumox_core::config::ProbeConfig {
            cycle_interval_secs: 60,
            sample_size: 50,
            fail_limit,
            // The tests dial loopback listeners, which the default policy
            // refuses.
            allow_private_targets: true,
            connect_timeout_secs: 2,
            tls_timeout_secs: 2,
            concurrency: 4,
            heartbeat_interval_secs: 30,
            // Deterministic second chance: exactly +24h, no jitter.
            second_chance_min_hours: 24,
            second_chance_spread_hours: 0,
            // Default ladder: +15m, +30m, +1h.
            recheck_delays_secs: vec![900, 1800, 3600],
            queue_stale_days: 7,
            retention_interval_secs: 86400,
            backlog_target_drain_minutes: 60,
            refresh_check_limit: None,
        },
        meow: fumox_core::config::MeowConfig {
            api_addr: meow_addr.into(),
            api_token: String::new(),
            config_path: meow_config,
            test_url: vec!["http://cp.cloudflare.com".to_string()],
            timeout_secs: 3,
            backoff_initial_secs: 60,
            backoff_max_secs: 900,
            ipv6: false,
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn t1_cycle_promotes_live_proxy_and_quarantines_dead_one() {
    let (_dir, pool) = temp_pool().await;

    // One proxy points at a live listener, the other at a closed port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let live_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(ok) => ok,
                Err(_) => break,
            };
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = socket.shutdown().await;
            });
        }
    });
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    let live = seed_proxy(&pool, "vless", "127.0.0.1", live_port, "unknown").await;
    let dying = seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "unknown").await;

    // meow-rs is absent, but the hand-off of `run_cycle` keeps both
    // rows out of its reach anyway: the dead one is `unknown` (never a
    // T2 candidate) and the live one's promotion cycle is covered by
    // the T1 sample first, so no T2 verdict ever arrives in this test.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config = test_config(2, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    // Cycle 1: live proxy becomes alive (T1), dead one collects fail #1
    // (T1). The T2 batch skips the row the T1 sample just gave a
    // verdict, so the promoted proxy sees no T2 check in this cycle:
    // it is the head of the next cycle's batch.
    run_cycle(ctx.clone()).await.unwrap();
    let row = proxies::get_by_id(&pool, live).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert!(row.latency_ms.is_some());
    assert_eq!(row.fail_count, 0);
    assert!(
        row.last_t2_failed_at.is_none(),
        "the T2 batch must skip the row the T1 sample just checked"
    );
    let (t2_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND probe_kind = 't2'",
    )
    .bind(live)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(t2_rows, 0, "no T2 attempt in the promotion cycle");
    let row = proxies::get_by_id(&pool, dying).await.unwrap().unwrap();
    assert_eq!(row.status, "unknown");
    assert_eq!(row.fail_count, 1);

    // Cycle 2: fail limit reached → quarantine with a scheduled second
    // chance exactly 24h out (zero spread configured).
    run_cycle(ctx.clone()).await.unwrap();
    let row = proxies::get_by_id(&pool, dying).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
    assert_eq!(row.fail_count, 2);
    let quarantined_at = row.quarantined_at.unwrap();
    assert_eq!(row.ladder_at, Some(quarantined_at + 86_400));
    assert_eq!(row.ladder_step, 0);

    // The live proxy stayed alive and stays in the T1 sample (`alive`
    // is eligible and nothing stamped a T2 block), so every cycle adds
    // one successful T1 while the T2 batch keeps skipping it.
    let row = proxies::get_by_id(&pool, live).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    let (ok_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND ok = 1")
            .bind(live)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(ok_count, 2);
    let (fail_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND ok = 0")
            .bind(dying)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(fail_count, 2);
    let (kinds,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT probe_kind) FROM probe_results WHERE proxy_id = ? AND ok = 1",
    )
    .bind(live)
    .fetch_one(&pool)
    .await
    .unwrap();
    // Only the T1 lane ever succeeded (the hand-off kept the row out
    // of the T2 batch, so no t2 record exists at all).
    assert_eq!(kinds, 1);
    let (t1_kind,): (String,) = sqlx::query_as(
        "SELECT DISTINCT probe_kind FROM probe_results WHERE proxy_id = ? AND ok = 1",
    )
    .bind(live)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(t1_kind, "tcp");
}

#[tokio::test]
async fn t2_cycle_distinguishes_bad_credential_from_live_proxy() {
    let (_dir, pool) = temp_pool().await;

    // Mock meow-rs: proxy 1 tunnels fine, proxy 2 fails with a
    // credential-style error.
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|Path(name): Path<String>| async move {
                if name == "fumox-1" {
                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({"delay": 42})),
                    )
                } else {
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message":"invalid credential"})),
                    )
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Both proxies are `ready`: T2 candidates the T1 sample never
    // draws, so only T2 differentiates them.
    let good = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    assert_eq!(good, 1);
    let bad = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    assert_eq!(bad, 2);

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let config = test_config(3, &meow_addr, config_path.clone());
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    // The generated Clash config reached the disk with both proxies.
    let yaml = std::fs::read_to_string(&config_path).unwrap();
    assert!(yaml.contains("fumox-1"));
    assert!(yaml.contains("fumox-2"));

    // Good proxy: T2 confirmed the tunnel, it reaches the
    // tunnel-verified `ready` tier,
    // latency from the tunnel test.
    let row = proxies::get_by_id(&pool, good).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");
    assert_eq!(row.fail_count, 0);
    assert_eq!(row.latency_ms, Some(42));

    // Bad proxy: port is open (T1 green) but the tunnel failed ,
    // exactly the case T2 exists for. It stays in the plain tier with
    // the fail counted.
    let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert_eq!(row.fail_count, 1);
    let (error,): (String,) = sqlx::query_as(
        "SELECT error FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2' AND ok = 0
             ORDER BY checked_at DESC LIMIT 1",
    )
    .bind(bad)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(error.contains("invalid credential"));

    // meow_last_ok was stamped.
    let stamp = fumox_core::repo::meta_get(&pool, "meow_last_ok")
        .await
        .unwrap();
    assert!(stamp.is_some());
}

/// A batch in which every tunnel failed is a verdict about the test
/// endpoint, not about the proxies: meow-rs answers a blocked or degraded
/// endpoint exactly like a dead tunnel. The proxies are stamped unverified
/// and the fail ladder is not charged, so one unreachable endpoint cannot
/// empty the pool.
#[tokio::test]
async fn a_batch_where_every_tunnel_failed_does_not_charge_the_proxies() {
    let (_dir, pool) = temp_pool().await;

    // The mock engine fails every delay check.
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({"message":"An error occurred in the delay test"})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let first = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let second = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let config = test_config(3, &meow_addr, config_path.clone());
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    probe_t2_batch(ctx.clone(), &[], test_cycle(&ctx.config))
        .await
        .unwrap();

    // Neither proxy was charged: the endpoint is the suspect. Both are
    // stamped unverified instead, the way an engine outage stamps them.
    for id in [first, second] {
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.fail_count, 0, "proxy {id} must not be charged");
        assert_eq!(row.status, "alive", "proxy {id} is demoted, not retired");
        assert!(
            row.last_t2_failed_at.is_some(),
            "proxy {id} must be stamped unverified"
        );
    }

    // The attempts are journaled all the same: the recency queue keeps
    // moving even though nobody was charged.
    let (attempts,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE probe_kind = 't2' AND ok = 0")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(attempts, 2, "both attempts must be journaled");
}

/// The meow.yaml chmod is re-asserted on every write: a pre-existing
/// file (older binary, hand-copied sample, restored backup) must not
/// keep its old, possibly world-readable mode while the probe
/// truncates and rewrites it with fresh proxy credentials.
#[cfg(unix)]
#[tokio::test]
async fn meow_config_permissions_are_reasserted_on_an_existing_file() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, pool) = temp_pool().await;

    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"message":"invalid credential"})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // A `ready` row: a T2 candidate the T1 sample never draws, so
    // the T2 batch really runs and rewrites the config file.
    seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;

    // Pre-create the config file world-readable, as an operator
    // copying a sample config into the shared volume would.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    std::fs::write(&config_path, "proxies: []\n").unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let ctx = Arc::new(
        Context::new(test_config(3, &meow_addr, config_path.clone()), pool).expect("test context"),
    );
    run_cycle(ctx).await.unwrap();

    let mode = std::fs::metadata(&config_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o640,
        "pre-existing permissions must be corrected on every write"
    );
}

/// The heartbeat payload is a cross-process contract: the admin panel
/// thresholds daemon staleness (beat) and meow-contact staleness
/// (cycle) against the reported periods, so both fields must survive
/// every payload change.
#[test]
fn heartbeat_payload_reports_the_effective_beat_and_cycle_periods() {
    let payload: serde_json::Value = serde_json::from_str(&heartbeat_payload(30, 60)).unwrap();
    assert_eq!(payload["interval_secs"], 30);
    assert_eq!(payload["cycle_interval_secs"], 60);
    assert!(payload["ts"].as_i64().is_some());
    assert!(payload["pid"].as_u64().is_some());
    assert!(payload["version"].as_str().is_some());
    // The same payload parses back through the shared contract with
    // the reported periods intact.
    let hb: probe_repo::meta::Heartbeat = serde_json::from_str(&heartbeat_payload(30, 60)).unwrap();
    assert_eq!(hb.interval_secs, Some(30));
    assert_eq!(hb.cycle_interval_secs, Some(60));
    assert_eq!(hb.pid, std::process::id());
    assert_eq!(hb.version, env!("CARGO_PKG_VERSION"));
}

/// Strict T2 priority: a tunnel-dead proxy
/// that keeps passing T1 must still reach quarantine, a T1 success
/// must not wipe the fail counter accumulated by T2. The lanes are
/// driven directly so a T1 verdict lands on top of a standing T2
/// failure; the cycle's own hand-off keeps the two lanes off the same
/// proxy (see `t1_sample_and_t2_batch_do_not_double_charge_a_cycle`).
#[tokio::test]
async fn t1_success_cannot_rescue_proxies_failing_t2() {
    let (_dir, pool) = temp_pool().await;

    // meow-rs mock: EVERY delay check fails with a credential error.
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"message":"invalid credential"})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // The proxy passes T1 (open port, a live listener) but fails T2
    // every time.
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match tcp.accept().await {
                Ok(ok) => ok,
                Err(_) => break,
            };
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = socket.shutdown().await;
            });
        }
    });
    let bad = seed_proxy(&pool, "vless", "127.0.0.1", tcp_port, "alive").await;

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let config = test_config(2, &meow_addr, config_path.clone());
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    // T1 success with no failures on record (the counter resets), then
    // a T2 failure → 1.
    probe_t1_sample(ctx.clone(), &[], test_cycle(&ctx.config))
        .await
        .unwrap();
    probe_t2_batch(ctx.clone(), &[], test_cycle(&ctx.config))
        .await
        .unwrap();
    let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
    assert_eq!(row.status, "alive");
    assert_eq!(row.fail_count, 1);

    // A T1 success on top of the standing T2 failure must NOT touch
    // the counter: the reset decision reads the last failed kind,
    // which is `t2`.
    let vetted = vet_target_addrs(&ctx, "127.0.0.1").await.unwrap();
    // The seeded proxy carries no parameters, so the shared predicate
    // reads it as a plain-TCP node.
    let entry = fumox_core::models::ProxyEntry {
        scheme: Scheme::Vless,
        name: "n".to_string(),
        host: "127.0.0.1".to_string(),
        port: tcp_port,
        credential: "c".to_string(),
        params: Vec::new(),
        raw_path: String::new(),
        raw_line: String::new(),
    };
    let target = t1::Target {
        host: "127.0.0.1",
        server_name: None,
        port: tcp_port,
        kind: t1::check_kind(Scheme::Vless, &entry),
        vetted: &vetted,
    };
    perform_t1_check(&ctx, bad, &target).await;
    let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
    assert_eq!(
        row.fail_count, 1,
        "a T1 success must not reset the T2 fail counter"
    );

    // The next T2 failure reaches the limit → quarantine.
    probe_t2_batch(ctx.clone(), &[], test_cycle(&ctx.config))
        .await
        .unwrap();
    let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
    assert_eq!(row.fail_count, 2);
    assert!(row.ladder_at.is_some());

    // Quarantined rows are sampled by nothing (T1 takes unknown/alive,
    // T2 takes alive; the second chance is ~24h out): further cycles
    // leave the proxy alone, no T1 success can revive it.
    run_cycle(ctx).await.unwrap();
    let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
}

#[tokio::test]
async fn quarantine_due_check_runs_after_second_chance_and_removes_after_ladder() {
    let (_dir, pool) = temp_pool().await;

    // Dead port: every recheck will fail.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);
    let id = seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "quarantine").await;

    // Second chance already due (in the past).
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 0 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config = test_config(2, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    // Each cycle advances one ladder step; the due moment is always in
    // the past, so consecutive cycles walk the whole ladder.
    run_cycle(ctx.clone()).await.unwrap();
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "quarantine");
    assert_eq!(row.ladder_step, 1);
    assert!(row.ladder_at.is_some());
    sqlx::query("UPDATE proxies SET ladder_at = 300 WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    run_cycle(ctx.clone()).await.unwrap();
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.ladder_step, 2);
    sqlx::query("UPDATE proxies SET ladder_at = 400 WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    run_cycle(ctx.clone()).await.unwrap();
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.ladder_step, 3);
    sqlx::query("UPDATE proxies SET ladder_at = 500 WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();

    run_cycle(ctx).await.unwrap();
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "removed");
    assert!(row.removed_at.is_some());
}

/// A quarantined hysteria2 row is revived by the T2 tunnel check, not a T1
/// connect (a TCP connect to a QUIC port proves nothing): the row comes back
/// in the `ready` tier with a clean slate, and no tcp attempt is journaled.
#[tokio::test]
async fn quarantined_hysteria2_is_revived_by_a_tunnel_check() {
    let (_dir, pool) = temp_pool().await;

    // Mock meow-rs: the revival tunnel check measures a real delay.
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::OK,
                    Json(serde_json::json!({"delay": 42})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let id = seed_proxy(&pool, "hysteria2", "127.0.0.1", 443, "quarantine").await;
    // Second chance already due, mid-ladder to prove the slate clears.
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 1 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config_path = config_dir.path().join("probe-test.yaml");
    let config = test_config(3, &meow_addr, config_path.clone());
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.status, "ready",
        "the tunnel check is the revival probe for a QUIC scheme"
    );
    assert_eq!(row.fail_count, 0);
    assert_eq!(row.ladder_at, None, "the quarantine schedule must clear");
    assert_eq!(row.ladder_step, 0);
    assert_eq!(row.latency_ms, Some(42));

    // The revival was a T2 verdict; the TCP connect never ran. (The same cycle's
    // T2 batch may re-verify the row, so more than one ok t2 record is fine.)
    let (tcp_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND probe_kind = 'tcp'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        tcp_rows, 0,
        "a QUIC scheme must never get a T1 revival check"
    );
    let (ok_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND probe_kind = 't2' AND ok = 1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(ok_rows >= 1, "the revival tunnel check must be journaled");

    // The quarantined row reached the engine config by name.
    let yaml = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        yaml.contains(&clash::proxy_name(id)),
        "the revival batch must carry the row into the meow config: {yaml}"
    );
}

/// The revival check must not weaken the ladder: a tunnel the engine
/// authoritatively fails is a failed recheck, the row walks the same
/// configured steps and is removed after the last one.
#[tokio::test]
async fn quarantined_hysteria2_tunnel_failure_walks_the_ladder_to_removal() {
    let (_dir, pool) = temp_pool().await;

    // Mock meow-rs: the engine tried, the tunnel is dead (its own
    // probe-result code, a verdict and not an outage).
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"message":"dial: connection refused"})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let id = seed_proxy(&pool, "hysteria2", "127.0.0.1", 443, "quarantine").await;
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 0 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config = test_config(3, &meow_addr, config_dir.path().join("probe-test.yaml"));
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    // Each due cycle advances one ladder step (the due moment is poked back
    // between cycles, the same walk the T1 quarantine test above runs).
    for (due_at, expected_step) in [(200, 1), (300, 2), (400, 3)] {
        sqlx::query("UPDATE proxies SET ladder_at = ? WHERE id = ?")
            .bind(due_at)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        run_cycle(ctx.clone()).await.unwrap();
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "quarantine");
        assert_eq!(row.ladder_step, expected_step);
        assert!(row.ladder_at.is_some());
    }

    sqlx::query("UPDATE proxies SET ladder_at = 500 WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    run_cycle(ctx).await.unwrap();
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "removed", "the final failed recheck removes");
    assert!(row.removed_at.is_some());

    // The verdicts were the engine's own, journaled as t2 failures.
    let (error,): (String,) = sqlx::query_as(
        "SELECT COALESCE(error, '') FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2' AND ok = 0
             ORDER BY id DESC LIMIT 1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(error.contains("dial: connection refused"), "{error}");
}

/// A meow-rs outage must not charge a quarantined row's ladder: the attempt
/// is journaled unverified, the row keeps its schedule and is retried on
/// the next cycle, where a recovered engine revives it.
#[tokio::test]
async fn quarantined_hysteria2_is_not_charged_for_a_meow_outage() {
    let (_dir, pool) = temp_pool().await;

    let id = seed_proxy(&pool, "hysteria2", "127.0.0.1", 443, "quarantine").await;
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 1 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    // Cycle 1: meow-rs unreachable on a closed port.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));
    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.status, "quarantine",
        "an engine outage must not retire a quarantined proxy"
    );
    assert_eq!(row.ladder_step, 1, "the outage is not a failed recheck");
    assert_eq!(
        row.ladder_at,
        Some(200),
        "the row stays due for the next cycle"
    );
    let (rows, error): (i64, String) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(MAX(error), '') FROM probe_results
             WHERE proxy_id = ? AND probe_kind = 't2_unverified' AND ok = 0",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 1, "the skipped revival must be journaled");
    assert!(error.contains("meow-rs unavailable"), "{error}");

    // Cycle 2: the engine is back (healthy mock), the still-due row is
    // retried and revived.
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::OK,
                    Json(serde_json::json!({"delay": 17})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config = test_config(3, &meow_addr, config_dir.path().join("probe-test.yaml"));
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));
    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "ready", "the retried revival must succeed");
}

/// The two T1 lanes of one cycle must not both charge the same proxy.
/// They overlap completely (the priority queue and the random sample
/// draw from the same `unknown` population and claiming a request only
/// deletes the queue row), so a dead proxy in both lanes collected two
/// `fail_count` steps from a single cycle and quarantined twice as
/// fast as `fail_limit` says.
#[tokio::test]
async fn queued_and_random_t1_lanes_do_not_double_charge_a_cycle() {
    let (_dir, pool) = temp_pool().await;

    // Dead port: every T1 check of the cycle fails.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    // A pool smaller than twice `sample_size` (50), so the random
    // sample necessarily overlaps the enqueued half.
    let mut ids = Vec::new();
    for _ in 0..20 {
        ids.push(seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "unknown").await);
    }
    let queued = probe_repo::enqueue_checks(&pool, &ids[..10], 50, now_ts())
        .await
        .unwrap();
    assert_eq!(queued, 10, "the priority queue must be seeded");

    // A fail limit the double charge would not reach in one cycle, so
    // the assertion below is about the counter, not about quarantine.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config = test_config(5, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    for id in &ids {
        let row = proxies::get_by_id(&pool, *id).await.unwrap().unwrap();
        assert_eq!(
            row.fail_count, 1,
            "id {id}: one cycle may charge one failure, whatever lane ran it"
        );
        let (attempts,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND ok = 0 AND probe_kind = 'tcp'",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(attempts, 1, "id {id}: the T1 verdict must be recorded once");
    }
}

/// The T1 sample and the T2 batch of one cycle must not both charge
/// the same proxy. They overlap on the `alive` population, so a dead
/// proxy drawn by both lanes collected one `fail_count` step from each
/// in a single cycle and quarantined in half the cycles `fail_limit`
/// promises (the same defect the queue-vs-sample hand-off fixed).
#[tokio::test]
async fn t1_sample_and_t2_batch_do_not_double_charge_a_cycle() {
    let (_dir, pool) = temp_pool().await;

    // Mock meow-rs: the engine is alive but every delay check fails,
    // so a T2 verdict is a charged failure: exactly the second charge
    // the hand-off must prevent.
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route("/configs", put(|| async { Json(serde_json::json!({})) }))
        .route(
            "/proxies/{name}/delay",
            get(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"message":"invalid credential"})),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let meow_addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // A dead port: the T1 dial fails too. The proxy is `alive`, so it
    // is eligible for both lanes of the same cycle.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    let id = seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "alive").await;

    // fail_limit = 2: without the hand-off the two charges quarantine
    // the proxy within this single cycle.
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config = test_config(2, &meow_addr, config_dir.path().join("probe-test.yaml"));
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.status, "alive",
        "one cycle may charge one failure, whatever lane ran it"
    );
    assert_eq!(row.fail_count, 1);
    // The T2 batch skipped the row the T1 sample just judged, and the
    // T1 sample produced the cycle's one verdict.
    let (t2_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND probe_kind = 't2'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        t2_rows, 0,
        "the T2 batch must skip the row the T1 sample just judged"
    );
    let (tcp_rows,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM probe_results WHERE proxy_id = ? AND probe_kind = 'tcp'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(tcp_rows, 1);
}

/// The refusal counters must stay apart from the engine-fault counters.
/// A private-address refusal is a failed check (the fail ladder runs and
/// the row is charged); an engine fault is not a verdict at all. Folding
/// the two together made a batch of refusals against a dead engine read
/// like a batch of engine faults, and the other way round.
#[tokio::test]
async fn a_refused_target_is_counted_as_a_refusal_not_an_engine_fault() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "127.0.0.1", 1, "alive").await;

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    let cycle = test_cycle(&ctx.config);
    let outcome = probe_t2_batch(ctx, &[], cycle).await.unwrap();
    assert_eq!(outcome.blocked, 1, "the refused row is a refusal");
    assert_eq!(outcome.engine_faults, 0, "a refusal is not an engine fault");
    assert_eq!(outcome.aborted, 0);
    assert_eq!(outcome.skipped, 0);
    assert_eq!(
        outcome.checked, 1,
        "a refusal is a verdict, so it is checked"
    );

    // The refusal is charged: it is a failed check, not a skipped one.
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.fail_count, 1);
}

/// The engine resolves `meow.config_path` in its own filesystem, so a
/// relative path is meaningless to it: the probe would write the file
/// happily and every batch would fail on the engine side with a
/// "file not found". The path is vetted at startup instead, and the
/// directory it names is created there so an unwritable location is a
/// startup message and not a per-cycle write error.
#[test]
fn a_relative_meow_config_path_is_refused_at_startup() {
    let error = validate_meow_config_path(std::path::Path::new("relative/meow.yaml"))
        .expect_err("a relative path must be refused");
    assert!(error.to_string().contains("not absolute"), "{error}");

    let dir = fumox_core::tempdir_lite::TempDir::new("probe-config-path");
    let path = dir.path().join("nested").join("meow.yaml");
    validate_meow_config_path(&path).expect("an absolute path must be accepted");
    assert!(
        path.parent().unwrap().is_dir(),
        "the parent directory must be created"
    );
}

/// The names of the entries of a directory, sorted.
fn directory_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The cycle has a wall-clock budget: a lane that starts after the
/// budget is spent issues no check, it defers the row to the next cycle.
/// A deferred row is not a verdict: it is not charged and not journaled.
#[tokio::test]
async fn a_spent_budget_defers_the_rows_of_the_lane() {
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "127.0.0.1", 443, "alive").await;

    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = true;
    // A one-second period: the budget is three quarters of it, rounded up
    // to a second.
    config.probe.cycle_interval_secs = 1;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    let cycle = test_cycle(&ctx.config);
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    assert!(cycle.budget.expired(), "the budget must be spent");

    let outcome = probe_t1_sample(ctx.clone(), &[], cycle.clone())
        .await
        .unwrap();
    assert_eq!(outcome.checked, 0, "a spent budget starts no check");
    assert_eq!(outcome.deferred, 1, "the row waits for the next cycle");
    assert!(
        outcome.claimed.is_empty(),
        "a deferred row is not a verdict of this cycle"
    );

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.fail_count, 0, "a deferred row is not charged");
    let (results,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM probe_results WHERE proxy_id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(results, 0, "a deferred row is not journaled");
}

/// A lane that fails is logged and skipped, the other lanes of the cycle
/// still run. A broken lane used to cancel the whole cycle, so a single
/// failing write left the fleet unprobed until the next cycle.
#[tokio::test]
async fn a_failing_lane_does_not_cancel_the_cycle() {
    // The lane in isolation: an error becomes the default counters.
    let failed = run_lane::<LaneCounts>("boom", async { anyhow::bail!("the lane exploded") }).await;
    assert_eq!(failed.checked, 0);
    assert_eq!(failed.deferred, 0);

    // The next lane still runs.
    let after = run_lane::<LaneCounts>("after", async {
        Ok(LaneCounts {
            checked: 3,
            blocked: 1,
            engine_faults: 0,
            deferred: 2,
        })
    })
    .await;
    assert_eq!(after.checked, 3);
    assert_eq!(after.blocked, 1);
    assert_eq!(after.deferred, 2);

    // End to end: a cycle whose lanes fail still completes.
    let (_dir, pool) = temp_pool().await;
    seed_proxy(&pool, "vless", "127.0.0.1", 443, "alive").await;
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    // The database is gone: every lane that touches it fails, and the
    // cycle still finishes.
    pool.close().await;
    run_cycle(ctx).await.unwrap();
}

/// The config the probe hands to the engine is written into a temporary
/// file in the target directory and renamed onto the target: the engine
/// reads either the old or the new config, never a half-written one, and
/// the temporary file never stays behind.
#[tokio::test]
async fn the_meow_config_is_renamed_into_place_inside_its_directory() {
    let dir = fumox_core::tempdir_lite::TempDir::new("probe-config");
    let path = dir.path().join("meow.yaml");

    write_meow_config(&path, "proxies: {}\n").unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "proxies: {}\n",
        "the config must be readable at its target"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640, "the credentials stay off other users");
    }
    assert_eq!(
        directory_names(dir.path()),
        vec!["meow.yaml".to_string()],
        "the temporary file must not stay behind"
    );

    // A second write replaces the content of the target.
    write_meow_config(&path, "proxies: {}\nsecond: true\n").unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("second: true")
    );
    assert_eq!(
        directory_names(dir.path()),
        vec!["meow.yaml".to_string()],
        "the temporary file of the second write must not stay behind"
    );
}

/// A symlink planted at the target path is replaced, not written through:
/// the config never lands in a file somebody else chose.
#[cfg(unix)]
#[tokio::test]
async fn the_meow_config_write_does_not_follow_a_planted_symlink() {
    let dir = fumox_core::tempdir_lite::TempDir::new("probe-config-link");
    let victim = dir.path().join("victim.yaml");
    std::fs::write(&victim, "original\n").unwrap();
    let path = dir.path().join("meow.yaml");
    std::os::unix::fs::symlink(&victim, &path).unwrap();

    write_meow_config(&path, "replacement\n").unwrap();

    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "original\n",
        "the write must not follow the symlink"
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "replacement\n",
        "the target must carry the new config"
    );
}

/// A host is resolved once per cycle: the rows of a feed often share
/// their host, and the T2 batch of a cycle reuses what the T1 lanes of
/// the same cycle already vetted.
#[tokio::test]
async fn the_hosts_of_a_cycle_are_resolved_once() {
    let (_dir, pool) = temp_pool().await;
    let config_dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let mut config = test_config(3, "127.0.0.1:1", config_dir.path().join("probe-test.yaml"));
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(Context::new(config, pool.clone()).expect("test context"));

    let cycle = test_cycle(&ctx.config);
    // Two rows on the same host.
    let hosts = vec!["127.0.0.1".to_string(), "127.0.0.1".to_string()];
    let verdicts = vet_hosts(&ctx, &hosts, &cycle.vetted).await;
    assert_eq!(verdicts.len(), 2);
    assert!(
        verdicts[0].is_ok() && verdicts[1].is_ok(),
        "the loopback host is allowed by the test config"
    );
    assert_eq!(
        verdicts[0], verdicts[1],
        "the rows of a host share one verdict"
    );

    let cached = cycle
        .vetted
        .get("127.0.0.1")
        .expect("the verdict must be cached for the rest of the cycle");
    // The next phase of the cycle asks for the same host and gets the
    // cached verdict: the cache still holds the very same one, so no
    // second resolution happened.
    let again = vet_hosts(&ctx, &hosts, &cycle.vetted).await;
    assert_eq!(again.len(), 2);
    let after = cycle
        .vetted
        .get("127.0.0.1")
        .expect("the verdict must stay cached");
    assert!(
        Arc::ptr_eq(&cached, &after),
        "the second phase of the cycle must reuse the cached verdict"
    );
}
