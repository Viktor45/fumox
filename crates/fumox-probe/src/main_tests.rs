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
    let (_dir, mut config) = test_config_with_dir(1, "127.0.0.1:1");
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    // The listener saw no connection.
    assert_eq!(hit.load(std::sync::atomic::Ordering::Relaxed), 0);
    // The refusal is journaled as a failed check...
    assert_eq!(
        count_probe_results(&pool, id, Some("tcp"), Some(false)).await,
        1,
        "the vet refusal must be journaled"
    );
    let error = last_probe_error(&pool, id, Some("tcp")).await;
    assert!(
        error.contains("blocked by the private-address policy"),
        "{error}"
    );
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
    let (_dir, mut config) = test_config_with_dir(3, "127.0.0.1:1");
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(
        Context::new(config.clone(), pool.clone())
            .await
            .expect("test context"),
    );
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
    let ctx = Arc::new(Context::new(config, pool).await.expect("test context"));
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
    let (_dir, mut config) = test_config_with_dir(3, "127.0.0.1:1");
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    // The failed t2 row exists, exactly what keeps the recency
    // selector moving past blocked rows.
    assert_eq!(
        count_probe_results(&pool, id, Some("t2"), Some(false)).await,
        1,
        "the T2 refusal must be journaled as t2"
    );
    let error = last_probe_error(&pool, id, Some("t2")).await;
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
    assert_eq!(
        count_probe_results(&pool, id, Some("tcp"), None).await,
        0,
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
    let meow_addr = spawn_mock(app).await;

    // Two due proxies, `ready` so the T1 sample never draws them and
    // the reload outage is the only thing that touches them.
    let a = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let b = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "ready").await;
    let (_dir, mut config) = test_config_with_dir(3, &meow_addr);
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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
    let (_dir, mut config) = test_config_with_dir(2, "127.0.0.1:1");
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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
        let tcp_verdicts = count_probe_results(&pool, alive, Some("tcp"), Some(true)).await;
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
/// the fan-out began), but every delay request now fails. Each outcome
/// survives the per-request retry, so it is a confirmed
/// engine-unavailable event: the third one crosses the threshold, the
/// tasks behind the flag journal an aborted-failure record without
/// further meow calls, and the one batch-level liveness ping at the end
/// classifies the collected outcomes as an outage.
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
    let meow_addr = spawn_mock(app).await;

    // One proxy more than the abort threshold, `ready` so the T1 sample
    // never draws them and the mid-batch outage is the only thing that
    // touches them: the tasks up to `MEOW_ABORT_THRESHOLD` record a
    // failure (engine_alive = false) and the last of them flips the
    // abort flag. The task behind it, whichever side of the
    // is_aborted() check it lands on, gets either a "mid-batch" record
    // or an "aborted:" record, both are engine-outage texts.
    //
    // One check at a time, so the order is deterministic: the last task
    // starts after the flag was flipped.
    let mut ids = Vec::new();
    for i in 0..MEOW_ABORT_THRESHOLD + 1 {
        // The ss spelling carries its cipher with the password: the shape
        // the parsers produce and the T2 validator expects.
        let (scheme, credential) = [
            ("vless", "uuid"),
            ("trojan", "pw"),
            ("vmess", "uuid"),
            ("ss", "aes-256-gcm:pw"),
        ][i % 4];
        ids.push(seed_proxy_credential(&pool, scheme, "127.0.0.1", 443, "ready", credential).await);
    }
    let (_dir, mut config) = test_config_with_dir(3, &meow_addr);
    config.probe.allow_private_targets = true;
    config.probe.concurrency = 1;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    // Every proxy of the batch carries a journaled t2 failure:
    // either the mid-batch reason (the task that crossed the
    // threshold) or the aborted marker (a task that arrived after
    // the flag was set). Both are engine-outage texts.
    let mut aborted = 0;
    let mut mid_batch = 0;
    for id in ids {
        let error = last_probe_error(&pool, id, Some("t2_unverified")).await;
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
    // With concurrency 1 the split is deterministic: the tasks up to
    // the threshold reached the engine and tripped it, the one behind
    // the flag never did. The count is not tied to the numeric value of
    // the threshold: the fixture draws `threshold + 1` proxies.
    assert_eq!(mid_batch, MEOW_ABORT_THRESHOLD);
    assert_eq!(
        aborted, 1,
        "the task behind the flag never reached the engine"
    );

    // L-088: the aborted task must not have reached the engine. The
    // tasks that crossed the threshold each asked for a delay twice
    // (the retry absorbs a transient failure), and the aborted task
    // adds none.
    assert_eq!(
        delay_calls.load(Ordering::SeqCst),
        mid_batch * 2,
        "the aborted task must not send a delay request"
    );
    // The /version pings: one pre-flight ping before the fan-out and the
    // ONE batch-level liveness ping that classifies the collected
    // `ServiceUnavailable` outcomes. No per-task probes.
    assert_eq!(
        version_calls.load(Ordering::SeqCst),
        2,
        "the /version budget is one pre-flight ping plus the one batch-level ping"
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
    let (_dir, mut config) = test_config_with_dir(3, "127.0.0.1:1");
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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
    let meow_addr = spawn_mock(app).await;

    seed_proxy(&pool, "vless", "127.0.0.1", 443, "alive").await;
    seed_proxy(&pool, "trojan", "127.0.0.1", 443, "alive").await;

    let (_dir, mut config) = test_config_with_dir(3, &meow_addr);
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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

    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"proxy not found"})),
        )
    })
    .await;

    // `ready` rows: T2 candidates the T1 sample never draws, so the
    // batch of two really runs through the engine. Two is below the
    // blip threshold (three), so the run never escalates.
    let a = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let b = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "ready").await;
    let (_dir, mut config) = test_config_with_dir(3, &meow_addr);
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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
        let error = last_probe_error(&pool, id, Some("t2_unverified")).await;
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
    assert_eq!(
        ctx.meow_retry_at.load(Ordering::Relaxed),
        0,
        "no backoff engaged when the engine is alive and only delay checks fail"
    );
}

/// A *run* of blips is a broken test path, not a run of unlucky
/// requests: the engine answers `/version` but cannot run the delay
/// test, and a batch that collected a threshold number of confirmed
/// engine-unavailable outcomes is treated as an engine fault at its end —
/// the backoff is armed and no proxy is charged. (Concurrency 1 makes
/// the split deterministic: the fourth task arrives after the abort
/// flag went up.)
#[tokio::test]
async fn a_run_of_blips_escalates_to_an_engine_fault() {
    let (_dir, pool) = temp_pool().await;

    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"proxy not found"})),
        )
    })
    .await;

    // Four blipping proxies: the third confirmed outage crosses the
    // abort threshold, the fourth is kept off the engine. (The ss row
    // carries its cipher: the shape the T2 validator expects.)
    let mut ids = Vec::new();
    for (scheme, credential) in [
        ("vless", "uuid"),
        ("trojan", "pw"),
        ("vmess", "uuid"),
        ("ss", "aes-256-gcm:pw"),
    ] {
        ids.push(seed_proxy_credential(&pool, scheme, "127.0.0.1", 443, "ready", credential).await);
    }
    let (_dir, mut config) = test_config_with_dir(3, &meow_addr);
    config.probe.allow_private_targets = true;
    config.probe.concurrency = 1;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    // The three checks really ran against the live engine: a check that
    // ran and did not succeed is *checked*, not aborted. The run of
    // blips backs the engine off, it does not undo the checks that
    // already happened.
    let cycle = test_cycle(&ctx.config);
    let outcome = probe_t2_batch(ctx.clone(), &[], cycle).await.unwrap();
    assert_eq!(outcome.checked, 3, "three checks really ran");
    assert_eq!(
        outcome.aborted, 1,
        "the fourth task arrived after the abort flag went up"
    );

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
                || error.contains("aborted: meow-rs became unavailable mid-batch"),
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

    // One flaky proxy; the second proxy is there to confirm the
    // batch keeps running and reports a clean Ok. Both are `ready`:
    // T2 candidates the T1 sample never draws. Seeded before the mock,
    // so the handler can fail only the flaky name.
    let flaky = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let stable = seed_proxy(&pool, "trojan", "127.0.0.1", 443, "ready").await;

    // Delay handler: the flaky proxy's first call returns 500, its
    // second call and every call for the stable proxy return 200.
    let flaky_name = clash::proxy_name(flaky);
    let stable_name = clash::proxy_name(stable);
    let handler_flaky_name = flaky_name.clone();
    let delay_calls: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let delay_calls_inner = delay_calls.clone();
    let meow_addr = spawn_mock_meow(move |Path(name): Path<String>| {
        let delay_calls = delay_calls_inner.clone();
        let flaky_name = handler_flaky_name.clone();
        async move {
            let attempt = {
                let mut guard = delay_calls.lock().unwrap();
                let n = guard.entry(name.clone()).or_insert(0);
                *n += 1;
                *n
            };
            if name == flaky_name && attempt == 1 {
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
    })
    .await;

    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    // The flaky proxy survived: the retry absorbed the first 5xx and
    // the second attempt returned Ok. The row becomes `ready`. (The
    // same cycle's T2 batch may re-verify the row, so more than one ok
    // t2 record is fine — the same invariant the revival test checks.)
    let row = proxies::get_by_id(&pool, flaky).await.unwrap().unwrap();
    assert_eq!(
        row.status, "ready",
        "retry should have rescued the flaky proxy from a transient blip"
    );
    let ok_count = count_probe_results(&pool, flaky, Some("t2"), Some(true)).await;
    assert!(ok_count >= 1, "the flaky proxy must have a successful T2");

    // The engine saw the flaky proxy twice (the retry) and the stable
    // proxy exactly once, answered 200 on its first call.
    let calls = delay_calls.lock().unwrap().clone();
    assert_eq!(calls.get(&flaky_name), Some(&2));
    assert_eq!(
        calls.get(&stable_name),
        Some(&1),
        "the stable proxy never sees a 5xx"
    );

    // The stable proxy was not touched by the abort counter at all: no
    // failed record of any kind exists for it.
    let row = proxies::get_by_id(&pool, stable).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");
    let failed = count_probe_results(&pool, stable, None, Some(false)).await;
    assert_eq!(
        failed, 0,
        "the stable proxy collected no failed probe_results"
    );
}

/// A vet-refused T2 target loses the ready tier as well: the check it
/// was due could not run, and (as everywhere) the refusal is a failed
/// check on the ladder. (The meow-outage counterpart of this test is
/// covered by `meow_outage_never_quarantines_a_healthy_proxy`, whose
/// `ready` row asserts the same demotion, and by
/// `t2_engine_failure_at_reload_fails_the_batch`, which owns the
/// "meow-rs unavailable" error text.)
#[tokio::test]
async fn ready_is_demoted_by_vet_block() {
    let (_dir, pool) = temp_pool().await;

    let id = seed_proxy(&pool, "vless", "127.0.0.1", 1, "ready").await;

    let (_dir, mut config) = test_config_with_dir(3, "127.0.0.1:1");
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.status, "alive",
        "the vet refusal demotes the ready tier"
    );
    let error = last_probe_error(&pool, id, Some("t2")).await;
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
    seed_proxy_credential(pool, scheme, host, port, status, "c").await
}

/// Seed a linked proxy row with an explicit credential (the malformed
/// entries the T2 validator drops carry an empty one); returns its id.
async fn seed_proxy_credential(
    pool: &DbPool,
    scheme: &str,
    host: &str,
    port: u16,
    status: &str,
    credential: &str,
) -> i64 {
    sqlx::query(
            "INSERT OR IGNORE INTO sources (id, name, url, enabled, encoding, cache_ttl_seconds, created_at, updated_at)
             VALUES ('srcT0000000', 'probe-test', 'https://example.com', 1, 'auto', 3600, 1, 1)",
        )
        .execute(pool)
        .await
        .unwrap();
    let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO proxies (fingerprint, scheme, name, host, port, credential, status, created_at, updated_at)
             VALUES (?, ?, 'n', ?, ?, ?, ?, 1, 1)
             RETURNING id",
        )
        .bind(format!("fp-{}", fumox_core::models::new_id()))
        .bind(scheme)
        .bind(host)
        .bind(i64::from(port))
        .bind(credential)
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

/// The test config together with the directory its `meow.config_path`
/// lives in: keep the directory in scope for as long as the path is read
/// (`let (_dir, config) = test_config_with_dir(..)`).
fn test_config_with_dir(
    fail_limit: u32,
    meow_addr: &str,
) -> (fumox_core::tempdir_lite::TempDir, AppConfig) {
    let dir = fumox_core::tempdir_lite::TempDir::new("probe-test");
    let config = test_config(fail_limit, meow_addr, dir.path().join("probe-test.yaml"));
    (dir, config)
}

/// A probe entry with the given parameters, the shape the parser produces.
fn entry(
    scheme: Scheme,
    credential: &str,
    params: &[(&str, &str)],
) -> fumox_core::models::ProxyEntry {
    fumox_core::models::ProxyEntry {
        scheme,
        name: "n".into(),
        host: "h.example.com".into(),
        port: 443,
        credential: credential.into(),
        params: params
            .iter()
            .map(|(k, v)| fumox_core::models::Param {
                key: (*k).into(),
                value: (*v).into(),
                known: true,
                bare: false,
            })
            .collect(),
        raw_path: String::new(),
        raw_line: String::new(),
        canonical: None,
    }
}

/// The storage row of one T2 batch, from an entry: the same
/// recognized-params serialization the upsert stores.
fn row_from_entry(id: i64, entry: fumox_core::models::ProxyEntry) -> proxies::ProxyRow {
    let known = serde_json::to_string(&entry.known_params_json()).unwrap();
    proxies::ProxyRow {
        id,
        fingerprint: format!("fp{id}"),
        scheme: entry.scheme.as_str().to_string(),
        name: entry.name.clone(),
        host: entry.host.clone(),
        port: i64::from(entry.port),
        credential: entry.credential.clone(),
        params: Some(known),
        unknown_params: None,
        raw_line: None,
        raw_path: None,
        last_t2_failed_at: None,
        geo_country: None,
        geo_city: None,
        geo_asn: None,
        geo_attempts: 0,
        last_geo_attempt_at: None,
        resolved_ip: None,
        status: "alive".into(),
        fail_count: 0,
        last_checked_at: None,
        last_alive_at: None,
        quarantined_at: None,
        ladder_at: None,
        ladder_step: 0,
        removed_at: None,
        latency_ms: None,
        speed_mbps: None,
        created_at: 1,
        updated_at: 1,
    }
}

/// A mixed T2 batch: a supported row, a scheme the mapping cannot express
/// and a row whose stored parameters do not parse. The config carries
/// exactly the supported proxy and `included` names only it, so the two
/// skipped rows are journaled by the caller instead of reaching an engine
/// that would report a misleading "proxy not found".
#[test]
fn mixed_batch_writes_exactly_the_supported_proxy() {
    let rows = vec![
        row_from_entry(1, entry(Scheme::Vless, "uuid-1", &[("security", "tls")])),
        row_from_entry(2, entry(Scheme::Tuic, "c", &[])),
        // Broken JSON in the recognized-params column: the row has no
        // entry at all.
        proxies::ProxyRow {
            params: Some("{not json".to_string()),
            ..row_from_entry(3, entry(Scheme::Ss, "aes-256-gcm:pw", &[]))
        },
    ];

    let records = engine_records(&rows, &std::collections::HashMap::new());
    let (yaml, included) = clash::generate(&records, false).unwrap();
    let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
    let proxies = parsed["proxies"].as_sequence().unwrap();
    assert_eq!(proxies.len(), 1, "{yaml}");
    assert_eq!(proxies[0]["name"].as_str(), Some("fumox-1"));
    assert_eq!(
        included,
        vec![1],
        "a skipped row must not be reported as included"
    );
}

/// Number of `probe_results` rows of one proxy, by kind (`None` = any
/// kind) and verdict (`None` = either).
async fn count_probe_results(
    pool: &DbPool,
    proxy_id: i64,
    kind: Option<&str>,
    ok: Option<bool>,
) -> i64 {
    let mut sql = sqlx::QueryBuilder::new("SELECT COUNT(*) FROM probe_results WHERE proxy_id = ");
    sql.push_bind(proxy_id);
    if let Some(kind) = kind {
        sql.push(" AND probe_kind = ").push_bind(kind);
    }
    if let Some(ok) = ok {
        sql.push(" AND ok = ").push_bind(ok);
    }
    sql.build_query_as::<(i64,)>()
        .fetch_one(pool)
        .await
        .unwrap()
        .0
}

/// The error text of the newest failed `probe_results` row of one proxy,
/// by kind (`None` = any kind).
async fn last_probe_error(pool: &DbPool, proxy_id: i64, kind: Option<&str>) -> String {
    let mut sql =
        sqlx::QueryBuilder::new("SELECT COALESCE(error, '') FROM probe_results WHERE proxy_id = ");
    sql.push_bind(proxy_id).push(" AND ok = 0");
    if let Some(kind) = kind {
        sql.push(" AND probe_kind = ").push_bind(kind);
    }
    sql.push(" ORDER BY id DESC LIMIT 1");
    sql.build_query_as::<(String,)>()
        .fetch_one(pool)
        .await
        .unwrap()
        .0
}

/// A loopback port nothing listens on: bound, dropped, then verified
/// closed with a trial connect. A port another test grabbed between the
/// drop and the probe would silently turn a "dead" fixture into a live
/// one, so the port is re-drawn until the connect is refused.
async fn closed_loopback_port() -> u16 {
    for _ in 0..10 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            // Refused, as a closed port must be.
            Err(_) => return port,
            // Somebody took the port back: draw another one.
            Ok(stream) => drop(stream),
        }
    }
    panic!("no closed loopback port in 10 draws");
}

/// Bind and serve a mock app on an ephemeral loopback port; the address
/// string is the `meow.api_addr` of the test config.
async fn spawn_mock(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A mock meow-rs with the healthy `/version` and `/configs` routes and
/// the caller's delay handler; returns the `meow.api_addr` string. Tests
/// with a non-default `/version` or `/configs` build their own `Router`
/// and hand it to [`spawn_mock`].
async fn spawn_mock_meow<H, T>(delay: H) -> String
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    spawn_mock(
        Router::new()
            .route(
                "/version",
                get(|| async { Json(serde_json::json!({"version":"mock"})) }),
            )
            .route("/configs", put(|| async { Json(serde_json::json!({})) }))
            .route("/proxies/{name}/delay", get(delay)),
    )
    .await
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
    let dead_port = closed_loopback_port().await;

    let live = seed_proxy(&pool, "vless", "127.0.0.1", live_port, "unknown").await;
    let dying = seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "unknown").await;

    // meow-rs is absent, but the hand-off of `run_cycle` keeps both
    // rows out of its reach anyway: the dead one is `unknown` (never a
    // T2 candidate) and the live one's promotion cycle is covered by
    // the T1 sample first, so no T2 verdict ever arrives in this test.
    let (_dir, config) = test_config_with_dir(2, "127.0.0.1:1");
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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
    assert_eq!(
        count_probe_results(&pool, live, Some("t2"), None).await,
        0,
        "no T2 attempt in the promotion cycle"
    );
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
    let ok_count = count_probe_results(&pool, live, None, Some(true)).await;
    assert_eq!(ok_count, 2);
    let fail_count = count_probe_results(&pool, dying, None, Some(false)).await;
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

    // Both proxies are `ready`: T2 candidates the T1 sample never
    // draws, so only T2 differentiates them. Seeded before the mock:
    // the handler tells them apart by their config names, never by
    // their row ids.
    let good = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let bad = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;

    // Mock meow-rs: the good proxy tunnels fine, the bad one fails
    // with a credential-style error.
    let good_name = clash::proxy_name(good);
    let handler_good_name = good_name.clone();
    let meow_addr = spawn_mock_meow(move |Path(name): Path<String>| {
        let good_name = handler_good_name.clone();
        async move {
            if name == good_name {
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
        }
    })
    .await;

    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let config_path = config.meow.config_path.clone();
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    // The generated Clash config reached the disk with both proxies.
    let yaml = std::fs::read_to_string(&config_path).unwrap();
    assert!(yaml.contains(&clash::proxy_name(good)));
    assert!(yaml.contains(&clash::proxy_name(bad)));

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
    let error = last_probe_error(&pool, bad, Some("t2")).await;
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
    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"message":"An error occurred in the delay test"})),
        )
    })
    .await;

    let first = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let second = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;

    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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

    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"invalid credential"})),
        )
    })
    .await;

    // A `ready` row: a T2 candidate the T1 sample never draws, so
    // the T2 batch really runs and rewrites the config file.
    seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;

    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let config_path = config.meow.config_path.clone();
    // Pre-create the config file world-readable, as an operator
    // copying a sample config into the shared volume would.
    std::fs::write(&config_path, "proxies: []\n").unwrap();
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let ctx = Arc::new(Context::new(config, pool).await.expect("test context"));
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
    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"invalid credential"})),
        )
    })
    .await;

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

    let (_dir, config) = test_config_with_dir(2, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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
        canonical: None,
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
    let dead_port = closed_loopback_port().await;
    let id = seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "quarantine").await;

    // Second chance already due (in the past).
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 0 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let (_dir, config) = test_config_with_dir(2, "127.0.0.1:1");
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    // Each cycle advances one ladder step; the due moment is always in
    // the past, so consecutive cycles walk the whole ladder.
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

    // Past the last step, the final failed recheck removes the row.
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
    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"delay": 42})),
        )
    })
    .await;

    let id = seed_proxy(&pool, "hysteria2", "127.0.0.1", 443, "quarantine").await;
    // Second chance already due, mid-ladder to prove the slate clears.
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 1 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let config_path = config.meow.config_path.clone();
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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

    // The revival was a T2 verdict; the TCP connect never ran. The
    // revival lane hands its verdict ids to the T2 batch of the same
    // cycle, so the fresh revival is not re-verified within the cycle:
    // exactly one ok t2 record exists.
    assert_eq!(
        count_probe_results(&pool, id, Some("tcp"), None).await,
        0,
        "a QUIC scheme must never get a T1 revival check"
    );
    let ok_rows = count_probe_results(&pool, id, Some("t2"), Some(true)).await;
    assert_eq!(
        ok_rows, 1,
        "the revival tunnel check must be journaled exactly once"
    );

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
    // probe-result code, a verdict and not an outage). The verdict is a
    // 503 with a body that is not JSON — the classification must read it
    // as a proxy failure and charge the ladder, never as an
    // `t2_unverified` outage.
    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test",
        )
    })
    .await;

    let id = seed_proxy(&pool, "hysteria2", "127.0.0.1", 443, "quarantine").await;
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 0 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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

    // The verdicts were the engine's own, journaled as t2 failures —
    // with the status leading the text, so 503 stays distinguishable.
    assert_eq!(
        count_probe_results(&pool, id, Some("t2_unverified"), None).await,
        0,
        "a tunnel verdict must never be journaled unverified"
    );
    let error = last_probe_error(&pool, id, Some("t2")).await;
    assert!(error.starts_with("503"), "{error}");
    assert!(error.contains("delay test"), "{error}");
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
    let (_dir, config) = test_config_with_dir(3, "127.0.0.1:1");
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );
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
    assert_eq!(
        count_probe_results(&pool, id, Some("t2_unverified"), Some(false)).await,
        1,
        "the skipped revival must be journaled"
    );
    let error = last_probe_error(&pool, id, Some("t2_unverified")).await;
    assert!(error.contains("meow-rs unavailable"), "{error}");

    // Cycle 2: the engine is back (healthy mock), the still-due row is
    // retried and revived. The cycle-1 outage persisted its backoff into
    // `meta`, and this fresh context (the restarted daemon) resumed it;
    // the test models the saved pause having expired, so the gate is
    // cleared.
    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"delay": 17})),
        )
    })
    .await;
    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );
    ctx.meow_retry_at.store(0, Ordering::Relaxed);
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
    let dead_port = closed_loopback_port().await;

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
    let (_dir, config) = test_config_with_dir(5, "127.0.0.1:1");
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    for id in &ids {
        let row = proxies::get_by_id(&pool, *id).await.unwrap().unwrap();
        assert_eq!(
            row.fail_count, 1,
            "id {id}: one cycle may charge one failure, whatever lane ran it"
        );
        let attempts = count_probe_results(&pool, *id, Some("tcp"), Some(false)).await;
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
    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"invalid credential"})),
        )
    })
    .await;

    // A dead port: the T1 dial fails too. The proxy is `alive`, so it
    // is eligible for both lanes of the same cycle.
    let dead_port = closed_loopback_port().await;

    let id = seed_proxy(&pool, "vless", "127.0.0.1", dead_port, "alive").await;

    // fail_limit = 2: without the hand-off the two charges quarantine
    // the proxy within this single cycle.
    let (_dir, config) = test_config_with_dir(2, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(
        row.status, "alive",
        "one cycle may charge one failure, whatever lane ran it"
    );
    assert_eq!(row.fail_count, 1);
    // The T2 batch skipped the row the T1 sample just judged, and the
    // T1 sample produced the cycle's one verdict.
    assert_eq!(
        count_probe_results(&pool, id, Some("t2"), None).await,
        0,
        "the T2 batch must skip the row the T1 sample just judged"
    );
    assert_eq!(count_probe_results(&pool, id, Some("tcp"), None).await, 1);
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

    let (_dir, mut config) = test_config_with_dir(3, "127.0.0.1:1");
    config.probe.allow_private_targets = false;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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

    let (_dir, mut config) = test_config_with_dir(3, "127.0.0.1:1");
    config.probe.allow_private_targets = true;
    // A one-second period: the budget is three quarters of it, rounded up
    // to a second.
    config.probe.cycle_interval_secs = 1;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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
    let results = count_probe_results(&pool, id, None, None).await;
    assert_eq!(results, 0, "a deferred row is not journaled");
}

/// A lane that fails is logged and skipped, the other lanes of the cycle
/// still run. A broken lane used to cancel the whole cycle, so a single
/// failing write left the fleet unprobed until the next cycle.
#[tokio::test]
async fn a_failing_lane_does_not_cancel_the_cycle() {
    // The lane in isolation: an error becomes the default counters.
    let failed =
        run_lane::<LaneOutcome>("boom", async { anyhow::bail!("the lane exploded") }).await;
    assert_eq!(failed.checked, 0);
    assert_eq!(failed.deferred, 0);

    // The next lane still runs.
    let after = run_lane::<LaneOutcome>("after", async {
        Ok(LaneOutcome {
            checked: 3,
            blocked: 1,
            engine_faults: 0,
            deferred: 2,
            claimed: Vec::new(),
        })
    })
    .await;
    assert_eq!(after.checked, 3);
    assert_eq!(after.blocked, 1);
    assert_eq!(after.deferred, 2);

    // End to end: a cycle whose lanes fail still completes.
    let (_dir, pool) = temp_pool().await;
    seed_proxy(&pool, "vless", "127.0.0.1", 443, "alive").await;
    let (_dir, mut config) = test_config_with_dir(3, "127.0.0.1:1");
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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
    let (_dir, mut config) = test_config_with_dir(3, "127.0.0.1:1");
    config.probe.allow_private_targets = true;
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

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

/// A capture of the log lines the events of one closure produce (the same
/// `MakeWriter` trick the core's logging tests use).
fn capture_log(event: impl FnOnce()) -> String {
    struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
        type Writer = SharedBufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            SharedBufWriter(self.0.clone())
        }
    }
    struct SharedBufWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for SharedBufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(SharedBuf(buffer.clone()))
        .finish();
    tracing::subscriber::with_default(subscriber, event);
    String::from_utf8(buffer.lock().unwrap().clone()).unwrap()
}

/// The sanitizer replaces every control character with a visible escape
/// and caps the length: a crafted reason can neither forge log lines nor
/// grow without bound in the journal.
#[test]
fn sanitize_reason_escapes_controls_and_caps_length() {
    let long = format!("a\r\n\x1b[31mb{}", "x".repeat(2000));
    let clean = sanitize_reason(&long);
    assert!(
        !clean.chars().any(char::is_control),
        "no control character may survive: {clean:?}"
    );
    // The escapes name the character they replace.
    assert!(clean.contains(r"\u{d}"), "{clean:?}");
    assert!(clean.contains(r"\u{a}"), "{clean:?}");
    assert!(clean.contains(r"\u{1b}"), "{clean:?}");
    // The cap counts the output bytes, escapes included.
    assert!(clean.len() <= MAX_REASON_LEN + '…'.len_utf8(), "{clean:?}");
    assert!(clean.ends_with('…'), "{clean:?}");
}

/// A stored scheme is feed-controlled text: the skip warning carries it
/// escaped and names the next step, so a CR/LF or an ANSI escape in the
/// value cannot forge log lines or garble a terminal.
#[test]
fn an_unknown_scheme_is_logged_sanitized() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let logged = capture_log(|| {
        runtime.block_on(async {
            let (_dir, pool) = temp_pool().await;
            let (_dir, config) = test_config_with_dir(3, "127.0.0.1:1");
            let ctx = Arc::new(Context::new(config, pool).await.expect("test context"));
            let candidates = vec![proxies::T1Candidate {
                id: 7,
                scheme: "vless\r\n\x1b[31mboom".to_string(),
                host: "h.example.com".to_string(),
                port: 443,
                params: None,
            }];
            let cycle = test_cycle(&ctx.config);
            run_t1_checks(ctx, candidates, cycle, T1Lane::Regular)
                .await
                .unwrap();
        });
    });
    // The fmt layer separates the events with real newlines, so the
    // buffer is checked for the control characters the *value* carried:
    // a carriage return and an escape must appear only in their escaped
    // spelling.
    assert!(
        !logged.contains('\r') && !logged.contains('\u{1b}'),
        "the log line must carry the scheme escaped: {logged:?}"
    );
    assert!(logged.contains("unknown scheme, skipped"), "{logged}");
    assert!(logged.contains(r"\u{d}"), "{logged}");
    assert!(logged.contains(r"\u{a}"), "{logged}");
    assert!(logged.contains(r"\u{1b}"), "{logged}");
    assert!(logged.contains("retried every cycle"), "{logged}");
}

/// Engine-controlled texts are sanitized before they reach
/// `probe_results.error`: the delay endpoint's error body below carries
/// CR/LF and an ANSI escape, and the journal row must carry neither.
#[tokio::test]
async fn engine_error_texts_are_sanitized_in_the_journal() {
    let (_dir, pool) = temp_pool().await;

    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred\r\n\x1b[31min the delay test",
        )
    })
    .await;

    let id = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    probe_t2_batch(ctx.clone(), &[], test_cycle(&ctx.config))
        .await
        .unwrap();

    let error = last_probe_error(&pool, id, Some("t2")).await;
    assert!(
        !error.chars().any(char::is_control),
        "the journal must carry no control characters: {error:?}"
    );
    assert!(error.contains("An error occurred"), "{error}");
    assert!(error.contains("in the delay test"), "{error}");
    assert!(error.len() <= MAX_REASON_LEN + 1, "{error}");
}

/// The engine refuses a config whose proxy carries no credential, and one
/// such record used to void the whole batch at `PUT /configs`. The
/// required fields are validated before the config is generated (the
/// generated YAML carries no such record, and the row is charged on the
/// spot), and a reload the engine still refuses splits the batch in half
/// so the valid half is tunnel-checked anyway.
#[tokio::test]
async fn an_entry_without_a_uuid_is_dropped_and_a_refused_batch_is_split() {
    let (_dir, pool) = temp_pool().await;

    // The reload refuses the first (whole-batch) attempt and accepts the
    // halves; the delay endpoint answers every tunnel check.
    let reloads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reloads_inner = reloads.clone();
    let delay_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let delay_calls_inner = delay_calls.clone();
    let app = Router::new()
        .route(
            "/version",
            get(|| async { Json(serde_json::json!({"version":"mock"})) }),
        )
        .route(
            "/configs",
            put(move || {
                let reloads = reloads_inner.clone();
                async move {
                    let n = reloads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if n == 0 {
                        (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"message":"invalid uuid"})),
                        )
                    } else {
                        (axum::http::StatusCode::OK, Json(serde_json::json!({})))
                    }
                }
            }),
        )
        .route(
            "/proxies/{name}/delay",
            get(move || {
                let delay_calls = delay_calls_inner.clone();
                async move {
                    delay_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (
                        axum::http::StatusCode::OK,
                        Json(serde_json::json!({"delay": 42})),
                    )
                }
            }),
        );
    let meow_addr = spawn_mock(app).await;

    let bad = seed_proxy_credential(&pool, "vless", "127.0.0.1", 443, "ready", "").await;
    let good = seed_proxy_credential(&pool, "trojan", "127.0.0.1", 443, "ready", "pw").await;
    let second =
        seed_proxy_credential(&pool, "ss", "127.0.0.1", 443, "ready", "aes-256-gcm:secret").await;

    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let config_path = config.meow.config_path.clone();
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    let outcome = probe_t2_batch(ctx.clone(), &[], test_cycle(&ctx.config))
        .await
        .unwrap();

    // The validator dropped the credential-less record before the config
    // was generated: it is journaled as a failed t2 check and charged,
    // never handed to the engine.
    assert_eq!(outcome.skipped, 1, "the invalid record is skipped");
    assert_eq!(outcome.checked, 2, "the valid records are checked");
    let error = last_probe_error(&pool, bad, Some("t2")).await;
    assert!(error.contains("missing uuid"), "{error}");
    let row = proxies::get_by_id(&pool, bad).await.unwrap().unwrap();
    assert_eq!(row.fail_count, 1, "the malformed record is charged");

    // The reload was refused once (the whole batch) and the split halves
    // were retried on their own: three reload attempts, two halves, both
    // tunnel-checked.
    assert_eq!(reloads.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(delay_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    for id in [good, second] {
        let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
        assert_eq!(row.status, "ready", "id {id}");
        assert_eq!(
            row.latency_ms,
            Some(42),
            "id {id}: the valid half got its verdict"
        );
    }

    // The config that reached the engine in the last attempt carries no
    // credential-less record.
    let yaml = std::fs::read_to_string(&config_path).unwrap();
    assert!(!yaml.contains(&clash::proxy_name(bad)), "{yaml}");
    assert!(yaml.contains(&clash::proxy_name(second)), "{yaml}");
}

/// A proxy the quarantine lane revived is not judged twice in its cycle:
/// the revival lane hands its verdict ids to the T1 and T2 lanes, so the
/// same cycle's T2 batch must not re-verify the fresh revival (the
/// revived row is the newest alive row without a t2 attempt, the head of
/// the recency order — it used to be picked immediately).
#[tokio::test]
async fn a_revived_proxy_is_not_rechecked_in_the_same_cycle() {
    let (_dir, pool) = temp_pool().await;

    let delay_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let delay_calls_inner = delay_calls.clone();
    let meow_addr = spawn_mock_meow(move || {
        let delay_calls = delay_calls_inner.clone();
        async move {
            delay_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({"delay": 42})),
            )
        }
    })
    .await;

    let id = seed_proxy(&pool, "hysteria2", "127.0.0.1", 443, "quarantine").await;
    sqlx::query(
        "UPDATE proxies SET quarantined_at = 100, ladder_at = 200, ladder_step = 0 WHERE id = ?",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();

    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    run_cycle(ctx).await.unwrap();

    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "ready", "the revival succeeded");
    // The tunnel engine saw the row exactly once: the revival check. The
    // same cycle's T2 batch skipped it, and T1 never draws a QUIC row.
    assert_eq!(
        delay_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one verdict per cycle: the revival, no re-check"
    );
    assert_eq!(
        count_probe_results(&pool, id, Some("t2"), Some(true)).await,
        1,
        "the revival verdict is journaled exactly once"
    );
    assert_eq!(
        count_probe_results(&pool, id, Some("tcp"), None).await,
        0,
        "a QUIC scheme is never T1-checked"
    );
}

/// The journal row and the recency stamp land together or not at all: a
/// T2 verdict leaves both behind, and a journal write that fails leaves
/// neither (the stamp used to be a separate statement and could advance
/// the recency queue past an attempt that was never journaled; the
/// lifecycle status write stays the source of truth, so it is applied
/// independently of the journal either way).
#[tokio::test]
async fn the_journal_row_and_the_recency_stamp_land_together_or_not_at_all() {
    let meow_addr = spawn_mock_meow(|| async {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"delay": 42})),
        )
    })
    .await;

    // Success: the verdict, the stamp and the status all land.
    let (_dir, pool) = temp_pool().await;
    let id = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );
    probe_t2_batch(ctx.clone(), &[], test_cycle(&ctx.config))
        .await
        .unwrap();
    let row = proxies::get_by_id(&pool, id).await.unwrap().unwrap();
    assert_eq!(row.status, "ready");
    assert!(
        last_t2_checked(&pool, id).await.is_some(),
        "the stamp landed with the journal row"
    );
    assert_eq!(
        count_probe_results(&pool, id, Some("t2"), Some(true)).await,
        1
    );

    // Failure: with the journal table gone the insert fails and the
    // transaction rolls back — the stamp stays where it was.
    sqlx::query("DROP TABLE probe_results")
        .execute(&pool)
        .await
        .unwrap();
    let id2 = seed_proxy(&pool, "vless", "127.0.0.1", 443, "ready").await;
    let (_dir2, config) = test_config_with_dir(3, &meow_addr);
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );
    let cycle = test_cycle(&ctx.config);
    probe_t2_batch(ctx, &[], cycle).await.unwrap();
    assert!(
        last_t2_checked(&pool, id2).await.is_none(),
        "a failed journal write must not leave the recency stamp behind"
    );
}

/// The `last_t2_checked_at` stamp of one proxy, read directly (the column
/// is not part of the `ProxyRow` projection).
async fn last_t2_checked(pool: &DbPool, proxy_id: i64) -> Option<i64> {
    let (stamped,): (Option<i64>,) =
        sqlx::query_as("SELECT last_t2_checked_at FROM proxies WHERE id = ?")
            .bind(proxy_id)
            .fetch_one(pool)
            .await
            .unwrap();
    stamped
}

/// The meow-rs backoff survives a restart: the state is mirrored into
/// `meta` on every change, a fresh `Context::new` (the restarted daemon)
/// reads it back, and its first cycle does not contact meow-rs until the
/// saved pause has expired.
#[tokio::test]
async fn the_meow_backoff_survives_a_restart() {
    let (_dir, pool) = temp_pool().await;

    let version_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let version_calls_inner = version_calls.clone();
    let app = Router::new().route(
        "/version",
        get(move || {
            let version_calls = version_calls_inner.clone();
            async move {
                version_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Json(serde_json::json!({"version":"mock"}))
            }
        }),
    );
    let meow_addr = spawn_mock(app).await;

    // Daemon 1: an outage arms the backoff, which is mirrored into meta.
    let (_dir, config) = test_config_with_dir(3, &meow_addr);
    let first = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );
    assert_eq!(first.meow_retry_at.load(Ordering::Relaxed), 0);
    first.backoff_meow().await;
    let saved_retry_at = first.meow_retry_at.load(Ordering::Relaxed);
    let saved_backoff = first.meow_backoff_secs.load(Ordering::Relaxed);
    assert!(
        fumox_core::models::now_ts() < saved_retry_at,
        "the outage must arm the backoff"
    );
    let stored = meta_get(&pool, probe_repo::meta::MEOW_RETRY_AT_KEY)
        .await
        .unwrap()
        .expect("the backoff gate must be persisted");
    assert_eq!(stored, saved_retry_at.to_string());

    // Daemon 2: the restart reads the saved pause back.
    let (_dir2, config) = test_config_with_dir(3, &meow_addr);
    let second = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );
    assert_eq!(second.meow_retry_at.load(Ordering::Relaxed), saved_retry_at);
    assert_eq!(
        second.meow_backoff_secs.load(Ordering::Relaxed),
        saved_backoff
    );

    // Its first cycle keeps off the engine until the pause expires.
    run_cycle(second).await.unwrap();
    assert_eq!(
        version_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the restarted daemon must not contact meow-rs during the saved pause"
    );
}

/// A failed retention run is stamped with `ok: false` and the error text
/// while the `ts` of the last successful run stands, so the panel's age
/// of the stamp keeps meaning "retention last succeeded". A failed purge
/// (the journal table is gone here) must not advance it.
#[tokio::test]
async fn a_failed_rotation_keeps_the_stamp_of_the_last_successful_one() {
    let (_dir, pool) = temp_pool().await;
    let (_dir, config) = test_config_with_dir(3, "127.0.0.1:1");
    let ctx = Arc::new(
        Context::new(config, pool.clone())
            .await
            .expect("test context"),
    );

    // The successful run stamps `ok: true` with the current time.
    run_retention(&ctx).await;
    let ok_stamp: probe_repo::meta::LastRotation = serde_json::from_str(
        &meta_get(&pool, probe_repo::meta::LAST_ROTATION_KEY)
            .await
            .unwrap()
            .expect("the run must be stamped"),
    )
    .unwrap();
    assert!(ok_stamp.ok);
    assert_eq!(ok_stamp.error, None);

    // The failed run keeps the ts and records the failure.
    sqlx::query("DROP TABLE probe_results")
        .execute(&pool)
        .await
        .unwrap();
    run_retention(&ctx).await;
    let stamp: probe_repo::meta::LastRotation = serde_json::from_str(
        &meta_get(&pool, probe_repo::meta::LAST_ROTATION_KEY)
            .await
            .unwrap()
            .expect("the failed run is stamped too"),
    )
    .unwrap();
    assert!(!stamp.ok, "the failed run must read as failed");
    let error = stamp.error.as_deref().expect("the failure must be named");
    assert!(error.contains("probe_results"), "{error}");
    assert_eq!(
        stamp.ts, ok_stamp.ts,
        "a failed run must not advance the last-successful-rotation stamp"
    );
}
