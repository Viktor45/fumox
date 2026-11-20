//! Test-only support shared by the log-capturing test modules (`admin`,
//! `scheduler`) and the fetch tests (`ingest`): the tracing-dispatcher
//! groundwork their `capture_logs` helpers all need, and the local HTTP
//! upstream the fetch-count assertions count against.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Keep ≥2 dispatchers permanently alive in tracing's global dispatcher
/// registry, for the log-capturing test modules: a call site's interest
/// is cached against the dispatchers live at its FIRST execution, and
/// with fewer than two the registry consults the registering thread's
/// thread-local default (usually no subscriber in a parallel suite), so
/// call sites get cached as `Interest::never` and their events go
/// silently nowhere for the rest of the process (an intermittent failure
/// depending purely on test scheduling). With the registry permanently
/// multi-dispatcher, every registration lands on `Interest::sometimes`,
/// so capture tests always see their lines. Runtime dispatch is
/// unaffected: threads without a scoped default still resolve to the
/// empty global default and drop their events as before.
///
/// Call once before the first capture; the two subscribers leak on
/// purpose: the permanently-live registrars are the point.
pub(crate) fn stabilize_callsite_interests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for _ in 0..2 {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .with_writer(std::io::sink)
                .finish();
            std::mem::forget(tracing::Dispatch::new(subscriber));
        }
    });
}

/// A local HTTP upstream for the fetch tests (ingest, scheduler): answers
/// every request with `HTTP/1.1 200 OK` carrying the next body from
/// `bodies` (a request beyond the list gets the last body again) and
/// counts the requests it received. Requests are answered sequentially,
/// and the counter increments on accept, doubling as the index of the body
/// the current request is answered with: the tests drive one fetch at a
/// time and read a count only after the fetch it belongs to has completed.
pub(crate) async fn one_shot_upstream(bodies: Vec<&'static str>) -> (SocketAddr, Arc<AtomicUsize>) {
    assert!(!bodies.is_empty(), "the upstream needs at least one body");
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&requests);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut sock, _)) = listener.accept().await {
            let index = counted.fetch_add(1, Ordering::SeqCst);
            let body = bodies[index.min(bodies.len() - 1)];
            // Read the request out before answering, like a real HTTP
            // server. Closing a socket that still holds unread client
            // bytes makes the kernel send RST, which can clobber the
            // client's buffered read of the response; the fetcher then
            // retries, opening a second connection the counter sees, and
            // the exact-fetch-count assertions would flake
            let mut received = Vec::with_capacity(1024);
            loop {
                let mut scratch = [0u8; 1024];
                match sock.read(&mut scratch).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        received.extend_from_slice(&scratch[..n]);
                        if received.windows(4).any(|w| w == b"\r\n\r\n")
                            || received.len() >= 16 * 1024
                        {
                            break;
                        }
                    }
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body.as_bytes()).await;
        }
    });
    (addr, requests)
}
