//! Response-hardening middleware for the admin listener:
//! clickjacking, MIME sniffing and referrer leakage protection, plus a
//! Content-Security-Policy. The panel renders with server-side askama
//! escaping and ships its script (`/admin/static/app.js`) as a file, so
//! the policy allows scripts from the origin only: no inline script and
//! no inline event handler. Inline styles stay allowed, the templates
//! still carry a `<noscript>` block and a few style attributes.

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// CSP for the admin panel: everything comes from itself. The panel's
/// script is a file (`/admin/static/app.js`) and every handler is
/// delegated from it, so no inline script and no inline event handler
/// has to be allowed. Inline styles stay for now: the templates still
/// carry a `<noscript>` block and a few style attributes.
pub(crate) const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     connect-src 'self'; \
     font-src 'self'; \
     object-src 'none'; \
     frame-ancestors 'none'; \
     base-uri 'none'; \
     form-action 'self'";

/// Attach the security headers to every admin response.
pub async fn headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        // `same-origin`, not `no-referrer`: per Fetch, a request whose
        // referrer policy resolves to `no-referrer` is stamped with
        // `Origin: null`, and the panel's own cross-site gate
        // (`admin::auth::cross_site_context`) rejects that before auth.
        // `no-referrer` on the login page therefore locked the operator
        // out of every browser: the form's own navigation POST came back
        // `403 err.cross_site`. `same-origin` still withholds the panel
        // URL from third-party origins, which is the leak this header
        // exists to stop.
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    // The panel renders secrets (masked headers, the alive-export link,
    // the config export); nothing it serves belongs in any shared or
    // intermediary cache.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// Every header the panel sets, on every response.
    ///
    /// The middleware is the only place that hardens the responses, so a
    /// route that bypasses it (or a refactor that drops a header) would
    /// leave the panel unprotected. The assertions name the exact values:
    /// `same-origin` and `no-store` are the two that are easy to get
    /// wrong (a `no-referrer` policy locks the operator out of the login
    /// form, see the comment in `headers`).
    #[tokio::test]
    async fn every_response_carries_the_security_headers() {
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(headers));

        let response = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .expect("the router answers");

        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY).unwrap(),
            "same-origin"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let csp = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .expect("the policy must be set")
            .to_str()
            .expect("the policy is ASCII");
        assert_eq!(csp, CONTENT_SECURITY_POLICY);
        // Inline scripts are not allowed: the panel's script is a file and
        // every handler is delegated from it. Inline styles still are.
        let script_src = csp
            .split(';')
            .map(str::trim)
            .find(|directive| directive.starts_with("script-src"))
            .expect("the policy names script-src");
        assert_eq!(script_src, "script-src 'self'");
    }
}
