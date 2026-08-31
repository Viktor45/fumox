//! Response-hardening middleware for the admin listener (ADMIN_PLAN §3):
//! clickjacking, MIME sniffing and referrer leakage protection, plus a
//! Content-Security-Policy (security audit, 2026-08-30). The panel renders
//! with server-side askama escaping and ships its script (htmx) and the
//! inline bootstrap scripts/styles from itself, so `'unsafe-inline'` for
//! script/style is the current floor — no external origins are allowed.

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// CSP for the admin panel: everything comes from itself; inline script and
/// style blocks (the base.html bootstrap, import page helper, theme
/// attributes) keep `unsafe-inline` until the templates are refactored.
pub(crate) const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self' 'unsafe-inline'; \
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
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    response
}
