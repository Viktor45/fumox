//! Redaction of the secrets that live inside URLs.
//!
//! A feed URL carries credentials in two places: the userinfo
//! (`https://user:pass@host/sub`) and the query string (`?token=…`).
//! Both reach the tracing log, the persisted fetch errors and the admin
//! panel, so the rules live here and every caller uses them: the log
//! line, `sources.last_error` and the panel cannot drift apart.
//!
//! Two audiences, two shapes:
//!
//! * the log line and the persisted error keep nothing: the userinfo is
//!   dropped whole and the secret query values are replaced by
//!   [`REDACTED`];
//! * the panel keeps the username of a URL (it tells the operator which
//!   account the feed belongs to) and masks the password instead.

use url::Url;

/// The stems of the query-parameter names that carry a credential.
///
/// The stems cover the shapes the feeds in the wild use: a bearer token,
/// an API key, an authorization header, a client secret, a password, a
/// signature (`sig`, `X-Amz-Signature`), a session id (`session`,
/// `jsessionid`) and a credential carried as a parameter of its own.
pub const SENSITIVE_QUERY_PARAMS: [&str; 8] = [
    "token",
    "key",
    "auth",
    "secret",
    "pass",
    "sig",
    "session",
    "credential",
];

/// The marker that stands in for a secret value.
pub const REDACTED: &str = "[redacted]";

/// Whether a query-parameter name looks credential-bearing (see
/// [`SENSITIVE_QUERY_PARAMS`]).
pub fn is_sensitive_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_QUERY_PARAMS
        .iter()
        .any(|stem| lower.contains(stem))
}

/// Mask the value of every credential-bearing pair of a raw query string,
/// keeping the harmless pairs verbatim; they are the diagnostics. The
/// raw string is edited in place rather than round-tripped through
/// `query_pairs_mut`, whose form-encoding would rewrite benign values
/// (`%20` → `+`) while "fixing" them.
pub fn redact_query(query: &str) -> String {
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            // A bare name (`?token` without `=`) carries no value to leak.
            Some((name, _)) if is_sensitive_param(name) => format!("{name}={REDACTED}"),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Strip userinfo (`user:pass@`) and mask the value of every
/// credential-bearing query pair from a URL string. Applied on every path
/// where a URL, or an error text embedding one, reaches the tracing log,
/// `fetch_log` or `sources.last_error`.
pub fn redact_url(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut parsed) => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            if let Some(query) = parsed.query() {
                parsed.set_query(Some(&redact_query(query)));
            }
            parsed.to_string()
        }
        // Not a URL (the error text embedded something else), nothing to leak.
        Err(_) => url.to_string(),
    }
}

/// The span of a URL's userinfo: the byte range of the `user:pass` part
/// and the index of the `@` that closes it.
pub fn userinfo_span(url: &str) -> Option<(usize, usize)> {
    let scheme_end = url.find("://")? + 3;
    let rest = &url[scheme_end..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let at = rest[..authority_end].rfind('@')?;
    Some((scheme_end, scheme_end + at))
}

/// The span of a URL's query string: the byte range without the `?` and
/// without the fragment that may follow it.
pub fn query_span(url: &str) -> Option<(usize, usize)> {
    let start = url.find('?')? + 1;
    let end = url[start..]
        .find('#')
        .map(|offset| start + offset)
        .unwrap_or(url.len());
    Some((start, end))
}

/// The query of a URL-shaped string with the value of every
/// credential-bearing pair replaced by the redaction marker; the rest of
/// the string is kept byte for byte.
pub fn mask_query(url: &str) -> String {
    let Some((start, end)) = query_span(url) else {
        return url.to_string();
    };
    let query = &url[start..end];
    let masked = redact_query(query);
    if masked == query {
        return url.to_string();
    }
    format!("{}{}{}", &url[..start], masked, &url[end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_strips_userinfo_and_secret_query_values() {
        assert_eq!(
            redact_url("https://user:pass@example.com/sub?a=1"),
            "https://example.com/sub?a=1"
        );
        assert_eq!(
            redact_url("http://user@example.com/"),
            "http://example.com/"
        );
        // Without userinfo the URL is untouched; non-URLs pass through.
        assert_eq!(redact_url("https://example.com/"), "https://example.com/");
        assert_eq!(redact_url("not a url"), "not a url");

        // Credential-bearing query pairs are masked, benign pairs survive:
        // the query is where a subscription token travels, and the
        // redacted URL reaches tracing output and fetch_log verbatim.
        assert_eq!(
            redact_url("https://example.com/sub?token=SECRET&page=2"),
            "https://example.com/sub?token=[redacted]&page=2"
        );
        // Case-insensitive, and the stem match covers compound names.
        assert_eq!(
            redact_url("https://example.com/sub?API_KEY=x&ok=1"),
            "https://example.com/sub?API_KEY=[redacted]&ok=1"
        );
        // A bare name carries no value, so it survives untouched.
        assert_eq!(
            redact_url("https://example.com/sub?token&ok=1"),
            "https://example.com/sub?token&ok=1"
        );
    }

    /// The spans the admin handlers splice on: the userinfo is the part
    /// between the scheme and the `@`, the query is the part between the
    /// `?` and the fragment.
    #[test]
    fn the_spans_cover_the_userinfo_and_the_query() {
        let url = "https://user:pass@example.com/sub?token=x#frag";
        let (start, end) = userinfo_span(url).unwrap();
        assert_eq!(&url[start..end], "user:pass");
        let (start, end) = query_span(url).unwrap();
        assert_eq!(&url[start..end], "token=x");

        // No query, no userinfo: nothing to splice on.
        assert!(query_span("https://example.com/sub").is_none());
        assert!(userinfo_span("https://example.com/sub").is_none());
    }
}
