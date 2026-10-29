//! Admin presentation helpers: the template methods that shape a value
//! for the screen, as opposed to the ones that translate a key.
//!
//! The split keeps [`crate::admin::i18n`] about the catalog alone. The
//! i18n layer resolves a key into a phrase; this module renders a
//! timestamp, a proxy name or a status badge. The two meet only in the
//! template structs, which get both sets of methods.

/// The stored status value and the catalog key that renders it.
///
/// A key looked up at runtime is invisible to the template scan: the scan
/// reads literal arguments, and a status badge is addressed by its value.
/// The list is the contract the key-existence check enforces — every key
/// named here must exist in every catalog.
pub(crate) const STATUS_KEYS: &[(&str, &str)] = &[
    ("alive", "common.status_alive"),
    ("ready", "common.status_ready"),
    ("quarantine", "common.status_quarantine"),
    ("removed", "common.status_removed"),
];

/// The key a status value outside [`STATUS_KEYS`] falls back to.
pub(crate) const UNKNOWN_STATUS_KEY: &str = "common.status_unknown";

/// Format a Unix timestamp as UTC `YYYY-MM-DD HH:MM:SS` (the no-JS
/// fallback). This text is the no-JS fallback inside [`fmt_ts_element`].
pub(crate) fn fmt_ts(ts: i64) -> String {
    const FMT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    match time::OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => dt.format(FMT).unwrap_or_else(|_| ts.to_string()),
        Err(_) => ts.to_string(),
    }
}

/// Render a Unix timestamp as a `<time class="ts">` element: the
/// `datetime` attribute carries the UTC instant in
/// RFC 3339 form, the text keeps the UTC `YYYY-MM-DD HH:MM:SS` fallback. The
/// admin JS (base.html) rewrites the text into the user's timezone and
/// re-runs after every HTMX swap; without JS the UTC text stays readable.
/// The output is HTML, templates must render it through askama's `| safe`.
/// Only server-generated digits and punctuation are interpolated, so it is
/// safe to trust.
pub(crate) fn fmt_ts_element(ts: i64) -> String {
    format!(
        "<time class=\"ts\" datetime=\"{}\">{}</time>",
        crate::security::fmt_rfc3339_utc(ts),
        fmt_ts(ts)
    )
}

/// [`fmt_ts_element`] for optional timestamps; `None` renders the en dash
/// used across the admin tables (plain text, no element).
pub(crate) fn fmt_opt_ts_element(ts: Option<i64>) -> String {
    ts.map(fmt_ts_element).unwrap_or_else(|| "–".into())
}

/// Render a Unix timestamp as a `<time class="ts day">` element carrying the
/// calendar **day** only, for the per-day buckets of the ingest chart.
///
/// A bucket is midnight UTC, so a timestamp formatter is the wrong shape
/// here: it spends the label's width on `00:00:00`, which the 64 px column
/// then clips. The `day` class tells `localize()` in `base.html` to format
/// the date without a time part, so the label survives the rewrite and the
/// tooltip still carries the full instant.
pub(crate) fn fmt_day_element(ts: i64) -> String {
    format!(
        "<time class=\"ts day\" datetime=\"{}\">{}</time>",
        crate::security::fmt_rfc3339_utc(ts),
        fmt_day_plain(ts)
    )
}

/// The `YYYY-MM-DD` calendar day of a timestamp, as plain text (no markup,
/// for attribute values).
pub(crate) fn fmt_day_plain(ts: i64) -> String {
    const FMT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]");
    match time::OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => dt.format(FMT).unwrap_or_else(|_| ts.to_string()),
        Err(_) => ts.to_string(),
    }
}

/// Add the presentation helpers to a template struct that carries a
/// `lang: Lang` field.
///
/// The helpers are separate from the i18n ones on purpose: they shape a
/// value for the screen rather than translate a key, and the i18n layer
/// stays free of the admin handlers.
macro_rules! impl_presentation {
    ($ty:ty) => {
        impl $ty {
            /// Localized display label for a proxy status (e.g. *alive*),
            /// so every status badge renders in the page language,
            /// including htmx-swapped fragments. Unknown values fall
            /// through to *unknown*, mirroring the template chains.
            #[allow(dead_code)]
            fn status_label(&self, status: &str) -> String {
                let key = crate::admin::presentation::STATUS_KEYS
                    .iter()
                    .find(|(value, _)| *value == status)
                    .map(|(_, key)| *key)
                    .unwrap_or(crate::admin::presentation::UNKNOWN_STATUS_KEY);
                self.lang.t(key).to_string()
            }
            /// Display name of a proxy: the source-provided name, or the
            /// server address when the source sent none, an empty name
            /// would render an empty, unclickable-looking link. Whitespace
            /// only counts as empty: it displays as nothing.
            #[allow(dead_code)]
            fn display_name(&self, name: &str, host: &str, port: &i64) -> String {
                if name.trim().is_empty() {
                    format!("{host}:{port}")
                } else {
                    name.to_string()
                }
            }
            /// Render a Unix timestamp as a `<time class="ts">` element
            /// (see [`fmt_ts_element`]); the template emits it through
            /// `| safe`.
            #[allow(dead_code)]
            fn ts(&self, ts: &i64) -> String {
                crate::admin::presentation::fmt_ts_element(*ts)
            }
            /// [`Self::ts`] for optional timestamps; `None` renders the en
            /// dash used across the admin tables (plain text, no element).
            #[allow(dead_code)]
            fn opt_ts(&self, ts: &Option<i64>) -> String {
                crate::admin::presentation::fmt_opt_ts_element(*ts)
            }
        }
    };
}
pub(crate) use impl_presentation;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_element_omits_the_time_part() {
        // A midnight-UTC ingest bucket must label its column with the date
        // alone: the `day` class keeps the admin JS from writing a time
        // back in, and a 64 px column has no room for one.
        let html = fmt_day_element(1_700_000_000);
        assert_eq!(
            html,
            "<time class=\"ts day\" datetime=\"2023-11-14T22:13:20Z\">2023-11-14</time>"
        );
        assert!(!html.contains("22:13:20</time>"), "the label kept a time");
    }

    #[test]
    fn fmt_ts_element_carries_utc_datetime_and_fallback_text() {
        // 1_700_000_000 == 2023-11-14 22:13:20 UTC.
        let html = fmt_ts_element(1_700_000_000);
        assert_eq!(
            html,
            "<time class=\"ts\" datetime=\"2023-11-14T22:13:20Z\">2023-11-14 22:13:20</time>"
        );

        assert_eq!(fmt_opt_ts_element(None), "–");
        assert_eq!(
            fmt_opt_ts_element(Some(1_700_000_000)),
            "<time class=\"ts\" datetime=\"2023-11-14T22:13:20Z\">2023-11-14 22:13:20</time>"
        );

        // Out-of-range timestamps fall back to the raw number in both forms.
        assert_eq!(
            fmt_ts_element(i64::MAX),
            format!("<time class=\"ts\" datetime=\"{0}\">{0}</time>", i64::MAX)
        );
    }
}
