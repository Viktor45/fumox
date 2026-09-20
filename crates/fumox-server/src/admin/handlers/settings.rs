//! Global settings overview: a read-only view of every
//! tunable of the proxy state machine and its supporting knobs, grouped by
//! the process that applies them.
//!
//! The values live in `config/app.toml` (plus the `FUMOX_*` environment
//! overrides) and the config is read once at startup, so each section is
//! badged with its owning process and the page states that changes apply
//! after that process restarts. The admin panel deliberately cannot edit
//! them: the config file is the single source of truth; an editable
//! overlay would need a DB-backed precedence layer, which was deferred.

use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use fumox_core::config::{GeoDbKind, RateLimit};

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    state: AdminState,
}

impl SettingsTemplate {
    /// The quarantine ladder as one localized sentence: «второй шанс →
    /// 15 мин → 30 мин → 1 ч → удаление». An empty configured ladder reads
    /// «второй шанс → удаление».
    fn ladder_sentence(&self) -> String {
        let mut parts = vec![self.lang.t("set.second_chance").to_string()];
        parts.extend(
            self.state
                .probe
                .recheck_delays_secs
                .iter()
                .map(|delay| self.fmt_delay(*delay)),
        );
        parts.push(self.lang.t("set.removal").to_string());
        parts.join(" → ")
    }

    /// Whole hours first, then whole minutes, then raw seconds.
    fn fmt_delay(&self, secs: i64) -> String {
        if secs % 3600 == 0 {
            format!("{} {}", secs / 3600, self.lang.t("probe.hours_short"))
        } else if secs % 60 == 0 {
            format!("{} {}", secs / 60, self.lang.t("probe.mins_short"))
        } else {
            format!("{secs} {}", self.lang.t("common.sec"))
        }
    }

    /// Human-readable byte cap: whole MiB, else whole KiB, else raw bytes.
    /// Takes a reference — askama field access yields one.
    fn fmt_bytes(&self, bytes: &u64) -> String {
        const MIB: u64 = 1024 * 1024;
        const KIB: u64 = 1024;
        if *bytes != 0 && bytes.is_multiple_of(MIB) {
            format!("{} MiB", bytes / MIB)
        } else if *bytes != 0 && bytes.is_multiple_of(KIB) {
            format!("{} KiB", bytes / KIB)
        } else {
            format!("{bytes} {}", self.lang.t("set.bytes"))
        }
    }

    /// A rate limit rendered back in the canonical config form («300/min»,
    /// «5/h», «100/day», «90/45s» for a non-round window).
    fn rate_limit(&self, rl: &RateLimit) -> String {
        let unit = match rl.window.as_secs() {
            60 => "min".to_string(),
            3600 => "h".to_string(),
            86400 => "day".to_string(),
            other => format!("{other}s"),
        };
        format!("{}/{}", rl.limit, unit)
    }

    /// The `[geo].db` value as the config-facing string. The key is legacy
    /// and inert — resolution merges every database in `db_dir` — but the
    /// row is still shown (marked as such) so the effective config is
    /// complete.
    fn geo_db(&self) -> &'static str {
        match self.state.geo_config.db {
            GeoDbKind::Country => "country",
            GeoDbKind::City => "city",
            GeoDbKind::Asn => "asn",
        }
    }
}

impl_i18n!(SettingsTemplate);

/// Settings overview: the effective configuration,
/// grouped by owning process.
pub async fn settings_overview(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let template = SettingsTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(&headers),
        lang,
        active: "settings",
        csrf: state.csrf_for(&headers),
        state: state.clone(),
    };
    render_html(template.lang.clone(), &template, StatusCode::OK)
}
