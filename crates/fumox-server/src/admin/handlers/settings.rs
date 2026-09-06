//! Global settings overview (ADMIN_PLAN §4.7): a read-only view of every
//! tunable of the proxy state machine and its supporting knobs, grouped by
//! the process that applies them.
//!
//! The values live in `config/app.toml` (plus the `FUMOX_*` environment
//! overrides) and the config is read once at startup, so each section is
//! badged with its owning process and the page states that changes apply
//! after that process restarts. The admin panel deliberately cannot edit
//! them: the config file is the single source of truth (owner decision
//! 2026-09-06); an editable overlay would need a DB-backed precedence
//! layer, which was explicitly deferred.

use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

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
}

impl_i18n!(SettingsTemplate);

/// Settings overview (ADMIN_PLAN §4.7): the effective configuration,
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
