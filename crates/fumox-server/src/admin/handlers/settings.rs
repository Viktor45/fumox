//! Settings overview + edit page.
//!
//! The overview (`GET /admin/settings`) is read-only and shows the
//! effective configuration grouped by owning process (server / probe /
//! shared). The edit page (`GET /admin/settings/edit`) is a form that
//! round-trips the on-disk TOML through `toml_edit`, preserving every
//! existing comment. Saving (`POST /admin/settings/update`) writes the
//! file atomically and tells the operator to restart both server and
//! probe for the changes to apply. A *Create from defaults* button on
//! the overview (`POST /admin/settings/create`) bootstraps a missing
//! `config/app.toml` from the embedded reference copy.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::config::{
    AppConfig, DEFAULT_CONFIG_PATH, GeoDbKind, RateLimit, ResolvedConfigPath, bounds,
};
use fumox_core::config_writer::{EditableConfig, item};
use fumox_core::models::IpFamily;

/// Settings overview template (read-only).
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
    /// The quarantine ladder as one localized sentence.
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

    fn fmt_delay(&self, secs: i64) -> String {
        if secs % 3600 == 0 {
            format!("{} {}", secs / 3600, self.lang.t("probe.hours_short"))
        } else if secs % 60 == 0 {
            format!("{} {}", secs / 60, self.lang.t("probe.mins_short"))
        } else {
            format!("{secs} {}", self.lang.t("common.sec"))
        }
    }

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

    fn rate_limit(&self, rl: &RateLimit) -> String {
        let unit = match rl.window.as_secs() {
            60 => "min".to_string(),
            3600 => "h".to_string(),
            86400 => "day".to_string(),
            other => format!("{other}s"),
        };
        format!("{}/{}", rl.limit, unit)
    }

    fn geo_db(&self) -> &'static str {
        match self.state.geo_config.db {
            GeoDbKind::Country => "country",
            GeoDbKind::City => "city",
            GeoDbKind::Asn => "asn",
        }
    }

    /// The path actually written by the editor, `Missing` reads as the
    /// default location for the "would be" message.
    fn editing_path(&self) -> String {
        match &self.state.config_path {
            ResolvedConfigPath::Loaded(p) => p.display().to_string(),
            ResolvedConfigPath::Missing => DEFAULT_CONFIG_PATH.to_string(),
        }
    }

    fn has_config_file(&self) -> bool {
        matches!(self.state.config_path, ResolvedConfigPath::Loaded(_))
    }
}

impl_i18n!(SettingsTemplate);

pub async fn settings_overview(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    // The overview prints the effective config (every panel under
    // *Settings*). Pull from the figment-merged live view so an edit
    // that landed between two page loads is visible without a restart
    //, destructured `state.admin` / `state.fetch` / … stay frozen at
    // startup, only `state.live_config` is refreshed by
    // `settings_update`.
    let state = state.with_fresh_config();
    let template = SettingsTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(&headers),
        lang,
        active: "settings",
        csrf: state.csrf_for(&headers),
        state,
    };
    render_html(template.lang.clone(), &template, StatusCode::OK)
}

// Edit page.

/// Edit-page template: holds the raw form values and the per-field
/// errors so the view can re-render on validation failure.
#[derive(Template)]
#[template(path = "settings_edit.html")]
struct SettingsEditTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    state: AdminState,
    /// Raw form values keyed by `<section>.<field>`. Booleans are
    /// stored as `"on"` when the box was ticked, absent otherwise.
    raw: HashMap<String, String>,
    /// `(field, message)` pairs produced by the validator.
    errors: Vec<(String, String)>,
    /// Top-level banner (no config file, file not writable, …).
    banner: Option<Banner>,
}

#[derive(Clone)]
enum Banner {
    Unwritable(String),
}

impl SettingsEditTemplate {
    fn raw_value<'a>(&'a self, field: &str) -> &'a str {
        self.raw.get(field).map(String::as_str).unwrap_or("")
    }

    fn bool_value(&self, field: &str) -> bool {
        self.raw.get(field).is_some_and(|v| !v.is_empty())
    }

    /// First error message attached to a field, if any.
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|(f, _)| f == field)
            .map(|(_, m)| m.as_str())
    }

    /// `min` for a number input, straight from the bounds table. An
    /// unbounded setting renders an empty attribute rather than a
    /// fabricated `0`.
    fn range_min(&self, field: &str) -> String {
        bounds::min_attr(field)
    }

    /// `max` for a number input, empty when the setting is unbounded.
    fn range_max(&self, field: &str) -> String {
        bounds::max_attr(field)
    }

    /// The range as the operator reads it, shown under the input. It is
    /// the same value the save handler enforces, so the number in the
    /// hint and the number in the error cannot drift apart.
    fn range_text(&self, field: &str) -> Option<String> {
        bounds::display(field, self.lang.t("set.range_open_ended"))
    }

    /// Longest recheck ladder the config accepts, in steps. The ladder
    /// is a list, so its bound is a count rather than a range; both
    /// numbers come from the same constants the deserializer enforces.
    fn ladder_steps(&self) -> usize {
        bounds::RECHECK_MAX_STEPS
    }

    /// Longest single recheck delay, in seconds.
    fn ladder_max_delay(&self) -> i64 {
        bounds::RECHECK_MAX_DELAY_SECS
    }

    /// Path the editor would write to. Surfaces in the page subtitle
    /// and in the intro paragraph so the operator sees the file.
    fn editing_path_str(&self) -> String {
        editing_target(&self.state).display().to_string()
    }

    fn banner_html(&self) -> Option<String> {
        let Banner::Unwritable(path) = self.banner.as_ref()?;
        Some(
            self.lang
                .t_named("set.edit_unwritable", &[("path", path.clone())]),
        )
    }
}

impl_i18n!(SettingsEditTemplate);

/// Path that the editor writes to, deriving a default when no file was
/// loaded at startup. Used by `settings_create` to know where to drop
/// the embedded reference copy.
fn editing_target(state: &AdminState) -> PathBuf {
    match &state.config_path {
        ResolvedConfigPath::Loaded(p) => p.clone(),
        ResolvedConfigPath::Missing => PathBuf::from(DEFAULT_CONFIG_PATH),
    }
}

/// Reassemble the full `AppConfig` from the destructured fields the
/// `AdminState` carries. Used by the unwritable / load-error fallback
/// paths, where reading the file on disk is not an option but the form
/// still needs sensible values to render.
fn state_appconfig(state: &AdminState) -> AppConfig {
    AppConfig {
        server: state.server.clone(),
        database: state.database.clone(),
        fetch: state.fetch.clone(),
        ingest: state.ingest.clone(),
        geo: state.geo_config.clone(),
        admin: state.admin.clone(),
        probe: state.probe.clone(),
        meow: state.meow.clone(),
        retention: state.retention.clone(),
        log: state.log.clone(),
    }
}

/// Build the edit template's `raw` map from an `AppConfig`, using the
/// canonical render of every field. Booleans become `"on"` when true,
/// absent otherwise; enums become their short name.
///
/// Loaded from the file on every `GET /admin/settings/edit` so the
/// form reflects the just-saved state, `state.config` is frozen at
/// startup and would otherwise lag behind every admin save. ENV
/// overrides keep their priority because `AppConfig::load` already
/// merges them on top of the file.
fn raw_from_config(c: &AppConfig) -> HashMap<String, String> {
    let mut raw = HashMap::new();
    let admin = &c.admin;
    let s = &c.server;
    let db = &c.database;
    let f = &c.fetch;
    let g = &c.geo;
    let p = &c.probe;
    let m = &c.meow;
    let r = &c.retention;

    raw.insert("server.bind".into(), s.bind.to_string());
    raw.insert(
        "server.trust_proxy_ips".into(),
        s.trust_proxy_ips.join("\n"),
    );
    raw.insert("server.allowed_hosts".into(), s.allowed_hosts.join("\n"));
    rate_into(&mut raw, "server.rate_limit", &s.rate_limit);
    rate_into(
        &mut raw,
        "server.auth_fail_rate_limit",
        &s.auth_fail_rate_limit,
    );

    raw.insert("database.path".into(), db.path.display().to_string());
    raw.insert(
        "database.busy_timeout_ms".into(),
        db.busy_timeout_ms.to_string(),
    );
    raw.insert(
        "database.max_connections".into(),
        db.max_connections.to_string(),
    );

    raw.insert(
        "fetch.connect_timeout_secs".into(),
        f.connect_timeout_secs.to_string(),
    );
    raw.insert(
        "fetch.read_timeout_secs".into(),
        f.read_timeout_secs.to_string(),
    );
    raw.insert(
        "fetch.max_response_bytes".into(),
        f.max_response_bytes.to_string(),
    );
    raw.insert(
        "fetch.max_concurrency".into(),
        f.max_concurrency.to_string(),
    );
    raw.insert("fetch.max_retries".into(), f.max_retries.to_string());
    raw.insert(
        "fetch.retry_base_backoff_ms".into(),
        f.retry_base_backoff_ms.to_string(),
    );
    raw.insert("fetch.user_agent".into(), f.user_agent.clone());
    raw.insert("fetch.ip_family".into(), ip_family_str(f.ip_family).into());

    raw.insert(
        "ingest.refresh_check_limit".into(),
        c.ingest.refresh_check_limit.to_string(),
    );
    raw.insert("ingest.drop_gate".into(), bool_to_raw(c.ingest.drop_gate));
    raw.insert(
        "ingest.removed_as_unknown".into(),
        bool_to_raw(c.ingest.removed_as_unknown),
    );

    raw.insert("geo.enabled".into(), bool_to_raw(g.enabled));
    raw.insert("geo.db".into(), geo_db_str(g.db).into());
    raw.insert("geo.db_dir".into(), g.db_dir.display().to_string());
    raw.insert(
        "geo.cache_max_entries".into(),
        g.cache_max_entries.to_string(),
    );
    raw.insert(
        "geo.dns_timeout_secs".into(),
        g.dns_timeout_secs.to_string(),
    );

    raw.insert("admin.enabled".into(), bool_to_raw(admin.enabled));
    raw.insert("admin.bind".into(), admin.bind.to_string());
    raw.insert("admin.token".into(), admin.token.clone());
    raw.insert(
        "admin.session_ttl_hours".into(),
        admin.session_ttl_hours.to_string(),
    );
    raw.insert(
        "admin.allow_private_urls".into(),
        bool_to_raw(admin.allow_private_urls),
    );
    rate_into(&mut raw, "admin.rate_limit", &admin.rate_limit);
    rate_into(&mut raw, "admin.login_rate_limit", &admin.login_rate_limit);
    raw.insert(
        "admin.secure_cookies".into(),
        bool_to_raw(admin.secure_cookies),
    );
    raw.insert("admin.locales_dir".into(), admin.locales_dir.clone());
    raw.insert(
        "admin.trust_proxy_ips".into(),
        admin.trust_proxy_ips.join("\n"),
    );
    raw.insert("admin.allowed_hosts".into(), admin.allowed_hosts.join("\n"));

    raw.insert("probe.fail_limit".into(), p.fail_limit.to_string());
    raw.insert(
        "probe.second_chance_min_hours".into(),
        p.second_chance_min_hours.to_string(),
    );
    raw.insert(
        "probe.second_chance_spread_hours".into(),
        p.second_chance_spread_hours.to_string(),
    );
    raw.insert(
        "probe.recheck_delays_secs".into(),
        p.recheck_delays_secs
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    );
    raw.insert(
        "probe.queue_stale_days".into(),
        p.queue_stale_days.to_string(),
    );
    raw.insert(
        "probe.retention_interval_secs".into(),
        p.retention_interval_secs.to_string(),
    );
    raw.insert(
        "probe.cycle_interval_secs".into(),
        p.cycle_interval_secs.to_string(),
    );
    raw.insert("probe.sample_size".into(), p.sample_size.to_string());
    raw.insert(
        "probe.allow_private_targets".into(),
        bool_to_raw(p.allow_private_targets),
    );
    raw.insert(
        "probe.connect_timeout_secs".into(),
        p.connect_timeout_secs.to_string(),
    );
    raw.insert(
        "probe.tls_timeout_secs".into(),
        p.tls_timeout_secs.to_string(),
    );
    raw.insert("probe.concurrency".into(), p.concurrency.to_string());
    raw.insert(
        "probe.heartbeat_interval_secs".into(),
        p.heartbeat_interval_secs.to_string(),
    );
    raw.insert(
        "probe.backlog_target_drain_minutes".into(),
        p.backlog_target_drain_minutes.to_string(),
    );

    raw.insert("meow.api_addr".into(), m.api_addr.clone());
    raw.insert(
        "meow.config_path".into(),
        m.config_path.display().to_string(),
    );
    raw.insert("meow.test_url".into(), m.test_url.join("\n"));
    raw.insert("meow.timeout_secs".into(), m.timeout_secs.to_string());
    raw.insert(
        "meow.backoff_initial_secs".into(),
        m.backoff_initial_secs.to_string(),
    );
    raw.insert(
        "meow.backoff_max_secs".into(),
        m.backoff_max_secs.to_string(),
    );
    // `bool_to_raw`, not `to_string()`: the edit page reads presence as
    // truth (an unchecked checkbox is simply absent from the form), so a
    // literal "false" would render the box as checked.
    raw.insert("meow.ipv6".into(), bool_to_raw(m.ipv6));

    raw.insert(
        "retention.probe_results_days".into(),
        r.probe_results_days.to_string(),
    );
    raw.insert(
        "retention.fetch_log_days".into(),
        r.fetch_log_days.to_string(),
    );

    raw.insert("log.server".into(), c.log.server.as_str().into());
    raw.insert("log.probe".into(), c.log.probe.as_str().into());

    raw
}

fn rate_into(raw: &mut HashMap<String, String>, prefix: &str, rl: &RateLimit) {
    raw.insert(format!("{prefix}.limit"), rl.limit.to_string());
    raw.insert(
        format!("{prefix}.unit"),
        match rl.window.as_secs() {
            1..=59 => "sec".to_string(),
            60..=3599 => "min".to_string(),
            3600..=86399 => "hour".to_string(),
            _ => "day".to_string(),
        },
    );
}

fn bool_to_raw(b: bool) -> String {
    if b { "on".to_string() } else { String::new() }
}

fn ip_family_str(f: IpFamily) -> &'static str {
    match f {
        IpFamily::Any => "any",
        // These strings are the SAME ones `IpFamily::from_str` accepts on
        // startup (crates/fumox-core/src/models.rs). If they ever drift,
        // admin saves silently revert on the next restart because the
        // parser falls back to the default. Keep them locked together ,
        // `apply_all_ip_family_round_trip` in this file proves the pair.
        IpFamily::Ipv4 => "ipv4",
        IpFamily::Ipv6 => "ipv6",
    }
}

fn geo_db_str(d: GeoDbKind) -> &'static str {
    match d {
        GeoDbKind::Country => "country",
        GeoDbKind::City => "city",
        GeoDbKind::Asn => "asn",
    }
}

pub async fn settings_edit(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);

    // Reload the file on every GET so the form reflects the last save
    // (the in-memory `state.config` is frozen at startup and would lag
    // behind every admin write). ENV overrides still win, `AppConfig::load`
    // merges them on top of the file.
    let target = editing_target(&state);
    let raw = match fumox_core::config::load(Some(&target)) {
        Ok(loaded) => raw_from_config(&loaded.config),
        Err(_) => raw_from_config(&state_appconfig(&state)),
    };

    let banner = if !state.config_writable {
        Some(Banner::Unwritable(target.display().to_string()))
    } else {
        None
    };
    let template = SettingsEditTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(&headers),
        lang,
        active: "settings",
        csrf: state.csrf_for(&headers),
        state: state.clone(),
        raw,
        errors: Vec::new(),
        banner,
    };
    render_html(template.lang.clone(), &template, StatusCode::OK)
}

pub async fn settings_update(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    if !state.config_writable {
        return settings_edit_unwritable(&state, &headers);
    }

    let lang = state.locales.lang_from_headers(&headers);
    let raw: HashMap<String, String> = form.into_iter().collect();

    // Build a fresh `EditableConfig` so we can fail-and-replay the form
    // before touching disk. The validator only reads `raw` and the
    // language catalog, no side effects.
    let mut cfg = match EditableConfig::load(&editing_target(&state)) {
        Ok(c) => c,
        Err(err) => return settings_edit_load_error(&state, &headers, err.to_string()),
    };

    let mut errors: Vec<(String, String)> = Vec::new();
    apply_all(&raw, &mut cfg, &lang, &mut errors);

    if !errors.is_empty() {
        let template = SettingsEditTemplate {
            langs: state.locales.choices().to_vec(),
            theme: theme::from_headers(&headers),
            lang: lang.clone(),
            active: "settings",
            csrf: state.csrf_for(&headers),
            state: state.clone(),
            raw,
            errors,
            banner: None,
        };
        return render_html(
            template.lang.clone(),
            &template,
            StatusCode::UNPROCESSABLE_ENTITY,
        );
    }

    // Persist atomically. On a backend that rejects `rename` (NFS / SMB),
    // `save()` falls back to a direct write with a tracing warning.
    if let Err(err) = cfg.save() {
        tracing::error!(error = %err, path = %cfg.path().display(), "failed to save settings");
        let template = SettingsEditTemplate {
            langs: state.locales.choices().to_vec(),
            theme: theme::from_headers(&headers),
            lang: lang.clone(),
            active: "settings",
            csrf: state.csrf_for(&headers),
            state: state.clone(),
            raw,
            errors: vec![(
                "".into(),
                lang.t_args("err.internal", &[format!("save: {err}")]),
            )],
            banner: None,
        };
        return render_html(
            template.lang.clone(),
            &template,
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    let path = cfg.path().display().to_string();
    tracing::info!(path = %path, "settings saved");

    // Refresh the figment-merged in-memory view so the next request to
    // /admin/settings (or any handler that calls `state.with_fresh_config`)
    // renders the values the operator just wrote, instead of the startup
    // snapshot. ENV overrides are re-applied by `config::load` itself, so
    // `FUMOX_*` env vars keep winning on top of the file.
    if let Err(err) = state.refresh_live_config(Path::new(&path)) {
        tracing::warn!(error = %err, path = %path, "live config refresh skipped");
    }

    let toast = lang.t_named("set.edit_saved_toast", &[("path", path)]);
    if headers.get("HX-Request").is_some() {
        return htmx_redirect_with_toast("/admin/settings", &toast);
    }
    Redirect::to("/admin/settings").into_response()
}

fn htmx_redirect_with_toast(redirect_to: &str, toast: &str) -> Response {
    let trigger = json_trigger("ok", toast);
    (
        StatusCode::SEE_OTHER,
        [
            ("HX-Redirect", redirect_to.to_string()),
            ("HX-Trigger", trigger),
        ],
    )
        .into_response()
}

fn json_trigger(level: &str, message: &str) -> String {
    // Match the shape the toast listener in `base.html` expects.
    serde_json::json!({ "toast": { "level": level, "message": message } }).to_string()
}

fn settings_edit_unwritable(state: &AdminState, headers: &HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(headers);
    let template = SettingsEditTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(headers),
        lang,
        active: "settings",
        csrf: state.csrf_for(headers),
        state: state.clone(),
        raw: raw_from_config(&state_appconfig(state)),
        errors: Vec::new(),
        banner: Some(Banner::Unwritable(
            editing_target(state).display().to_string(),
        )),
    };
    render_html(
        template.lang.clone(),
        &template,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
}

fn settings_edit_load_error(state: &AdminState, headers: &HeaderMap, message: String) -> Response {
    let lang = state.locales.lang_from_headers(headers);
    let internal = lang.t("err.internal").to_string();
    let template = SettingsEditTemplate {
        langs: state.locales.choices().to_vec(),
        theme: theme::from_headers(headers),
        lang: lang.clone(),
        active: "settings",
        csrf: state.csrf_for(headers),
        state: state.clone(),
        raw: raw_from_config(&state_appconfig(state)),
        errors: vec![("".into(), format!("{internal}: {message}"))],
        banner: None,
    };
    render_html(
        template.lang.clone(),
        &template,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
}

/// Create `config/app.toml` from the embedded reference copy when it is
/// missing. No-op when the file already exists, so a retry from a stale
/// tab is harmless.
pub async fn settings_create(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let target = editing_target(&state);

    if target.exists() {
        return redirect_after_create(&target, lang.t("set.file_created_noop").to_string());
    }

    if !fumox_core::config_writer::is_writable(target.parent().unwrap_or(Path::new("."))) {
        return settings_edit_unwritable(&state, &headers);
    }

    if let Err(err) = std::fs::write(&target, fumox_core::config_writer::REFERENCE_CONFIG) {
        tracing::error!(error = %err, path = %target.display(), "failed to write reference config");
        return settings_edit_load_error(&state, &headers, err.to_string());
    }

    // The file was just materialised from the embedded reference copy;
    // pull the freshly-merged view into the in-memory cache so the next
    // GET to /admin/settings/edit (and the *Settings* overview) renders
    // every default rather than the empty startup snapshot.
    if let Err(err) = state.refresh_live_config(&target) {
        tracing::warn!(error = %err, path = %target.display(), "live config refresh after create skipped");
    }

    let path = target.display().to_string();
    let msg = lang.t_named("set.file_created_toast", &[("path", path)]);
    redirect_after_create(&target, msg)
}

fn redirect_after_create(target: &Path, toast: String) -> Response {
    let is_htmx = false; // form posts here are never htmx-driven
    let _ = is_htmx;
    let path = target.display().to_string();
    let _ = path;
    let trigger = json_trigger("ok", &toast);
    (
        StatusCode::SEE_OTHER,
        [
            ("Location", "/admin/settings/edit".to_string()),
            ("HX-Trigger", trigger),
        ],
    )
        .into_response()
}

// Validation / application.

/// Walk every supported setting. Each field is parsed in isolation ,
/// errors accumulate without short-circuiting so the operator sees
/// every problem on a single submit.
fn apply_all(
    raw: &HashMap<String, String>,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    // --- server ---
    bind(raw, "server.bind", cfg, lang, errors);
    string_list(
        raw,
        "server.trust_proxy_ips",
        cfg,
        "server.trust_proxy_ips",
        lang,
        errors,
    );
    string_list(
        raw,
        "server.allowed_hosts",
        cfg,
        "server.allowed_hosts",
        lang,
        errors,
    );
    rate_limit(
        raw,
        "server.rate_limit",
        cfg,
        "server.rate_limit",
        lang,
        errors,
    );
    rate_limit(
        raw,
        "server.auth_fail_rate_limit",
        cfg,
        "server.auth_fail_rate_limit",
        lang,
        errors,
    );

    // --- database ---
    string_field(raw, "database.path", cfg, "database.path", lang, errors);
    u64_field(
        raw,
        "database.busy_timeout_ms",
        cfg,
        "database.busy_timeout_ms",
        lang,
        errors,
    );
    u32_field(
        raw,
        "database.max_connections",
        cfg,
        "database.max_connections",
        lang,
        errors,
    );

    // --- fetch ---
    u64_field(
        raw,
        "fetch.connect_timeout_secs",
        cfg,
        "fetch.connect_timeout_secs",
        lang,
        errors,
    );
    u64_field(
        raw,
        "fetch.read_timeout_secs",
        cfg,
        "fetch.read_timeout_secs",
        lang,
        errors,
    );
    u64_field(
        raw,
        "fetch.max_response_bytes",
        cfg,
        "fetch.max_response_bytes",
        lang,
        errors,
    );
    usize_field(
        raw,
        "fetch.max_concurrency",
        cfg,
        "fetch.max_concurrency",
        lang,
        errors,
    );
    u32_field(
        raw,
        "fetch.max_retries",
        cfg,
        "fetch.max_retries",
        lang,
        errors,
    );
    u64_field(
        raw,
        "fetch.retry_base_backoff_ms",
        cfg,
        "fetch.retry_base_backoff_ms",
        lang,
        errors,
    );
    string_field(
        raw,
        "fetch.user_agent",
        cfg,
        "fetch.user_agent",
        lang,
        errors,
    );
    enum_field(
        raw,
        "fetch.ip_family",
        cfg,
        "fetch.ip_family",
        &["any", "ipv4", "ipv6"],
        |s| match s {
            "any" => Some("any".to_string()),
            "ipv4" => Some("ipv4".to_string()),
            "ipv6" => Some("ipv6".to_string()),
            _ => None,
        },
        lang,
        errors,
    );

    // --- ingest ---
    u32_field(
        raw,
        "ingest.refresh_check_limit",
        cfg,
        "ingest.refresh_check_limit",
        lang,
        errors,
    );
    bool_field(raw, "ingest.drop_gate", cfg, "ingest.drop_gate", errors);
    bool_field(
        raw,
        "ingest.removed_as_unknown",
        cfg,
        "ingest.removed_as_unknown",
        errors,
    );

    // --- geo ---
    bool_field(raw, "geo.enabled", cfg, "geo.enabled", errors);
    enum_field(
        raw,
        "geo.db",
        cfg,
        "geo.db",
        &["country", "city", "asn"],
        |s| match s {
            "country" => Some("country".to_string()),
            "city" => Some("city".to_string()),
            "asn" => Some("asn".to_string()),
            _ => None,
        },
        lang,
        errors,
    );
    string_field(raw, "geo.db_dir", cfg, "geo.db_dir", lang, errors);
    u64_field(
        raw,
        "geo.cache_max_entries",
        cfg,
        "geo.cache_max_entries",
        lang,
        errors,
    );
    u64_field(
        raw,
        "geo.dns_timeout_secs",
        cfg,
        "geo.dns_timeout_secs",
        lang,
        errors,
    );

    // --- admin ---
    bool_field(raw, "admin.enabled", cfg, "admin.enabled", errors);
    bind(raw, "admin.bind", cfg, lang, errors);
    string_field(raw, "admin.token", cfg, "admin.token", lang, errors);
    u32_field(
        raw,
        "admin.session_ttl_hours",
        cfg,
        "admin.session_ttl_hours",
        lang,
        errors,
    );
    bool_field(
        raw,
        "admin.allow_private_urls",
        cfg,
        "admin.allow_private_urls",
        errors,
    );
    rate_limit(
        raw,
        "admin.rate_limit",
        cfg,
        "admin.rate_limit",
        lang,
        errors,
    );
    rate_limit(
        raw,
        "admin.login_rate_limit",
        cfg,
        "admin.login_rate_limit",
        lang,
        errors,
    );
    bool_field(
        raw,
        "admin.secure_cookies",
        cfg,
        "admin.secure_cookies",
        errors,
    );
    string_field(
        raw,
        "admin.locales_dir",
        cfg,
        "admin.locales_dir",
        lang,
        errors,
    );
    string_list(
        raw,
        "admin.trust_proxy_ips",
        cfg,
        "admin.trust_proxy_ips",
        lang,
        errors,
    );
    string_list(
        raw,
        "admin.allowed_hosts",
        cfg,
        "admin.allowed_hosts",
        lang,
        errors,
    );

    // --- probe ---
    u32_field(
        raw,
        "probe.fail_limit",
        cfg,
        "probe.fail_limit",
        lang,
        errors,
    );
    u64_field(
        raw,
        "probe.second_chance_min_hours",
        cfg,
        "probe.second_chance_min_hours",
        lang,
        errors,
    );
    u64_field(
        raw,
        "probe.second_chance_spread_hours",
        cfg,
        "probe.second_chance_spread_hours",
        lang,
        errors,
    );
    // Bounds mirror `fumox_core::config::de_recheck_delays`, the parser
    // both binaries load the file with: at most 16 steps of 1..=30 days.
    i64_list_field(
        raw,
        "probe.recheck_delays_secs",
        cfg,
        "probe.recheck_delays_secs",
        bounds::RECHECK_MAX_STEPS,
        1,
        bounds::RECHECK_MAX_DELAY_SECS,
        lang,
        errors,
    );
    u64_field(
        raw,
        "probe.queue_stale_days",
        cfg,
        "probe.queue_stale_days",
        lang,
        errors,
    );
    u64_field(
        raw,
        "probe.retention_interval_secs",
        cfg,
        "probe.retention_interval_secs",
        lang,
        errors,
    );
    u64_field(
        raw,
        "probe.cycle_interval_secs",
        cfg,
        "probe.cycle_interval_secs",
        lang,
        errors,
    );
    u32_field(
        raw,
        "probe.sample_size",
        cfg,
        "probe.sample_size",
        lang,
        errors,
    );
    bool_field(
        raw,
        "probe.allow_private_targets",
        cfg,
        "probe.allow_private_targets",
        errors,
    );
    u64_field(
        raw,
        "probe.connect_timeout_secs",
        cfg,
        "probe.connect_timeout_secs",
        lang,
        errors,
    );
    u64_field(
        raw,
        "probe.tls_timeout_secs",
        cfg,
        "probe.tls_timeout_secs",
        lang,
        errors,
    );
    usize_field(
        raw,
        "probe.concurrency",
        cfg,
        "probe.concurrency",
        lang,
        errors,
    );
    u64_field(
        raw,
        "probe.heartbeat_interval_secs",
        cfg,
        "probe.heartbeat_interval_secs",
        lang,
        errors,
    );
    u64_field(
        raw,
        "probe.backlog_target_drain_minutes",
        cfg,
        "probe.backlog_target_drain_minutes",
        lang,
        errors,
    );

    // --- meow ---
    string_field(raw, "meow.api_addr", cfg, "meow.api_addr", lang, errors);
    string_field(
        raw,
        "meow.config_path",
        cfg,
        "meow.config_path",
        lang,
        errors,
    );
    string_list(raw, "meow.test_url", cfg, "meow.test_url", lang, errors);
    u64_field(
        raw,
        "meow.timeout_secs",
        cfg,
        "meow.timeout_secs",
        lang,
        errors,
    );
    u64_field(
        raw,
        "meow.backoff_initial_secs",
        cfg,
        "meow.backoff_initial_secs",
        lang,
        errors,
    );
    u64_field(
        raw,
        "meow.backoff_max_secs",
        cfg,
        "meow.backoff_max_secs",
        lang,
        errors,
    );
    bool_field(raw, "meow.ipv6", cfg, "meow.ipv6", errors);

    // --- retention ---
    u32_field(
        raw,
        "retention.probe_results_days",
        cfg,
        "retention.probe_results_days",
        lang,
        errors,
    );
    u32_field(
        raw,
        "retention.fetch_log_days",
        cfg,
        "retention.fetch_log_days",
        lang,
        errors,
    );

    // --- log ---
    enum_field(
        raw,
        "log.server",
        cfg,
        "log.server",
        &["error", "warn", "info", "debug", "trace"],
        |s| Some(s.to_string()),
        lang,
        errors,
    );
    enum_field(
        raw,
        "log.probe",
        cfg,
        "log.probe",
        &["error", "warn", "info", "debug", "trace"],
        |s| Some(s.to_string()),
        lang,
        errors,
    );

    // Cross-field checks the serde model cannot express.
    let max = raw
        .get("meow.backoff_max_secs")
        .and_then(|s| s.parse::<u64>().ok());
    let min = raw
        .get("meow.backoff_initial_secs")
        .and_then(|s| s.parse::<u64>().ok());
    if let (Some(min), Some(max)) = (min, max)
        && max < min
    {
        errors.push((
            "meow.backoff_max_secs".into(),
            lang.t_args("val.in_range", &[format!("≥ {min}"), min.to_string()]),
        ));
    }
}

// Field helpers.

/// Bounds of the quarantine recheck ladder, copied from
/// `fumox_core::config::de_recheck_delays` (the deserializer both
/// binaries load the file with). The panel writes the file verbatim, so
/// it must refuse exactly what that parser refuses: a value the loader
/// rejects aborts the next start of fumox-server and fumox-probe.
/// Return the value at `field` only when the form actually carried it.
/// Missing fields are skipped silently, the editor only writes the
/// sections the operator touched, preserving every other setting as it
/// is on disk. Required-only-on-write validation lives in the per-field
/// helpers (empty string is an error, no string at all is not).
fn raw_get<'a>(raw: &'a HashMap<String, String>, field: &str) -> Option<&'a str> {
    raw.get(field).map(String::as_str)
}

fn bind(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    match v.parse::<SocketAddr>() {
        Ok(addr) => {
            let _ = cfg.set(field, item::string(addr.to_string()));
        }
        Err(_) => {
            errors.push((field.into(), lang.t("val.invalid_bind").into()));
        }
    }
}

fn string_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    target: &str,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    if v.is_empty() {
        errors.push((field.into(), lang.t("val.required").into()));
        return;
    }
    let _ = cfg.set(target, item::string(v.to_string()));
}

/// The error text for a value outside its setting's range. Reads the
/// bound from [`bounds`] by the field name, so a numeric setting cannot
/// be enforced against one range and advertised with another.
fn out_of_range(field: &str, value: u64, lang: &Lang) -> String {
    let Some(range) = bounds::range_of(field) else {
        // A numeric field with no entry in the table is a wiring bug,
        // not a user error. Say so instead of blaming the input.
        return format!("{field} has no configured range");
    };
    match range.max {
        Some(max) => lang.t_args("val.in_range", &[range.min.to_string(), max.to_string()]),
        None => lang.t_args("val.at_least", &[range.min.to_string(), value.to_string()]),
    }
}

fn u64_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    target: &str,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    let parsed = match v.parse::<u64>() {
        Ok(n) => n,
        Err(_) => {
            errors.push((field.into(), lang.t("val.must_be_u64").into()));
            return;
        }
    };
    if !bounds::range_of(field).is_some_and(|r| r.contains(parsed)) {
        errors.push((field.into(), out_of_range(field, parsed, lang)));
        return;
    }
    let _ = cfg.set(target, item::integer(parsed as i64));
}

fn u32_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    target: &str,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    let parsed = match v.parse::<u32>() {
        Ok(n) => n,
        Err(_) => {
            errors.push((field.into(), lang.t("val.must_be_u64").into()));
            return;
        }
    };
    if !bounds::range_of(field).is_some_and(|r| r.contains(u64::from(parsed))) {
        errors.push((field.into(), out_of_range(field, u64::from(parsed), lang)));
        return;
    }
    let _ = cfg.set(target, item::integer(i64::from(parsed)));
}

fn usize_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    target: &str,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let v = v.trim();
    let parsed = match v.parse::<usize>() {
        Ok(n) => n,
        Err(_) => {
            errors.push((field.into(), lang.t("val.must_be_u64").into()));
            return;
        }
    };
    if !bounds::range_of(field).is_some_and(|r| r.contains(parsed as u64)) {
        errors.push((field.into(), out_of_range(field, parsed as u64, lang)));
        return;
    }
    let _ = cfg.set(target, item::integer(parsed as i64));
}

fn bool_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    target: &str,
    errors: &mut Vec<(String, String)>,
) {
    // Booleans default to `false` when the checkbox was absent, the
    // browser drops unchecked checkboxes from the form submission.
    let v = raw_get(raw, field).unwrap_or("");
    let b = match v {
        "" | "off" | "false" | "0" => false,
        "on" | "true" | "1" => true,
        other => {
            errors.push((field.into(), format!("unexpected bool literal: {other}")));
            return;
        }
    };
    let _ = cfg.set(target, item::boolean(b));
}

#[allow(clippy::too_many_arguments)]
fn enum_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    target: &str,
    choices: &[&str],
    map: impl Fn(&str) -> Option<String>,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let Some(value) = map(v) else {
        let msg = lang.t_args("val.must_be_enum", &[choices.join(", ")]);
        errors.push((field.into(), msg));
        return;
    };
    let _ = cfg.set(target, item::string(value));
}

fn string_list(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    target: &str,
    _lang: &Lang,
    _errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let items: Vec<String> = v
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let _ = cfg.set(target, item::string_array(items));
}

/// One integer per line, bounded the way the canonical loader bounds the
/// field it writes: at most `max_items` entries, each within `min..=max`.
/// The admin panel writes the file verbatim and the next start of both
/// binaries aborts on anything `fumox_core::config` refuses, so a bound
/// the loader does not share would turn a green toast into a dead server.
///
/// An empty list is refused even though the loader accepts one: for the
/// only field using this helper today, the recheck ladder, `[]` means
/// «remove the proxy right after the failed second chance», and the field
/// hint never says so, silently emptying the textarea would disable the
/// quarantine ladder behind a success toast. An operator who wants that
/// configures the file directly.
#[allow(clippy::too_many_arguments)]
fn i64_list_field(
    raw: &HashMap<String, String>,
    field: &str,
    cfg: &mut EditableConfig,
    target: &str,
    max_items: usize,
    min: i64,
    max: i64,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    let Some(v) = raw_get(raw, field) else { return };
    let mut parsed = Vec::new();
    let mut had_error = false;
    for line in v.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match trimmed.parse::<i64>() {
            Ok(n) => parsed.push(n),
            Err(_) => {
                errors.push((
                    field.into(),
                    lang.t_args("val.must_be_i64_list", &[trimmed.to_string()]),
                ));
                had_error = true;
                break;
            }
        }
    }
    if had_error {
        return;
    }
    if parsed.is_empty() {
        errors.push((field.into(), lang.t("val.empty_list").into()));
        return;
    }
    // The count, not a value, is what failed: `val.in_range` is the
    // scalar range key the other helpers use and would read as a per-value
    // bound that the very same check accepts `max_items` of. No catalog
    // key names a list length, and the locales are not this file's to
    // extend, so the sentence is written out here, the same escape
    // `bool_field` takes for an unexpected literal. It counts generic
    // entries, not whatever the caller's field calls them.
    if parsed.len() > max_items {
        errors.push((field.into(), format!("at most {max_items} entries")));
        return;
    }
    for n in &parsed {
        if *n < min || *n > max {
            let msg = lang.t_args("val.in_range", &[min.to_string(), max.to_string()]);
            errors.push((field.into(), msg));
            return;
        }
    }
    let _ = cfg.set(target, item::i64_array(parsed));
}

fn rate_limit(
    raw: &HashMap<String, String>,
    prefix: &str,
    cfg: &mut EditableConfig,
    target: &str,
    lang: &Lang,
    errors: &mut Vec<(String, String)>,
) {
    // Both halves of the pair must be present, leaving one out means
    // the form was incomplete.
    let Some(limit_str) = raw_get(raw, &format!("{prefix}.limit")) else {
        return;
    };
    let Some(unit_str) = raw_get(raw, &format!("{prefix}.unit")) else {
        return;
    };

    let limit: u32 = match limit_str.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            errors.push((format!("{prefix}.limit"), lang.t("val.must_be_u64").into()));
            return;
        }
    };
    // The form has always advertised `min="1" max="1000000"` on this
    // input, but nothing checked it: the browser's number validation is
    // the only thing that ever enforced it, so a hand-crafted POST wrote
    // `0/min` and every public request met the limit. The bound now
    // comes from the same table the form renders, which is the point of
    // having one.
    let field = format!("{prefix}.limit");
    if !bounds::range_of(&field).is_some_and(|r| r.contains(u64::from(limit))) {
        let msg = out_of_range(&field, u64::from(limit), lang);
        errors.push((field, msg));
        return;
    }
    let secs = match unit_str {
        "sec" => 1u64,
        "min" => 60,
        "hour" => 3600,
        "day" => 86_400,
        _ => {
            errors.push((
                format!("{prefix}.unit"),
                lang.t_args("val.must_be_enum", &["sec, min, hour, day".into()]),
            ));
            return;
        }
    };
    let _ = cfg.set(
        target,
        item::string(format!("{}/{}", limit, unit_for_secs(secs))),
    );
    let _ = lang;
}

fn unit_for_secs(secs: u64) -> &'static str {
    match secs {
        1 => "s",
        60 => "min",
        3600 => "h",
        86_400 => "day",
        other if other < 60 => "s",
        other if other < 3600 => "min",
        other if other < 86_400 => "h",
        _ => "day",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_minimal_config(dir: &Path) -> PathBuf {
        let path = dir.join("app.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"[server]\nbind = \"0.0.0.0:8080\"\n[probe]\nfail_limit = 3\n")
            .unwrap();
        path
    }

    fn collect_field<'a>(errors: &'a [(String, String)], field: &str) -> Option<&'a str> {
        errors
            .iter()
            .find(|(f, _)| f == field)
            .map(|(_, m)| m.as_str())
    }

    fn temp_dir(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fumox-settings-{label}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_lang() -> Lang {
        // Embedded catalogs load without a directory. Resolve an explicit
        // English code so the per-error assertions read stable text;
        // the Russian copy is exercised by the i18n catalog tests.
        crate::admin::i18n::Locales::load(Path::new("/nonexistent-fumox-locales")).resolve("en")
    }

    #[test]
    fn apply_all_writes_valid_bind_and_int() {
        let dir = temp_dir("happy");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("server.bind".into(), "127.0.0.1:9999".into());
        raw.insert("probe.fail_limit".into(), "5".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
        let serialized = cfg.doc().to_string();
        assert!(serialized.contains("bind = \"127.0.0.1:9999\""));
        assert!(serialized.contains("fail_limit = 5"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_flags_invalid_bind() {
        let dir = temp_dir("bad-bind");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("server.bind".into(), "not-a-socket".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert_eq!(
            collect_field(&errors, "server.bind"),
            Some("invalid socket address"),
            "actual: {errors:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_rejects_out_of_range() {
        let dir = temp_dir("range");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        // fail_limit min=1 max=32
        raw.insert("probe.fail_limit".into(), "0".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert!(
            collect_field(&errors, "probe.fail_limit").is_some(),
            "expected an error for fail_limit=0, got {errors:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_flags_unknown_enum() {
        let dir = temp_dir("enum");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("fetch.ip_family".into(), "ipv9".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert!(collect_field(&errors, "fetch.ip_family").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_ip_family_round_trips_through_parser() {
        // The dropdown values must match IpFamily::from_str, otherwise
        // the admin save writes a value that the canonical parser
        // refuses on the next restart, silently reverting to default.
        use std::str::FromStr;

        let dir = temp_dir("ip-roundtrip");
        let path = write_minimal_config(&dir);

        for family in [IpFamily::Any, IpFamily::Ipv4, IpFamily::Ipv6] {
            let mut raw = HashMap::new();
            raw.insert(
                "fetch.ip_family".into(),
                super::ip_family_str(family).into(),
            );

            let lang = test_lang();
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors);
            assert!(
                errors.is_empty(),
                "save produced errors for {family:?}: {errors:?}"
            );

            let serialized = cfg.doc().to_string();
            let parsed = IpFamily::from_str(super::ip_family_str(family))
                .expect("ip_family_str must produce a value IpFamily accepts");
            assert_eq!(parsed, family, "round-trip drifted for {family:?}");

            // toml_edit serialises the leaf under its `[fetch]` section
            // header, so the on-disk text contains the bare key
            // (`ip_family = "ipv4"`) rather than the dotted form.
            assert!(
                serialized.contains(&format!("ip_family = \"{}\"", super::ip_family_str(family))),
                "saved config missing the literal for {family:?}: {serialized}"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_all_handles_meow_backoff_cross_check() {
        let dir = temp_dir("cross");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("meow.backoff_initial_secs".into(), "60".into());
        raw.insert("meow.backoff_max_secs".into(), "30".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert!(
            collect_field(&errors, "meow.backoff_max_secs").is_some(),
            "expected cross-field error, got {errors:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A `false` boolean must reach the edit page as an ABSENT raw value:
    /// `bool_value` reads presence as truth, so storing the literal "false"
    /// would render the box as checked: the raw map is the whole contract.
    #[test]
    fn meow_ipv6_raw_value_round_trips_as_a_checkbox() {
        // `bool_value` reads a non-empty value as true, so `false` has to
        // land as an empty string, the literal "false" would check the box.
        let mut cfg = AppConfig::default();
        cfg.meow.ipv6 = false;
        assert_eq!(
            raw_from_config(&cfg).get("meow.ipv6").map(String::as_str),
            Some(""),
            "false must map to an empty raw value, not the literal"
        );

        cfg.meow.ipv6 = true;
        assert_eq!(
            raw_from_config(&cfg).get("meow.ipv6").map(String::as_str),
            Some("on")
        );
    }

    #[test]
    fn apply_all_parses_bool_checkboxes() {
        let dir = temp_dir("bool");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("ingest.drop_gate".into(), "on".into());
        // `removed_as_unknown` is absent → false.

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert!(errors.is_empty());
        let serialized = cfg.doc().to_string();
        assert!(serialized.contains("drop_gate = true"));
        assert!(serialized.contains("removed_as_unknown = false"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rate_into_renders_minutes() {
        let mut raw = HashMap::new();
        let rl = RateLimit {
            limit: 300,
            window: std::time::Duration::from_secs(60),
        };
        rate_into(&mut raw, "server.rate_limit", &rl);
        assert_eq!(raw.get("server.rate_limit.limit").unwrap(), "300");
        assert_eq!(raw.get("server.rate_limit.unit").unwrap(), "min");
    }

    #[test]
    fn rate_limit_field_round_trip() {
        let dir = temp_dir("rate");
        let path = write_minimal_config(&dir);

        let mut raw = HashMap::new();
        raw.insert("server.rate_limit.limit".into(), "120".into());
        raw.insert("server.rate_limit.unit".into(), "min".into());

        let lang = test_lang();
        let mut errors = Vec::new();
        let mut cfg = EditableConfig::load(&path).unwrap();
        apply_all(&raw, &mut cfg, &lang, &mut errors);

        assert!(errors.is_empty());
        let serialized = cfg.doc().to_string();
        assert!(
            serialized.contains("rate_limit = \"120/min\""),
            "got: {serialized}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The recheck ladder is the only integer list the panel writes, and
    /// the canonical loader (`config::de_recheck_delays`) refuses more
    /// than 16 steps and any delay outside 1..=30 days, both binaries
    /// abort on a file the loader rejects. The bounds checked here must
    /// therefore be the loader's: a ladder the panel accepts has to round
    /// trip through `config::load_config`, and one it rejects must never
    /// reach the file. An emptied textarea is the one value the loader
    /// takes and the panel does not, and that asymmetry is deliberate
    /// (see `i64_list_field`).
    #[test]
    fn recheck_ladder_bounds_match_the_canonical_loader() {
        use fumox_core::config::load_config;

        let dir = temp_dir("ladder");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        // One admin save cycle. `load_config` deliberately does NOT take the
        // `EditLock` that `EditableConfig::load` holds: the plain loader
        // reads the file without it, and has to keep doing so, because the
        // admin handler re-reads through it while the editor handle is still
        // in scope. A loader that took the lock would deadlock the request.
        // See `fumox_core::config_writer::EditLock`.
        let save = |raw: &HashMap<String, String>| -> Vec<(String, String)> {
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(raw, &mut cfg, &lang, &mut errors);
            if errors.is_empty() {
                cfg.save().unwrap();
            }
            errors
        };
        let ladder = |steps: &[i64]| -> HashMap<String, String> {
            HashMap::from([(
                "probe.recheck_delays_secs".to_string(),
                steps
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )])
        };

        // A ladder the loader accepts must save and reload unchanged.
        let steps: Vec<i64> = (1..=16).collect();
        let errors = save(&ladder(&steps));
        assert!(errors.is_empty(), "16 steps must be accepted: {errors:?}");
        let loaded = load_config(Some(&path)).expect("the saved ladder must load");
        assert_eq!(loaded.probe.recheck_delays_secs, steps);

        // 17 steps: the panel must refuse it, the loader would not. The
        // message must name the count, not borrow the scalar range wording
        // `u64_field` and friends use, «must be between 0 and 16» reads
        // as a per-delay bound and contradicts the 16 steps just accepted.
        // It also must stay generic: `i64_list_field` is parameterised by
        // `max_items` and knows nothing about ladders, so it counts
        // entries, not steps.
        let errors = save(&ladder(&(1..=17).collect::<Vec<i64>>()));
        let message = collect_field(&errors, "probe.recheck_delays_secs")
            .unwrap_or_else(|| panic!("17 steps must be refused with a message, got {errors:?}"));
        assert_ne!(
            message,
            lang.t_args("val.in_range", &["0".to_string(), "16".to_string()]),
            "an over-long ladder must not be reported as a scalar range"
        );
        assert_eq!(
            message, "at most 16 entries",
            "the count message must not borrow this helper's caller's vocabulary"
        );
        assert!(
            load_config(Some(&path)).is_ok(),
            "the refused ladder must not have been written"
        );

        // Per-delay range: 0, a negative and 30 days + 1s are out,
        // 30 days exactly is in.
        for (value, accepted) in [
            ("0", false),
            ("-1", false),
            ("2592001", false),
            ("2592000", true),
        ] {
            let raw = HashMap::from([("probe.recheck_delays_secs".to_string(), value.into())]);
            let errors = save(&raw);
            assert_eq!(
                collect_field(&errors, "probe.recheck_delays_secs").is_some(),
                !accepted,
                "delay {value} accepted={accepted}, errors: {errors:?}"
            );
        }

        // An emptied textarea is refused, not silently written as an empty
        // ladder: the field hint never mentions that `[]` means «remove
        // the proxy right after the failed second chance», and the panel
        // must not trade the operator's ladder for that on a stray
        // select-all + delete.
        let errors = save(&ladder(&[]));
        assert_eq!(
            collect_field(&errors, "probe.recheck_delays_secs"),
            Some(lang.t("val.empty_list")),
            "an emptied ladder must be refused: {errors:?}"
        );
        let loaded = load_config(Some(&path)).expect("the last good ladder must still load");
        assert_eq!(
            loaded.probe.recheck_delays_secs,
            vec![2_592_000],
            "the refused empty ladder must not have been written"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writer_helper_compiles() {
        let s = String::from("ok");
        assert_eq!(s, "ok");
    }

    /// Regression for the *Edit settings* bug where the page re-rendered
    /// stale `state.config` instead of reading the file the editor just
    /// wrote to. After `EditableConfig::save()`, a subsequent reload
    /// must hand the form the new on-disk values, not the in-memory
    /// snapshot frozen at startup.
    #[test]
    fn raw_from_config_reflects_post_save_file_state() {
        use fumox_core::config::load_config;

        let dir = std::env::temp_dir().join(format!("fumox-edit-postsave-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.toml");

        std::fs::write(
            &path,
            "[ingest]\ndrop_gate = false\n[admin]\nsecure_cookies = true\n",
        )
        .unwrap();

        let cfg = load_config(Some(&path)).expect("initial load must work");
        let raw = raw_from_config(&cfg);
        // `drop_gate = false` in the file → key present with empty value
        // (template's `bool_value` returns `!v.is_empty()`, so empty ==
        // unchecked).
        assert_eq!(raw.get("ingest.drop_gate").map(String::as_str), Some(""));
        // `secure_cookies = true` → "on".
        assert_eq!(
            raw.get("admin.secure_cookies").map(String::as_str),
            Some("on")
        );

        // Simulate the admin save: flip the bool values in the file.
        std::fs::write(
            &path,
            "[ingest]\ndrop_gate = true\n[admin]\nsecure_cookies = false\n",
        )
        .unwrap();

        let cfg = load_config(Some(&path)).expect("post-save load must work");
        let raw = raw_from_config(&cfg);
        // The fresh load must see the *new* file values, not the
        // startup snapshot, this is the regression for the bug where
        // the edit page re-rendered stale in-memory state.
        assert_eq!(raw.get("ingest.drop_gate").map(String::as_str), Some("on"));
        assert_eq!(
            raw.get("admin.secure_cookies").map(String::as_str),
            Some("")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every number input in the settings form resolves to a row in
    /// `config::bounds`, and no bound in that table is left unrendered.
    ///
    /// The ranges used to exist twice: as literal `min`/`max` attributes
    /// in the template and as literal arguments at the save site. The two
    /// could disagree and nothing noticed, which is how the rate-limit
    /// inputs ended up advertising a range the server never checked. Now
    /// that both read one table, the only drift left to guard is the
    /// table losing or gaining a key the form does not use, and a key
    /// typed into a field that is not in the table at all.
    #[test]
    fn every_number_input_has_a_bounds_entry() {
        let template = include_str!("../../../templates/settings_edit.html");
        let mut seen = Vec::new();
        for line in template.lines() {
            let Some(rest) = line.split(r#"type="number""#).nth(1) else {
                continue;
            };
            let Some(name) = rest
                .split(r#"name=""#)
                .nth(1)
                .and_then(|s| s.split('"').next())
            else {
                continue;
            };
            seen.push(name.to_string());
        }
        assert!(seen.len() > 25, "template parsing broke: {seen:?}");
        for name in &seen {
            assert!(
                bounds::range_of(name).is_some(),
                "{name} is a number input with no range in config::bounds::RANGES"
            );
        }
        for (key, _) in bounds::RANGES {
            assert!(
                seen.iter().any(|n| n == key),
                "{key} is bounded but no input edits it; drop it or add the field"
            );
        }
    }

    /// The form must not carry its own numbers: a literal `min="1"` is
    /// exactly the duplication this table replaced, and it is the one a
    /// reviewer will not notice is now out of date.
    #[test]
    fn the_template_takes_no_literal_bounds() {
        let template = include_str!("../../../templates/settings_edit.html");
        for line in template.lines() {
            assert!(
                !line.contains(r#"min=""#) || line.contains("self.range_min"),
                "literal min in: {line}"
            );
            assert!(
                !line.contains(r#"max=""#) || line.contains("self.range_max"),
                "literal max in: {line}"
            );
        }
    }

    /// The form has always advertised `min="1" max="1000000"` on the
    /// rate-limit inputs. Before the table existed nothing checked it:
    /// only the browser's own number validation enforced it, so a POST
    /// that skipped the browser wrote `0/min` and locked every public
    /// route behind a zero budget. The bound is now the loader's.
    #[test]
    fn rate_limit_rejects_a_value_outside_the_advertised_range() {
        let dir = temp_dir("rate-range");
        let path = write_minimal_config(&dir);
        let lang = test_lang();

        for (value, expect_error) in [("0", true), ("1000001", true), ("1", false)] {
            let mut raw = HashMap::new();
            raw.insert("server.rate_limit.limit".into(), value.into());
            raw.insert("server.rate_limit.unit".into(), "min".into());
            let mut errors = Vec::new();
            let mut cfg = EditableConfig::load(&path).unwrap();
            apply_all(&raw, &mut cfg, &lang, &mut errors);

            assert_eq!(
                collect_field(&errors, "server.rate_limit.limit").is_some(),
                expect_error,
                "rate_limit.limit = {value}: {errors:?}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An unbounded setting says so in words and leaves `max` empty.
    /// Printing `u64::MAX / 2` would be a true number nobody can type,
    /// and printing `0` would be a lie the browser reads as "max zero".
    #[test]
    fn an_unbounded_setting_renders_an_empty_max() {
        assert_eq!(bounds::max_attr("fetch.max_response_bytes"), "");
        assert_eq!(bounds::min_attr("fetch.max_response_bytes"), "1024");
        assert_eq!(
            bounds::display("fetch.max_response_bytes", "and up").as_deref(),
            Some("1024 and up")
        );
        assert_eq!(bounds::max_attr("probe.sample_size"), "100000");
        assert_eq!(
            bounds::display("probe.sample_size", "and up").as_deref(),
            Some("0..=100000")
        );
    }
}
