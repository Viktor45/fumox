//! Profile screens: list, create/edit form with source composition
//! (ADMIN_PLAN §4.3), card with dedup stats and an in-process output
//! preview, toggle / delete actions.

use super::{action_response, is_htmx, mask_secret, not_found, server_error};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::pipeline_editor::{BuilderState, widget_from_posted, widget_from_stored};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use crate::pipeline::CompiledPipeline;
use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::models::{OutputFormat, Profile, new_id, now_ts};
use fumox_core::repo::{profiles, sources};
use std::str::FromStr;

/// Slug rules shared with sources (ADMIN_PLAN §4.2): starts alphanumeric,
/// then `[A-Za-z0-9_-]`, total length 2–64.
const SLUG_RE: &str = r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$";

/// Preview length on the profile card (ADMIN_PLAN §4.3).
const PREVIEW_LINES: usize = 50;

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct ProfileListRow {
    id: String,
    name: String,
    slug: Option<String>,
    output_format: String,
    enabled: bool,
    protected: bool,
    sources_count: i64,
}

#[derive(Template)]
#[template(path = "profiles/list.html")]
struct ProfilesListTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    rows: Vec<ProfileListRow>,
}

impl_i18n!(ProfilesListTemplate);

pub async fn profiles_list(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let rows: Vec<ProfileListRow> = match sqlx::query_as(
        "SELECT p.id, p.name, p.slug, p.output_format, p.enabled,
                p.access_token IS NOT NULL AS protected,
                (SELECT COUNT(*) FROM profile_sources ps WHERE ps.profile_id = p.id) AS sources_count
         FROM profiles p
         ORDER BY p.created_at",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };
    render_html(
        lang.clone(),
        &ProfilesListTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "profiles",
            csrf: state.csrf_for(&headers),
            rows,
        },
        StatusCode::OK,
    )
}

// ---------------------------------------------------------------------------
// Form (create / edit)
// ---------------------------------------------------------------------------

/// Display/edit values of the profile form (all as strings, as typed). The
/// pipeline is carried by the widget HTML, not by these values.
#[derive(Debug, Clone, Default)]
struct ProfileFormValues {
    name: String,
    slug: String,
    access_token: String,
    output_format: String,
    countries: String,
    enabled: bool,
}

/// One output-format option of the select.
#[derive(Debug, Clone)]
struct FormatOption {
    value: String,
    label: String,
    available: bool,
    selected: bool,
}

/// One source row of the composition checklist.
#[derive(Debug, Clone)]
struct SourcePick {
    id: String,
    name: String,
    enabled: bool,
    checked: bool,
    position: i64,
}

#[derive(Template)]
#[template(path = "profiles/form.html")]
struct ProfileFormTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    form_id: Option<String>,
    action: String,
    values: ProfileFormValues,
    errors: Vec<(String, String)>,
    formats: Vec<FormatOption>,
    source_picks: Vec<SourcePick>,
    token_masked_note: bool,
    /// Pipeline widget HTML (builder ⇄ raw, PIPELINE.md §3): the profile
    /// flavor with tri-state section controls (inherit / defaults / set).
    widget_html: String,
}

impl ProfileFormTemplate {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|(f, _)| f == field)
            .map(|(_, m)| m.as_str())
    }
}

impl_i18n!(ProfileFormTemplate);

fn format_options(selected: &str, lang: &Lang) -> Vec<FormatOption> {
    vec![
        FormatOption {
            value: "uri_list".into(),
            label: lang.t("prof.format_uri_list").into(),
            available: true,
            selected: selected == "uri_list" || selected.is_empty(),
        },
        FormatOption {
            value: "base64".into(),
            label: "Base64".into(),
            available: true,
            selected: selected == "base64",
        },
        FormatOption {
            value: "clash".into(),
            label: lang.t("prof.format_clash").into(),
            available: true,
            selected: selected == "clash",
        },
        FormatOption {
            value: "sing_box".into(),
            label: lang.t("prof.format_sing_box").into(),
            available: true,
            selected: selected == "sing_box",
        },
    ]
}

/// Composition checklist rows: every source with its current selection and
/// position for this profile.
async fn source_picks(
    state: &AdminState,
    composition: &[(String, i64)],
) -> Result<Vec<SourcePick>, fumox_core::Error> {
    let all = sources::list(&state.pool, false).await?;
    Ok(all
        .into_iter()
        .map(|source| {
            let position = composition
                .iter()
                .find(|(id, _)| *id == source.id)
                .map(|(_, pos)| *pos);
            SourcePick {
                id: source.id.clone(),
                name: source.name.clone(),
                enabled: source.enabled,
                checked: position.is_some(),
                position: position.unwrap_or(0),
            }
        })
        .collect())
}

pub async fn profile_form(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let picks = match source_picks(&state, &[]).await {
        Ok(picks) => picks,
        Err(err) => return server_error(lang, &err),
    };
    let formats = format_options("uri_list", &lang);
    render_html(
        lang.clone(),
        &ProfileFormTemplate {
            lang: lang.clone(),
            langs: state.locales.choices().to_vec(),
            theme,
            active: "profiles",
            csrf: state.csrf_for(&headers),
            form_id: None,
            action: "/admin/profiles/new".into(),
            values: ProfileFormValues {
                enabled: true,
                output_format: "uri_list".into(),
                ..Default::default()
            },
            errors: Vec::new(),
            formats,
            source_picks: picks,
            token_masked_note: false,
            // New profile: nothing stored yet — an empty builder widget.
            widget_html: widget_from_stored(
                lang,
                &state.csrf_for(&headers),
                None,
                String::new(),
                true,
            ),
        },
        StatusCode::OK,
    )
}

pub async fn profile_edit_form(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let profile = match profiles::get(&state.pool, &id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return not_found(lang, "err.profile_not_found"),
        Err(err) => return server_error(lang, &err),
    };
    let composition = match profiles::get_sources(&state.pool, &id).await {
        Ok(composition) => composition,
        Err(err) => return server_error(lang, &err),
    };
    let picks = match source_picks(&state, &composition).await {
        Ok(picks) => picks,
        Err(err) => return server_error(lang, &err),
    };
    let format = profile.output_format.as_str().to_string();
    let raw_value = profile
        .pipeline
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
        .unwrap_or_default();
    let widget_html = widget_from_stored(
        lang.clone(),
        &state.csrf_for(&headers),
        profile.pipeline.as_ref(),
        raw_value,
        true,
    );
    let values = ProfileFormValues {
        name: profile.name.clone(),
        slug: profile.slug.clone().unwrap_or_default(),
        access_token: profile
            .access_token
            .as_deref()
            .map(mask_secret)
            .unwrap_or_default(),
        output_format: format.clone(),
        countries: profile.countries.join(", "),
        enabled: profile.enabled,
    };
    let formats = format_options(&format, &lang);
    render_html(
        lang.clone(),
        &ProfileFormTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "profiles",
            csrf: state.csrf_for(&headers),
            form_id: Some(profile.id.clone()),
            action: format!("/admin/profiles/{}/edit", profile.id),
            values,
            errors: Vec::new(),
            formats,
            source_picks: picks,
            token_masked_note: profile.access_token.is_some(),
            widget_html,
        },
        StatusCode::OK,
    )
}

/// Parse the submitted composition: checked `sources` fields ordered by
/// their `pos_{id}` numbers (ties keep the checkbox order), normalized to
/// dense 0-based positions.
fn composition_from_form(form: &[(String, String)]) -> Vec<(String, i64)> {
    let selected: Vec<String> = form
        .iter()
        .filter(|(k, _)| k == "sources")
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    let mut ordered: Vec<(i64, usize, String)> = selected
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let position = form
                .iter()
                .rev()
                .find(|(k, _)| k == &format!("pos_{id}"))
                .and_then(|(_, v)| v.trim().parse::<i64>().ok())
                .unwrap_or(index as i64);
            (position, index, id.clone())
        })
        .collect();
    ordered.sort_by_key(|(position, index, _)| (*position, *index));
    // Deduplicate defensively, then normalize positions.
    let mut seen = std::collections::HashSet::new();
    ordered
        .into_iter()
        .filter(|(_, _, id)| seen.insert(id.clone()))
        .enumerate()
        .map(|(index, (_, _, id))| (id, index as i64))
        .collect()
}

/// Validate + assemble a `Profile` from form fields. Returns the model or
/// per-field errors (localized, shown next to fields).
async fn build_profile_from_form(
    state: &AdminState,
    lang: &Lang,
    form: &[(String, String)],
    existing_id: Option<&str>,
) -> Result<Profile, Vec<(String, String)>> {
    let get = |key: &str| -> String {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };

    let mut errors: Vec<(String, String)> = Vec::new();

    let name = get("name");
    if name.is_empty() {
        errors.push(("name".into(), lang.t("val.required").into()));
    } else if name.chars().count() > 200 {
        errors.push(("name".into(), lang.t("val.name_too_long").into()));
    }

    let slug_raw = get("slug");
    let slug = if slug_raw.is_empty() {
        None
    } else {
        if !regex::Regex::new(SLUG_RE).is_ok_and(|re| re.is_match(&slug_raw)) {
            errors.push(("slug".into(), lang.t("val.slug_format").into()));
        } else if let Ok(Some(other)) = profiles::get_by_slug(&state.pool, &slug_raw).await
            && other.id != existing_id.unwrap_or_default()
        {
            errors.push(("slug".into(), lang.t("val.slug_taken").into()));
        }
        Some(slug_raw)
    };

    // Access token: an unchanged masked placeholder keeps the stored secret;
    // an empty field clears the token (public endpoint).
    let token_raw = get("access_token");
    let mut access_token = if token_raw.is_empty() {
        None
    } else {
        Some(token_raw.clone())
    };
    if let Some(id) = existing_id
        && token_raw.contains('•')
        && let Ok(Some(stored)) = profiles::get(&state.pool, id).await
    {
        access_token = stored.access_token;
    }

    let format_raw = get("output_format");
    let output_format = match OutputFormat::from_str(&format_raw) {
        Ok(format) => format,
        Err(_) => {
            errors.push(("output_format".into(), lang.t("val.unknown_value").into()));
            OutputFormat::UriList
        }
    };

    // Pipeline (PIPELINE.md §3, §6): in builder mode the JSON is generated
    // from the widget fields server-side (a stale `pipeline` textarea, if
    // any, is ignored); in raw mode the textarea is the input, as before.
    // The tri-state radios let a profile explicitly reset a source's
    // section to the SPEC defaults by emitting an empty section.
    let pipeline = if get("pipeline_mode") == "builder" {
        let generated = BuilderState::from_form(form).emit();
        match generated {
            None => None,
            Some(value) => match CompiledPipeline::from_json(Some(&value)) {
                Ok(_) => Some(value),
                Err(issues) => {
                    for issue in issues {
                        errors.push(("pipeline".into(), lang.t_args(issue.key, &issue.args)));
                    }
                    None
                }
            },
        }
    } else {
        let pipeline_raw = get("pipeline");
        if pipeline_raw.trim().is_empty() {
            None
        } else {
            match serde_json::from_str::<serde_json::Value>(&pipeline_raw) {
                Ok(value) => match CompiledPipeline::from_json(Some(&value)) {
                    Ok(_) => Some(value),
                    Err(issues) => {
                        for issue in issues {
                            errors.push(("pipeline".into(), lang.t_args(issue.key, &issue.args)));
                        }
                        None
                    }
                },
                Err(err) => {
                    errors.push((
                        "pipeline".into(),
                        lang.t("val.invalid_json").replace("{}", &err.to_string()),
                    ));
                    None
                }
            }
        }
    };

    // Country allowlist: comma-separated ISO 3166-1 alpha-2 codes; empty
    // means no filtering. Validated per code, normalized to uppercase.
    let countries_raw = get("countries");
    let mut countries: Vec<String> = Vec::new();
    for code in countries_raw.split(',') {
        let code = code.trim();
        if code.is_empty() {
            continue;
        }
        let upper = code.to_ascii_uppercase();
        if upper.len() != 2 || !upper.chars().all(|c| c.is_ascii_alphabetic()) {
            errors.push((
                "countries".into(),
                lang.t("val.country_format").replace("{}", code),
            ));
            continue;
        }
        if !countries.contains(&upper) {
            countries.push(upper);
        }
    }

    // Every selected source must exist (guards against stale form posts).
    let composition = composition_from_form(form);
    for (source_id, _) in &composition {
        match sources::get(&state.pool, source_id).await {
            Ok(Some(_)) => {}
            Ok(None) => errors.push((
                "sources".into(),
                lang.t("val.source_missing").replace("{}", source_id),
            )),
            Err(err) => errors.push(("sources".into(), err.to_string())),
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let now = now_ts();
    let existing = match existing_id {
        Some(id) => profiles::get(&state.pool, id).await.ok().flatten(),
        None => None,
    };

    Ok(Profile {
        id: existing_id.map(str::to_string).unwrap_or_else(new_id),
        slug,
        access_token,
        name,
        output_format,
        pipeline,
        countries,
        enabled: form.iter().any(|(k, _)| k == "enabled"),
        created_at: existing.map(|p| p.created_at).unwrap_or(now),
        updated_at: now,
    })
}

fn form_values_from(form: &[(String, String)]) -> ProfileFormValues {
    let get = |key: &str| -> String {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    ProfileFormValues {
        name: get("name"),
        slug: get("slug"),
        access_token: get("access_token"),
        output_format: get("output_format"),
        countries: get("countries"),
        enabled: form.iter().any(|(k, _)| k == "enabled"),
    }
}

/// Re-render the form after a validation failure, preserving typed values.
async fn form_error_response(
    state: &AdminState,
    lang: Lang,
    headers: &HeaderMap,
    form: &[(String, String)],
    form_id: Option<String>,
    errors: Vec<(String, String)>,
) -> Response {
    let values = form_values_from(form);
    let composition = composition_from_form(form);
    let picks = source_picks(state, &composition).await.unwrap_or_default();
    let formats = format_options(&values.output_format, &lang);
    let pipeline_error = errors
        .iter()
        .find(|(field, _)| field == "pipeline")
        .map(|(_, message)| message.clone());
    let widget_html = widget_from_posted(
        lang.clone(),
        &state.csrf_for(headers),
        form,
        true,
        pipeline_error,
    );
    render_html(
        lang.clone(),
        &ProfileFormTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme: theme::from_headers(headers),
            active: "profiles",
            csrf: state.csrf_for(headers),
            action: match &form_id {
                Some(id) => format!("/admin/profiles/{id}/edit"),
                None => "/admin/profiles/new".into(),
            },
            formats,
            token_masked_note: values.access_token.contains('•'),
            form_id,
            values,
            errors,
            source_picks: picks,
            widget_html,
        },
        StatusCode::UNPROCESSABLE_ENTITY,
    )
}

pub async fn profile_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let composition = composition_from_form(&form);
    let profile = match build_profile_from_form(&state, &lang, &form, None).await {
        Ok(profile) => profile,
        Err(errors) => {
            return form_error_response(&state, lang, &headers, &form, None, errors).await;
        }
    };
    if let Err(err) = profiles::create(&state.pool, &profile).await {
        return server_error(lang, &err);
    }
    if let Err(err) = profiles::set_sources(&state.pool, &profile.id, &composition).await {
        return server_error(lang, &err);
    }
    tracing::info!(profile = %profile.id, "profile created");
    Redirect::to(&format!("/admin/profiles/{}", profile.id)).into_response()
}

pub async fn profile_update(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let composition = composition_from_form(&form);
    let profile = match build_profile_from_form(&state, &lang, &form, Some(&id)).await {
        Ok(profile) => profile,
        Err(errors) => {
            return form_error_response(&state, lang, &headers, &form, Some(id), errors).await;
        }
    };
    if let Err(err) = profiles::update(&state.pool, &profile).await {
        return server_error(lang, &err);
    }
    if let Err(err) = profiles::set_sources(&state.pool, &profile.id, &composition).await {
        return server_error(lang, &err);
    }
    // Saved means immediately effective (ADMIN_PLAN §7).
    state.caches.invalidate_profile(&profile.id).await;
    tracing::info!(profile = %profile.id, "profile updated");
    Redirect::to(&format!("/admin/profiles/{}", profile.id)).into_response()
}

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct CompositionRow {
    source_id: String,
    position: i64,
    name: Option<String>,
    enabled: Option<bool>,
}

#[derive(Template)]
#[template(path = "profiles/detail.html")]
struct ProfileDetailTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    profile: Profile,
    serve_path: String,
    serve_url: String,
    token_display: String,
    countries_display: String,
    pipeline_display: String,
    composition: Vec<CompositionRow>,
    stats_total: i64,
    stats_unique: i64,
    stats_dupes: i64,
    preview: Vec<String>,
    preview_note: Option<String>,
}

impl ProfileDetailTemplate {
    fn ts(&self, ts: &i64) -> String {
        super::fmt_ts_element(*ts)
    }
}

impl_i18n!(ProfileDetailTemplate);

pub async fn profile_detail(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let profile = match profiles::get(&state.pool, &id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return not_found(lang, "err.profile_not_found"),
        Err(err) => return server_error(lang, &err),
    };

    let composition: Vec<CompositionRow> = match sqlx::query_as(
        "SELECT ps.source_id, ps.position, s.name, s.enabled
         FROM profile_sources ps LEFT JOIN sources s ON s.id = ps.source_id
         WHERE ps.profile_id = ?
         ORDER BY ps.position, ps.source_id",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    // Dedup statistics across the composition (ADMIN_PLAN §4.3):
    // total link rows vs distinct fingerprints.
    let (stats_total, stats_unique): (i64, i64) = match sqlx::query_as(
        "SELECT COUNT(*), COUNT(DISTINCT p.fingerprint)
         FROM profile_sources ps
         JOIN proxy_source_links l ON l.source_id = ps.source_id
         JOIN proxies p ON p.id = l.proxy_id
         WHERE ps.profile_id = ?",
    )
    .bind(&id)
    .fetch_one(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(err) => return server_error(lang, &err),
    };

    // Output preview: render in-process exactly what /sub would serve.
    let app_state = crate::serve::AppState {
        pool: state.pool.clone(),
        caches: state.caches.clone(),
        geo: state.geo.clone(),
        refresh_tx: state.refresh_tx.clone(),
        // The preview renders in-process and never crosses the public
        // rate-limit middleware; fresh counters here are never consulted.
        limits: crate::serve::PublicRateLimits::unlimited(),
    };
    let (preview, preview_note) =
        match crate::serve::preview_sub(&app_state, &profile, PREVIEW_LINES).await {
            Ok(lines) if lines.is_empty() => {
                (Vec::new(), Some(lang.t("prof.preview_empty").to_string()))
            }
            Ok(lines) => (lines, None),
            Err(message) => (
                Vec::new(),
                Some(lang.t("prof.preview_unavailable").replace("{}", &message)),
            ),
        };

    let serve_path = format!(
        "/sub/{}",
        profile.slug.clone().unwrap_or_else(|| profile.id.clone())
    );
    // Absolute serve link: the host the admin panel was opened on with the
    // public port from [server].bind (ADMIN_PLAN §4.2).
    let serve_url = format!("{}{}", state.serve_base(&headers), serve_path);

    let token_display = profile
        .access_token
        .as_deref()
        .map(mask_secret)
        .unwrap_or_else(|| lang.t("prof.token_public").to_string());
    let countries_display = if profile.countries.is_empty() {
        lang.t("prof.countries_none").to_string()
    } else {
        profile.countries.join(", ")
    };
    render_html(
        lang.clone(),
        &ProfileDetailTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "profiles",
            csrf: state.csrf_for(&headers),
            serve_path,
            serve_url,
            token_display,
            countries_display,
            pipeline_display: profile
                .pipeline
                .as_ref()
                .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
                .unwrap_or_default(),
            stats_dupes: stats_total - stats_unique,
            profile,
            composition,
            stats_total,
            stats_unique,
            preview,
            preview_note,
        },
        StatusCode::OK,
    )
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

pub async fn profile_toggle(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let mut profile = match profiles::get(&state.pool, &id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return not_found(lang, "err.profile_not_found"),
        Err(err) => return server_error(lang, &err),
    };
    profile.enabled = !profile.enabled;
    profile.updated_at = now_ts();
    if let Err(err) = profiles::update(&state.pool, &profile).await {
        return server_error(lang, &err);
    }
    state.caches.invalidate_profile(&id).await;
    let message = if profile.enabled {
        lang.t("prof.enabled_toast")
    } else {
        lang.t("prof.disabled_toast")
    };
    tracing::info!(profile = %id, enabled = profile.enabled, "profile toggled");
    action_response(
        is_htmx(&headers),
        &format!("/admin/profiles/{id}"),
        format!(
            r#"<span class="badge {}">{}</span>"#,
            if profile.enabled { "on" } else { "off" },
            if profile.enabled {
                lang.t("common.on")
            } else {
                lang.t("common.off")
            }
        ),
        message,
    )
}

pub async fn profile_delete(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    match profiles::delete(&state.pool, &id).await {
        Ok(true) => {}
        Ok(false) => return not_found(lang, "err.profile_not_found"),
        Err(err) => return server_error(lang, &err),
    }
    state.caches.invalidate_profile(&id).await;
    tracing::info!(profile = %id, "profile deleted");
    action_response(
        is_htmx(&headers),
        "/admin/profiles",
        String::new(),
        lang.t("prof.deleted_toast"),
    )
}
