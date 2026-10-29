//! Profile screens: list, create/edit form with source composition
//!, card with dedup stats and an in-process output
//! preview, toggle / delete actions.

use super::{
    FormError, action_response, is_htmx, mask_secret, not_found, pipeline_from_form,
    row_error_response, server_error, validate_countries, validate_name, validate_slug,
    validate_token,
};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::pipeline_editor::{widget_from_posted, widget_from_stored};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{ConnectInfo, Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::models::{OutputFormat, Profile, new_id, now_ts};
use fumox_core::repo::{profiles, sources};
use std::net::SocketAddr;
use std::str::FromStr;

/// Preview length on the profile card.
const PREVIEW_LINES: usize = 50;

/// The placeholder the token field shows for a stored token.
///
/// The token is stored as a hash, so there is nothing to mask: the field
/// shows a fixed stand-in, and an unchanged stand-in means "keep the
/// stored token". A row written before hashing still holds the token in
/// plain text, and its mask is what the form shows.
const TOKEN_PLACEHOLDER: &str = "••••••";

/// The profile fields the admin card renders.
///
/// The card never receives the model: the model's access token is a
/// secret (the database keeps its hash), and a template must not be able
/// to reach it.
#[derive(Debug, Clone)]
struct ProfileCard {
    id: String,
    slug: Option<String>,
    name: String,
    output_format: OutputFormat,
    created_at: i64,
    updated_at: i64,
    enabled: bool,
}

impl ProfileCard {
    fn from_profile(profile: &Profile) -> Self {
        Self {
            id: profile.id.clone(),
            slug: profile.slug.clone(),
            name: profile.name.clone(),
            output_format: profile.output_format,
            created_at: profile.created_at,
            updated_at: profile.updated_at,
            enabled: profile.enabled,
        }
    }
}

/// The value the token field of the form carries: a stand-in for a
/// stored token, empty when the profile has none.
fn token_placeholder(stored: Option<&str>) -> String {
    match stored {
        None => String::new(),
        Some(value) if fumox_core::token::is_hashed(value) => TOKEN_PLACEHOLDER.to_string(),
        Some(value) => mask_secret(value),
    }
}

/// Whether the token field carries a placeholder rather than a value the
/// operator typed: the fixed stand-in of a hashed token, or the mask of a
/// legacy plain-text one. A typed token never contains a mask character
/// (the charset check refuses them), so the two cannot be confused.
fn is_token_placeholder(value: &str) -> bool {
    value == TOKEN_PLACEHOLDER || value == "••••" || value.ends_with("…••••")
}

// List

#[derive(Template)]
#[template(path = "profiles/list.html")]
struct ProfilesListTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    rows: Vec<profiles::ProfileListRow>,
}

impl_i18n!(ProfilesListTemplate);

pub async fn profiles_list(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let rows: Vec<profiles::ProfileListRow> = match profiles::list_with_counts(&state.pool).await {
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

// Form (create / edit)

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
    /// Pipeline widget HTML (builder ⇄ raw): the profile
    /// flavor with tri-state section controls (inherit / defaults / set).
    widget_html: String,
}

impl_i18n!(ProfileFormTemplate, errors);

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
            // New profile: nothing stored yet, an empty builder widget.
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
        access_token: token_placeholder(profile.access_token.as_deref()),
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
/// the reason it could not be built: per-field errors (localized, shown
/// next to fields) or a row that could not be read.
async fn build_profile_from_form(
    state: &AdminState,
    lang: &Lang,
    form: &[(String, String)],
    existing_id: Option<&str>,
) -> Result<Profile, FormError> {
    let get = |key: &str| -> String {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };

    let mut errors: Vec<(String, String)> = Vec::new();

    let name = get("name");
    if let Err(message) = validate_name(&name, lang) {
        errors.push(("name".into(), message));
    }

    let slug_raw = get("slug");
    let slug = validate_slug(
        &slug_raw,
        existing_id,
        lang,
        &mut errors,
        profiles::get_by_slug(&state.pool, &slug_raw),
    )
    .await;

    // The placeholder is resolved before validation: `…`/`•` are outside
    // the token charset, so an unchanged placeholder must never be
    // checked as typed.
    let token_raw = get("access_token");
    let stored = match existing_id {
        Some(id) => match profiles::get(&state.pool, id).await {
            Ok(Some(profile)) => Some(profile),
            Ok(None) => {
                return Err(FormError::Server(fumox_core::Error::NotFound(format!(
                    "profile {id}"
                ))));
            }
            Err(err) => return Err(FormError::Server(err)),
        },
        None => None,
    };
    let stored_token = stored.as_ref().and_then(|p| p.access_token.as_deref());
    // An unchanged placeholder keeps the stored token; anything else is a
    // token the operator typed.
    let unchanged = stored_token.is_some() && token_raw == token_placeholder(stored_token);
    let access_token = if unchanged {
        stored_token.map(str::to_string)
    } else if token_raw.is_empty() {
        None
    } else {
        Some(token_raw.clone())
    };
    // Token format cap: the token guards a public
    // endpoint, so it is URL-safe and bounded like every other field.
    if !unchanged
        && let Some(token) = access_token.as_ref()
        && let Err(message) = validate_token(token, lang)
    {
        errors.push(("access_token".into(), message));
    }

    let format_raw = get("output_format");
    let output_format = match OutputFormat::from_str(&format_raw) {
        Ok(format) => format,
        Err(_) => {
            errors.push(("output_format".into(), lang.t("val.unknown_value").into()));
            OutputFormat::UriList
        }
    };

    // Pipeline: the shared form validation. The tri-state radios let a
    // profile explicitly reset a source's section to the built-in defaults
    // by emitting an empty section.
    let pipeline = pipeline_from_form(form, lang, &mut errors);

    // Country allowlist: comma-separated ISO 3166-1 alpha-2 codes; empty
    // means no filtering. Validated per code, normalized to uppercase.
    let countries_raw = get("countries");
    let countries: Vec<String> = match validate_countries(
        &countries_raw
            .split(',')
            .map(|code| code.trim().to_string())
            .filter(|code| !code.is_empty())
            .collect::<Vec<_>>(),
        lang,
    ) {
        Ok(list) => list,
        Err(message) => {
            errors.push(("countries".into(), message));
            Vec::new()
        }
    };

    // Every selected source must exist (guards against stale form posts).
    let composition = composition_from_form(form);
    for (source_id, _) in &composition {
        match sources::get(&state.pool, source_id).await {
            Ok(Some(_)) => {}
            Ok(None) => errors.push((
                "sources".into(),
                lang.t("val.source_missing").replace("{}", source_id),
            )),
            // A failed query is not a bad choice of sources: it is a
            // broken database, and it must not be rendered as a field
            // error the operator can "fix".
            Err(err) => return Err(FormError::Server(err)),
        }
    }

    if !errors.is_empty() {
        return Err(FormError::Validation(errors));
    }

    let now = now_ts();

    Ok(Profile {
        id: existing_id.map(str::to_string).unwrap_or_else(new_id),
        slug,
        access_token,
        name,
        output_format,
        pipeline,
        countries,
        enabled: form.iter().any(|(k, _)| k == "enabled"),
        // `stored` is the row read above for the mask, so `created_at`
        // carries over without a second query.
        created_at: stored.as_ref().map(|p| p.created_at).unwrap_or(now),
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
            token_masked_note: is_token_placeholder(&values.access_token),
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
        Err(FormError::Validation(errors)) => {
            return form_error_response(&state, lang, &headers, &form, None, errors).await;
        }
        Err(FormError::Server(err)) => {
            return row_error_response(lang, &err, "err.profile_not_found");
        }
    };
    if let Err(err) = profiles::create(&state.pool, &profile).await {
        return server_error(lang, &err);
    }
    if let Err(err) = profiles::replace_sources(&state.pool, &profile.id, &composition).await {
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
        Err(FormError::Validation(errors)) => {
            return form_error_response(&state, lang, &headers, &form, Some(id), errors).await;
        }
        Err(FormError::Server(err)) => {
            return row_error_response(lang, &err, "err.profile_not_found");
        }
    };
    if let Err(err) = profiles::update(&state.pool, &profile).await {
        return row_error_response(lang, &err, "err.profile_not_found");
    }
    if let Err(err) = profiles::replace_sources(&state.pool, &profile.id, &composition).await {
        return server_error(lang, &err);
    }
    // Saved means immediately effective.
    state.caches.invalidate_profile(&profile.id).await;
    tracing::info!(profile = %profile.id, "profile updated");
    Redirect::to(&format!("/admin/profiles/{}", profile.id)).into_response()
}

// Card

#[derive(Template)]
#[template(path = "profiles/detail.html")]
struct ProfileDetailTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    profile: ProfileCard,
    serve_path: String,
    serve_url: String,
    token_display: String,
    /// Whether the endpoint is protected by an access token; the card
    /// says so next to the link, which can no longer carry the token.
    token_required: bool,
    countries_display: String,
    pipeline_display: String,
    composition: Vec<profiles::CompositionRow>,
    stats_total: i64,
    stats_unique: i64,
    stats_dupes: i64,
    preview: Vec<String>,
    preview_note: Option<String>,
    /// The card includes `profiles/_toggle_form.html`, whose standalone
    /// variant marks the form as an out-of-band swap in the toggle
    /// response; the page itself always renders it plain.
    swap_oob: bool,
}

impl_i18n!(ProfileDetailTemplate);

pub async fn profile_detail(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let profile = match profiles::get(&state.pool, &id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return not_found(lang, "err.profile_not_found"),
        Err(err) => return server_error(lang, &err),
    };

    let composition: Vec<profiles::CompositionRow> =
        match profiles::composition(&state.pool, &id).await {
            Ok(rows) => rows,
            Err(err) => return server_error(lang, &err),
        };

    // Dedup statistics across the composition:
    // total link rows vs distinct fingerprints.
    let stats = match profiles::dedup_stats(&state.pool, &id).await {
        Ok(stats) => stats,
        Err(err) => return server_error(lang, &err),
    };
    let (stats_total, stats_unique) = (stats.total, stats.unique);

    // Output preview: render in-process exactly what /sub would serve.
    let app_state = crate::serve::AppState::new(
        state.pool.clone(),
        state.caches.clone(),
        state.geo.clone(),
        // The preview renders in-process and never crosses the public
        // rate-limit middleware; fresh counters here are never consulted.
        crate::serve::PublicRateLimits::unlimited(),
        Vec::new(),
        fumox_core::config::TrustedHeader::None,
        Vec::new(),
        state.server().export_max_rows,
        state.export_token.clone(),
    );
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
    // The token is stored as a hash: the panel cannot show it and the
    // copyable link cannot carry it, so the endpoint answers only with
    // `?token=…` (or a Bearer header). The operator appends the token
    // they set.
    let base = match state.serve_base(peer, &headers) {
        Ok(b) => b,
        Err(err) => return super::server_error(lang, &fumox_core::Error::Config(err.to_string())),
    };
    let serve_url = format!("{base}{serve_path}");

    let token_required = profile.access_token.is_some();
    let token_display = if token_required {
        token_placeholder(profile.access_token.as_deref())
    } else {
        lang.t("prof.token_public").to_string()
    };
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
            token_required,
            countries_display,
            pipeline_display: profile
                .pipeline
                .as_ref()
                .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
                .unwrap_or_default(),
            stats_dupes: stats_total - stats_unique,
            profile: ProfileCard::from_profile(&profile),
            composition,
            stats_total,
            stats_unique,
            preview,
            preview_note,
            swap_oob: false,
        },
        StatusCode::OK,
    )
}

// Actions

/// The enabled badge of the profile card, as a standalone fragment: the
/// detail page includes the same file, and the toggle action re-renders it
/// after every swap, so the initial markup and the swap are one definition.
#[derive(Template)]
#[template(path = "profiles/_enabled_badge.html")]
struct EnabledBadgeFragment {
    lang: Lang,
    profile: ProfileCard,
}

impl_i18n!(EnabledBadgeFragment);

/// The toggle form of the profile card, same include-as-initial-render
/// pattern as [`EnabledBadgeFragment`]. `swap_oob` adds the
/// `hx-swap-oob` attribute that makes the form in a toggle response
/// replace itself out-of-band; the initial page renders it plain.
#[derive(Template)]
#[template(path = "profiles/_toggle_form.html")]
struct ToggleFormFragment {
    lang: Lang,
    profile: ProfileCard,
    csrf: String,
    swap_oob: bool,
}

impl_i18n!(ToggleFormFragment);

/// The toggle response body: the badge swapped into `#enabled-badge`
/// normally plus the form marked out-of-band. Both halves come from the
/// fragment templates the detail page includes, so the ids, aria
/// attributes and the hx-* contract cannot drift from the initial render.
fn toggle_swap_fragment(lang: &Lang, profile: &Profile, csrf: &str) -> String {
    let card = ProfileCard::from_profile(profile);
    let badge = EnabledBadgeFragment {
        lang: lang.clone(),
        profile: card.clone(),
    }
    .render()
    .expect("badge fragment renders");
    let form = ToggleFormFragment {
        lang: lang.clone(),
        profile: card,
        csrf: csrf.to_string(),
        swap_oob: true,
    }
    .render()
    .expect("toggle form fragment renders");
    format!("{badge}\n{form}")
}

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
        return row_error_response(lang, &err, "err.profile_not_found");
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
        // The wrapper id must survive the swap (the form's hx-target points
        // at it), and the toggle button must flip with the state, it lives
        // outside the badge, so it travels along as an out-of-band swap.
        // Both elements are rendered from the same fragment templates the
        // detail page includes, so the swap cannot drop the aria attributes
        // or drift from the initial markup.
        toggle_swap_fragment(&lang, &profile, &state.csrf_for(&headers)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::handlers::caps;

    /// Admin state on a throwaway migrated database: the form builder
    /// only touches the pool (slug/target lookups, stored token).
    async fn test_state() -> (fumox_core::tempdir_lite::TempDir, AdminState) {
        crate::admin::test_admin_state(Default::default(), Default::default()).await
    }

    fn stored_profile(token: Option<&str>) -> Profile {
        let now = now_ts();
        Profile {
            id: new_id(),
            slug: Some("p1".into()),
            access_token: token.map(str::to_string),
            name: "p1".into(),
            output_format: OutputFormat::UriList,
            pipeline: None,
            countries: Vec::new(),
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// The per-field errors of a refused form. A server-side failure is
    /// not a form error, so it fails the test instead of hiding behind
    /// an empty error list.
    fn field_errors(err: FormError) -> Vec<(String, String)> {
        match err {
            FormError::Validation(errors) => errors,
            FormError::Server(err) => panic!("the form failed on the server: {err}"),
        }
    }

    /// The edit form re-renders the stored secret as a fixed placeholder
    /// (`••••••`) and posts it back verbatim on any save. The placeholder
    /// is not a token, so the charset check used to reject it and the
    /// whole save came back 422: a profile with an access token could
    /// never be renamed, re-slugged or re-pointed at other sources.
    #[tokio::test]
    async fn unchanged_masked_token_keeps_the_stored_secret() {
        let (_dir, state) = test_state().await;
        let lang = state.locales.default_lang();
        let secret = "supersecretvalue";
        let stored = stored_profile(Some(secret));
        profiles::create(&state.pool, &stored).await.unwrap();

        // The row holds the hash, never the secret.
        let stored_row = profiles::get(&state.pool, &stored.id)
            .await
            .unwrap()
            .unwrap();
        let stored_hash = stored_row
            .access_token
            .clone()
            .expect("the token is stored");
        assert_ne!(stored_hash, secret, "the secret must not be at rest");
        assert!(fumox_core::token::is_hashed(&stored_hash));

        // Exactly what GET /admin/profiles/{id}/edit hands the browser.
        let placeholder = token_placeholder(Some(&stored_hash));
        assert_eq!(placeholder, TOKEN_PLACEHOLDER);
        let form: Vec<(String, String)> = vec![
            ("name".into(), "renamed".into()),
            ("slug".into(), "p1".into()),
            ("access_token".into(), placeholder),
            ("output_format".into(), "uri_list".into()),
            ("enabled".into(), "on".into()),
        ];

        let built = build_profile_from_form(&state, &lang, &form, Some(&stored.id))
            .await
            .expect("posting the form back unchanged must save");
        assert_eq!(
            built.access_token.as_deref(),
            Some(stored_hash.as_str()),
            "the unchanged placeholder must keep the stored token"
        );
        // The other fields of the same save did change.
        assert_eq!(built.name, "renamed");

        // An empty field still clears the token (public endpoint).
        let form: Vec<(String, String)> = vec![
            ("name".into(), "renamed".into()),
            ("slug".into(), "p1".into()),
            ("access_token".into(), String::new()),
            ("output_format".into(), "uri_list".into()),
        ];
        let built = build_profile_from_form(&state, &lang, &form, Some(&stored.id))
            .await
            .expect("clearing the token must save");
        assert_eq!(built.access_token, None);
    }

    /// The mask bypass is narrow: a token the operator actually typed is
    /// still held to the format and the cap.
    #[tokio::test]
    async fn a_typed_token_is_still_validated() {
        let (_dir, state) = test_state().await;
        let lang = state.locales.default_lang();
        let stored = stored_profile(None);
        profiles::create(&state.pool, &stored).await.unwrap();

        let with_token = |token: &str| -> Vec<(String, String)> {
            vec![
                ("name".into(), "p1".into()),
                ("slug".into(), "free".into()),
                ("access_token".into(), token.to_string()),
                ("output_format".into(), "uri_list".into()),
            ]
        };

        let errors = field_errors(
            build_profile_from_form(&state, &lang, &with_token("bad token!"), None)
                .await
                .expect_err("a token outside the charset must be refused"),
        );
        assert!(
            errors.iter().any(|(field, _)| field == "access_token"),
            "the format check must still fire: {errors:?}"
        );

        let over = "a".repeat(caps::ACCESS_TOKEN + 1);
        let errors = field_errors(
            build_profile_from_form(&state, &lang, &with_token(&over), None)
                .await
                .expect_err("an over-long token must be refused"),
        );
        assert!(
            errors.iter().any(|(field, _)| field == "access_token"),
            "the cap must still fire: {errors:?}"
        );

        let built = build_profile_from_form(&state, &lang, &with_token("good-token_1"), None)
            .await
            .expect("a well-formed token must save");
        assert_eq!(built.access_token.as_deref(), Some("good-token_1"));
    }

    /// Only the placeholder itself restores the stored token; anything
    /// else typed is validated as typed.
    #[tokio::test]
    async fn a_typed_bullet_is_not_mistaken_for_the_mask() {
        let (_dir, state) = test_state().await;
        let lang = state.locales.default_lang();
        let stored = stored_profile(Some("supersecretvalue"));
        profiles::create(&state.pool, &stored).await.unwrap();
        let stored_row = profiles::get(&state.pool, &stored.id)
            .await
            .unwrap()
            .unwrap();
        let stored_hash = stored_row
            .access_token
            .clone()
            .expect("the token is stored");

        let with_token = |token: &str| -> Vec<(String, String)> {
            vec![
                ("name".into(), "p1".into()),
                ("slug".into(), "p1".into()),
                ("access_token".into(), token.to_string()),
                ("output_format".into(), "uri_list".into()),
            ]
        };

        // The placeholder itself still restores the stored token.
        let placeholder = token_placeholder(Some(&stored_hash));
        let built =
            build_profile_from_form(&state, &lang, &with_token(&placeholder), Some(&stored.id))
                .await
                .expect("the unchanged placeholder must save");
        assert_eq!(built.access_token.as_deref(), Some(stored_hash.as_str()));

        // A typed value that merely contains a bullet is not the
        // placeholder, so it is validated like any other typed value:
        // '•' is outside the token charset and the save is refused rather
        // than silently keeping the old token.
        let errors = field_errors(
            build_profile_from_form(&state, &lang, &with_token("tok•en"), Some(&stored.id))
                .await
                .expect_err("a typed bullet must not resolve to the stored token"),
        );
        assert!(
            errors.iter().any(|(field, _)| field == "access_token"),
            "the format check must fire on a typed bullet: {errors:?}"
        );

        // …and a different, well-formed token rotates the secret.
        let built = build_profile_from_form(
            &state,
            &lang,
            &with_token("rotated-token"),
            Some(&stored.id),
        )
        .await
        .expect("a typed token must replace the stored one");
        assert_eq!(built.access_token.as_deref(), Some("rotated-token"));
    }

    /// The shared slug validation: a bad format and a slug held by another
    /// row are refused, the row's own slug survives an edit, and an empty
    /// field simply means "no slug".
    #[tokio::test]
    async fn slug_validation_rejects_format_and_duplicate() {
        let (_dir, state) = test_state().await;
        let lang = state.locales.default_lang();
        let mut stored = stored_profile(None);
        stored.slug = Some("p1".into());
        profiles::create(&state.pool, &stored).await.unwrap();

        let with_slug = |slug: &str| -> Vec<(String, String)> {
            vec![
                ("name".into(), "p1".into()),
                ("slug".into(), slug.to_string()),
                ("output_format".into(), "uri_list".into()),
            ]
        };

        // Bad format: outside the shared slug charset/length rules.
        let errors = field_errors(
            build_profile_from_form(&state, &lang, &with_slug("no spaces"), None)
                .await
                .expect_err("an invalid slug format must be refused"),
        );
        assert!(
            errors.iter().any(|(field, _)| field == "slug"),
            "the format check must fire on the slug field: {errors:?}"
        );

        // Taken: a new profile may not claim the stored row's slug.
        let errors = field_errors(
            build_profile_from_form(&state, &lang, &with_slug("p1"), None)
                .await
                .expect_err("a slug held by another profile must be refused"),
        );
        assert!(
            errors.iter().any(|(field, _)| field == "slug"),
            "the uniqueness check must fire on the slug field: {errors:?}"
        );

        // Editing the row itself: its own slug stays valid…
        let built = build_profile_from_form(&state, &lang, &with_slug("p1"), Some(&stored.id))
            .await
            .expect("the row's own slug must stay valid on edit");
        assert_eq!(built.slug.as_deref(), Some("p1"));

        // …and an empty field stores no slug at all.
        let built = build_profile_from_form(&state, &lang, &with_slug(""), None)
            .await
            .expect("an empty slug must save");
        assert_eq!(built.slug, None);
    }

    /// A profile row for the swap-fragment tests (id and enabled flag are
    /// all the templates read).
    fn sample_profile(enabled: bool) -> Profile {
        let now = now_ts();
        Profile {
            id: new_id(),
            slug: Some("p1".into()),
            access_token: None,
            name: "p1".into(),
            output_format: OutputFormat::UriList,
            pipeline: None,
            countries: Vec::new(),
            enabled,
            created_at: now,
            updated_at: now,
        }
    }

    fn test_lang() -> Lang {
        crate::admin::i18n::Locales::load(std::path::Path::new("/nonexistent")).default_lang()
    }

    /// The toggle swap is rendered from the fragment templates the detail
    /// page includes, so the ids, aria attributes and the hx-* contract
    /// cannot drift apart.
    #[test]
    fn toggle_swap_fragment_carries_the_page_contract() {
        let lang = test_lang();
        let profile = sample_profile(true);
        let swap = toggle_swap_fragment(&lang, &profile, "csrf-token");

        assert!(
            swap.contains(r#"<span id="enabled-badge" aria-live="polite" aria-atomic="true">"#),
            "the badge half lost the live-region contract: {swap}"
        );
        assert!(swap.contains(r#"<span class="badge on">"#), "{swap}");
        assert!(swap.contains(r#"id="toggle-form""#), "{swap}");
        assert!(
            swap.contains(&format!(
                r#"hx-post="/admin/profiles/{}/toggle""#,
                profile.id
            )),
            "{swap}"
        );
        assert!(
            swap.contains(r##"hx-target="#enabled-badge""##),
            "the form must keep targeting the badge: {swap}"
        );
        assert!(
            swap.contains(r#"hx-swap-oob="outerHTML:#toggle-form""#),
            "the form must travel as an out-of-band swap: {swap}"
        );
        assert!(
            swap.contains(r#"aria-pressed="true""#),
            "the pressed state must flip with the badge: {swap}"
        );
        assert!(swap.contains(r#"value="csrf-token""#), "{swap}");
        assert!(swap.contains(lang.t("common.disable")), "{swap}");
        assert!(swap.contains(lang.t("common.on")), "{swap}");
    }

    /// The disabled flip: badge class, pressed state and button label all
    /// follow the stored state.
    #[test]
    fn toggle_swap_fragment_flips_with_the_disabled_state() {
        let lang = test_lang();
        let swap = toggle_swap_fragment(&lang, &sample_profile(false), "csrf-token");

        assert!(swap.contains(r#"<span class="badge off">"#), "{swap}");
        assert!(!swap.contains(r#"<span class="badge on">"#), "{swap}");
        assert!(swap.contains(r#"aria-pressed="false""#), "{swap}");
        assert!(swap.contains(lang.t("common.enable")), "{swap}");
    }

    /// Byte-compatibility: the page renders the form fragment with
    /// `swap_oob = false`, the swap with `swap_oob = true`, and the two
    /// outputs are identical apart from exactly the one attribute.
    #[test]
    fn the_oob_marker_is_the_only_difference_from_the_page_render() {
        let lang = test_lang();
        let profile = sample_profile(true);
        let page_form = ToggleFormFragment {
            lang: lang.clone(),
            profile: ProfileCard::from_profile(&profile),
            csrf: "csrf-token".into(),
            swap_oob: false,
        }
        .render()
        .unwrap();
        let swap_form = ToggleFormFragment {
            lang: lang.clone(),
            profile: ProfileCard::from_profile(&profile),
            csrf: "csrf-token".into(),
            swap_oob: true,
        }
        .render()
        .unwrap();

        assert!(!page_form.contains("hx-swap-oob"), "{page_form}");
        assert_eq!(
            swap_form.replace(r#" hx-swap-oob="outerHTML:#toggle-form""#, ""),
            page_form,
            "the swap render must be the page render plus the oob marker"
        );
    }
}
