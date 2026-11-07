//! Source screens: list with filters, create/edit form with full
//! validation, card with aggregates and fetch log,
//! toggle / *Refresh now* / delete actions.

use super::logs::{decode_fetch_cursor, journal_page_link};
use super::profiles::token_placeholder;
use super::{
    FormError, FormMap, action_response, action_response_err, caps, flash_redirect, fmt_opt_bytes,
    is_htmx, mask_secret, not_found, pipeline_from_form, row_error_response, server_error,
    ttl_range_message, url_problem_message, validate_header_map, validate_name, validate_slug,
    validate_tags, validate_token, validate_ttl,
};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::pipeline_editor::{widget_from_posted, widget_from_stored};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use crate::fetcher;
use crate::redact::{REDACTED, is_sensitive_param, mask_query, query_span, userinfo_span};
use askama::Template;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::models::{
    Encoding, ErrorClass, InputFormat, IpFamily, Scheme, Source, new_id, now_ts,
};
use fumox_core::repo::{fetch_log, proxies, sources};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;

/// Rows of the fetch log shown on the source card and its polled
/// `sources/_log.html` fragment: one fixed page size, no query parameter
/// (the log is a card detail, not a browsable list screen).
const LOG_PAGE_SIZE: i64 = 20;

/// The source fields the admin card renders.
///
/// The card never receives the model: the model's headers carry the
/// source's `Authorization` and the like, so they must stay out of a
/// template's reach. The masked pairs the card shows are a separate
/// field.
#[derive(Debug, Clone)]
struct SourceCard {
    id: String,
    slug: Option<String>,
    name: String,
    encoding: Encoding,
    input_format: Option<InputFormat>,
    ip_family: Option<IpFamily>,
    tags: Option<Vec<String>>,
    cache_ttl_seconds: i64,
    created_at: i64,
    updated_at: i64,
    last_fetched_at: Option<i64>,
    last_error: Option<String>,
    error_class: Option<ErrorClass>,
    enabled: bool,
    /// Whether `/src` requires the source's own access token (the model's
    /// token is a hash, so the card shows the fact, not the secret).
    token_protected: bool,
}

impl SourceCard {
    fn from_source(source: &Source) -> Self {
        Self {
            id: source.id.clone(),
            slug: source.slug.clone(),
            name: source.name.clone(),
            encoding: source.encoding,
            input_format: source.input_format,
            ip_family: source.ip_family,
            tags: source.tags.clone(),
            cache_ttl_seconds: source.cache_ttl_seconds,
            created_at: source.created_at,
            updated_at: source.updated_at,
            last_fetched_at: source.last_fetched_at,
            last_error: source.last_error.clone(),
            error_class: source.error_class,
            enabled: source.enabled,
            token_protected: source.access_token.is_some(),
        }
    }
}

// List

#[derive(Template)]
#[template(path = "sources/list.html")]
struct SourcesListTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    rows: Vec<sources::SourceListRow>,
    f_enabled: String,
    f_error: bool,
    f_tag: String,
    f_q: String,
    tags: Vec<String>,
}

impl_i18n!(SourcesListTemplate);

/// The `enabled` filter of the list. The select sends `on`/`off`; the
/// boolean synonyms mean the same, so a hand-typed `?enabled=1` or
/// `?enabled=false` filters instead of being dropped on the floor.
/// Any other value filters nothing, like the empty "all" option.
fn enabled_filter_value(raw: &str) -> Option<bool> {
    match raw {
        "on" | "true" | "1" => Some(true),
        "off" | "false" | "0" => Some(false),
        _ => None,
    }
}

pub async fn sources_list(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let f_enabled = params.get("enabled").cloned().unwrap_or_default();
    let f_error = params.get("err").map(|v| v == "1").unwrap_or(false);
    let f_tag = params.get("tag").cloned().unwrap_or_default();
    let f_q = params.get("q").cloned().unwrap_or_default();

    // The filter clause set lives once in the repo (`SourceListFilter`);
    // every value flows through a bind.
    let filter = sources::SourceListFilter {
        enabled: enabled_filter_value(&f_enabled),
        with_errors: f_error,
        tag: f_tag.clone(),
        query: f_q.clone(),
    };
    let rows = match sources::list_filtered(&state.pool, &filter).await {
        Ok(rows) => rows
            .into_iter()
            .map(|mut row| {
                // The list shows the URL of every source: the password
                // of the userinfo and the value of a credential-bearing
                // query pair are secrets and stay in the database.
                row.url = mask_url_secrets(&row.url);
                row
            })
            .collect(),
        Err(err) => return server_error(&state, &headers, "sources.list", &err),
    };

    let tags: Vec<String> = sources::distinct_tags(&state.pool)
        .await
        .unwrap_or_default();

    render_html(
        lang.clone(),
        "sources/list.html",
        &SourcesListTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "sources",
            csrf: state.csrf_for(&headers),
            rows,
            f_enabled,
            f_error,
            f_tag,
            f_q,
            tags,
        },
        StatusCode::OK,
    )
}

// Form (create / edit)

/// Display/edit values of the source form (all as strings, as typed). The
/// pipeline is carried by the widget HTML, not by these values.
#[derive(Debug, Clone, Default)]
struct SourceFormValues {
    name: String,
    slug: String,
    /// The endpoint token as the field shows it: empty, or the
    /// placeholder of a stored token (never the secret itself).
    access_token: String,
    url: String,
    /// Whether the URL field carries a mask: the note about the restore
    /// is only shown when there is a secret to restore.
    url_masked: bool,
    enabled: bool,
    encoding: String,
    input_format: String,
    ip_family: String,
    protocols: Vec<String>,
    cache_ttl_seconds: String,
    tags: String,
    headers: String,
}

#[derive(Template)]
#[template(path = "sources/form.html")]
struct SourceFormTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    form_id: Option<String>,
    action: String,
    values: SourceFormValues,
    errors: Vec<(String, String)>,
    all_protocols: Vec<(String, bool)>,
    headers_masked_note: bool,
    /// Whether the token field shows a placeholder of a stored token: the
    /// note that explains the placeholder is only shown then.
    token_masked_note: bool,
    /// Pipeline widget HTML (builder ⇄ raw), rendered by the
    /// editor module; prefilled from the stored pipeline on GET, from the
    /// posted fields on validation errors.
    widget_html: String,
}

impl_i18n!(SourceFormTemplate, errors);

fn all_protocols_with_selection(selected: &[String]) -> Vec<(String, bool)> {
    Scheme::all()
        .iter()
        .map(|scheme| {
            let name = scheme.as_str().to_string();
            let is_selected = selected.iter().any(|s| s == &name);
            (name, is_selected)
        })
        .collect()
}

/// Render one screen of the source editor. The four call sites — the two
/// GET renders and the two validation-error replays — share the chrome
/// and the response shape here; what differs between them (the form id,
/// the action, the values, the protocol selection, the errors, the
/// status, the header-note flag) rides in the arguments. A caller that
/// re-renders a posted submission parses the form once
/// ([`form_values_from`]) and hands the parsed value over, so the values
/// and the protocol selection cannot drift apart.
#[allow(clippy::too_many_arguments)]
fn render_source_form(
    state: &AdminState,
    headers: &HeaderMap,
    lang: Lang,
    theme: Theme,
    status: StatusCode,
    form_id: Option<String>,
    action: String,
    values: SourceFormValues,
    selected_protocols: &[String],
    errors: Vec<(String, String)>,
    headers_masked_note: bool,
    token_masked_note: bool,
    widget_html: String,
) -> Response {
    render_html(
        lang.clone(),
        "sources/form.html",
        &SourceFormTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "sources",
            csrf: state.csrf_for(headers),
            form_id,
            action,
            values,
            errors,
            all_protocols: all_protocols_with_selection(selected_protocols),
            headers_masked_note,
            token_masked_note,
            widget_html,
        },
        status,
    )
}

pub async fn source_form(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let values = SourceFormValues {
        enabled: true,
        encoding: "auto".into(),
        input_format: String::new(),
        cache_ttl_seconds: "3600".into(),
        ..Default::default()
    };
    // New source: nothing stored yet, an empty builder widget.
    let widget_html = widget_from_stored(
        lang.clone(),
        &state.csrf_for(&headers),
        None,
        String::new(),
        false,
    );
    render_source_form(
        &state,
        &headers,
        lang,
        theme,
        StatusCode::OK,
        None,
        "/admin/sources/new".into(),
        values,
        &[],
        Vec::new(),
        false,
        false,
        widget_html,
    )
}

pub async fn source_edit_form(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let source = match sources::get(&state.pool, &id).await {
        Ok(Some(source)) => source,
        Ok(None) => return not_found(lang, "err.source_not_found"),
        Err(err) => return server_error(&state, &headers, "sources.edit_row", &err),
    };
    // The widget is prefilled from the stored pipeline when the builder can
    // represent it; otherwise it opens in raw mode with the stored JSON and
    // the raw-mode warning.
    let raw_value = source
        .pipeline
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
        .unwrap_or_default();
    let widget_html = widget_from_stored(
        lang.clone(),
        &state.csrf_for(&headers),
        source.pipeline.as_ref(),
        raw_value.clone(),
        false,
    );
    let values = SourceFormValues {
        name: source.name.clone(),
        slug: source.slug.clone().unwrap_or_default(),
        // The stored token is a hash, so the field shows a placeholder.
        access_token: token_placeholder(source.access_token.as_deref()),
        // The secrets of the URL are masked: the form hands the masks
        // back on submit, and the save puts the stored values under them.
        url: mask_url_secrets(&source.url),
        url_masked: mask_url_secrets(&source.url) != source.url,
        enabled: source.enabled,
        encoding: source.encoding.as_str().to_string(),
        input_format: source
            .input_format
            .map(|f| f.as_str().to_string())
            .unwrap_or_default(),
        ip_family: source
            .ip_family
            .map(|f| f.as_str().to_string())
            .unwrap_or_default(),
        protocols: source
            .protocols
            .as_ref()
            .map(|list| list.iter().map(|s| s.as_str().to_string()).collect())
            .unwrap_or_default(),
        cache_ttl_seconds: source.cache_ttl_seconds.to_string(),
        tags: source
            .tags
            .as_ref()
            .map(|tags| tags.join(", "))
            .unwrap_or_default(),
        headers: source
            .headers
            .as_ref()
            .map(|map| {
                map.iter()
                    .map(|(k, v)| format!("{k}: {}", mask_secret(v)))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
    };
    let headers_masked_note = source.headers.as_ref().is_some_and(|map| !map.is_empty());
    render_source_form(
        &state,
        &headers,
        lang,
        theme,
        StatusCode::OK,
        Some(source.id.clone()),
        format!("/admin/sources/{}/edit", source.id),
        values,
        &values_for_select(&source),
        Vec::new(),
        headers_masked_note,
        source.access_token.is_some(),
        widget_html,
    )
}

fn values_for_select(source: &Source) -> Vec<String> {
    source
        .protocols
        .as_ref()
        .map(|list| list.iter().map(|s| s.as_str().to_string()).collect())
        .unwrap_or_default()
}

// The URL and the header values carry the credentials of the upstream
// feed. The admin screens show them, so the secrets are masked there and
// restored from the stored row when the form comes back — the mask is a
// display form, never the value that is stored.

/// The password of a URL's userinfo, if it has one.
fn url_password(url: &str) -> Option<&str> {
    let (start, end) = userinfo_span(url)?;
    let userinfo = &url[start..end];
    let colon = userinfo.find(':')?;
    Some(&userinfo[colon + 1..])
}

/// The URL as the admin shows it: the password of the userinfo masked.
///
/// The username stays: it tells the operator which account the feed
/// belongs to. The password is the secret, so it is replaced by its
/// mask, exactly like the header values.
fn mask_url_userinfo(url: &str) -> String {
    let Some((start, end)) = userinfo_span(url) else {
        return url.to_string();
    };
    let userinfo = &url[start..end];
    let Some(colon) = userinfo.find(':') else {
        // A userinfo without a password carries no secret.
        return url.to_string();
    };
    let masked = mask_secret(&userinfo[colon + 1..]);
    format!(
        "{}{}:{masked}{}",
        &url[..start],
        &userinfo[..colon],
        &url[end..]
    )
}

/// The URL as the admin shows it: the password of the userinfo masked and
/// the value of every credential-bearing query pair redacted.
///
/// A subscription token travels in the query as often as a password
/// travels in the userinfo, and the query value is replaced whole: there
/// is no account name to keep, the pair itself is the secret.
fn mask_url_secrets(url: &str) -> String {
    mask_query(&mask_url_userinfo(url))
}

/// The submitted URL with the stored password put back where the form
/// still carries the mask rendered from it.
///
/// The mask is valid in the one place it was rendered for — the password
/// of the userinfo — so it is restored only there. A password that is
/// not the mask is kept exactly as typed: a fresh secret replaces the
/// mask, and a URL without a password keeps the one it was given.
fn restore_url_password(submitted: &str, stored: &str) -> String {
    let Some(stored_password) = url_password(stored) else {
        return submitted.to_string();
    };
    let Some(submitted_password) = url_password(submitted) else {
        return submitted.to_string();
    };
    if submitted_password != mask_secret(stored_password) {
        return submitted.to_string();
    }
    let (start, end) = match userinfo_span(submitted) {
        Some(span) => span,
        None => return submitted.to_string(),
    };
    let userinfo = &submitted[start..end];
    let Some(colon) = userinfo.find(':') else {
        return submitted.to_string();
    };
    format!(
        "{}{}:{stored_password}{}",
        &submitted[..start],
        &userinfo[..colon],
        &submitted[end..]
    )
}

/// The query of the submitted URL with the stored values put back where
/// the form still carries the redaction marker.
///
/// The marker is valid in the one place it was rendered for — the value
/// of a credential-bearing pair — so it is restored only there, and only
/// for a pair the stored URL still carries: a pair the operator added
/// keeps the value that was typed.
fn restore_url_query(submitted: &str, stored: &str) -> String {
    let Some((s_start, s_end)) = query_span(submitted) else {
        return submitted.to_string();
    };
    let Some((t_start, t_end)) = query_span(stored) else {
        return submitted.to_string();
    };
    let mut pool: HashMap<&str, VecDeque<&str>> = HashMap::new();
    for pair in stored[t_start..t_end].split('&') {
        if let Some((name, value)) = pair.split_once('=')
            && is_sensitive_param(name)
        {
            pool.entry(name).or_default().push_back(value);
        }
    }
    let mut restored: Vec<String> = Vec::with_capacity(4);
    for pair in submitted[s_start..s_end].split('&') {
        let value = match pair.split_once('=') {
            Some((name, value)) if value == REDACTED && is_sensitive_param(name) => {
                match pool.get_mut(name).and_then(|values| values.pop_front()) {
                    Some(stored_value) => format!("{name}={stored_value}"),
                    None => pair.to_string(),
                }
            }
            _ => pair.to_string(),
        };
        restored.push(value);
    }
    format!(
        "{}{}{}",
        &submitted[..s_start],
        restored.join("&"),
        &submitted[s_end..]
    )
}

/// The submitted URL with the stored secrets put back where the form
/// still carries the masks rendered from them.
fn restore_url_secrets(submitted: &str, stored: &str) -> String {
    restore_url_query(&restore_url_password(submitted, stored), stored)
}

/// Whether the edit leaves the URL and its preferred family alone. Both
/// go into the save-time SSRF vet, so only the unchanged pair lets the
/// stored row's existing verdict stand; a create (no stored row) always
/// vets.
fn url_and_family_unchanged(
    existing: Option<&Source>,
    url: &str,
    ip_family: Option<IpFamily>,
) -> bool {
    match existing {
        Some(stored) => stored.url == url && stored.ip_family == ip_family,
        None => false,
    }
}

/// Validate + assemble a `Source` from form fields. Returns the model
/// with the stored row it was built over (`None` for a create), or the
/// reason it could not be built: per-field errors (translated, shown
/// next to fields) or a row that could not be read.
async fn build_source_from_form(
    state: &AdminState,
    lang: &Lang,
    form: &[(String, String)],
    existing_id: Option<&str>,
) -> Result<(Source, Option<Source>), FormError> {
    let get = |key: &str| -> String {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    let get_all = |key: &str| -> Vec<String> {
        form.iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect()
    };

    let mut errors: Vec<(String, String)> = Vec::new();

    // The stored row is read once, up front: the form hands back the
    // secrets it masked (the password of the URL, the header values),
    // and the updated row carries the creation stamp of the row it
    // replaces. A row that cannot be read is a broken database or a
    // vanished source, never a form error.
    let existing = match existing_id {
        Some(id) => match sources::get(&state.pool, id).await {
            Ok(Some(stored)) => Some(stored),
            // The row is gone: the save has nothing to update.
            Ok(None) => {
                return Err(FormError::Server(fumox_core::Error::NotFound(format!(
                    "source {id}"
                ))));
            }
            Err(err) => {
                tracing::error!(error = %err, source = %id, "failed to read the source row");
                return Err(FormError::Server(err));
            }
        },
        None => None,
    };

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
        sources::get_by_slug(&state.pool, &slug_raw),
    )
    .await;

    // The source's own access token guards `/src` (the profile token does
    // not extend there). Same contract as the profile form: the stored
    // token is a hash, so the field shows a placeholder, an unchanged
    // placeholder keeps the stored token, and an empty field clears it.
    let token_raw = get("access_token");
    let stored_token = existing.as_ref().and_then(|s| s.access_token.as_deref());
    let unchanged = stored_token.is_some() && token_raw == token_placeholder(stored_token);
    let access_token = if unchanged {
        stored_token.map(str::to_string)
    } else if token_raw.is_empty() {
        None
    } else {
        Some(token_raw.clone())
    };
    // Token format cap: the token guards a public endpoint, so it is
    // URL-safe and bounded like the profile one.
    if !unchanged && let Some(token) = access_token.as_ref() {
        if token.chars().count() < caps::TOKEN_MIN {
            errors.push((
                "access_token".into(),
                lang.t("val.token_too_short")
                    .replace("{}", &caps::TOKEN_MIN.to_string()),
            ));
        }
        if let Err(message) = validate_token(token, lang) {
            errors.push(("access_token".into(), message));
        }
    }

    // The preferred family is parsed before the URL so the save-time SSRF
    // check can vet the host under the source's own constraint.
    let ip_family_raw = get("ip_family");
    let ip_family = if ip_family_raw.is_empty() {
        None
    } else {
        match IpFamily::from_str(&ip_family_raw) {
            Ok(family) => Some(family),
            Err(_) => {
                errors.push(("ip_family".into(), lang.t("val.unknown_value").into()));
                None
            }
        }
    };

    // The URL: the edit form shows the secrets of the URL masked, so the
    // stored values go back where the form still carries those masks.
    // The restored URL is the one that is vetted and stored.
    let url_raw = get("url");
    let url = match existing.as_ref() {
        Some(stored) => restore_url_secrets(&url_raw, &stored.url),
        None => url_raw.clone(),
    };
    if url.is_empty() {
        errors.push(("url".into(), lang.t("val.required").into()));
    } else if url.len() > caps::URL {
        errors.push((
            "url".into(),
            lang.t("val.field_too_long")
                .replace("{}", &caps::URL.to_string()),
        ));
    // The stored row was vetted when it was saved: an edit that leaves
    // the URL and its preferred family alone skips the vet, so saving a
    // renamed source does not depend on the feed host's DNS answering
    // this time too.
    } else if !url_and_family_unchanged(existing.as_ref(), &url, ip_family)
        && let Err(issue) = fetcher::vet_url_with_policy(
            &url,
            state.admin().allow_private_urls,
            ip_family.unwrap_or_else(|| state.fetcher.default_family()),
            state.fetcher.dns_timeout,
        )
        .await
    {
        errors.push(("url".into(), url_problem_message(lang, &issue)));
    }

    let encoding_raw = get("encoding");
    let encoding = if encoding_raw.is_empty() {
        Encoding::Auto
    } else {
        match Encoding::from_str(&encoding_raw) {
            Ok(encoding) => encoding,
            Err(_) => {
                errors.push(("encoding".into(), lang.t("val.unknown_value").into()));
                Encoding::Auto
            }
        }
    };

    let input_format_raw = get("input_format");
    let input_format = if input_format_raw.is_empty() {
        None
    } else {
        match InputFormat::from_str(&input_format_raw) {
            Ok(format) => Some(format),
            Err(_) => {
                errors.push(("input_format".into(), lang.t("val.unknown_value").into()));
                None
            }
        }
    };

    let protocol_names = get_all("protocols");
    let protocols = if protocol_names.is_empty() {
        None
    } else {
        let mut schemes = Vec::new();
        for raw in &protocol_names {
            match Scheme::from_str(raw) {
                Ok(scheme) => schemes.push(scheme),
                Err(_) => errors.push((
                    "protocols".into(),
                    lang.t("val.unknown_protocol").replace("{}", raw),
                )),
            }
        }
        Some(schemes)
    };

    let ttl_raw = get("cache_ttl_seconds");
    let cache_ttl_seconds: i64 = match ttl_raw.parse::<i64>() {
        Ok(ttl) => match validate_ttl(ttl, lang) {
            Ok(()) => ttl,
            Err(message) => {
                errors.push(("cache_ttl_seconds".into(), message));
                3600
            }
        },
        Err(_) => {
            errors.push(("cache_ttl_seconds".into(), ttl_range_message(lang)));
            3600
        }
    };

    let tags_raw = get("tags");
    let tags: Option<Vec<String>> = if tags_raw.is_empty() {
        None
    } else {
        let list: Vec<String> = tags_raw
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        if let Err(message) = validate_tags(&list, lang) {
            errors.push(("tags".into(), message));
        }
        Some(list)
    };

    // Headers: "Key: value" lines. Masked values from the edit form are
    // kept as-is only when unchanged, a masked placeholder means "keep the
    // stored secret"; we re-read it from the DB below.
    let headers_raw = get("headers");
    let mut headers_map: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for line in headers_raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            errors.push((
                "headers".into(),
                lang.t("val.header_line").replace("{}", line),
            ));
            continue;
        };
        let key = key.trim().to_string();
        if key.is_empty() {
            errors.push(("headers".into(), lang.t("val.header_empty_key").into()));
            continue;
        }
        let value = value.trim().to_string();
        // Two lines for one header are a mistake, not a silent overwrite:
        // the second value would replace the first without a trace.
        if headers_map.insert(key.clone(), value).is_some() {
            errors.push((
                "headers".into(),
                lang.t("val.header_duplicate").replace("{}", &key),
            ));
        }
    }
    // The masked values go back where the form still carries the mask
    // rendered from them. A mask is valid only under the key it was
    // rendered for: under any other key it is reported, so the operator
    // enters the value again instead of a mask reaching the upstream
    // fetch as a credential.
    if let Some(stored_headers) = existing.as_ref().and_then(|s| s.headers.as_ref())
        && let Some(key) = restore_masked_headers(&mut headers_map, stored_headers)
    {
        errors.push((
            "headers".into(),
            lang.t("val.header_mask").replace("{}", &key),
        ));
    }
    // The caps and the header syntax are the shared rules: the whole map
    // is replayed on every fetch of the source, so it is bounded like
    // every other field, and a name/value the HTTP layer would refuse
    // fails the form now instead of every future fetch.
    if let Err(message) = validate_header_map(&headers_map, lang) {
        errors.push(("headers".into(), message));
    }

    // Pipeline: in builder mode the JSON is generated from the widget
    // fields server-side (a stale `pipeline` textarea, if any, is ignored);
    // in raw mode the textarea is the input, as before.
    let pipeline = pipeline_from_form(form, lang, &mut errors);

    if !errors.is_empty() {
        return Err(FormError::Validation(errors));
    }

    let now = now_ts();

    Ok((
        Source {
            id: existing_id.map(str::to_string).unwrap_or_else(new_id),
            slug,
            access_token,
            name,
            url,
            // HTML checkbox semantics: an unchecked checkbox submits nothing,
            // a checked one submits its value (`1` in the source form), so
            // the flag is read from the value, not from the field's presence.
            enabled: is_checkbox_on(form, "enabled"),
            encoding,
            input_format,
            protocols,
            cache_ttl_seconds,
            tags,
            pipeline,
            headers: if headers_map.is_empty() {
                None
            } else {
                Some(headers_map)
            },
            ip_family,
            created_at: existing.as_ref().map(|s| s.created_at).unwrap_or(now),
            updated_at: now,
            // The fetcher owns these three columns: the admin write path
            // does not carry them (`sources::update_settings` leaves the
            // stored values alone), so the assembled row leaves them empty.
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        },
        existing,
    ))
}

/// Names of the settings fields the assembled row changes relative to
/// the stored one. Names only: the values carry the URL's secrets and
/// the header values, and neither belongs in the log.
fn changed_fields(existing: Option<&Source>, updated: &Source) -> Vec<&'static str> {
    let Some(existing) = existing else {
        return Vec::new();
    };
    let mut changed = Vec::new();
    if existing.slug != updated.slug {
        changed.push("slug");
    }
    if existing.access_token != updated.access_token {
        changed.push("access_token");
    }
    if existing.name != updated.name {
        changed.push("name");
    }
    if existing.url != updated.url {
        changed.push("url");
    }
    if existing.enabled != updated.enabled {
        changed.push("enabled");
    }
    if existing.encoding != updated.encoding {
        changed.push("encoding");
    }
    if existing.input_format != updated.input_format {
        changed.push("input_format");
    }
    if existing.protocols != updated.protocols {
        changed.push("protocols");
    }
    if existing.cache_ttl_seconds != updated.cache_ttl_seconds {
        changed.push("cache_ttl_seconds");
    }
    if existing.tags != updated.tags {
        changed.push("tags");
    }
    if existing.pipeline != updated.pipeline {
        changed.push("pipeline");
    }
    if existing.headers != updated.headers {
        changed.push("headers");
    }
    if existing.ip_family != updated.ip_family {
        changed.push("ip_family");
    }
    changed
}

/// Put the stored secret back where the form still carries the mask
/// rendered from it (`mask_secret`).
///
/// A mask is valid only under the key it was rendered for: the key and
/// the mask must both match the stored pair, so a secret is restored
/// into its own header and nowhere else. A mask under any other key —
/// or a mask several stored secrets could have been rendered from — is
/// not a secret to be guessed: the header key is reported and the form
/// asks for the value again.
///
/// Anything that is not a mask of a stored secret stays exactly as
/// typed, a real value that happens to contain a bullet included.
fn restore_masked_headers(
    headers_map: &mut std::collections::BTreeMap<String, String>,
    stored: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    if headers_map.is_empty() || stored.is_empty() {
        return None;
    }
    // The masks of the stored values: a submitted value that equals one
    // of them is a mask, whichever key it was rendered for.
    let masks: std::collections::BTreeSet<String> =
        stored.values().map(|value| mask_secret(value)).collect();
    let mut offender: Option<String> = None;
    for (key, value) in headers_map.iter_mut() {
        match stored.get(key.as_str()) {
            Some(original) if *value == mask_secret(original) => {
                *value = original.to_string();
                continue;
            }
            _ => {}
        }
        if masks.contains(value.as_str()) {
            offender.get_or_insert_with(|| key.clone());
        }
    }
    offender
}

/// Whether a URL field carries a mask that the save restores: the
/// redaction marker of a secret query value or the mask of a password.
fn url_carries_mask(url: &str) -> bool {
    url.contains(REDACTED) || url.contains(super::MASK_TAIL)
}

/// The state of an HTML checkbox field in a posted form. An unchecked
/// checkbox submits nothing at all; a checked one submits its `value`
/// (`1` for the source form). The truthy synonyms are read the same way
/// so a hand-built post means what it says, and any other value — an
/// `enabled=false` included — counts as unchecked instead of flipping
/// the flag on by mere presence.
fn is_checkbox_on(form: &[(String, String)], key: &str) -> bool {
    form.iter()
        .rev()
        .find(|(k, _)| k == key)
        .is_some_and(|(_, v)| matches!(v.trim(), "1" | "on" | "true"))
}

fn form_values_from(form: &[(String, String)]) -> SourceFormValues {
    let get = |key: &str| -> String {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    let url = get("url");
    SourceFormValues {
        name: get("name"),
        slug: get("slug"),
        access_token: get("access_token"),
        url_masked: url_carries_mask(&url),
        url,
        // Same read as the save (`is_checkbox_on`): the replayed form
        // shows the checkbox exactly the way the row would be saved.
        enabled: is_checkbox_on(form, "enabled"),
        encoding: get("encoding"),
        input_format: get("input_format"),
        ip_family: get("ip_family"),
        protocols: form
            .iter()
            .filter(|(k, _)| k == "protocols")
            .map(|(_, v)| v.trim().to_string())
            .collect(),
        cache_ttl_seconds: get("cache_ttl_seconds"),
        tags: get("tags"),
        headers: get("headers"),
    }
}

pub async fn source_create(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let (source, _) = match build_source_from_form(&state, &lang, &form, None).await {
        Ok(source) => source,
        Err(FormError::Validation(errors)) => {
            let pipeline_error = errors
                .iter()
                .find(|(field, _)| field == "pipeline")
                .map(|(_, message)| message.clone());
            let widget_html = widget_from_posted(
                lang.clone(),
                &state.csrf_for(&headers),
                &form,
                false,
                pipeline_error,
            );
            // The posted form is parsed once; the values and the protocol
            // selection come from the same parse.
            let values = form_values_from(&form);
            return render_source_form(
                &state,
                &headers,
                lang,
                theme,
                StatusCode::UNPROCESSABLE_ENTITY,
                None,
                "/admin/sources/new".into(),
                values.clone(),
                &values.protocols,
                errors,
                false,
                false,
                widget_html,
            );
        }
        Err(FormError::Server(err)) => {
            return row_error_response(&state, &headers, &err, "err.source_not_found");
        }
    };
    if let Err(err) = sources::create(&state.pool, &source).await {
        return server_error(&state, &headers, "sources.create", &err);
    }
    tracing::info!(source = %source.id, "source created");
    Redirect::to(&format!("/admin/sources/{}", source.id)).into_response()
}

pub async fn source_update(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let (source, existing) = match build_source_from_form(&state, &lang, &form, Some(&id)).await {
        Ok(source) => source,
        Err(FormError::Validation(errors)) => {
            let action = format!("/admin/sources/{id}/edit");
            let pipeline_error = errors
                .iter()
                .find(|(field, _)| field == "pipeline")
                .map(|(_, message)| message.clone());
            let widget_html = widget_from_posted(
                lang.clone(),
                &state.csrf_for(&headers),
                &form,
                false,
                pipeline_error,
            );
            // The posted form is parsed once; the values and the protocol
            // selection come from the same parse.
            let values = form_values_from(&form);
            // The header note follows the stored row, computed the same
            // way as the GET render: it is about the values the form
            // shows masked, not about what was posted. The assembled row
            // does not exist here (validation failed), so the row is
            // read again; a row that cannot be read keeps the note on,
            // the previous render's assumption.
            let headers_masked_note = match sources::get(&state.pool, &id).await {
                Ok(Some(stored)) => stored.headers.as_ref().is_some_and(|m| !m.is_empty()),
                Ok(None) | Err(_) => true,
            };
            // The token note follows the stored row the same way: the
            // placeholder note is about the value the form shows, which is
            // the stored token's stand-in, not what was posted.
            let token_masked_note = match sources::get(&state.pool, &id).await {
                Ok(Some(stored)) => stored.access_token.is_some(),
                Ok(None) | Err(_) => true,
            };
            return render_source_form(
                &state,
                &headers,
                lang,
                theme,
                StatusCode::UNPROCESSABLE_ENTITY,
                Some(id),
                action,
                values.clone(),
                &values.protocols,
                errors,
                headers_masked_note,
                token_masked_note,
                widget_html,
            );
        }
        Err(FormError::Server(err)) => {
            return row_error_response(&state, &headers, &err, "err.source_not_found");
        }
    };
    if let Err(err) = sources::update_settings(&state.pool, &source).await {
        return row_error_response(&state, &headers, &err, "err.source_not_found");
    }
    // Saved → effective immediately. The freshness stamp lives on the
    // source row (`sources::update_settings` resets it when a
    // fetch-relevant field changed); only the rendered outputs need
    // dropping here.
    state
        .caches
        .invalidate_processed_for_source(&source.id)
        .await;
    tracing::info!(
        source = %source.id,
        changed = ?changed_fields(existing.as_ref(), &source),
        "source updated"
    );
    if is_htmx(&headers) {
        let target = format!("/admin/sources/{}", source.id);
        let mut response = Redirect::to(&target).into_response();
        if let Ok(value) = axum::http::HeaderValue::from_str(&target) {
            response.headers_mut().insert("HX-Redirect", value);
        }
        response
    } else {
        Redirect::to(&format!("/admin/sources/{}", source.id)).into_response()
    }
}

// Card

#[derive(Template)]
#[template(path = "sources/detail.html")]
struct SourceDetailTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    source: SourceCard,
    url_display: String,
    /// Whether the URL carries a mask: the note about the secrets is
    /// only shown when there is something to hide.
    url_masked: bool,
    headers_display: Vec<(String, String)>,
    pipeline_display: String,
    protocols_display: String,
    serve_url: String,
    counts: Vec<(String, i64)>,
    log: Vec<fetch_log::FetchLogRow>,
    /// The computed time of the source's next attempt; `None` when the
    /// last attempt succeeded (see [`SourceCardView::next_retry_at`]).
    /// Rendered inside the last-error row.
    next_retry_at: Option<i64>,
    /// The keyset navigation of the journal panel: the links to the
    /// first, the previous and the next page of the log; `None` when
    /// that page does not exist (the shared `_cursor_nav.html` renders
    /// the strip only then).
    nav_first: Option<String>,
    nav_prev: Option<String>,
    nav_next: Option<String>,
    /// The toggle endpoint of this source and its current state, as flat
    /// fields: the markup lives once in the shared `_toggle_form.html`,
    /// which the page includes directly (sources and profiles render the
    /// same fragment).
    toggle_url: String,
    enabled: bool,
    /// The card includes `sources/_toggle_form.html`, whose standalone
    /// variant marks the form as an out-of-band swap in the toggle
    /// response; the page itself always renders it plain.
    swap_oob: bool,
}

impl_i18n!(SourceDetailTemplate);

/// Everything the source card renders, gathered by the endpoint: the
/// stored row plus the aggregates of the card. One argument instead of
/// five parallel ones.
struct SourceCardView {
    source: Source,
    counts: Vec<(String, i64)>,
    log: Vec<fetch_log::FetchLogRow>,
    /// The computed time of the source's next attempt (newest journal
    /// attempt plus the backoff its consecutive failures earned, see
    /// [`crate::scheduler::next_retry_at`]); `None` when the last attempt
    /// succeeded. Rendered next to the last error, so a dead feed reads
    /// as "retry scheduled", not as "the scheduler gave up".
    next_retry_at: Option<i64>,
    nav_first: Option<String>,
    nav_prev: Option<String>,
    nav_next: Option<String>,
}

pub async fn source_detail(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let source = match sources::get(&state.pool, &id).await {
        Ok(Some(source)) => source,
        Ok(None) => return not_found(lang, "err.source_not_found"),
        Err(err) => return server_error(&state, &headers, "sources.detail", &err),
    };

    // The cursor of the requested page: the same journal token the global
    // screen pages by. A token of another sort is not a position in this
    // one, so the log falls back to its first page.
    let page = params
        .get("cur")
        .and_then(|token| decode_fetch_cursor(token))
        .map(|(cursor, direction)| fetch_log::FetchLogPage { cursor, direction });

    // The rows over-fetch by one: the extra row says whether a further
    // page exists without a second count.
    let mut log: Vec<fetch_log::FetchLogRow> = match fetch_log::list_for_source(
        &state.pool,
        &id,
        LOG_PAGE_SIZE + 1,
        page.as_ref(),
    )
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(&state, &headers, "sources.detail", &err),
    };

    // The navigation of the log, assembled exactly like the global
    // journal screen's: the over-fetched row dropped on a backwards page,
    // then the neighbours of the page.
    let backward = page
        .as_ref()
        .is_some_and(|page| page.direction == fetch_log::FetchLogDirection::Backward);
    let has_more = log.len() as i64 > LOG_PAGE_SIZE;
    if backward && has_more {
        // The rows closest to the cursor come last: the over-fetched row
        // is the farthest one, the page keeps the rows right before the
        // cursor.
        log.remove(0);
    }
    log.truncate(LOG_PAGE_SIZE as usize);
    let cursor_of = |row: &fetch_log::FetchLogRow| fetch_log::FetchLogCursor {
        fetched_at: row.fetched_at,
        id: row.id,
    };
    let first_cursor = log.first().map(cursor_of);
    let last_cursor = log.last().map(cursor_of);
    let (prev, next) = if backward {
        (
            if has_more {
                first_cursor.map(|cursor| (cursor, fetch_log::FetchLogDirection::Backward))
            } else {
                None
            },
            last_cursor.map(|cursor| (cursor, fetch_log::FetchLogDirection::Forward)),
        )
    } else {
        (
            if page.is_some() {
                first_cursor.map(|cursor| (cursor, fetch_log::FetchLogDirection::Backward))
            } else {
                None
            },
            if has_more {
                last_cursor.map(|cursor| (cursor, fetch_log::FetchLogDirection::Forward))
            } else {
                None
            },
        )
    };
    let base = format!("/admin/sources/{id}");
    let nav_first = page
        .is_some()
        .then(|| journal_page_link(&base, LOG_PAGE_SIZE, "", None));
    let nav_prev = prev.map(|page| journal_page_link(&base, LOG_PAGE_SIZE, "", Some(page)));
    let nav_next = next.map(|page| journal_page_link(&base, LOG_PAGE_SIZE, "", Some(page)));

    let counts = match proxies::count_by_status_for_source(&state.pool, &id).await {
        Ok(counts) => counts,
        Err(err) => return server_error(&state, &headers, "sources.detail", &err),
    };
    let next_retry_at = crate::scheduler::next_retry_at(&state.pool, &id).await;

    render_source_detail(
        &state,
        lang,
        peer,
        &headers,
        SourceCardView {
            source,
            counts,
            log,
            next_retry_at,
            nav_first,
            nav_prev,
            nav_next,
        },
    )
}

fn render_source_detail(
    state: &AdminState,
    lang: Lang,
    peer: SocketAddr,
    headers: &HeaderMap,
    view: SourceCardView,
) -> Response {
    let SourceCardView {
        source,
        counts,
        log,
        next_retry_at,
        nav_first,
        nav_prev,
        nav_next,
    } = view;
    let serve_path = format!(
        "/src/{}",
        source.slug.clone().unwrap_or_else(|| source.id.clone())
    );
    // Absolute serve link: the host the admin panel was opened on with the
    // public port from [server].bind.
    let base = match state.serve_base(peer, headers) {
        Ok(b) => b,
        Err(err) => {
            return super::server_error(
                state,
                headers,
                "sources.serve_base",
                &fumox_core::Error::Config(err.to_string()),
            );
        }
    };
    let serve_url = format!("{base}{serve_path}");
    let headers_display: Vec<(String, String)> = source
        .headers
        .as_ref()
        .map(|map| {
            map.iter()
                .map(|(k, v)| (k.clone(), mask_secret(v)))
                .collect()
        })
        .unwrap_or_default();
    let pipeline_display = source
        .pipeline
        .as_ref()
        .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
        .unwrap_or_default();
    let protocols_display = source
        .protocols
        .as_ref()
        .map(|list| {
            list.iter()
                .map(|s| s.as_str().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| lang.t("src.all_auto").to_string());

    render_html(
        lang.clone(),
        "sources/detail.html",
        &SourceDetailTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme: theme::from_headers(headers),
            active: "sources",
            csrf: state.csrf_for(headers),
            // The secrets of the URL are secrets: the card shows their
            // masks, the full URL stays in the database.
            url_display: mask_url_secrets(&source.url),
            url_masked: mask_url_secrets(&source.url) != source.url,
            source: SourceCard::from_source(&source),
            headers_display,
            pipeline_display,
            protocols_display,
            serve_url,
            counts,
            log,
            next_retry_at,
            nav_first,
            nav_prev,
            nav_next,
            toggle_url: format!("/admin/sources/{}/toggle", source.id),
            enabled: source.enabled,
            swap_oob: false,
        },
        StatusCode::OK,
    )
}

/// Fetch-log fragment for the source card (also polled after refresh).
#[derive(Template)]
#[template(path = "sources/_log.html")]
struct SourceLogFragment {
    lang: Lang,
    log: Vec<fetch_log::FetchLogRow>,
}

impl_i18n!(SourceLogFragment);

pub async fn source_log(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    // The fragment belongs to a card: a source that is gone gets the
    // same not-found the detail page returns, not an empty log.
    match sources::get(&state.pool, &id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(lang, "err.source_not_found"),
        Err(err) => return server_error(&state, &headers, "sources.log", &err),
    }
    let log: Vec<fetch_log::FetchLogRow> =
        match fetch_log::recent_for_source(&state.pool, &id, LOG_PAGE_SIZE).await {
            Ok(rows) => rows,
            Err(err) => return server_error(&state, &headers, "sources.log", &err),
        };
    render_html(
        lang.clone(),
        "sources/_log.html",
        &SourceLogFragment { lang, log },
        StatusCode::OK,
    )
}

// Actions

/// The enabled badge of the source card, as a standalone fragment: the
/// detail page includes the same file, and the toggle action re-renders it
/// after every swap, so the initial markup and the swap are one definition.
#[derive(Template)]
#[template(path = "sources/_enabled_badge.html")]
struct EnabledBadgeFragment {
    lang: Lang,
    source: SourceCard,
}

impl_i18n!(EnabledBadgeFragment);

/// The toggle form of the source card, same include-as-initial-render
/// pattern as [`EnabledBadgeFragment`]. The markup lives in the shared
/// `_toggle_form.html` (sources and profiles render the same fragment);
/// this wrapper binds the source context to it as flat fields.
/// `swap_oob` adds the `hx-swap-oob` attribute that makes the form in a
/// toggle response replace itself out-of-band; the initial page renders
/// it plain.
#[derive(Template)]
#[template(path = "sources/_toggle_form.html")]
struct ToggleFormFragment {
    lang: Lang,
    toggle_url: String,
    enabled: bool,
    csrf: String,
    swap_oob: bool,
}

impl_i18n!(ToggleFormFragment);

/// The toggle response body: the badge swapped into `#enabled-badge`
/// normally plus the form marked out-of-band. Both halves come from the
/// fragment templates the detail page includes, so the ids, aria
/// attributes and the hx-* contract cannot drift from the initial render.
fn toggle_swap_fragment(lang: &Lang, source: &Source, csrf: &str) -> String {
    let card = SourceCard::from_source(source);
    let badge = EnabledBadgeFragment {
        lang: lang.clone(),
        source: card.clone(),
    }
    .render()
    .expect("badge fragment renders");
    let form = ToggleFormFragment {
        lang: lang.clone(),
        toggle_url: format!("/admin/sources/{}/toggle", card.id),
        enabled: card.enabled,
        csrf: csrf.to_string(),
        swap_oob: true,
    }
    .render()
    .expect("toggle form fragment renders");
    format!("{badge}\n{form}")
}

pub async fn source_toggle(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let mut source = match sources::get(&state.pool, &id).await {
        Ok(Some(source)) => source,
        Ok(None) => return not_found(lang, "err.source_not_found"),
        Err(err) => return server_error(&state, &headers, "sources.toggle", &err),
    };
    let enabled = !source.enabled;
    // The toggle writes the flag and nothing else: the settings columns
    // keep the values they have.
    match sources::set_enabled(&state.pool, &id, enabled).await {
        Ok(true) => {}
        Ok(false) => return not_found(lang, "err.source_not_found"),
        Err(err) => return row_error_response(&state, &headers, &err, "err.source_not_found"),
    }
    source.enabled = enabled;
    source.updated_at = now_ts();
    // The enabled flip reset the row's freshness stamp (a fetch-relevant
    // change, see `sources::set_enabled`); the rendered outputs go here.
    state.caches.invalidate_processed_for_source(&id).await;
    let message = if source.enabled {
        lang.t("src.enabled_toast")
    } else {
        lang.t("src.disabled_toast")
    };
    tracing::info!(source = %id, enabled = source.enabled, "source toggled");
    action_response(
        is_htmx(&headers),
        &format!("/admin/sources/{id}"),
        // The wrapper id must survive the swap (the form's hx-target points
        // at it), and the toggle button must flip with the state, it lives
        // outside the badge, so it travels along as an out-of-band swap.
        // Both elements are rendered from the same fragment templates the
        // detail page includes, so the swap cannot drop the aria attributes
        // or drift from the initial markup.
        toggle_swap_fragment(&lang, &source, &state.csrf_for(&headers)),
        message,
    )
}

/// *Refresh now*: enqueue an immediate fetch.
/// The scheduler's per-source guard deduplicates concurrent requests.
pub async fn source_refresh(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    match sources::get(&state.pool, &id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(lang, "err.source_not_found"),
        Err(err) => return server_error(&state, &headers, "sources.refresh", &err),
    }
    match state.refresh_tx.try_send(id.clone()) {
        Ok(()) => {}
        // The bounded queue is full: the loop is behind on its dispatches.
        // The click is dropped here instead of piling up behind it; the
        // operator gets the "busy" toast, the log names the dropped one.
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!(
                source = %id,
                "refresh enqueue failed: scheduler channel full"
            );
            return action_response(
                is_htmx(&headers),
                &format!("/admin/sources/{id}"),
                String::new(),
                lang.t("src.scheduler_busy"),
            );
        }
        // The scheduler is gone (shutdown or a wedged loop): the operator
        // gets the "unavailable" toast, the log names the failed enqueue.
        Err(err) => {
            tracing::warn!(
                source = %id,
                error = %err,
                "refresh enqueue failed: scheduler channel closed"
            );
            return action_response(
                is_htmx(&headers),
                &format!("/admin/sources/{id}"),
                String::new(),
                lang.t("src.scheduler_unavailable"),
            );
        }
    }
    tracing::info!(source = %id, "immediate refresh queued");
    if is_htmx(&headers) {
        // The initial state is the fragment the polled status renders,
        // so the two cannot drift apart: the swap and the first render
        // carry the same markup and the same polling contract.
        render_html(
            lang.clone(),
            "sources/_status.html",
            &RefreshStatusFragment {
                lang: lang.clone(),
                source_id: id.clone(),
                busy: true,
                pending: false,
                done_at: None,
                error_message: None,
                ok: true,
                // The task is queued, not running yet: the elapsed time
                // starts when the scheduler picks the source up.
                elapsed_seconds: None,
                budget_hint: refresh_budget_hint(&lang),
            },
            StatusCode::ACCEPTED,
        )
    } else {
        // Plain-browser path: the queued refresh is announced with a
        // flash toast, like every other action's fallback — a bare
        // redirect would land silently.
        flash_redirect(
            &format!("/admin/sources/{id}"),
            lang.t("common.refreshing"),
            "ok",
        )
    }
}

/// Polled refresh status: keeps `data-busy="1"` while the fetch is in
/// flight, then shows the outcome and stops polling.
#[derive(Template)]
#[template(path = "sources/_status.html")]
struct RefreshStatusFragment {
    lang: Lang,
    source_id: String,
    busy: bool,
    /// The source has never been fetched: a neutral state, not an error
    /// and not busy — there is no outcome to show yet.
    pending: bool,
    /// Unix timestamp of the completed fetch, rendered by the template as a
    /// `<time>` element next to the `src.refresh_done` label; `None` while
    /// busy or on error.
    done_at: Option<i64>,
    /// Escaped human-readable fetch error; `None` while busy, pending or
    /// on success.
    error_message: Option<String>,
    ok: bool,
    /// Seconds since the running refresh started; `None` when no refresh
    /// is running or it has not been picked up yet.
    elapsed_seconds: Option<i64>,
    /// What a refresh may cost: the wall-clock budget and the number of
    /// requests it may make. Quoted next to the spinner so a slow source
    /// looks like a slow source and not like a stuck panel.
    budget_hint: String,
}

impl_i18n!(RefreshStatusFragment);

/// The text of the refresh budget: the wall-clock ceiling of one fetch
/// and the number of requests it may make.
fn refresh_budget_hint(lang: &Lang) -> String {
    lang.t_named(
        "src.refresh_budget",
        &[
            ("seconds", crate::fetcher::budget_seconds().to_string()),
            ("attempts", crate::fetcher::max_requests().to_string()),
        ],
    )
}

/// Polled refresh status: keeps `data-busy="1"` while the fetch is in
/// flight, then shows the outcome and stops polling.
///
/// The endpoint reports the source's *current* state, not the outcome
/// of one particular click of *Refresh now*: the per-source scheduler
/// deduplicates fetches, and a scheduled fetch or another operator's
/// refresh may complete between the press and a poll, so the poll then
/// shows that outcome. The fragment reads as "the latest known outcome
/// for this source" — the same state the card shows everywhere else;
/// nothing here claims to attribute it to the pressed button.
pub async fn source_refresh_status(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let busy = state.scheduler.is_in_flight(&id).await;
    // How long the running refresh has been going. The clock starts when
    // the scheduler picks the source up, so a request that waits for a
    // concurrency permit is counted too.
    let elapsed_seconds = state
        .scheduler
        .in_flight_since(&id)
        .await
        .map(|started_at| now_ts().saturating_sub(started_at).max(0));
    let (pending, done_at, error_message, ok) = if busy {
        (false, None, None, true)
    } else {
        let source = match sources::get(&state.pool, &id).await {
            Ok(Some(source)) => source,
            // The source is gone: the poll has nothing left to report.
            Ok(None) => return not_found(lang, "err.source_not_found"),
            Err(err) => return server_error(&state, &headers, "sources.refresh_status", &err),
        };
        if source.error_class.is_none() && source.last_fetched_at.is_some() {
            (false, source.last_fetched_at, None, true)
        } else if source.error_class.is_none() {
            // Never fetched: there is no outcome yet, and "unknown
            // error" would describe a fetch that never happened.
            (true, None, None, false)
        } else {
            (
                false,
                None,
                Some(
                    lang.t("src.refresh_error").replace(
                        "{}",
                        source
                            .last_error
                            .as_deref()
                            .unwrap_or_else(|| lang.t("src.refresh_error_unknown")),
                    ),
                ),
                false,
            )
        }
    };
    render_html(
        lang.clone(),
        "sources/_status.html",
        &RefreshStatusFragment {
            lang: lang.clone(),
            source_id: id,
            busy,
            pending,
            done_at,
            error_message,
            ok,
            elapsed_seconds,
            budget_hint: refresh_budget_hint(&lang),
        },
        StatusCode::OK,
    )
}

pub async fn source_delete(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    // Orphaned proxies (no remaining links) transition to `removed`;
    // reconciliation never resets it, a proxy that reappears in a fetch
    // keeps its state. The sweep runs while the links still name this
    // source, so it picks exactly the proxies it fed and leaves the
    // ones another source still feeds alone: deleting one source must
    // not walk the whole table.
    //
    // With `drop_gate = false` the admin click is intentionally
    // conservative: a `ready` row is tunnel-verified and an `unknown`
    // row has not yet had its first verdict, neither should be retired
    // just because its source went away. The probe is the only authority
    // on the lifecycle of a verified proxy, and the priority queue is
    // the only authority on a not-yet-checked one.
    // With `drop_gate = true` the strict policy applies and every
    // orphan retires.
    let protected = fumox_core::ingest::IngestPolicy::from_drop_gate(state.ingest().drop_gate)
        .protected_statuses();
    let sweep = proxies::mark_source_orphans_removed(&state.pool, &id, protected).await;
    match sources::delete(&state.pool, &id).await {
        Ok(true) => {}
        Ok(false) => return not_found(lang, "err.source_not_found"),
        Err(err) => return server_error(&state, &headers, "sources.delete", &err),
    }
    // The row is gone; the rendered outputs that still name it go here.
    state.caches.invalidate_processed_for_source(&id).await;
    tracing::info!(source = %id, "source deleted");
    match sweep {
        Ok(sweep) => {
            if sweep.retired > 0 {
                tracing::info!(
                    source = %id,
                    retired = sweep.retired,
                    "orphaned proxies marked removed"
                );
            }
            if sweep.protected > 0 {
                // The rows the sweep left alone on purpose: they have no
                // source link any more, so no probe lane can reach them.
                tracing::info!(
                    source = %id,
                    protected = sweep.protected,
                    "orphaned proxies left detached by the protected statuses"
                );
            }
            action_response(
                is_htmx(&headers),
                "/admin/sources",
                String::new(),
                lang.t("src.deleted_toast"),
            )
        }
        Err(err) => {
            // The source is gone, but the proxies it fed are not
            // flagged: the operator has to hear it, the toast is the
            // only place they will see it.
            tracing::error!(
                source = %id,
                error = %err,
                "failed to mark orphans removed"
            );
            action_response_err(
                is_htmx(&headers),
                "/admin/sources",
                String::new(),
                lang.t("src.deleted_orphans_failed"),
            )
        }
    }
}

// Dry-run fetch

/// Dry-run result fragment: what a real fetch would see, without writing
/// anything to the database.
#[derive(Template)]
#[template(path = "sources/_dryrun.html")]
struct DryRunFragment {
    lang: Lang,
    ok: bool,
    message: String,
    http_status: Option<u16>,
    bytes: Option<u64>,
    proxies_found: Option<usize>,
    /// Discarded by the source's own filters (allowlist, drop rules); shown
    /// only when something was actually thrown away.
    dropped: Option<usize>,
    sample: Vec<String>,
}

impl DryRunFragment {
    /// The rendered size of the response body: the template only asks
    /// for it when the fetch reported one (`bytes` is `Some` there), so
    /// the `None` placeholder never shows up in the table.
    fn fmt_bytes(&self, bytes: &u64) -> String {
        fmt_opt_bytes(&self.lang, Some(*bytes as i64))
    }
}

impl_i18n!(DryRunFragment);

/// Fetch + parse the source without reconciling or journaling (dry run).
/// Uses the same [`fetcher::Fetcher`] as the scheduler, so SSRF vetting,
/// timeouts and retries are exactly the production code path.
pub async fn source_dry_run(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let source = match sources::get(&state.pool, &id).await {
        Ok(Some(source)) => source,
        Ok(None) => return not_found(lang, "err.source_not_found"),
        Err(err) => return server_error(&state, &headers, "sources.dry_run", &err),
    };

    let outcome = crate::ingest::dry_run_source(&state.fetcher, &state.geo, &source).await;
    // One event per outcome, without the URL or the headers: the log
    // tail names the source and the verdict, the secrets stay in the
    // database.
    match &outcome {
        crate::ingest::DryRunOutcome::Ok {
            http_status,
            bytes,
            proxies_found,
            ..
        } => {
            tracing::info!(source = %id, http_status, bytes, proxies_found, "dry run ok");
        }
        crate::ingest::DryRunOutcome::FetchFailed { failure } => {
            tracing::warn!(
                source = %id,
                error_class = %failure.error_class().as_str(),
                "dry run failed"
            );
        }
        crate::ingest::DryRunOutcome::ParseFailed { .. } => {
            tracing::warn!(source = %id, error_class = "parse", "dry run failed");
        }
    }
    let fragment = match outcome {
        crate::ingest::DryRunOutcome::Ok {
            http_status,
            bytes,
            proxies_found,
            dropped,
            sample,
        } => DryRunFragment {
            ok: true,
            message: lang.t("src.dryrun_ok").into(),
            http_status: Some(http_status),
            bytes: Some(bytes),
            proxies_found: Some(proxies_found),
            dropped: (dropped > 0).then_some(dropped),
            sample,
            lang,
        },
        crate::ingest::DryRunOutcome::FetchFailed { failure } => DryRunFragment {
            ok: false,
            message: lang
                .t("src.dryrun_fetch_error")
                .replacen("{}", failure.error_class().as_str(), 1)
                .replacen("{}", &failure.to_string(), 1),
            http_status: failure.http_status(),
            bytes: None,
            proxies_found: None,
            dropped: None,
            sample: Vec::new(),
            lang,
        },
        crate::ingest::DryRunOutcome::ParseFailed {
            http_status,
            message,
        } => DryRunFragment {
            ok: false,
            message: lang.t("src.dryrun_parse_error").replace("{}", &message),
            http_status: Some(http_status),
            bytes: None,
            proxies_found: Some(0),
            dropped: None,
            sample: Vec::new(),
            lang,
        },
    };
    if is_htmx(&headers) {
        render_html(
            fragment.lang.clone(),
            "sources/_dryrun.html",
            &fragment,
            StatusCode::OK,
        )
    } else {
        // Plain-browser path: this fragment is the HTMX swap target inside
        // the source card, so a plain POST would land on a chrome-less
        // page. Redirect back to the card with the outcome as a flash
        // message instead, the same plain-browser fallback as
        // `source_refresh`.
        flash_redirect(
            &format!("/admin/sources/{id}"),
            &fragment.message,
            if fragment.ok { "ok" } else { "error" },
        )
    }
}

// Formatting helpers exposed to the askama templates of this module.
// askama passes call arguments by reference, so every helper takes &T.
impl SourcesListTemplate {
    fn tag_selected(&self, tag: &str) -> bool {
        self.f_tag == tag
    }
}

impl SourceDetailTemplate {
    fn bytes(&self, n: &Option<i64>) -> String {
        fmt_opt_bytes(&self.lang, *n)
    }

    /// The next-retry hint for the last-error row, or an empty string when
    /// the last attempt succeeded (no backoff applies): the computed time
    /// of the next attempt, so a dead feed reads as "retry scheduled"
    /// rather than "the scheduler gave up". Rendered through `| safe`,
    /// like the other `<time>` elements.
    fn next_retry_line(&self) -> String {
        let Some(ts) = self.next_retry_at else {
            return String::new();
        };
        format!(
            "<div class=\"hint\">{} {}</div>",
            self.lang.t("src.next_retry"),
            self.opt_ts(&Some(ts))
        )
    }
}

impl SourceLogFragment {
    fn bytes(&self, n: &Option<i64>) -> String {
        fmt_opt_bytes(&self.lang, *n)
    }
}

#[cfg(test)]
mod tests {
    use super::restore_masked_headers;
    use super::*;
    use std::collections::BTreeMap;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// The mask the edit form renders is replaced by the stored secret
    /// under its own key.
    #[test]
    fn unchanged_mask_is_restored_from_the_stored_secret() {
        let stored = headers(&[("X-Token", "supersecretvalue")]);
        let mut submitted = headers(&[("X-Token", &super::mask_secret("supersecretvalue"))]);
        assert_eq!(restore_masked_headers(&mut submitted, &stored), None);
        assert_eq!(submitted["X-Token"], "supersecretvalue");
    }

    /// A mask is valid only under the key it was rendered for: under
    /// any other key it is reported, so the operator enters the value
    /// again instead of a mask reaching the upstream fetch as a
    /// credential.
    #[test]
    fn a_mask_under_a_renamed_key_is_reported() {
        let stored = headers(&[("X-Token", "supersecretvalue")]);
        let mut submitted = headers(&[("Authorization", &super::mask_secret("supersecretvalue"))]);
        assert_eq!(
            restore_masked_headers(&mut submitted, &stored),
            Some("Authorization".to_string())
        );
        assert_eq!(
            submitted["Authorization"],
            super::mask_secret("supersecretvalue"),
            "the mask must not be stored as a credential"
        );
    }

    /// A real value that happens to contain the bullet the mask is drawn
    /// with is a value, not a mask: the old `contains('•')` test threw it
    /// away and stored the stored secret instead.
    #[test]
    fn typed_value_with_a_bullet_is_kept() {
        let stored = headers(&[("X-Token", "supersecretvalue")]);
        let mut submitted = headers(&[("X-Token", "tok•en"), ("X-Other", "abc…••••extra")]);
        assert_eq!(restore_masked_headers(&mut submitted, &stored), None);
        assert_eq!(submitted["X-Token"], "tok•en");
        assert_eq!(submitted["X-Other"], "abc…••••extra");
    }

    /// Two stored headers holding the *same* secret render one mask. Under
    /// a new key that mask names no single secret any more, so it is
    /// reported instead of being guessed.
    #[test]
    fn a_shared_mask_under_a_new_key_is_reported() {
        let stored = headers(&[("X-A", "supersecretvalue"), ("X-B", "supersecretvalue")]);
        let mut submitted = headers(&[("X-Renamed", &super::mask_secret("supersecretvalue"))]);
        assert_eq!(
            restore_masked_headers(&mut submitted, &stored),
            Some("X-Renamed".to_string())
        );
    }

    /// A new source has nothing stored to restore from.
    #[test]
    fn restore_is_a_noop_without_stored_headers() {
        let mut submitted = headers(&[("X-Token", "tok•en")]);
        assert_eq!(
            restore_masked_headers(&mut submitted, &BTreeMap::new()),
            None
        );
        assert_eq!(submitted["X-Token"], "tok•en");
    }

    /// Two secrets whose first three characters are equal (any two JWTs)
    /// mask identically. Each header keeps its own: the key and the mask
    /// are compared together.
    #[test]
    fn secrets_sharing_a_mask_prefix_restore_independently() {
        let stored = headers(&[
            ("Authorization", "eyJAAA-first-secret"),
            ("X-Api-Key", "eyJBBB-second-secret"),
        ]);
        let mut submitted = headers(&[
            ("Authorization", &super::mask_secret("eyJAAA-first-secret")),
            ("X-Api-Key", &super::mask_secret("eyJBBB-second-secret")),
        ]);
        assert_eq!(restore_masked_headers(&mut submitted, &stored), None);
        assert_eq!(submitted["Authorization"], "eyJAAA-first-secret");
        assert_eq!(submitted["X-Api-Key"], "eyJBBB-second-secret");
    }

    /// A mask that several stored secrets could have been rendered from is
    /// not resolved by guesswork when its key is new: the form rendered it
    /// ambiguous, so it is reported and the operator enters the value
    /// again.
    #[test]
    fn a_colliding_mask_under_a_new_key_is_reported() {
        let stored = headers(&[
            ("Authorization", "eyJAAA-first-secret"),
            ("X-Api-Key", "eyJBBB-second-secret"),
        ]);
        let mut submitted = headers(&[("X-Renamed", &super::mask_secret("eyJAAA-first-secret"))]);
        assert_eq!(
            restore_masked_headers(&mut submitted, &stored),
            Some("X-Renamed".to_string())
        );
    }

    /// The URL of the card and of the edit form shows the password of the
    /// userinfo masked: the secret stays in the database and in the
    /// fetcher.
    #[test]
    fn the_url_password_is_masked() {
        assert_eq!(
            mask_url_userinfo("https://user:secret123@example.com/sub"),
            "https://user:sec…••••@example.com/sub"
        );
        // A userinfo without a password carries no secret.
        assert_eq!(
            mask_url_userinfo("https://user@example.com/sub"),
            "https://user@example.com/sub"
        );
        // A URL without a userinfo is untouched.
        assert_eq!(
            mask_url_userinfo("https://example.com/sub"),
            "https://example.com/sub"
        );
    }

    /// The mask the form hands back is restored under the stored
    /// password; a password the operator typed is kept as typed.
    #[test]
    fn the_stored_password_comes_back_under_the_mask() {
        let stored = "https://user:secret123@example.com/sub";
        let masked = mask_url_userinfo(stored);
        assert_eq!(restore_url_password(&masked, stored), stored);
        // A fresh password replaces the mask.
        assert_eq!(
            restore_url_password("https://user:fresh456@example.com/sub", stored),
            "https://user:fresh456@example.com/sub"
        );
        // A URL without a password stays as typed.
        assert_eq!(
            restore_url_password("https://example.com/sub", stored),
            "https://example.com/sub"
        );
    }

    /// The subscription token travels in the query of the feed URL, so
    /// the query value is redacted in the panel the same way it is in
    /// the log. The harmless pairs survive: they are the diagnostics.
    #[test]
    fn the_secret_query_values_are_redacted() {
        assert_eq!(
            mask_url_secrets("https://example.com/sub?token=SECRET&page=2"),
            "https://example.com/sub?token=[redacted]&page=2"
        );
        // The name is kept, the value is not: the operator must see
        // which parameter carries the credential.
        assert_eq!(
            mask_url_secrets("https://example.com/sub?api_key=x&ok=1"),
            "https://example.com/sub?api_key=[redacted]&ok=1"
        );
        // A URL without a query is untouched.
        assert_eq!(
            mask_url_secrets("https://example.com/sub"),
            "https://example.com/sub"
        );
    }

    /// The masked URL is what the edit form shows, and the form hands it
    /// back on submit: the stored secret must come back under the mask,
    /// or saving the form would silently drop the token and the feed
    /// would stop working.
    #[test]
    fn the_stored_secrets_come_back_under_the_masks() {
        let stored = "https://user:secret123@example.com/sub?token=ABC&page=2";
        let masked = mask_url_secrets(stored);
        assert!(!masked.contains("secret123"), "{masked}");
        assert!(!masked.contains("ABC"), "{masked}");
        assert_eq!(restore_url_secrets(&masked, stored), stored);

        // A typed token replaces the mask.
        assert_eq!(
            restore_url_secrets("https://example.com/sub?token=NEW&page=2", stored),
            "https://example.com/sub?token=NEW&page=2"
        );
        // A pair the operator added keeps the value that was typed.
        assert_eq!(
            restore_url_secrets("https://example.com/sub?token=[redacted]&new=1", stored),
            "https://example.com/sub?token=ABC&new=1"
        );
    }

    /// The mask is restored only under the pair it was rendered for: a
    /// stored URL with two credential-bearing pairs gives each of them
    /// its own value back, in the order they appear.
    #[test]
    fn every_masked_pair_gets_its_own_value_back() {
        let stored = "https://example.com/sub?token=AAA&api_key=BBB";
        let masked = mask_url_secrets(stored);
        assert_eq!(
            masked,
            "https://example.com/sub?token=[redacted]&api_key=[redacted]"
        );
        assert_eq!(restore_url_secrets(&masked, stored), stored);
    }

    /// A URL without a secret is not marked as masked: the note about
    /// the restore would then describe a restore that never happens.
    #[test]
    fn the_mask_is_recognized_in_a_url() {
        assert!(url_carries_mask("https://example.com/sub?token=[redacted]"));
        assert!(url_carries_mask("https://user:sec…••••@example.com/sub"));
        assert!(!url_carries_mask("https://example.com/sub?page=2"));
        assert!(!url_carries_mask("https://example.com/sub"));
    }

    /// L-185: a running refresh shows how long it has been going and
    /// what it may cost. The operator must be able to tell a slow
    /// source from a stuck panel.
    #[test]
    fn the_running_refresh_shows_the_elapsed_time_and_the_budget() {
        let lang = test_lang();
        let fragment = RefreshStatusFragment {
            lang: lang.clone(),
            source_id: "src1".into(),
            busy: true,
            pending: false,
            done_at: None,
            error_message: None,
            ok: true,
            elapsed_seconds: Some(42),
            budget_hint: refresh_budget_hint(&lang),
        };
        let html = fragment.render().unwrap();
        let elapsed = lang.t_named("src.refresh_elapsed", &[("seconds", "42".to_string())]);
        assert!(html.contains(&elapsed), "{html}");
        // The budget is quoted next to the spinner: the ceiling of one
        // fetch and the number of requests it may make.
        assert!(html.contains(&refresh_budget_hint(&lang)), "{html}");
        // The polled element stays the one that carries the polling
        // contract, and it swaps its content into the page's permanent
        // `#refresh-status` live region instead of re-rendering the
        // region itself (a recreated live region is never announced).
        assert!(!html.contains(r#"id="refresh-status""#), "{html}");
        assert!(html.contains(r#"data-busy="1""#), "{html}");
        assert!(html.contains(r##"hx-target="#refresh-status""##), "{html}");
        assert!(html.contains(r#"hx-swap="innerHTML""#), "{html}");
    }

    /// A finished refresh has no elapsed time: the moment it ended is
    /// what the fragment shows then.
    #[test]
    fn a_finished_refresh_shows_no_elapsed_time() {
        let lang = test_lang();
        let fragment = RefreshStatusFragment {
            lang: lang.clone(),
            source_id: "src1".into(),
            busy: false,
            pending: false,
            done_at: Some(1_700_000_000),
            error_message: None,
            ok: true,
            elapsed_seconds: None,
            budget_hint: refresh_budget_hint(&lang),
        };
        let html = fragment.render().unwrap();
        assert!(!html.contains("refresh_elapsed"), "{html}");
        assert!(!html.contains("data-busy"), "{html}");
    }

    /// A source that has never been fetched has no outcome to show: the
    /// fragment renders the neutral pending badge, neither the error
    /// badge nor the busy marker of a fetch in flight.
    #[test]
    fn a_never_fetched_source_renders_the_pending_state() {
        let lang = test_lang();
        let fragment = RefreshStatusFragment {
            lang: lang.clone(),
            source_id: "src1".into(),
            busy: false,
            pending: true,
            done_at: None,
            error_message: None,
            ok: false,
            elapsed_seconds: None,
            budget_hint: refresh_budget_hint(&lang),
        };
        let html = fragment.render().unwrap();
        assert!(html.contains(lang.t("src.refresh_pending")), "{html}");
        assert!(!html.contains("data-busy"), "{html}");
        assert!(!html.contains(lang.t("common.error")), "{html}");
    }

    /// The replayed form is parsed once: multi-valued `protocols` keep
    /// every value in order, a repeated single field takes the last
    /// value (the browser sends them in document order), and empty or
    /// absent fields stay that way.
    #[test]
    fn form_values_from_parses_the_posted_pairs() {
        let form = vec![
            ("name".to_string(), "feed".to_string()),
            ("name".to_string(), "feed 2".to_string()),
            ("url".to_string(), "https://example.com/sub".to_string()),
            ("protocols".to_string(), "http".to_string()),
            ("protocols".to_string(), "socks5".to_string()),
            ("cache_ttl_seconds".to_string(), String::new()),
        ];
        let values = form_values_from(&form);
        assert_eq!(
            values.name, "feed 2",
            "a repeated field takes the last value"
        );
        assert_eq!(values.url, "https://example.com/sub");
        assert_eq!(values.protocols, ["http", "socks5"]);
        assert_eq!(values.cache_ttl_seconds, "", "an empty field stays empty");
        assert!(!values.enabled, "an absent checkbox is unchecked");
    }

    /// The `enabled` checkbox follows HTML semantics: a checked box
    /// submits the field with its value, and the truthy synonyms read
    /// as checked; everything else, an explicit `false` included, is
    /// unchecked — presence alone must not flip the flag on.
    #[test]
    fn the_enabled_checkbox_is_read_from_its_value() {
        for checked in ["1", "on", "true"] {
            let form = vec![("enabled".to_string(), checked.to_string())];
            assert!(
                form_values_from(&form).enabled,
                "{checked} must read as checked"
            );
        }
        for unchecked in ["0", "false", "off", ""] {
            let form = vec![("enabled".to_string(), unchecked.to_string())];
            assert!(
                !form_values_from(&form).enabled,
                "{unchecked} must read as unchecked"
            );
        }
    }

    /// The list filter reads the select's `on`/`off` plus their boolean
    /// synonyms; anything else filters nothing, like the empty "all"
    /// option.
    #[test]
    fn the_enabled_filter_reads_the_boolean_synonyms() {
        assert_eq!(enabled_filter_value("on"), Some(true));
        assert_eq!(enabled_filter_value("true"), Some(true));
        assert_eq!(enabled_filter_value("1"), Some(true));
        assert_eq!(enabled_filter_value("off"), Some(false));
        assert_eq!(enabled_filter_value("false"), Some(false));
        assert_eq!(enabled_filter_value("0"), Some(false));
        assert_eq!(enabled_filter_value(""), None);
        assert_eq!(enabled_filter_value("nonsense"), None);
    }

    /// A source row as the toggle action holds it after the flip.
    fn sample_source(enabled: bool) -> Source {
        let now = now_ts();
        Source {
            id: new_id(),
            slug: Some("s1".into()),
            access_token: None,
            name: "s1".into(),
            url: "https://example.com/sub".into(),
            enabled,
            encoding: Encoding::Auto,
            input_format: None,
            protocols: None,
            cache_ttl_seconds: 3600,
            tags: None,
            pipeline: None,
            headers: None,
            ip_family: None,
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        }
    }

    fn test_lang() -> Lang {
        crate::admin::i18n::Locales::load(std::path::Path::new("/nonexistent")).default_lang()
    }

    /// The toggle swap is rendered from the fragment templates the detail
    /// page includes, so the ids, aria attributes and the hx-* contract
    /// cannot drift apart: the badge half must be the plain badge the
    /// page wraps in a live region (a live region that is recreated with
    /// every swap is never announced), and the form half must fill that
    /// region, replace itself out-of-band and flip its action label.
    #[test]
    fn toggle_swap_fragment_carries_the_page_contract() {
        let lang = test_lang();
        let source = sample_source(true);
        let swap = toggle_swap_fragment(&lang, &source, "csrf-token");

        assert!(
            !swap.contains(r#"id="enabled-badge""#),
            "the badge half must not carry the live region, the page owns it: {swap}"
        );
        assert!(swap.contains(r#"<span class="badge on">"#), "{swap}");
        assert!(swap.contains(r#"id="toggle-form""#), "{swap}");
        assert!(
            swap.contains(&format!(r#"hx-post="/admin/sources/{}/toggle""#, source.id)),
            "{swap}"
        );
        assert!(
            swap.contains(r##"hx-target="#enabled-badge""##),
            "the form must keep targeting the badge: {swap}"
        );
        assert!(
            swap.contains(r##"hx-swap="innerHTML""##),
            "the form must fill the badge, not replace the live region: {swap}"
        );
        assert!(
            swap.contains(r#"hx-swap-oob="outerHTML:#toggle-form""#),
            "the form must travel as an out-of-band swap: {swap}"
        );
        assert!(
            swap.contains(r#"hx-disabled-elt="find button""#),
            "the button must be locked while the request runs: {swap}"
        );
        assert!(
            swap.contains(r#"data-error-target="toggle-error""#),
            "a failed toggle needs a slot to write into: {swap}"
        );
        assert!(
            !swap.contains(r#"aria-pressed"#),
            "the button carries the action, the badge carries the state: {swap}"
        );
        assert!(swap.contains(r#"value="csrf-token""#), "{swap}");
        assert!(swap.contains(lang.t("common.disable")), "{swap}");
        assert!(swap.contains(lang.t("common.on")), "{swap}");
    }

    /// The disabled flip: the badge class and the button label follow the
    /// stored state.
    #[test]
    fn toggle_swap_fragment_flips_with_the_disabled_state() {
        let lang = test_lang();
        let swap = toggle_swap_fragment(&lang, &sample_source(false), "csrf-token");

        assert!(swap.contains(r#"<span class="badge off">"#), "{swap}");
        assert!(!swap.contains(r#"<span class="badge on">"#), "{swap}");
        assert!(swap.contains(lang.t("common.enable")), "{swap}");
    }

    /// Byte-compatibility: the page renders the form fragment with
    /// `swap_oob = false`, the swap with `swap_oob = true`, and the two
    /// outputs are identical apart from exactly the one attribute.
    #[test]
    fn the_oob_marker_is_the_only_difference_from_the_page_render() {
        let lang = test_lang();
        let source = sample_source(true);
        let page_form = ToggleFormFragment {
            lang: lang.clone(),
            toggle_url: format!("/admin/sources/{}/toggle", source.id),
            enabled: source.enabled,
            csrf: "csrf-token".into(),
            swap_oob: false,
        }
        .render()
        .unwrap();
        let swap_form = ToggleFormFragment {
            lang: lang.clone(),
            toggle_url: format!("/admin/sources/{}/toggle", source.id),
            enabled: source.enabled,
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
