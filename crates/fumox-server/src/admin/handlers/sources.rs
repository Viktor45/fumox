//! Source screens: list with filters, create/edit form with full
//! validation, card with aggregates and fetch log,
//! toggle / *Refresh now* / delete actions.

use super::{
    FormError, FormMap, action_response, action_response_err, caps, flash_redirect, fmt_bytes,
    is_htmx, mask_secret, not_found, page_offset, pagination_pages, pipeline_from_form,
    row_error_response, server_error, validate_header_map, validate_name, validate_slug,
    validate_tags, validate_ttl,
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
        enabled: match f_enabled.as_str() {
            "on" => Some(true),
            "off" => Some(false),
            _ => None,
        },
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
        Err(err) => return server_error(lang, &err),
    };

    let tags: Vec<String> = sources::distinct_tags(&state.pool)
        .await
        .unwrap_or_default();

    render_html(
        lang.clone(),
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
    render_html(
        lang.clone(),
        &SourceFormTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "sources",
            csrf: state.csrf_for(&headers),
            form_id: None,
            action: "/admin/sources/new".into(),
            values,
            errors: Vec::new(),
            all_protocols: all_protocols_with_selection(&[]),
            headers_masked_note: false,
            widget_html,
        },
        StatusCode::OK,
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
        Err(err) => return server_error(lang, &err),
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
    render_html(
        lang.clone(),
        &SourceFormTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "sources",
            csrf: state.csrf_for(&headers),
            form_id: Some(source.id.clone()),
            action: format!("/admin/sources/{}/edit", source.id),
            values,
            errors: Vec::new(),
            all_protocols: all_protocols_with_selection(&values_for_select(&source)),
            headers_masked_note: source.headers.as_ref().is_some_and(|map| !map.is_empty()),
            widget_html,
        },
        StatusCode::OK,
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

/// Validate + assemble a `Source` from form fields. Returns the model or
/// the reason it could not be built: per-field errors (translated, shown
/// next to fields) or a row that could not be read.
async fn build_source_from_form(
    state: &AdminState,
    lang: &Lang,
    form: &[(String, String)],
    existing_id: Option<&str>,
) -> Result<Source, FormError> {
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
    } else if let Err(issue) = fetcher::vet_url_with_policy(
        &url,
        state.admin().allow_private_urls,
        ip_family.unwrap_or_else(|| state.fetcher.default_family()),
        state.fetcher.dns_timeout,
    )
    .await
    {
        errors.push(("url".into(), lang.t_args(issue.key, &issue.args)));
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
            errors.push(("cache_ttl_seconds".into(), lang.t("val.ttl_range").into()));
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

    Ok(Source {
        id: existing_id.map(str::to_string).unwrap_or_else(new_id),
        slug,
        name,
        url,
        enabled: form.iter().any(|(k, _)| k == "enabled"),
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
    })
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
        url_masked: url_carries_mask(&url),
        url,
        enabled: form.iter().any(|(k, _)| k == "enabled"),
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
    let source = match build_source_from_form(&state, &lang, &form, None).await {
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
            return render_html(
                lang.clone(),
                &SourceFormTemplate {
                    lang,
                    langs: state.locales.choices().to_vec(),
                    theme,
                    active: "sources",
                    csrf: state.csrf_for(&headers),
                    form_id: None,
                    action: "/admin/sources/new".into(),
                    all_protocols: all_protocols_with_selection(&form_values_from(&form).protocols),
                    values: form_values_from(&form),
                    errors,
                    headers_masked_note: false,
                    widget_html,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        }
        Err(FormError::Server(err)) => {
            return row_error_response(lang, &err, "err.source_not_found");
        }
    };
    if let Err(err) = sources::create(&state.pool, &source).await {
        return server_error(lang, &err);
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
    let source = match build_source_from_form(&state, &lang, &form, Some(&id)).await {
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
            return render_html(
                lang.clone(),
                &SourceFormTemplate {
                    lang,
                    langs: state.locales.choices().to_vec(),
                    theme,
                    active: "sources",
                    csrf: state.csrf_for(&headers),
                    form_id: Some(id),
                    action,
                    all_protocols: all_protocols_with_selection(&form_values_from(&form).protocols),
                    values: form_values_from(&form),
                    errors,
                    headers_masked_note: true,
                    widget_html,
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        }
        Err(FormError::Server(err)) => {
            return row_error_response(lang, &err, "err.source_not_found");
        }
    };
    if let Err(err) = sources::update_settings(&state.pool, &source).await {
        return row_error_response(lang, &err, "err.source_not_found");
    }
    // Saved → effective immediately. The freshness stamp lives on the
    // source row (`sources::update_settings` resets it when a
    // fetch-relevant field changed); only the rendered outputs need
    // dropping here.
    state
        .caches
        .invalidate_processed_for_source(&source.id)
        .await;
    tracing::info!(source = %source.id, "source updated");
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
    pages: Vec<(i64, bool)>,
    /// The card includes `sources/_toggle_form.html`, whose standalone
    /// variant marks the form as an out-of-band swap in the toggle
    /// response; the page itself always renders it plain.
    swap_oob: bool,
}

impl_i18n!(SourceDetailTemplate);

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
        Err(err) => return server_error(lang, &err),
    };
    let page: i64 = params
        .get("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);

    let total: i64 = match fetch_log::count_for_source(&state.pool, &id).await {
        Ok(total) => total,
        Err(err) => return server_error(lang, &err),
    };
    let log: Vec<fetch_log::FetchLogRow> = match fetch_log::list_for_source(
        &state.pool,
        &id,
        LOG_PAGE_SIZE,
        page_offset(page, LOG_PAGE_SIZE),
    )
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    let counts = match proxies::count_by_status_for_source(&state.pool, &id).await {
        Ok(counts) => counts,
        Err(err) => return server_error(lang, &err),
    };

    render_source_detail(
        &state, lang, peer, &headers, source, counts, log, page, total,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_source_detail(
    state: &AdminState,
    lang: Lang,
    peer: SocketAddr,
    headers: &HeaderMap,
    source: Source,
    counts: Vec<(String, i64)>,
    log: Vec<fetch_log::FetchLogRow>,
    page: i64,
    total: i64,
) -> Response {
    let serve_path = format!(
        "/src/{}",
        source.slug.clone().unwrap_or_else(|| source.id.clone())
    );
    // Absolute serve link: the host the admin panel was opened on with the
    // public port from [server].bind.
    let base = match state.serve_base(peer, headers) {
        Ok(b) => b,
        Err(err) => return super::server_error(lang, &fumox_core::Error::Config(err.to_string())),
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
            pages: pagination_pages(page, total, LOG_PAGE_SIZE),
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
    let log: Vec<fetch_log::FetchLogRow> =
        match fetch_log::recent_for_source(&state.pool, &id, LOG_PAGE_SIZE).await {
            Ok(rows) => rows,
            Err(err) => return server_error(lang, &err),
        };
    render_html(
        lang.clone(),
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
/// pattern as [`EnabledBadgeFragment`]. `swap_oob` adds the
/// `hx-swap-oob` attribute that makes the form in a toggle response
/// replace itself out-of-band; the initial page renders it plain.
#[derive(Template)]
#[template(path = "sources/_toggle_form.html")]
struct ToggleFormFragment {
    lang: Lang,
    source: SourceCard,
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
        source: card,
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
        Err(err) => return server_error(lang, &err),
    };
    let enabled = !source.enabled;
    // The toggle writes the flag and nothing else: the settings columns
    // keep the values they have.
    match sources::set_enabled(&state.pool, &id, enabled).await {
        Ok(true) => {}
        Ok(false) => return not_found(lang, "err.source_not_found"),
        Err(err) => return row_error_response(lang, &err, "err.source_not_found"),
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
        Err(err) => return server_error(lang, &err),
    }
    if state.refresh_tx.send(id.clone()).is_err() {
        return action_response(
            is_htmx(&headers),
            &format!("/admin/sources/{id}"),
            String::new(),
            lang.t("src.scheduler_unavailable"),
        );
    }
    tracing::info!(source = %id, "immediate refresh queued");
    if is_htmx(&headers) {
        // The initial state is the fragment the polled status renders,
        // so the two cannot drift apart: the swap and the first render
        // carry the same markup and the same polling contract.
        render_html(
            lang.clone(),
            &RefreshStatusFragment {
                lang: lang.clone(),
                source_id: id.clone(),
                busy: true,
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
        Redirect::to(&format!("/admin/sources/{id}")).into_response()
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
    /// Unix timestamp of the completed fetch, rendered by the template as a
    /// `<time>` element next to the `src.refresh_done` label; `None` while
    /// busy or on error.
    done_at: Option<i64>,
    /// Escaped human-readable fetch error; `None` while busy or on success.
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
    let (done_at, error_message, ok) = if busy {
        (None, None, true)
    } else {
        let source = match sources::get(&state.pool, &id).await {
            Ok(Some(source)) => source,
            // The source is gone: the poll has nothing left to report.
            Ok(None) => return not_found(lang, "err.source_not_found"),
            Err(err) => return server_error(lang, &err),
        };
        if source.error_class.is_none() && source.last_fetched_at.is_some() {
            (source.last_fetched_at, None, true)
        } else {
            (
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
        &RefreshStatusFragment {
            lang: lang.clone(),
            source_id: id,
            busy,
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
        Err(err) => return server_error(lang, &err),
    }
    // The row is gone; the rendered outputs that still name it go here.
    state.caches.invalidate_processed_for_source(&id).await;
    tracing::info!(source = %id, "source deleted");
    match sweep {
        Ok(sweep) => {
            if sweep.retired > 0 {
                tracing::info!(retired = sweep.retired, "orphaned proxies marked removed");
            }
            if sweep.protected > 0 {
                // The rows the sweep left alone on purpose: they have no
                // source link any more, so no probe lane can reach them.
                tracing::info!(
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
            tracing::error!(error = %err, "failed to mark orphans removed");
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
    fn fmt_bytes(&self, bytes: &Option<u64>) -> String {
        bytes
            .map(|b| fmt_bytes(&self.lang, b as i64))
            .unwrap_or_else(|| ",".into())
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
        Err(err) => return server_error(lang, &err),
    };

    let outcome = crate::ingest::dry_run_source(&state.fetcher, &state.geo, &source).await;
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
        render_html(fragment.lang.clone(), &fragment, StatusCode::OK)
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
        n.map(|n| fmt_bytes(&self.lang, n))
            .unwrap_or_else(|| ",".into())
    }
}

impl SourceLogFragment {
    fn bytes(&self, n: &Option<i64>) -> String {
        n.map(|n| fmt_bytes(&self.lang, n))
            .unwrap_or_else(|| ",".into())
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
        // contract: everything the busy state shows lives inside it, or
        // the swap would leave the rest behind on every poll.
        assert!(html.contains(r#"id="refresh-status""#), "{html}");
        assert!(html.contains(r#"data-busy="1""#), "{html}");
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

    /// A source row as the toggle action holds it after the flip.
    fn sample_source(enabled: bool) -> Source {
        let now = now_ts();
        Source {
            id: new_id(),
            slug: Some("s1".into()),
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
            source: SourceCard::from_source(&source),
            csrf: "csrf-token".into(),
            swap_oob: false,
        }
        .render()
        .unwrap();
        let swap_form = ToggleFormFragment {
            lang: lang.clone(),
            source: SourceCard::from_source(&source),
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
