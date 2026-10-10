//! Source screens: list with filters, create/edit form with full
//! validation, card with aggregates and fetch log,
//! toggle / *Refresh now* / delete actions.

use super::{
    FormMap, action_response, caps, flash_redirect, fmt_bytes, is_htmx, mask_secret, not_found,
    page_offset, pagination_pages, pipeline_from_form, server_error, validate_slug,
};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::pipeline_editor::{widget_from_posted, widget_from_stored};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use crate::fetcher;
use askama::Template;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::models::{Encoding, InputFormat, IpFamily, Scheme, Source, new_id, now_ts};
use fumox_core::repo::{fetch_log, proxies, sources};
use std::net::SocketAddr;
use std::str::FromStr;

/// Rows of the fetch log shown on the source card and its polled
/// `sources/_log.html` fragment: one fixed page size, no query parameter
/// (the log is a card detail, not a browsable list screen).
const LOG_PAGE_SIZE: i64 = 20;

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
        Ok(rows) => rows,
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
        url: source.url.clone(),
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

/// Validate + assemble a `Source` from form fields. Returns the model or
/// per-field errors (translated, shown next to fields).
async fn build_source_from_form(
    state: &AdminState,
    lang: &Lang,
    form: &[(String, String)],
    existing_id: Option<&str>,
) -> Result<Source, Vec<(String, String)>> {
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

    let name = get("name");
    if name.is_empty() {
        errors.push(("name".into(), lang.t("val.required").into()));
    } else if name.chars().count() > 200 {
        errors.push(("name".into(), lang.t("val.name_too_long").into()));
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

    let url = get("url");
    if url.is_empty() {
        errors.push(("url".into(), lang.t("val.required").into()));
    } else if url.len() > caps::URL {
        errors.push((
            "url".into(),
            lang.t("val.field_too_long")
                .replace("{}", &caps::URL.to_string()),
        ));
    } else if let Err(issue) = fetcher::vet_url(
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
    let cache_ttl_seconds: i64 = match ttl_raw.parse() {
        Ok(ttl) if (60..=86_400).contains(&ttl) => ttl,
        _ => {
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
        if list.len() > caps::TAGS {
            errors.push((
                "tags".into(),
                lang.t("val.too_many_tags")
                    .replace("{}", &caps::TAGS.to_string()),
            ));
        }
        if list.iter().any(|t| t.len() > caps::TAG_BYTES) {
            errors.push((
                "tags".into(),
                lang.t("val.field_too_long")
                    .replace("{}", &caps::TAG_BYTES.to_string()),
            ));
        }
        Some(list)
    };

    // Headers: "Key: value" lines. Masked values from the edit form are
    // kept as-is only when unchanged, a masked placeholder means "keep the
    // stored secret"; we re-read it from the DB below.
    let headers_raw = get("headers");
    let mut headers_map: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    // Header caps: the whole map is replayed on
    // every fetch of the source, so it is bounded like every other field.
    let non_empty_lines = headers_raw.lines().filter(|l| !l.trim().is_empty()).count();
    if non_empty_lines > caps::HEADER_LINES {
        errors.push((
            "headers".into(),
            lang.t("val.too_many_headers")
                .replace("{}", &caps::HEADER_LINES.to_string()),
        ));
    }
    let headers_bytes: usize = headers_raw
        .lines()
        .map(|l| l.trim().len())
        .filter(|len| *len > 0)
        .sum();
    if headers_bytes > caps::HEADER_BYTES {
        errors.push((
            "headers".into(),
            lang.t("val.headers_too_long")
                .replace("{}", &caps::HEADER_BYTES.to_string()),
        ));
    }
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
        // Reject names/values the HTTP layer would refuse, so a bad line
        // fails the form now instead of every future fetch.
        if axum::http::HeaderName::try_from(key.as_str()).is_err()
            || axum::http::HeaderValue::try_from(value.as_str()).is_err()
        {
            errors.push((
                "headers".into(),
                lang.t("val.header_invalid").replace("{}", line),
            ));
            continue;
        }
        headers_map.insert(key, value);
    }

    // Pipeline: in builder mode the JSON is generated from the widget
    // fields server-side (a stale `pipeline` textarea, if any, is ignored);
    // in raw mode the textarea is the input, as before.
    let pipeline = pipeline_from_form(form, lang, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }

    // Restore unchanged masked header secrets from the stored row.
    if let Some(id) = existing_id
        && let Ok(Some(stored)) = sources::get(&state.pool, id).await
        && let Some(stored_headers) = stored.headers
    {
        restore_masked_headers(&mut headers_map, &stored_headers);
    }

    let now = now_ts();
    let existing = match existing_id {
        Some(id) => sources::get(&state.pool, id).await.ok().flatten(),
        None => None,
    };

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
        last_fetched_at: existing.as_ref().and_then(|s| s.last_fetched_at),
        last_error: existing.as_ref().and_then(|s| s.last_error.clone()),
        error_class: existing.as_ref().and_then(|s| s.error_class),
    })
}

/// Put the stored secret back where the form still carries the mask
/// rendered from it (`mask_secret`).
///
/// An unchanged key is matched by key *and* mask, so it restores its own
/// secret exactly and a value the operator retyped (`tok•en`, or a fresh
/// secret replacing the mask) is left alone. Only a key that is not in the
/// stored row falls back to the mask lookup, which is what restores a mask
/// whose header was renamed.
///
/// Matching on the mask itself, not on "the value contains a bullet", is
/// what keeps a real header value the operator typed with a bullet in it
/// from being silently reverted. Anything that is not a mask of a stored
/// secret stays exactly as typed.
fn restore_masked_headers(
    headers_map: &mut std::collections::BTreeMap<String, String>,
    stored: &std::collections::BTreeMap<String, String>,
) {
    if headers_map.is_empty() || stored.is_empty() {
        return;
    }
    // The mask is a three-character prefix, so two secrets sharing one
    // (any two JWTs, both starting `eyJ`) render identically. Such a mask
    // is left out of the fallback map entirely rather than resolved to an
    // arbitrary one of its candidates: the key path above already gave
    // every unchanged key its own secret, and a renamed key carrying a
    // colliding mask is kept as typed instead of being rewritten into
    // somebody else's secret. Only *different* secrets colliding make it
    // ambiguous - two stored headers carrying the same secret render the
    // same mask but have one single answer, and that answer is the secret.
    let mut masks: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    let mut ambiguous: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for original in stored.values() {
        let mask = mask_secret(original);
        if ambiguous.contains(&mask) {
            continue;
        }
        match masks.get(mask.as_str()) {
            Some(previous) if *previous != original.as_str() => {
                masks.remove(&mask);
                ambiguous.insert(mask);
            }
            Some(_) => {}
            None => {
                masks.insert(mask, original.as_str());
            }
        }
    }
    for (key, value) in headers_map.iter_mut() {
        let restored = match stored.get(key.as_str()) {
            Some(original) if *value == mask_secret(original) => Some(original.as_str()),
            _ => masks.get(value.as_str()).copied(),
        };
        if let Some(original) = restored {
            *value = original.to_string();
        }
    }
}

fn form_values_from(form: &[(String, String)]) -> SourceFormValues {
    let get = |key: &str| -> String {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    SourceFormValues {
        name: get("name"),
        slug: get("slug"),
        url: get("url"),
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
        Err(errors) => {
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
        Err(errors) => {
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
    };
    if let Err(err) = sources::update(&state.pool, &source).await {
        return server_error(lang, &err);
    }
    // Saved → effective immediately. The freshness stamp lives on the
    // source row (`sources::update` resets it when a fetch-relevant field
    // changed); only the rendered outputs need dropping here.
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
    source: Source,
    url_display: String,
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
            url_display: source.url.clone(),
            source,
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
    source: Source,
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
    source: Source,
    csrf: String,
    swap_oob: bool,
}

impl_i18n!(ToggleFormFragment);

/// The toggle response body: the badge swapped into `#enabled-badge`
/// normally plus the form marked out-of-band. Both halves come from the
/// fragment templates the detail page includes, so the ids, aria
/// attributes and the hx-* contract cannot drift from the initial render.
fn toggle_swap_fragment(lang: &Lang, source: &Source, csrf: &str) -> String {
    let badge = EnabledBadgeFragment {
        lang: lang.clone(),
        source: source.clone(),
    }
    .render()
    .expect("badge fragment renders");
    let form = ToggleFormFragment {
        lang: lang.clone(),
        source: source.clone(),
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
    source.enabled = !source.enabled;
    source.updated_at = now_ts();
    if let Err(err) = sources::update(&state.pool, &source).await {
        return server_error(lang, &err);
    }
    // The enabled flip reset the row's freshness stamp (a fetch-relevant
    // change, see `sources::update`); the rendered outputs go here.
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
    if sources::get(&state.pool, &id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return not_found(lang, "err.source_not_found");
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
        let fragment = format!(
            r#"<span id="refresh-status" data-busy="1"
                  hx-get="/admin/sources/{id}/refresh-status"
                  hx-trigger="every 2s" hx-swap="outerHTML">
                 <span class="badge neutral">{}</span>
               </span>"#,
            lang.t("common.refreshing")
        );
        (
            StatusCode::ACCEPTED,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            fragment,
        )
            .into_response()
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
}

impl_i18n!(RefreshStatusFragment);

pub async fn source_refresh_status(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let busy = state.scheduler.is_in_flight(&id).await;
    let (done_at, error_message, ok) = if busy {
        (None, None, true)
    } else {
        let source = sources::get(&state.pool, &id).await.ok().flatten();
        match source {
            Some(s) if s.error_class.is_none() && s.last_fetched_at.is_some() => {
                (s.last_fetched_at, None, true)
            }
            Some(s) => (
                None,
                Some(
                    lang.t("src.refresh_error").replace(
                        "{}",
                        s.last_error
                            .as_deref()
                            .unwrap_or_else(|| lang.t("src.refresh_error_unknown")),
                    ),
                ),
                false,
            ),
            None => (None, Some(lang.t("err.source_not_found").into()), false),
        }
    };
    render_html(
        lang.clone(),
        &RefreshStatusFragment {
            lang,
            source_id: id,
            busy,
            done_at,
            error_message,
            ok,
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
    match sources::delete(&state.pool, &id).await {
        Ok(true) => {}
        Ok(false) => return not_found(lang, "err.source_not_found"),
        Err(err) => return server_error(lang, &err),
    }
    // Orphaned proxies (no remaining links) transition to `removed`;
    // reconciliation never resets it, a proxy that reappears in a fetch
    // keeps its state. With `drop_gate = false` the admin click is
    // intentionally conservative: a `ready` row is tunnel-verified and
    // an `unknown` row has not yet had its first verdict, neither
    // should be retired just because its source went away. The probe is
    // the only authority on the lifecycle of a verified proxy, and the
    // priority queue is the only authority on a not-yet-checked one.
    // With `drop_gate = true` the strict policy applies and every
    // orphan retires.
    let protected: &[&str] = if state.ingest().drop_gate {
        &[]
    } else {
        &["ready", "unknown"]
    };
    match proxies::mark_orphans_removed(&state.pool, protected).await {
        Ok(orphans) if orphans > 0 => {
            tracing::info!(orphans, "orphaned proxies marked removed");
        }
        Err(err) => tracing::error!(error = %err, "failed to mark orphans removed"),
        _ => {}
    }
    // The row is gone; the rendered outputs that still name it go here.
    state.caches.invalidate_processed_for_source(&id).await;
    tracing::info!(source = %id, "source deleted");
    action_response(
        is_htmx(&headers),
        "/admin/sources",
        String::new(),
        lang.t("src.deleted_toast"),
    )
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
        // message instead — the same plain-browser fallback as
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
    /// under its own key, as before.
    #[test]
    fn unchanged_mask_is_restored_from_the_stored_secret() {
        let stored = headers(&[("X-Token", "supersecretvalue")]);
        let mut submitted = headers(&[("X-Token", &super::mask_secret("supersecretvalue"))]);
        restore_masked_headers(&mut submitted, &stored);
        assert_eq!(submitted["X-Token"], "supersecretvalue");
    }

    /// A header the operator renamed keeps its secret: the mask is matched
    /// by value, not by key, so it never reaches the upstream fetch as a
    /// literal `abc…••••`.
    #[test]
    fn mask_under_a_renamed_key_is_restored() {
        let stored = headers(&[("X-Token", "supersecretvalue")]);
        let mut submitted = headers(&[("Authorization", &super::mask_secret("supersecretvalue"))]);
        restore_masked_headers(&mut submitted, &stored);
        assert_eq!(submitted["Authorization"], "supersecretvalue");
    }

    /// A real value that happens to contain the bullet the mask is drawn
    /// with is a value, not a mask: the old `contains('•')` test threw it
    /// away and stored the stored secret instead.
    #[test]
    fn typed_value_with_a_bullet_is_kept() {
        let stored = headers(&[("X-Token", "supersecretvalue")]);
        let mut submitted = headers(&[("X-Token", "tok•en"), ("X-Other", "abc…••••extra")]);
        restore_masked_headers(&mut submitted, &stored);
        assert_eq!(submitted["X-Token"], "tok•en");
        assert_eq!(submitted["X-Other"], "abc…••••extra");
    }

    /// Two stored headers holding the *same* secret render one mask with
    /// one single answer, so a renamed key carrying that mask restores it
    /// instead of keeping the mask and replaying `sup…••••` upstream as a
    /// credential. Blacklisting the mask on a duplicate key rather than on
    /// two different secrets is what made this one a no-op.
    #[test]
    fn renamed_key_mask_restores_a_secret_two_headers_share() {
        let stored = headers(&[("X-A", "supersecretvalue"), ("X-B", "supersecretvalue")]);
        let mut submitted = headers(&[("X-Renamed", &super::mask_secret("supersecretvalue"))]);
        restore_masked_headers(&mut submitted, &stored);
        assert_eq!(submitted["X-Renamed"], "supersecretvalue");
    }

    /// A new source has nothing stored to restore from.
    #[test]
    fn restore_is_a_noop_without_stored_headers() {
        let mut submitted = headers(&[("X-Token", "tok•en")]);
        restore_masked_headers(&mut submitted, &BTreeMap::new());
        assert_eq!(submitted["X-Token"], "tok•en");
    }

    /// Two secrets whose first three characters are equal (any two JWTs)
    /// mask identically. Keyed by mask alone they collapse into one entry
    /// and the second secret is written over the first, so each header
    /// keeps its own.
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
        restore_masked_headers(&mut submitted, &stored);
        assert_eq!(submitted["Authorization"], "eyJAAA-first-secret");
        assert_eq!(submitted["X-Api-Key"], "eyJBBB-second-secret");
    }

    /// A mask that several stored secrets could have been rendered from is
    /// not resolved by guesswork when its key is new: the form rendered it
    /// ambiguous, so it stays as submitted.
    #[test]
    fn colliding_mask_under_a_new_key_is_not_guessed() {
        let stored = headers(&[
            ("Authorization", "eyJAAA-first-secret"),
            ("X-Api-Key", "eyJBBB-second-secret"),
        ]);
        let mut submitted = headers(&[("X-Renamed", &super::mask_secret("eyJAAA-first-secret"))]);
        restore_masked_headers(&mut submitted, &stored);
        assert_eq!(
            submitted["X-Renamed"],
            super::mask_secret("eyJAAA-first-secret")
        );
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
    /// cannot drift apart: the badge half must announce itself as a live
    /// region and the form half must replace itself out-of-band with the
    /// pressed state flipped.
    #[test]
    fn toggle_swap_fragment_carries_the_page_contract() {
        let lang = test_lang();
        let source = sample_source(true);
        let swap = toggle_swap_fragment(&lang, &source, "csrf-token");

        assert!(
            swap.contains(r#"<span id="enabled-badge" aria-live="polite" aria-atomic="true">"#),
            "the badge half lost the live-region contract: {swap}"
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
        let swap = toggle_swap_fragment(&lang, &sample_source(false), "csrf-token");

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
        let source = sample_source(true);
        let page_form = ToggleFormFragment {
            lang: lang.clone(),
            source: source.clone(),
            csrf: "csrf-token".into(),
            swap_oob: false,
        }
        .render()
        .unwrap();
        let swap_form = ToggleFormFragment {
            lang: lang.clone(),
            source,
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
