//! Source screens: list with filters, create/edit form with full
//! validation (ADMIN_PLAN §4.2), card with aggregates and fetch log,
//! toggle / "обновить сейчас" / delete actions.

use super::{
    FormMap, action_response, clamp_limit, fmt_bytes, fmt_opt_ts_element, fmt_ts_element, is_htmx,
    mask_secret, not_found, pagination_pages, server_error,
};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::pipeline_editor::{BuilderState, widget_from_posted, widget_from_stored};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use crate::fetcher;
use crate::pipeline::CompiledPipeline;
use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::models::{Encoding, InputFormat, IpFamily, Scheme, Source, new_id, now_ts};
use fumox_core::repo::{proxies, sources};
use std::str::FromStr;

/// Slug rules (ADMIN_PLAN §4.2): starts alphanumeric, then `[A-Za-z0-9_-]`,
/// total length 2–64.
const SLUG_RE: &str = r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$";

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct SourceListRow {
    id: String,
    name: String,
    slug: Option<String>,
    url: String,
    enabled: bool,
    cache_ttl_seconds: i64,
    last_fetched_at: Option<i64>,
    error_class: Option<String>,
    proxies_count: i64,
}

#[derive(Template)]
#[template(path = "sources/list.html")]
struct SourcesListTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    rows: Vec<SourceListRow>,
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

    let mut sql = String::from(
        "SELECT s.id, s.name, s.slug, s.url, s.enabled, s.cache_ttl_seconds,
                s.last_fetched_at, s.error_class,
                (SELECT COUNT(*) FROM proxy_source_links l WHERE l.source_id = s.id) AS proxies_count
         FROM sources s",
    );
    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if f_enabled == "on" {
        clauses.push("s.enabled = 1".into());
    } else if f_enabled == "off" {
        clauses.push("s.enabled = 0".into());
    }
    if f_error {
        clauses.push("s.error_class IS NOT NULL".into());
    }
    if !f_tag.is_empty() {
        clauses.push("EXISTS (SELECT 1 FROM json_each(s.tags) WHERE json_each.value = ?)".into());
        binds.push(f_tag.clone());
    }
    if !f_q.is_empty() {
        clauses.push("(s.name LIKE ? OR s.url LIKE ?)".into());
        binds.push(format!("%{f_q}%"));
        binds.push(format!("%{f_q}%"));
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY s.created_at DESC");

    let mut query = sqlx::query_as::<_, SourceListRow>(sqlx::AssertSqlSafe(sql.as_str()));
    for value in &binds {
        query = query.bind(value);
    }
    let rows = match query.fetch_all(&state.pool).await {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };

    let tags: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT json_each.value FROM sources, json_each(sources.tags) ORDER BY 1",
    )
    .fetch_all(&state.pool)
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

// ---------------------------------------------------------------------------
// Form (create / edit)
// ---------------------------------------------------------------------------

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
    /// Pipeline widget HTML (builder ⇄ raw, PIPELINE.md §3), rendered by the
    /// editor module; prefilled from the stored pipeline on GET, from the
    /// posted fields on validation errors.
    widget_html: String,
}

impl SourceFormTemplate {
    fn error_for(&self, field: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|(f, _)| f == field)
            .map(|(_, m)| m.as_str())
    }
}

impl_i18n!(SourceFormTemplate);

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
    // New source: nothing stored yet — an empty builder widget.
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
    // the raw-mode warning (PIPELINE.md §2.2).
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
    let slug = if slug_raw.is_empty() {
        None
    } else {
        if !regex::Regex::new(SLUG_RE).is_ok_and(|re| re.is_match(&slug_raw)) {
            errors.push(("slug".into(), lang.t("val.slug_format").into()));
        } else if let Ok(Some(other)) = sources::get_by_slug(&state.pool, &slug_raw).await
            && other.id != existing_id.unwrap_or_default()
        {
            errors.push(("slug".into(), lang.t("val.slug_taken").into()));
        }
        Some(slug_raw)
    };

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
    } else if let Err(issue) = fetcher::vet_url(
        &url,
        state.admin.allow_private_urls,
        ip_family.unwrap_or_else(|| state.fetcher.default_family()),
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
        Some(
            tags_raw
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect(),
        )
    };

    // Headers: "Key: value" lines. Masked values from the edit form are
    // kept as-is only when unchanged — a masked placeholder means "keep the
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
        // Reject names/values the HTTP layer would refuse, so a bad line
        // fails the form now instead of every future fetch (security audit,
        // 2026-08-30).
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

    // Pipeline (PIPELINE.md §3): in builder mode the JSON is generated from
    // the widget fields server-side (a stale `pipeline` textarea, if any,
    // is ignored); in raw mode the textarea is the input, as before.
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

    if !errors.is_empty() {
        return Err(errors);
    }

    // Restore unchanged masked header secrets from the stored row.
    if let Some(id) = existing_id
        && let Ok(Some(stored)) = sources::get(&state.pool, id).await
        && let Some(stored_headers) = stored.headers
    {
        for (key, value) in headers_map.iter_mut() {
            if value.contains('•')
                && let Some(original) = stored_headers.get(key)
            {
                *value = original.clone();
            }
        }
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
    // "Сохранил → сразу действует" (ADMIN_PLAN §7).
    state.caches.invalidate_source(&source.id).await;
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

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct LogRow {
    fetched_at: i64,
    ok: i64,
    http_status: Option<i64>,
    bytes: Option<i64>,
    proxies_found: Option<i64>,
    error: Option<String>,
    error_class: Option<String>,
}

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
    log: Vec<LogRow>,
    pages: Vec<(i64, bool)>,
}

impl_i18n!(SourceDetailTemplate);

pub async fn source_detail(
    State(state): State<AdminState>,
    Path(id): Path<String>,
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
    let per_page = clamp_limit(params.get("per_page").and_then(|v| v.parse().ok()));

    let total: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM fetch_log WHERE source_id = ?")
        .bind(&id)
        .fetch_one(&state.pool)
        .await
    {
        Ok(total) => total,
        Err(err) => return server_error(lang, &err),
    };
    let log: Vec<LogRow> = match sqlx::query_as(
        "SELECT fetched_at, ok, http_status, bytes, proxies_found, error, error_class
         FROM fetch_log WHERE source_id = ?
         ORDER BY fetched_at DESC, id DESC LIMIT ? OFFSET ?",
    )
    .bind(&id)
    .bind(per_page.min(20))
    .bind((page - 1) * per_page.min(20))
    .fetch_all(&state.pool)
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
        &state, lang, &headers, source, counts, log, page, per_page, total,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_source_detail(
    state: &AdminState,
    lang: Lang,
    headers: &HeaderMap,
    source: Source,
    counts: Vec<(String, i64)>,
    log: Vec<LogRow>,
    page: i64,
    per_page: i64,
    total: i64,
) -> Response {
    let serve_path = format!(
        "/src/{}",
        source.slug.clone().unwrap_or_else(|| source.id.clone())
    );
    // Absolute serve link: the host the admin panel was opened on with the
    // public port from [server].bind (ADMIN_PLAN §4.2).
    let serve_url = format!("{}{}", state.serve_base(headers), serve_path);
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
            pages: pagination_pages(page, total, per_page.min(20)),
        },
        StatusCode::OK,
    )
}

/// Fetch-log fragment for the source card (also polled after refresh).
#[derive(Template)]
#[template(path = "sources/_log.html")]
struct SourceLogFragment {
    lang: Lang,
    log: Vec<LogRow>,
}

impl_i18n!(SourceLogFragment);

pub async fn source_log(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let log: Vec<LogRow> = match sqlx::query_as(
        "SELECT fetched_at, ok, http_status, bytes, proxies_found, error, error_class
         FROM fetch_log WHERE source_id = ?
         ORDER BY fetched_at DESC, id DESC LIMIT 20",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(err) => return server_error(lang, &err),
    };
    render_html(
        lang.clone(),
        &SourceLogFragment { lang, log },
        StatusCode::OK,
    )
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

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
    state.caches.invalidate_source(&id).await;
    let message = if source.enabled {
        lang.t("src.enabled_toast")
    } else {
        lang.t("src.disabled_toast")
    };
    tracing::info!(source = %id, enabled = source.enabled, "source toggled");
    action_response(
        is_htmx(&headers),
        &format!("/admin/sources/{id}"),
        format!(
            r#"<span class="badge {}">{}</span>"#,
            if source.enabled { "on" } else { "off" },
            if source.enabled {
                lang.t("common.on")
            } else {
                lang.t("common.off")
            }
        ),
        message,
    )
}

/// "Обновить сейчас": enqueue an immediate fetch (ADMIN_PLAN §5, §7).
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
/// flight, then shows the outcome and stops polling (ADMIN_PLAN §5).
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

impl RefreshStatusFragment {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts_element(*ts)
    }
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
    // reconciliation never resets it — a proxy that reappears in a fetch
    // keeps its state (ADMIN_PLAN §13.1, decisions 9 and 23).
    match proxies::mark_orphans_removed(&state.pool).await {
        Ok(orphans) if orphans > 0 => {
            tracing::info!(orphans, "orphaned proxies marked removed");
        }
        Err(err) => tracing::error!(error = %err, "failed to mark orphans removed"),
        _ => {}
    }
    state.caches.invalidate_source(&id).await;
    tracing::info!(source = %id, "source deleted");
    action_response(
        is_htmx(&headers),
        "/admin/sources",
        String::new(),
        lang.t("src.deleted_toast"),
    )
}

// ---------------------------------------------------------------------------
// Dry-run fetch (ADMIN_PLAN §13.11)
// ---------------------------------------------------------------------------

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
            .unwrap_or_else(|| "—".into())
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

    let outcome = crate::ingest::dry_run_source(&state.fetcher, &source).await;
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
    render_html(fragment.lang.clone(), &fragment, StatusCode::OK)
}

// Formatting helpers exposed to the askama templates of this module.
// askama passes call arguments by reference, so every helper takes &T.
impl SourcesListTemplate {
    fn ts(&self, ts: &Option<i64>) -> String {
        fmt_opt_ts_element(*ts)
    }
    fn tag_selected(&self, tag: &str) -> bool {
        self.f_tag == tag
    }
}

impl SourceDetailTemplate {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts_element(*ts)
    }
    fn opt_ts(&self, ts: &Option<i64>) -> String {
        fmt_opt_ts_element(*ts)
    }
    fn bytes(&self, n: &Option<i64>) -> String {
        n.map(|n| fmt_bytes(&self.lang, n))
            .unwrap_or_else(|| "—".into())
    }
}

impl SourceLogFragment {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts_element(*ts)
    }
    fn bytes(&self, n: &Option<i64>) -> String {
        n.map(|n| fmt_bytes(&self.lang, n))
            .unwrap_or_else(|| "—".into())
    }
}
