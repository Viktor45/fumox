//! Global fetch journal screen (ADMIN_PLAN §4.6): `fetch_log` across all
//! sources with ok/error, error-class and source filters plus pagination.
//! Probe history intentionally has no page of its own — it lives on the
//! proxy card.

use super::{FormMap, clamp_limit, fmt_bytes, fmt_ts_element, pagination_pages, server_error};
use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use askama::Template;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

#[derive(Debug, sqlx::FromRow)]
struct FetchLogListRow {
    source_id: String,
    source_name: Option<String>,
    fetched_at: i64,
    ok: i64,
    http_status: Option<i64>,
    bytes: Option<i64>,
    proxies_found: Option<i64>,
    error: Option<String>,
    error_class: Option<String>,
}

#[derive(Template)]
#[template(path = "logs/fetch.html")]
struct FetchLogsTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    rows: Vec<FetchLogListRow>,
    total: i64,
    pages: Vec<(i64, bool)>,
    per_page: i64,
    f_result: String,
    f_class: String,
    f_source: String,
    sources: Vec<(String, String, bool)>,
}

impl FetchLogsTemplate {
    fn ts(&self, ts: &i64) -> String {
        fmt_ts_element(*ts)
    }
    fn bytes(&self, n: &Option<i64>) -> String {
        n.map(|bytes| fmt_bytes(&self.lang, bytes))
            .unwrap_or_else(|| "—".into())
    }

    fn source_selected(&self, id: &str) -> bool {
        self.f_source == id
    }

    /// Preserve the current filters in pagination links.
    fn query_suffix(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.f_result.is_empty() {
            parts.push(format!("result={}", self.f_result));
        }
        if !self.f_class.is_empty() {
            parts.push(format!("class={}", self.f_class));
        }
        if !self.f_source.is_empty() {
            parts.push(format!(
                "source={}",
                percent_encoding::utf8_percent_encode(
                    &self.f_source,
                    percent_encoding::NON_ALPHANUMERIC
                )
            ));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("&{}", parts.join("&"))
        }
    }
}

impl_i18n!(FetchLogsTemplate);

pub async fn fetch_logs(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(params): Query<FormMap>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let f_result = params.get("result").cloned().unwrap_or_default();
    let f_class = params.get("class").cloned().unwrap_or_default();
    let f_source = params.get("source").cloned().unwrap_or_default();
    let page: i64 = params
        .get("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = clamp_limit(params.get("per_page").and_then(|v| v.parse().ok()));

    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    if f_result == "ok" {
        clauses.push("f.ok = 1".into());
    } else if f_result == "error" {
        clauses.push("f.ok = 0".into());
    }
    if !f_class.is_empty() {
        clauses.push("f.error_class = ?".into());
        binds.push(f_class.clone());
    }
    if !f_source.is_empty() {
        clauses.push("f.source_id = ?".into());
        binds.push(f_source.clone());
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };

    let total: i64 = {
        let sql = format!("SELECT COUNT(*) FROM fetch_log f{where_sql}");
        let mut query = sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str()));
        for value in &binds {
            query = query.bind(value);
        }
        match query.fetch_one(&state.pool).await {
            Ok(total) => total,
            Err(err) => return server_error(lang, &err),
        }
    };

    let rows: Vec<FetchLogListRow> = {
        let sql = format!(
            "SELECT f.source_id, s.name AS source_name, f.fetched_at, f.ok,
                    f.http_status, f.bytes, f.proxies_found, f.error, f.error_class
             FROM fetch_log f LEFT JOIN sources s ON s.id = f.source_id
             {where_sql}
             ORDER BY f.fetched_at DESC, f.id DESC
             LIMIT ? OFFSET ?"
        );
        let mut query = sqlx::query_as::<_, FetchLogListRow>(sqlx::AssertSqlSafe(sql.as_str()));
        for value in &binds {
            query = query.bind(value);
        }
        query = query.bind(per_page).bind((page - 1) * per_page);
        match query.fetch_all(&state.pool).await {
            Ok(rows) => rows,
            Err(err) => return server_error(lang, &err),
        }
    };

    let sources = match super::all_sources_for_selects(&state.pool).await {
        Ok(sources) => sources,
        Err(err) => return server_error(lang, &err),
    };

    render_html(
        lang.clone(),
        &FetchLogsTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "logs",
            csrf: state.csrf_for(&headers),
            rows,
            total,
            pages: pagination_pages(page, total, per_page),
            per_page,
            f_result,
            f_class,
            f_source,
            sources,
        },
        StatusCode::OK,
    )
}
