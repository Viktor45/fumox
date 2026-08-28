//! Public subscription endpoints (SPEC §10).
//!
//! `GET /sub/{token|slug}` serves a profile, `GET /src/{token|slug}` a
//! single source. Output format is fixed by the profile (`?format=` is
//! forbidden, SPEC §10.1); only 200 responses are cached, and the full
//! SPEC §10.2 outcome table is implemented:
//!
//! - recoverable source errors (`network`, `http_server`) → serve the DB
//!   snapshot as stale + `X-Fumox-Stale: true`, no cutoff;
//! - unrecoverable `http_client` → the upstream status code, not cached;
//! - `parse_error` → stale snapshot or empty output + `X-Fumox-Warning:
//!   parse-error`;
//! - every proxy quarantined/removed → empty valid output +
//!   `X-Fumox-Warning: all-proxies-quarantined`.

use crate::cache::{Caches, Rendered};
use crate::pipeline::{self, Candidate, CompiledPipeline};
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use fumox_core::db::DbPool;
use fumox_core::geo::GeoResolver;
use fumox_core::models::{ErrorClass, OutputFormat, Profile, ProxyStatus, Source};
use fumox_core::repo::{fetch_log, profiles, proxies, sources};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

/// Shared state of the public listener.
#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub caches: Caches,
    pub geo: Arc<GeoResolver>,
    /// Immediate-refresh channel into the scheduler (source ids); the
    /// admin "обновить сейчас" handler posts here (Phase 2.5).
    #[allow(dead_code)]
    pub refresh_tx: tokio::sync::mpsc::UnboundedSender<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/sub/{id}", get(serve_sub))
        .route("/src/{id}", get(serve_src))
        .with_state(state)
}

/// Non-cacheable error reply bubbling up from rendering.
#[derive(Debug)]
struct ErrorReply {
    status: StatusCode,
    message: String,
}

impl ErrorReply {
    fn internal(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "serving failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "внутренняя ошибка".to_string(),
        }
    }

    /// A corrupted pipeline config should be impossible (validated at save
    /// time); if it happens anyway, report it as a server error.
    fn corrupted_pipeline(target: &str, errors: &[String]) -> Self {
        tracing::error!(target, errors = ?errors, "stored pipeline config failed validation");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "внутренняя ошибка".to_string(),
        }
    }
}

async fn serve_sub(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if params.contains_key("format") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "параметр ?format= не поддерживается: формат задаётся профилем",
        );
    }
    let profile = match profiles::resolve_token(&state.pool, &id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "профиль не найден"),
        Err(err) => {
            tracing::error!(error = %err, "profile lookup failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "внутренняя ошибка");
        }
    };
    if !profile.enabled {
        return error_response(StatusCode::NOT_FOUND, "профиль не найден");
    }
    // Optional per-profile access token (SPEC §10.1): query parameter or
    // Authorization: Bearer. NULL means the endpoint is public.
    if let Some(required) = &profile.access_token {
        let provided = params
            .get("token")
            .cloned()
            .or_else(|| bearer_token(&headers));
        if provided.as_deref() != Some(required.as_str()) {
            return error_response(
                StatusCode::FORBIDDEN,
                "токен доступа отсутствует или неверен",
            );
        }
    }

    let key = format!("sub:{}", profile.id);
    let render_state = state.clone();
    let render_profile = profile.clone();
    serve_cached(&state, key, move || {
        let state = render_state.clone();
        let profile = render_profile.clone();
        async move { render_sub(&state, &profile).await }
    })
    .await
}

async fn serve_src(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if params.contains_key("format") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "параметр ?format= не поддерживается",
        );
    }
    let source = match sources::resolve_token(&state.pool, &id).await {
        Ok(Some(source)) => source,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "источник не найден"),
        Err(err) => {
            tracing::error!(error = %err, "source lookup failed");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "внутренняя ошибка");
        }
    };
    if !source.enabled {
        return error_response(StatusCode::NOT_FOUND, "источник не найден");
    }

    let key = format!("src:{}", source.id);
    let render_state = state.clone();
    let render_source = source.clone();
    serve_cached(&state, key, move || {
        let state = render_state.clone();
        let source = render_source.clone();
        async move { render_src(&state, &source).await }
    })
    .await
}

/// Cache lookup with stale-while-revalidate (SPEC §7): a fresh entry is
/// served as-is; a stale one is served immediately while a background
/// re-render refreshes the entry; a miss renders inline. Only 200
/// responses are stored (SPEC §10.2).
async fn serve_cached<F, Fut>(state: &AppState, key: String, make_render: F) -> Response
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = Result<Rendered, ErrorReply>> + Send + 'static,
{
    let now = fumox_core::models::now_ts();
    if let Some(rendered) = state.caches.processed_get(&key).await {
        if rendered.is_fresh(now) {
            return to_response(&rendered);
        }
        if state.caches.try_start_revalidate(&key).await {
            let state = state.clone();
            let key = key.clone();
            tokio::spawn(async move {
                match make_render().await {
                    Ok(rendered) => {
                        state.caches.processed_put(&key, rendered).await;
                    }
                    Err(err) => {
                        // Keep serving the stale snapshot; the failure is
                        // journaled where it happened.
                        tracing::warn!(key = %key, status = %err.status, "revalidation failed");
                    }
                }
                state.caches.finish_revalidate(&key).await;
            });
        }
        return to_response(&rendered);
    }

    match make_render().await {
        Ok(rendered) => {
            let rendered = if rendered.status == 200 {
                state.caches.processed_put(&key, rendered).await
            } else {
                Arc::new(rendered)
            };
            to_response(&rendered)
        }
        Err(err) => error_response(err.status, &err.message),
    }
}

/// Render a profile: per-source merged pipelines → merge → dedup → sort →
/// encode (SPEC §5), with the §10.2 outcome policy.
async fn render_sub(state: &AppState, profile: &Profile) -> Result<Rendered, ErrorReply> {
    let links = profiles::get_sources(&state.pool, &profile.id)
        .await
        .map_err(ErrorReply::internal)?;

    // Load member sources in profile order; disabled or vanished sources
    // drop out of the output.
    let mut members: Vec<(Source, CompiledPipeline)> = Vec::new();
    for (source_id, _position) in links {
        let Some(source) = sources::get(&state.pool, &source_id)
            .await
            .map_err(ErrorReply::internal)?
        else {
            continue;
        };
        if !source.enabled {
            continue;
        }
        let merged = pipeline::merge_configs(source.pipeline.as_ref(), profile.pipeline.as_ref());
        let compiled = CompiledPipeline::from_json(merged.as_ref()).map_err(|errors| {
            ErrorReply::corrupted_pipeline(&format!("sub:{}", profile.id), &errors)
        })?;
        members.push((source, compiled));
    }

    // An unrecoverable source error short-circuits the whole profile to
    // the upstream status code (SPEC §10.2), not cached.
    for (source, _) in &members {
        if source.error_class == Some(ErrorClass::HttpClient) {
            let upstream = last_http_status(state, &source.id).await.unwrap_or(502);
            return Err(ErrorReply {
                status: StatusCode::from_u16(upstream).unwrap_or(StatusCode::BAD_GATEWAY),
                message: format!(
                    "источник «{}» недоступен: {}",
                    source.name,
                    source
                        .last_error
                        .as_deref()
                        .unwrap_or("HTTP-ошибка клиента")
                ),
            });
        }
    }

    let profile_pipeline =
        CompiledPipeline::from_json(profile.pipeline.as_ref()).map_err(|errors| {
            ErrorReply::corrupted_pipeline(&format!("sub:{}", profile.id), &errors)
        })?;

    let source_ids: Vec<String> = members.iter().map(|(s, _)| s.id.clone()).collect();
    let rows = proxies::list_with_source(&state.pool, &source_ids)
        .await
        .map_err(ErrorReply::internal)?;
    let mut by_source: HashMap<String, Vec<proxies::ProxyRow>> = HashMap::new();
    for linked in rows {
        by_source
            .entry(linked.source_id)
            .or_default()
            .push(linked.proxy);
    }

    let mut all: Vec<Candidate> = Vec::new();
    let mut loaded_statuses: Vec<ProxyStatus> = Vec::new();
    let mut any_stale = false;
    let mut any_parse_error = false;

    for (position, (source, compiled)) in members.iter().enumerate() {
        match source.error_class {
            None => {}
            Some(ErrorClass::Network) | Some(ErrorClass::HttpServer) => any_stale = true,
            Some(ErrorClass::ParseError) => any_parse_error = true,
            Some(ErrorClass::HttpClient) => unreachable!("handled above"),
        }
        let rows = by_source.remove(&source.id).unwrap_or_default();
        let candidates = rows_to_candidates(rows, position as i64);
        loaded_statuses.extend(candidates.iter().map(|c| c.status));
        all.extend(compiled.apply_per_source(candidates, &state.geo).await);
    }
    // "All proxies quarantined/removed" verdict (SPEC §10.2): the profile
    // does hold proxies, but every one of them was dropped by a health
    // filter.
    let all_quarantined = !loaded_statuses.is_empty()
        && all.is_empty()
        && loaded_statuses
            .iter()
            .all(|status| matches!(status, ProxyStatus::Quarantine | ProxyStatus::Removed));

    // Global sort: the profile's explicit `sort` wins, otherwise the first
    // source (in profile order) that set one, otherwise source order.
    let sorter = members
        .iter()
        .find(|(_, compiled)| compiled.sort_explicit)
        .map(|(_, compiled)| compiled)
        .filter(|_| !profile_pipeline.sort_explicit)
        .unwrap_or(&profile_pipeline);
    sorter.finalize(&mut all);

    let (body, content_type) = encode(&all, profile.output_format);

    let mut extra_headers: Vec<(String, String)> = vec![
        ("profile-title".to_string(), profile.name.clone()),
        (
            "profile-update-interval".to_string(),
            update_interval_hours(&members),
        ),
    ];
    if any_stale {
        extra_headers.push(("X-Fumox-Stale".to_string(), "true".to_string()));
    }
    if any_parse_error {
        extra_headers.push(("X-Fumox-Warning".to_string(), "parse-error".to_string()));
    } else if all_quarantined {
        extra_headers.push((
            "X-Fumox-Warning".to_string(),
            "all-proxies-quarantined".to_string(),
        ));
    }

    let min_ttl = members
        .iter()
        .map(|(s, _)| s.cache_ttl_seconds)
        .min()
        .unwrap_or(60)
        .max(1);
    Ok(Rendered {
        status: 200,
        body,
        content_type,
        extra_headers,
        fresh_until: fumox_core::models::now_ts() + min_ttl,
        source_ids,
    })
}

/// Render a single source for `/src/{id}`: the source's own pipeline,
/// always the plain URI-list format.
async fn render_src(state: &AppState, source: &Source) -> Result<Rendered, ErrorReply> {
    if source.error_class == Some(ErrorClass::HttpClient) {
        let upstream = last_http_status(state, &source.id).await.unwrap_or(502);
        return Err(ErrorReply {
            status: StatusCode::from_u16(upstream).unwrap_or(StatusCode::BAD_GATEWAY),
            message: format!(
                "источник «{}» недоступен: {}",
                source.name,
                source
                    .last_error
                    .as_deref()
                    .unwrap_or("HTTP-ошибка клиента")
            ),
        });
    }

    let compiled = CompiledPipeline::from_json(source.pipeline.as_ref())
        .map_err(|errors| ErrorReply::corrupted_pipeline(&format!("src:{}", source.id), &errors))?;

    let rows = proxies::list_with_source(&state.pool, std::slice::from_ref(&source.id))
        .await
        .map_err(ErrorReply::internal)?;
    let mut candidates =
        rows_to_candidates(rows.into_iter().map(|linked| linked.proxy).collect(), 0);
    // /src serves only health-checked, currently-alive proxies: rows that
    // were never probed (unknown), quarantined or removed stay out even when
    // the pipeline's health filter would let them through.
    candidates.retain(|c| c.status == ProxyStatus::Alive);
    let out = compiled.apply(candidates, &state.geo).await;

    let (body, content_type) = encode(&out, OutputFormat::UriList);

    let mut extra_headers: Vec<(String, String)> = Vec::new();
    match source.error_class {
        None => {}
        Some(ErrorClass::Network) | Some(ErrorClass::HttpServer) => {
            extra_headers.push(("X-Fumox-Stale".to_string(), "true".to_string()));
        }
        Some(ErrorClass::ParseError) => {
            extra_headers.push(("X-Fumox-Warning".to_string(), "parse-error".to_string()));
        }
        Some(ErrorClass::HttpClient) => unreachable!("handled above"),
    }

    Ok(Rendered {
        status: 200,
        body,
        content_type,
        extra_headers,
        fresh_until: fumox_core::models::now_ts() + source.cache_ttl_seconds.max(1),
        source_ids: vec![source.id.clone()],
    })
}

/// In-process preview of a profile's output for the admin card
/// (ADMIN_PLAN §4.3): renders exactly what `/sub` would serve — without an
/// HTTP round trip to self — and returns the first `max_lines` lines.
/// Base64 output is decoded so the preview stays readable.
pub(crate) async fn preview_sub(
    state: &AppState,
    profile: &Profile,
    max_lines: usize,
) -> Result<Vec<String>, String> {
    let rendered = render_sub(state, profile).await.map_err(|e| e.message)?;
    let text = if profile.output_format == OutputFormat::Base64 {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&rendered.body)
            .unwrap_or_else(|_| rendered.body.clone());
        String::from_utf8_lossy(&decoded).into_owned()
    } else {
        String::from_utf8_lossy(&rendered.body).into_owned()
    };
    Ok(text.lines().take(max_lines).map(str::to_string).collect())
}

/// Map DB rows to pipeline candidates; corrupt rows are logged and skipped
/// (errors never abort a rendering).
fn rows_to_candidates(rows: Vec<proxies::ProxyRow>, source_position: i64) -> Vec<Candidate> {
    let mut candidates = Vec::with_capacity(rows.len());
    for row in rows {
        let entry = match row.to_entry() {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(proxy_id = row.id, error = %err, "skipping corrupt proxy row");
                continue;
            }
        };
        let status = match row.status.parse::<ProxyStatus>() {
            Ok(status) => status,
            Err(err) => {
                tracing::warn!(proxy_id = row.id, error = %err, "skipping proxy with unknown status");
                continue;
            }
        };
        candidates.push(Candidate {
            entry,
            source_position,
            status,
            latency_ms: row.latency_ms,
            geo_country: row.geo_country.clone(),
        });
    }
    candidates
}

/// Serialize candidates into the profile's output format (SPEC §10).
fn encode(candidates: &[Candidate], format: OutputFormat) -> (Vec<u8>, String) {
    match format {
        OutputFormat::UriList => (
            uri_lines(candidates).into_bytes(),
            "text/plain; charset=utf-8".to_string(),
        ),
        OutputFormat::Base64 => (
            base64::engine::general_purpose::STANDARD
                .encode(uri_lines(candidates).as_bytes())
                .into_bytes(),
            "text/plain; charset=utf-8".to_string(),
        ),
        OutputFormat::Clash => {
            let entries: Vec<fumox_core::models::ProxyEntry> =
                candidates.iter().map(|c| c.entry.clone()).collect();
            (
                fumox_core::formats::clash::encode_clash(&entries).into_bytes(),
                "text/yaml; charset=utf-8".to_string(),
            )
        }
        OutputFormat::SingBox => {
            let entries: Vec<fumox_core::models::ProxyEntry> =
                candidates.iter().map(|c| c.entry.clone()).collect();
            (
                fumox_core::formats::singbox::encode_singbox(&entries).into_bytes(),
                "application/json; charset=utf-8".to_string(),
            )
        }
    }
}

/// Canonical URI lines, one per candidate (input of uri_list/base64 output).
fn uri_lines(candidates: &[Candidate]) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        lines.push(fumox_core::parsers::serialize(&candidate.entry));
    }
    lines.join("\n")
}

/// `profile-update-interval` in whole hours (mihomo convention), rounded
/// up from the shortest member-source TTL, at least 1.
fn update_interval_hours(members: &[(Source, CompiledPipeline)]) -> String {
    let min_ttl = members
        .iter()
        .map(|(s, _)| s.cache_ttl_seconds)
        .min()
        .unwrap_or(3600)
        .max(1);
    // Whole hours rounded up, at least one.
    let hours = (min_ttl + 3599) / 3600;
    hours.to_string()
}

/// The upstream HTTP status of the source's latest fetch attempt, for the
/// "return the original code" policy (SPEC §10.2).
async fn last_http_status(state: &AppState, source_id: &str) -> Option<u16> {
    let rows = fetch_log::recent_for_source(&state.pool, source_id, 1)
        .await
        .ok()?;
    let status = rows.first()?.http_status?;
    u16::try_from(status).ok()
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

fn to_response(rendered: &Rendered) -> Response {
    let mut response = (
        StatusCode::from_u16(rendered.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Body::from(rendered.body.clone()),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_bytes(rendered.content_type.as_bytes()) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    for (name, value) in &rendered.extra_headers {
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) else {
            continue;
        };
        response.headers_mut().insert(name, value);
    }
    response
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{message}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use fumox_core::models::{OutputFormat, Param, ProxyEntry, Scheme};
    use fumox_core::repo::sources::FetchOutcome;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn test_state() -> AppState {
        let dir =
            std::env::temp_dir().join(format!("fumox-serve-test-{}", fumox_core::models::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = fumox_core::config::DatabaseConfig {
            path: dir.join("test.db"),
            ..Default::default()
        };
        let pool = fumox_core::db::connect_pool(&cfg).await.unwrap();
        fumox_core::db::migrate(&pool).await.unwrap();
        let (refresh_tx, refresh_rx) = tokio::sync::mpsc::unbounded_channel();
        std::mem::forget(refresh_rx); // keep the channel open for sends
        let geo_cfg = fumox_core::config::GeoConfig {
            enabled: false,
            ..Default::default()
        };
        AppState {
            pool,
            caches: Caches::new(),
            geo: Arc::new(GeoResolver::new(&geo_cfg)),
            refresh_tx,
        }
    }

    fn entry(name: &str, host: &str, port: u16) -> ProxyEntry {
        ProxyEntry {
            scheme: Scheme::Vless,
            name: name.to_string(),
            host: host.to_string(),
            port,
            credential: "3e4d70e5-7ec9-48f9-a4e0-48c44c6063fd".to_string(),
            params: vec![Param {
                key: "security".to_string(),
                value: "reality".to_string(),
                known: true,
            }],
            raw_path: String::new(),
            raw_line: String::new(),
        }
    }

    async fn make_source(state: &AppState, id: &str) -> Source {
        let now = fumox_core::models::now_ts();
        let source = Source {
            id: id.to_string(),
            slug: None,
            name: format!("source {id}"),
            url: "https://example.com/list".to_string(),
            enabled: true,
            encoding: Default::default(),
            input_format: None,
            protocols: None,
            cache_ttl_seconds: 3600,
            tags: None,
            pipeline: None,
            headers: None,
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        };
        sources::create(&state.pool, &source).await.unwrap();
        source
    }

    async fn make_profile(state: &AppState, id: &str, source_ids: &[&str]) -> Profile {
        let now = fumox_core::models::now_ts();
        let profile = Profile {
            id: id.to_string(),
            slug: None,
            access_token: None,
            name: format!("Profile {id}"),
            output_format: Default::default(),
            pipeline: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        profiles::create(&state.pool, &profile).await.unwrap();
        let composition: Vec<(String, i64)> = source_ids
            .iter()
            .enumerate()
            .map(|(idx, source_id)| (source_id.to_string(), idx as i64))
            .collect();
        profiles::set_sources(&state.pool, id, &composition)
            .await
            .unwrap();
        profile
    }

    async fn ingest(state: &AppState, source_id: &str, entries: &[ProxyEntry]) {
        proxies::reconcile_source(
            &state.pool,
            source_id,
            entries,
            &[],
            fumox_core::models::now_ts(),
        )
        .await
        .unwrap();
    }

    /// Perform one GET and return (status, headers, body text).
    async fn get(app: Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn header_str<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
        headers.get(name).and_then(|v| v.to_str().ok())
    }

    #[tokio::test]
    async fn sub_serves_merged_deduped_output() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_source(&state, "srcB0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000", "srcB0000000"]).await;
        // The same server advertised by both sources plus one unique each.
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("dup", "h1.example.com", 443),
                entry("a-only", "h2.example.com", 443),
            ],
        )
        .await;
        ingest(
            &state,
            "srcB0000000",
            &[
                entry("dup renamed", "h1.example.com", 443),
                entry("b-only", "h3.example.com", 443),
            ],
        )
        .await;

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, "profile-title"),
            Some("Profile profA0000000")
        );
        assert_eq!(header_str(&headers, "profile-update-interval"), Some("1"));
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3, "duplicate must collapse: {body:?}");
        assert!(body.contains("h1.example.com:443"));
        assert!(body.contains("h2.example.com:443"));
        assert!(body.contains("h3.example.com:443"));
        // The shared fingerprint is a single DB row; reconciliation is
        // last-writer-wins for the name, and serving emits it exactly once.
        let dup_count = body.matches("h1.example.com:443").count();
        assert_eq!(dup_count, 1, "duplicate must appear once: {body:?}");
    }

    #[tokio::test]
    async fn unknown_or_disabled_profile_is_404() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.enabled = false;
        profiles::update(&state.pool, &profile).await.unwrap();

        let (status, _, _) = get(router(state.clone()), "/sub/doesnotexist0").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _, _) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn access_token_is_enforced() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.access_token = Some("secret-token".to_string());
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (status, _, _) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) =
            get(router(state.clone()), "/sub/profA0000000?token=wrong-token").await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _, _) = get(
            router(state.clone()),
            "/sub/profA0000000?token=secret-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let request = Request::builder()
            .uri("/sub/profA0000000")
            .header("Authorization", "Bearer secret-token")
            .body(Body::empty())
            .unwrap();
        let response = router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn format_query_param_is_rejected() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        let (status, _, _) = get(router(state), "/sub/profA0000000?format=clash").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn slug_resolves_like_token() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.slug = Some("ru-free".to_string());
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (status, _, body) = get(router(state), "/sub/ru-free").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"));
    }

    #[tokio::test]
    async fn all_quarantined_produces_warning_and_empty_body() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        sqlx::query("UPDATE proxies SET status = 'quarantine'")
            .execute(&state.pool)
            .await
            .unwrap();

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty(), "{body:?}");
        assert_eq!(
            header_str(&headers, "x-fumox-warning"),
            Some("all-proxies-quarantined")
        );
    }

    #[tokio::test]
    async fn recoverable_source_error_serves_stale_with_header() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        sources::record_fetch_outcome(
            &state.pool,
            "srcA0000000",
            &FetchOutcome::Failure {
                at: fumox_core::models::now_ts(),
                error: "connection timed out",
                class: ErrorClass::Network,
            },
        )
        .await
        .unwrap();

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("h1.example.com"),
            "stale snapshot must be served"
        );
        assert_eq!(header_str(&headers, "x-fumox-stale"), Some("true"));
    }

    #[tokio::test]
    async fn http_client_error_returns_upstream_code() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        fetch_log::insert(
            &state.pool,
            &fetch_log::FetchLogEntry {
                source_id: "srcA0000000",
                fetched_at: fumox_core::models::now_ts(),
                ok: false,
                http_status: Some(404),
                bytes: None,
                proxies_found: None,
                error: Some("Not Found"),
                error_class: Some(ErrorClass::HttpClient),
            },
        )
        .await
        .unwrap();
        sources::record_fetch_outcome(
            &state.pool,
            "srcA0000000",
            &FetchOutcome::Failure {
                at: fumox_core::models::now_ts(),
                error: "HTTP 404",
                class: ErrorClass::HttpClient,
            },
        )
        .await
        .unwrap();

        let (status, _, _) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn parse_error_sets_warning_header() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
        sources::record_fetch_outcome(
            &state.pool,
            "srcA0000000",
            &FetchOutcome::Failure {
                at: fumox_core::models::now_ts(),
                error: "no proxies recognized",
                class: ErrorClass::ParseError,
            },
        )
        .await
        .unwrap();

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.contains("h1.example.com"),
            "stale snapshot must be served"
        );
        assert_eq!(header_str(&headers, "x-fumox-warning"), Some("parse-error"));
    }

    #[tokio::test]
    async fn base64_profile_wraps_uri_list() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.output_format = OutputFormat::Base64;
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (status, _, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .expect("body must be valid base64");
        let text = String::from_utf8(decoded).unwrap();
        assert!(text.contains("vless://"), "{text:?}");
        assert!(text.contains("h1.example.com:443"));
    }

    #[tokio::test]
    async fn src_endpoint_serves_single_source() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("u", "h2.example.com", 443),
            ],
        )
        .await;
        // Only the first proxy passed the health check; the second stays
        // unknown (never probed).
        sqlx::query("UPDATE proxies SET status = 'alive' WHERE host = 'h1.example.com'")
            .execute(&state.pool)
            .await
            .unwrap();

        let (status, _, body) = get(router(state.clone()), "/src/srcA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("h1.example.com"));
        // alive-only endpoint: untested proxies are not served.
        assert!(!body.contains("h2.example.com"));

        let (status, _, _) = get(router(state), "/src/missing00000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn processed_cache_serves_snapshot_until_invalidated() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;

        let (_, _, first) = get(router(state.clone()), "/sub/profA0000000").await;

        // A new proxy lands in the DB, but the fresh cache entry wins.
        ingest(&state, "srcA0000000", &[entry("b", "h9.example.com", 443)]).await;
        let (_, _, cached) = get(router(state.clone()), "/sub/profA0000000").await;
        assert_eq!(first, cached);
        assert!(!cached.contains("h9.example.com"));

        // Admin save handlers invalidate on change; the next render sees it.
        state.caches.invalidate_profile("profA0000000").await;
        let (_, _, refreshed) = get(router(state), "/sub/profA0000000").await;
        assert!(refreshed.contains("h9.example.com"));
    }

    #[tokio::test]
    async fn source_pipeline_filters_protocols() {
        let state = test_state().await;
        let mut source = make_source(&state, "srcA0000000").await;
        source.pipeline = Some(serde_json::json!({
            "version": 1,
            "filter": { "protocols": ["trojan"] }
        }));
        sources::update(&state.pool, &source).await.unwrap();
        make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        let mut trojan = entry("t", "h2.example.com", 443);
        trojan.scheme = Scheme::Trojan;
        trojan.credential = "password".to_string();
        trojan.params.clear();
        ingest(
            &state,
            "srcA0000000",
            &[entry("v", "h1.example.com", 443), trojan],
        )
        .await;

        let (status, _, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("trojan://"));
        assert!(!body.contains("vless://"));
    }

    #[tokio::test]
    async fn clash_profile_serves_yaml() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.output_format = OutputFormat::Clash;
        profiles::update(&state.pool, &profile).await.unwrap();
        // Two servers sharing a name (collision → auto-suffix) plus an
        // unsupported tuic entry that must be skipped.
        let mut tuic = entry("t", "h3.example.com", 443);
        tuic.scheme = Scheme::Tuic;
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("a", "h2.example.com", 443),
                tuic,
            ],
        )
        .await;

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, "content-type"),
            Some("text/yaml; charset=utf-8")
        );
        let parsed: serde_norway::Value =
            serde_norway::from_str(&body).expect("body must be valid YAML");
        let proxies = parsed["proxies"]
            .as_sequence()
            .expect("proxies must be a list");
        assert_eq!(proxies.len(), 2, "tuic must be skipped: {body:?}");
        assert_eq!(proxies[0]["type"].as_str(), Some("vless"));
        assert_eq!(proxies[0]["name"].as_str(), Some("a"));
        assert_eq!(proxies[1]["name"].as_str(), Some("a (2)"));
        assert_eq!(proxies[0]["server"].as_str(), Some("h1.example.com"));
    }

    #[tokio::test]
    async fn singbox_profile_serves_json() {
        let state = test_state().await;
        make_source(&state, "srcA0000000").await;
        let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
        profile.output_format = OutputFormat::SingBox;
        profiles::update(&state.pool, &profile).await.unwrap();
        ingest(
            &state,
            "srcA0000000",
            &[
                entry("a", "h1.example.com", 443),
                entry("a", "h2.example.com", 443),
            ],
        )
        .await;

        let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            header_str(&headers, "content-type"),
            Some("application/json; charset=utf-8")
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("body must be valid JSON");
        let outbounds = parsed["outbounds"]
            .as_array()
            .expect("outbounds must be an array");
        assert_eq!(outbounds.len(), 2, "{body:?}");
        assert_eq!(outbounds[0]["type"].as_str(), Some("vless"));
        assert_eq!(outbounds[0]["tag"].as_str(), Some("a"));
        assert_eq!(outbounds[1]["tag"].as_str(), Some("a (2)"));
        assert_eq!(outbounds[0]["server"].as_str(), Some("h1.example.com"));
    }

    #[tokio::test]
    async fn all_quarantined_structured_formats_serve_empty_valid_config() {
        for (format, kind) in [
            (OutputFormat::Clash, "clash"),
            (OutputFormat::SingBox, "singbox"),
        ] {
            let state = test_state().await;
            make_source(&state, "srcA0000000").await;
            let mut profile = make_profile(&state, "profA0000000", &["srcA0000000"]).await;
            profile.output_format = format;
            profiles::update(&state.pool, &profile).await.unwrap();
            ingest(&state, "srcA0000000", &[entry("a", "h1.example.com", 443)]).await;
            sqlx::query("UPDATE proxies SET status = 'quarantine'")
                .execute(&state.pool)
                .await
                .unwrap();

            let (status, headers, body) = get(router(state), "/sub/profA0000000").await;
            assert_eq!(status, StatusCode::OK, "{kind}");
            assert_eq!(
                header_str(&headers, "x-fumox-warning"),
                Some("all-proxies-quarantined"),
                "{kind}"
            );
            match kind {
                "clash" => {
                    let parsed: serde_norway::Value =
                        serde_norway::from_str(&body).expect("valid YAML");
                    assert!(
                        parsed["proxies"].as_sequence().unwrap().is_empty(),
                        "{body:?}"
                    );
                }
                _ => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&body).expect("valid JSON");
                    assert!(
                        parsed["outbounds"].as_array().unwrap().is_empty(),
                        "{body:?}"
                    );
                }
            }
        }
    }
}
