//! Configuration import/export.
//!
//! Export serializes every source and profile (plus profile composition)
//! into a versioned JSON file; import recreates them. The semantics are
//! **create-new only**: imported objects always
//! receive fresh `nanoid(12)` ids, profile composition is remapped onto the
//! new source ids, and existing rows are never overwritten. Slug collisions
//! with the database (or within the file) drop the slug rather than the
//! object; a source and a profile live in separate slug name-spaces (one
//! UNIQUE column each), so the same slug on both is kept on both. References
//! to sources absent from the file are excluded from the composition. Both
//! cases surface as warnings, not errors. A reference
//! repeated inside one profile is kept once (the composition is keyed by
//! source, a repeat would abort the insert after the profile row was
//! already written). Two *source rows* sharing one reference are a hard
//! error: the reference binds them together, so the file does not say
//! which row a profile composition means.
//!
//! Validation mirrors the source/profile forms (the shared field
//! validators in [`super`]) and is all-or-nothing: any hard error yields a
//! 422 with the full list and writes nothing. A *transient* DNS failure is
//! not a hard error: the URL is vetted again at fetch time, so it is
//! reported as a warning and the import continues.
//!
//! The write phase runs in one transaction: a failure half-way through
//! leaves the database exactly as it was.

use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use crate::alive_export::export_date;
use crate::fetcher;
use crate::pipeline::CompiledPipeline;
use askama::Template;
use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use fumox_core::models::{self, Encoding, InputFormat, IpFamily, OutputFormat, Scheme};
use fumox_core::repo::{profiles, proxies, sources};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;

use super::{
    caps, pipeline_size, validate_countries, validate_header_map, validate_name,
    validate_slug_format, validate_tags, validate_token, validate_ttl,
};

/// Body of `POST /admin/import`. A typed `Form` extractor parses only the
/// `payload` field (the admin router's `DefaultBodyLimit::max(1 MiB)` still
/// caps the raw body), so an attacker cannot force a `Vec<(String, String)>`
/// of every duplicate pair into memory before the handler picks the field
/// it actually needs.
#[derive(Deserialize)]
pub(in crate::admin) struct ImportPayloadForm {
    #[serde(default)]
    payload: String,
}

/// Only schema version we understand today.
const SUPPORTED_VERSION: u32 = 1;

// Wire format

/// Versioned export file. `ref` carries the original id so profile
/// composition can be remapped onto fresh ids at import time; primary keys
/// and runtime fields (timestamps, last error) are intentionally excluded.
#[derive(Debug, Serialize, Deserialize)]
struct ConfigExport {
    version: u32,
    exported_at: i64,
    #[serde(default)]
    sources: Vec<ExportSource>,
    #[serde(default)]
    profiles: Vec<ExportProfile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExportSource {
    /// Original source id; the remap key for profile composition.
    #[serde(rename = "ref")]
    reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
    name: String,
    url: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    encoding: Encoding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    input_format: Option<InputFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocols: Option<Vec<Scheme>>,
    cache_ttl_seconds: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pipeline: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    headers: Option<BTreeMap<String, String>>,
    /// Preferred IP protocol family for fetching; `None` inherits the
    /// deployment default (`[fetch] ip_family`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip_family: Option<IpFamily>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExportProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slug: Option<String>,
    /// The profile's access token **as stored**: a hash, never the secret.
    /// The export therefore cannot leak a working token, and the import
    /// keeps the endpoint usable on the target deployment (the same secret
    /// still opens it) without ever handling the plaintext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    name: String,
    #[serde(default)]
    output_format: OutputFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pipeline: Option<serde_json::Value>,
    /// ISO 3166-1 alpha-2 allowlist; empty = no filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    countries: Vec<String>,
    #[serde(default)]
    enabled: bool,
    /// Member sources, referenced by their original id, in profile order.
    #[serde(default, rename = "sources")]
    source_refs: Vec<String>,
}

// Export

/// Which import cap an export exceeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ImportCap {
    /// The number of rows in one table (sources or profiles).
    Rows,
    /// The size of the document.
    Bytes,
}

/// The import cap an export exceeds: the file cannot be imported back.
///
/// `actual` is the size of the document *without* this marker (the
/// marker itself is a few dozen bytes on top).
#[derive(Debug, Clone, Copy, Serialize)]
struct ImportLimit {
    cap: ImportCap,
    limit: usize,
    actual: usize,
}

/// Serialize the export and say whether the import would take it.
///
/// The import accepts at most [`caps::IMPORT_ROWS`] rows per table and a
/// document of at most [`caps::IMPORT_BODY_BYTES`] bytes. A bigger
/// deployment exports a file the import refuses, so the file says so
/// instead of the operator finding out at the import step.
fn serialize_export(
    file: &ConfigExport,
) -> Result<(String, Option<ImportLimit>), serde_json::Error> {
    let plain = serde_json::to_string_pretty(file)?;
    let limit = if file.sources.len() > caps::IMPORT_ROWS {
        Some(ImportLimit {
            cap: ImportCap::Rows,
            limit: caps::IMPORT_ROWS,
            actual: file.sources.len(),
        })
    } else if file.profiles.len() > caps::IMPORT_ROWS {
        Some(ImportLimit {
            cap: ImportCap::Rows,
            limit: caps::IMPORT_ROWS,
            actual: file.profiles.len(),
        })
    } else if plain.len() > caps::IMPORT_BODY_BYTES {
        Some(ImportLimit {
            cap: ImportCap::Bytes,
            limit: caps::IMPORT_BODY_BYTES,
            actual: plain.len(),
        })
    } else {
        None
    };
    let Some(limit) = limit else {
        return Ok((plain, None));
    };
    let mut value = serde_json::to_value(file)?;
    value["import_limit"] = serde_json::to_value(limit)?;
    Ok((serde_json::to_string_pretty(&value)?, Some(limit)))
}

/// `GET /admin/export`, download the whole configuration as JSON.
pub async fn export_config(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);

    let src_rows = match sources::list(&state.pool, false).await {
        Ok(rows) => rows,
        Err(err) => return super::server_error(lang, &err),
    };
    let prof_rows = match profiles::list(&state.pool, false).await {
        Ok(rows) => rows,
        Err(err) => return super::server_error(lang, &err),
    };

    let mut export_sources = Vec::with_capacity(src_rows.len());
    for s in src_rows {
        export_sources.push(ExportSource {
            reference: s.id.clone(),
            slug: s.slug.clone(),
            name: s.name.clone(),
            url: s.url.clone(),
            enabled: s.enabled,
            encoding: s.encoding,
            input_format: s.input_format,
            protocols: s.protocols.clone(),
            cache_ttl_seconds: s.cache_ttl_seconds,
            tags: s.tags.clone(),
            pipeline: s.pipeline.clone(),
            headers: s.headers.clone(),
            ip_family: s.ip_family,
        });
    }

    let mut export_profiles = Vec::with_capacity(prof_rows.len());
    for p in prof_rows {
        let composition = match profiles::get_sources(&state.pool, &p.id).await {
            Ok(composition) => composition,
            Err(err) => return super::server_error(lang, &err),
        };
        let mut ordered = composition;
        ordered.sort_by_key(|(_, position)| *position);
        export_profiles.push(ExportProfile {
            slug: p.slug.clone(),
            // The stored token is a hash, so the file carries the hash: no
            // working secret ever leaves the deployment, and the import
            // stores the same hash, which keeps the endpoint usable for
            // the clients that already know the token.
            access_token: p.access_token.clone(),
            name: p.name.clone(),
            output_format: p.output_format,
            pipeline: p.pipeline.clone(),
            countries: p.countries.clone(),
            enabled: p.enabled,
            source_refs: ordered.into_iter().map(|(id, _)| id).collect(),
        });
    }

    let file = ConfigExport {
        version: SUPPORTED_VERSION,
        exported_at: models::now_ts(),
        sources: export_sources,
        profiles: export_profiles,
    };
    let (body, limit) = match serialize_export(&file) {
        Ok(body) => body,
        Err(err) => return super::server_error(lang, &err),
    };

    // The audit line carries the row counts only: no URL, no token, no
    // peer data.
    tracing::info!(
        sources = file.sources.len(),
        profiles = file.profiles.len(),
        "configuration exported"
    );
    if let Some(limit) = limit {
        tracing::warn!(
            cap = ?limit.cap,
            limit = limit.limit,
            actual = limit.actual,
            "the export exceeds the import limits and cannot be imported back"
        );
    }

    let date = export_date();
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    // ASCII-only value (fixed prefix + calendar date), try_from cannot fail.
    if let Ok(value) =
        header::HeaderValue::try_from(format!("attachment; filename=\"fumox-config-{date}.json\""))
    {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

// Import

/// Outcome of a successful import.
#[derive(Debug, Default)]
struct ImportSummary {
    sources_created: usize,
    profiles_created: usize,
    warnings: Vec<String>,
}

/// The «all alive»/«all ready» export links of the import screen.
struct EndpointLinks {
    alive_url: String,
    alive_count: i64,
    ready_url: String,
    ready_count: i64,
}

#[derive(Template)]
#[template(path = "import.html")]
struct ImportTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
    /// Hard validation errors (import aborted, nothing written).
    errors: Vec<String>,
    /// The submitted payload echoed back on an error so a fix-and-retry
    /// does not start from an empty textarea. Empty on a fresh page.
    payload: String,
    /// The export links; absent when the token or the counters could not
    /// be read. The block is then hidden instead of the whole screen
    /// turning into an error page.
    endpoints: Option<EndpointLinks>,
    /// The import limits, rendered next to the upload control.
    limits_hint: String,
    /// The same limits, next to the export button: a bigger export
    /// cannot be imported back.
    export_limit_hint: String,
}

impl_i18n!(ImportTemplate);

/// Inputs for [`render_page`], bundled to keep the call sites compact
/// and the function's signature below clippy's argument-count cap.
struct RenderArgs<'a> {
    lang: Lang,
    theme: Theme,
    peer: SocketAddr,
    headers: &'a HeaderMap,
    status: StatusCode,
    errors: Vec<String>,
    payload: Option<String>,
}

/// The export links of the import screen: the shared capability token and
/// the two counters.
async fn endpoint_links(
    state: &AdminState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<EndpointLinks, fumox_core::Error> {
    let token = state.export_token.current(&state.pool).await?;
    let alive_count = proxies::count_alive(&state.pool).await?;
    let ready_count = proxies::count_ready(&state.pool).await?;
    let base = state
        .serve_base(peer, headers)
        .map_err(|err| fumox_core::Error::Config(err.to_string()))?;
    Ok(EndpointLinks {
        alive_url: format!("{base}/export/alive/{token}"),
        alive_count,
        ready_url: format!("{base}/export/ready/{token}"),
        ready_count,
    })
}

/// Render the import/export screen, filling in the alive-export link data
/// shared by every entry point (fresh page, validation errors).
async fn render_page(state: &AdminState, args: RenderArgs<'_>) -> Response {
    let RenderArgs {
        lang,
        theme,
        peer,
        headers,
        status,
        errors,
        payload,
    } = args;
    // The links are a convenience panel, not the subject of the page: a
    // broken counter or token hides the block instead of replacing the
    // whole screen with an error page.
    let endpoints = match endpoint_links(state, peer, headers).await {
        Ok(links) => Some(links),
        Err(err) => {
            tracing::warn!(error = %err, "the export links are unavailable");
            None
        }
    };
    let limits_hint = lang.t_named(
        "io.limits_hint",
        &[
            ("rows", caps::IMPORT_ROWS.to_string()),
            ("bytes", (caps::IMPORT_BODY_BYTES / 1024).to_string()),
        ],
    );
    let export_limit_hint = lang.t_named(
        "io.export_limit_hint",
        &[
            ("rows", caps::IMPORT_ROWS.to_string()),
            ("bytes", (caps::IMPORT_BODY_BYTES / 1024).to_string()),
        ],
    );
    render_html(
        lang.clone(),
        &ImportTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "import",
            csrf: state.csrf_for(headers),
            errors,
            payload: payload.unwrap_or_default(),
            endpoints,
            limits_hint,
            export_limit_hint,
        },
        status,
    )
}

/// `GET /admin/import`, the import/export screen.
pub async fn import_form(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    render_page(
        &state,
        RenderArgs {
            lang,
            theme,
            peer,
            headers: &headers,
            status: StatusCode::OK,
            errors: Vec::new(),
            payload: None,
        },
    )
    .await
}

/// `POST /admin/import`, validate then create-new.
pub async fn import_submit(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(ImportPayloadForm { payload }): Form<ImportPayloadForm>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let payload = payload.trim().to_string();

    // The document cap: the payload travels urlencoded (every byte up to
    // three), so the transport limit is not the document limit. The
    // document is measured here, before it is parsed.
    if payload.len() > caps::IMPORT_BODY_BYTES {
        let errors = vec![lang.t_args(
            "io.err_too_large",
            &[
                payload.len().to_string(),
                caps::IMPORT_BODY_BYTES.to_string(),
            ],
        )];
        return render_page(
            &state,
            RenderArgs {
                lang,
                theme,
                peer,
                headers: &headers,
                status: StatusCode::UNPROCESSABLE_ENTITY,
                errors,
                payload: Some(payload),
            },
        )
        .await;
    }

    let file: ConfigExport = match serde_json::from_str(&payload) {
        Ok(file) => file,
        Err(err) => {
            let errors = vec![lang.t("io.err_parse").replace("{}", &err.to_string())];
            return render_page(
                &state,
                RenderArgs {
                    lang,
                    theme,
                    peer,
                    headers: &headers,
                    status: StatusCode::UNPROCESSABLE_ENTITY,
                    errors,
                    payload: Some(payload),
                },
            )
            .await;
        }
    };
    if file.version != SUPPORTED_VERSION {
        let errors = vec![
            lang.t("io.err_version")
                .replace("{}", &file.version.to_string()),
        ];
        return render_page(
            &state,
            RenderArgs {
                lang,
                theme,
                peer,
                headers: &headers,
                status: StatusCode::UNPROCESSABLE_ENTITY,
                errors,
                payload: Some(payload),
            },
        )
        .await;
    }

    // All-or-nothing validation pass.
    let validation = validate_import(&state, &lang, &file).await;
    if !validation.errors.is_empty() {
        return render_page(
            &state,
            RenderArgs {
                lang,
                theme,
                peer,
                headers: &headers,
                status: StatusCode::UNPROCESSABLE_ENTITY,
                errors: validation.errors,
                payload: Some(payload),
            },
        )
        .await;
    }

    match apply_import(&state, &lang, file, validation.warnings).await {
        Ok(summary) => {
            tracing::info!(
                sources = summary.sources_created,
                profiles = summary.profiles_created,
                warnings = summary.warnings.len(),
                "configuration imported"
            );
            // The operator gets the totals in a toast on the import
            // screen; the details stay in the log.
            for warning in &summary.warnings {
                tracing::info!(warning = %warning, "import warning");
            }
            let message = if summary.warnings.is_empty() {
                lang.t_named(
                    "io.import_done",
                    &[
                        ("sources", summary.sources_created.to_string()),
                        ("profiles", summary.profiles_created.to_string()),
                    ],
                )
            } else {
                lang.t_named(
                    "io.import_done_warnings",
                    &[
                        ("sources", summary.sources_created.to_string()),
                        ("profiles", summary.profiles_created.to_string()),
                        ("warnings", summary.warnings.len().to_string()),
                    ],
                )
            };
            super::flash_redirect("/admin/import", &message, "ok")
        }
        Err(err) => super::server_error(lang, &err),
    }
}

/// `GET /admin/import/alive-token`, the confirmation page of the token
/// rotation.
///
/// The rotation revokes a capability the clients hold: both export links
/// stop working the moment it happens, and the old token is gone. The
/// confirmation is therefore a page of its own — it states the
/// consequences and the second click performs the rotation. A
/// `data-confirm` dialog would have been one click less, but it depends
/// on JavaScript and the browser's own question says nothing about what
/// is lost.
#[derive(Template)]
#[template(path = "import_rotate.html")]
struct RotateTokenTemplate {
    lang: Lang,
    langs: Vec<(String, String)>,
    theme: Theme,
    active: &'static str,
    csrf: String,
}

impl_i18n!(RotateTokenTemplate);

pub async fn rotate_alive_token_form(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    render_html(
        lang.clone(),
        &RotateTokenTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "import",
            csrf: state.csrf_for(&headers),
        },
        StatusCode::OK,
    )
}

/// `POST /admin/import/alive-token`, issue a fresh token for the «all
/// alive» export link; the previous link stops working immediately.
pub async fn rotate_alive_token(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    match state.export_token.rotate(&state.pool).await {
        Ok(_) => {
            // Audit line for a capability change that instantly invalidates
            // both export links (one secret, shared by /export/alive and
            // /export/ready). The token value itself is never logged.
            tracing::info!("alive-export capability token rotated");
            super::flash_redirect("/admin/import", lang.t("io.alive_rotated"), "ok")
        }
        Err(err) => super::server_error(lang, &err),
    }
}

/// What the validation pass found: hard errors (the import is refused and
/// nothing is written) and warnings (the import goes ahead).
#[derive(Debug, Default)]
struct ImportValidation {
    errors: Vec<String>,
    warnings: Vec<String>,
}

/// Validate every imported object with the same rules as the forms.
/// Returns the hard errors and the warnings; any error aborts the import.
///
/// The pass runs in two steps: a static one over every row (no name
/// resolution, no I/O) and a DNS one over the first
/// [`caps::IMPORT_DNS_VET`] URLs. A *transient* resolution failure (a
/// timeout, a SERVFAIL) is a warning, not an error: the fetch path
/// re-vets every request anyway, so the row is imported and checked
/// again later. Only a policy violation (a private address) is fatal.
async fn validate_import(state: &AdminState, lang: &Lang, file: &ConfigExport) -> ImportValidation {
    let mut validation = ImportValidation::default();

    // Row-count caps: one 1 MiB body could carry
    // thousands of rows, each triggering cache invalidation and (before the
    // window below) a DNS lookup.
    if file.sources.len() > caps::IMPORT_ROWS {
        validation.errors.push(
            lang.t("val.import_too_many_rows")
                .replace("{}", &caps::IMPORT_ROWS.to_string())
                + " ("
                + lang.t("io.source_word")
                + ")",
        );
    }
    if file.profiles.len() > caps::IMPORT_ROWS {
        validation.errors.push(
            lang.t("val.import_too_many_rows")
                .replace("{}", &caps::IMPORT_ROWS.to_string())
                + " ("
                + lang.t("io.profile_word")
                + ")",
        );
    }
    if !validation.errors.is_empty() {
        return validation; // nothing else is worth checking past the row caps
    }

    // A reference is the join key between a source row and the profile
    // compositions naming it. Two rows sharing one are ambiguous: the
    // write phase keys new ids by reference, so the second row would win
    // and the first be silently orphaned. Reject the file instead of
    // guessing which of the two the operator meant.
    let mut seen_refs: HashSet<&str> = HashSet::new();

    // Whether each source's URL passed the static check: only those are
    // worth a name lookup.
    let mut url_is_valid: Vec<bool> = Vec::with_capacity(file.sources.len());

    for s in &file.sources {
        let ctx = format!("{} «{}»", lang.t("io.source_word"), s.name);
        if !seen_refs.insert(s.reference.as_str()) {
            validation.errors.push(format!(
                "{ctx}: {}",
                lang.t("val.dup_ref").replace("{ref}", &s.reference)
            ));
        }
        if let Err(message) = validate_name(&s.name, lang) {
            validation.errors.push(format!("{ctx}: {message}"));
        }
        let mut url_ok = true;
        if s.url.trim().is_empty() {
            validation
                .errors
                .push(format!("{ctx}: {}", lang.t("val.required")));
            url_ok = false;
        } else if s.url.len() > caps::URL {
            validation.errors.push(format!(
                "{ctx}: {}",
                lang.t("val.field_too_long")
                    .replace("{}", &caps::URL.to_string())
            ));
            url_ok = false;
        } else if let Err(issue) = fetcher::validate_url(&s.url) {
            validation
                .errors
                .push(format!("{ctx}: {}", lang.t_args(issue.key, &issue.args)));
            url_ok = false;
        }
        url_is_valid.push(url_ok);
        if let Some(slug) = s.slug.as_deref()
            && !slug.is_empty()
            && let Err(message) = validate_slug_format(slug, lang)
        {
            validation.errors.push(format!("{ctx}: {message}"));
        }
        if let Err(message) = validate_ttl(s.cache_ttl_seconds, lang) {
            validation.errors.push(format!("{ctx}: {message}"));
        }
        if let Some(tags) = s.tags.as_ref()
            && let Err(message) = validate_tags(tags, lang)
        {
            validation.errors.push(format!("{ctx}: {message}"));
        }
        if let Some(map) = s.headers.as_ref()
            && let Err(message) = validate_header_map(map, lang)
        {
            validation.errors.push(format!("{ctx}: {message}"));
        }
        if let Some(pipeline) = s.pipeline.as_ref() {
            // Same cap the source form applies: the JSON is stored verbatim
            // and re-rendered into every edit form, and the preview
            // recompiles it on each keystroke.
            if pipeline_size(pipeline) > caps::PIPELINE_BYTES {
                validation.errors.push(format!(
                    "{ctx}: {}",
                    lang.t("val.field_too_long")
                        .replace("{}", &caps::PIPELINE_BYTES.to_string())
                ));
            }
            for issue in CompiledPipeline::from_json(Some(pipeline))
                .err()
                .into_iter()
                .flatten()
            {
                validation
                    .errors
                    .push(format!("{ctx}: {}", lang.t_args(issue.key, &issue.args)));
            }
        }
    }

    for p in &file.profiles {
        let ctx = format!("{} «{}»", lang.t("io.profile_word"), p.name);
        if let Err(message) = validate_name(&p.name, lang) {
            validation.errors.push(format!("{ctx}: {message}"));
        }
        if let Some(slug) = p.slug.as_deref()
            && !slug.is_empty()
            && let Err(message) = validate_slug_format(slug, lang)
        {
            validation.errors.push(format!("{ctx}: {message}"));
        }
        // Imported access tokens: a third-party file
        // must not plant a guessable secret on a public endpoint. Tokens
        // shorter than the floor are hard errors, silently regenerating
        // them would change what the operator expects the file to contain.
        //
        // A token that is already a hash is not a secret the file chooses:
        // it is what this deployment stored (the export of a hashed row),
        // and the plaintext rules below do not apply to it.
        if let Some(token) = p.access_token.as_deref()
            && !token.is_empty()
            && !fumox_core::token::is_hashed(token)
        {
            if token.chars().count() < caps::TOKEN_MIN {
                validation
                    .errors
                    .push(format!("{ctx}: {}", lang.t("val.token_too_short_import")));
            }
            if let Err(message) = validate_token(token, lang) {
                validation.errors.push(format!("{ctx}: {message}"));
            }
        }
        if let Some(pipeline) = p.pipeline.as_ref() {
            if pipeline_size(pipeline) > caps::PIPELINE_BYTES {
                validation.errors.push(format!(
                    "{ctx}: {}",
                    lang.t("val.field_too_long")
                        .replace("{}", &caps::PIPELINE_BYTES.to_string())
                ));
            }
            for issue in CompiledPipeline::from_json(Some(pipeline))
                .err()
                .into_iter()
                .flatten()
            {
                validation
                    .errors
                    .push(format!("{ctx}: {}", lang.t_args(issue.key, &issue.args)));
            }
        }
        if let Err(message) = validate_countries(&p.countries, lang) {
            validation.errors.push(format!("{ctx}: {message}"));
        }
    }

    // The DNS window: the first `IMPORT_DNS_VET` URLs are resolved inside
    // the request, the rest are only statically validated (the fetch path
    // re-vets every request anyway, so this is latency/DNS-traffic
    // hygiene, not a security hole). The whole window is bounded by
    // `IMPORT_DNS_WINDOW`: the per-URL timeout alone would add up.
    let mut vetted = 0usize;
    let deadline = tokio::time::Instant::now() + caps::IMPORT_DNS_WINDOW;
    for (s, url_ok) in file.sources.iter().zip(url_is_valid.iter()) {
        if !url_ok {
            continue;
        }
        if vetted >= caps::IMPORT_DNS_VET {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            validation
                .warnings
                .push(lang.t("io.warn_dns_window").to_string());
            break;
        }
        vetted += 1;
        let family = s
            .ip_family
            .unwrap_or_else(|| state.fetcher.default_family());
        let outcome = tokio::time::timeout(
            remaining,
            fetcher::vet_url_with_policy(
                &s.url,
                state.admin().allow_private_urls,
                family,
                state.fetcher.dns_timeout,
            ),
        )
        .await;
        let ctx = format!("{} «{}»", lang.t("io.source_word"), s.name);
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(issue)) => {
                let message = lang.t_args(issue.key, &issue.args);
                if issue.kind.is_permanent() {
                    validation.errors.push(format!("{ctx}: {message}"));
                } else {
                    // A name that did not resolve (timeout, SERVFAIL) says
                    // nothing about the target: the row goes in and is
                    // vetted again at fetch time.
                    validation.warnings.push(format!(
                        "{ctx}: {message} — {}",
                        lang.t("io.warn_dns_transient")
                    ));
                }
            }
            Err(_elapsed) => {
                validation
                    .warnings
                    .push(lang.t("io.warn_dns_window").to_string());
                break;
            }
        }
    }

    // Not an error: the remaining URLs were only statically validated and
    // are re-vetted (with DNS) at fetch time.
    if vetted < file.sources.len() {
        tracing::info!(
            vetted,
            total = file.sources.len(),
            "import DNS vetting hit the per-request window"
        );
    }

    validation
}

/// Write phase: create sources (fresh ids), then profiles with composition
/// remapped onto the new ids. Collects warnings for dropped slugs/refs.
///
/// The whole phase runs in one transaction: a failure half-way through
/// (a write error, a constraint the file slipped past) leaves the
/// database exactly as it was, instead of a half-imported configuration.
async fn apply_import(
    state: &AdminState,
    lang: &Lang,
    file: ConfigExport,
    warnings: Vec<String>,
) -> Result<ImportSummary, fumox_core::Error> {
    let mut summary = ImportSummary {
        warnings,
        ..Default::default()
    };

    // Slugs already present in the DB or used earlier in this file cannot be
    // reused; the object is still created, just without a slug. Sources and
    // profiles are tracked separately: `slug` is UNIQUE per table, and each
    // side resolves its own only, `profiles::resolve_token` behind
    // `/sub/{id}` (serve.rs:234) and `sources::resolve_token` behind
    // `/src/{id}` (serve.rs:295), each querying one table. The same slug is
    // therefore legal on a source and on a profile, and must survive the
    // round trip on both.
    let mut taken_source_slugs: HashSet<String> = HashSet::new();
    for s in sources::list(&state.pool, false).await? {
        if let Some(slug) = s.slug {
            taken_source_slugs.insert(slug);
        }
    }
    let mut taken_profile_slugs: HashSet<String> = HashSet::new();
    for p in profiles::list(&state.pool, false).await? {
        if let Some(slug) = p.slug {
            taken_profile_slugs.insert(slug);
        }
    }

    let now = models::now_ts();
    let mut ref_to_id: HashMap<String, String> = HashMap::new();
    let mut created_profiles: Vec<String> = Vec::new();

    // BEGIN IMMEDIATE: the write phase takes the WAL write lock up front,
    // so a concurrent writer cannot slip in between the rows of one
    // import.
    let mut tx = state.pool.begin_with("BEGIN IMMEDIATE").await?;

    for s in file.sources {
        let id = models::new_id();
        ref_to_id.insert(s.reference.clone(), id.clone());
        let slug = claim_slug(s.slug, &mut taken_source_slugs, &s.name, lang, &mut summary);
        let source = models::Source {
            id: id.clone(),
            slug,
            name: s.name.clone(),
            url: s.url,
            enabled: s.enabled,
            encoding: s.encoding,
            input_format: s.input_format,
            // An empty allowlist means "no filter", never "nothing passes":
            // the list is normalised before the source is written.
            protocols: models::normalize_protocols(s.protocols),
            cache_ttl_seconds: s.cache_ttl_seconds,
            tags: s.tags,
            pipeline: s.pipeline,
            headers: s.headers,
            ip_family: s.ip_family,
            created_at: now,
            updated_at: now,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        };
        sources::create(&mut *tx, &source).await?;
        // No cache invalidation: the id is brand new, no rendered output can
        // reference it yet, and `last_fetched_at` is NULL, so the first
        // ingest is due immediately.
        summary.sources_created += 1;
    }

    for p in file.profiles {
        let id = models::new_id();
        let slug = claim_slug(
            p.slug,
            &mut taken_profile_slugs,
            &p.name,
            lang,
            &mut summary,
        );

        // Remap composition onto the freshly created source ids; references
        // to sources missing from the file are dropped with a warning.
        // A reference repeated inside one profile collapses to its first
        // position: `profile_sources` is keyed by (profile_id, source_id),
        // so writing it twice aborts the whole composition insert, after
        // the profile row was already committed, leaving an empty profile
        // behind a 500. `/admin/export` never emits a duplicate ref, so
        // this only ever sees a hand-edited file.
        let mut composition: Vec<(String, i64)> = Vec::new();
        let mut placed: HashSet<String> = HashSet::new();
        for (position, reference) in p.source_refs.iter().enumerate() {
            match ref_to_id.get(reference) {
                Some(new_id) if !placed.contains(new_id) => {
                    placed.insert(new_id.clone());
                    composition.push((new_id.clone(), position as i64));
                }
                Some(_) => {}
                None => summary.warnings.push(
                    lang.t("io.warn_unknown_ref")
                        .replace("{profile}", &p.name)
                        .replace("{ref}", reference),
                ),
            }
        }

        let profile = models::Profile {
            id: id.clone(),
            slug,
            // A plaintext token from a hand-written file is hashed by the
            // repository; a hash from an export is stored as it is.
            access_token: p.access_token,
            name: p.name,
            output_format: p.output_format,
            pipeline: p.pipeline,
            // The same normalization the profile form applies: the
            // allowlist is compared against the uppercase country codes of
            // the proxies.
            countries: validate_countries(&p.countries, lang).unwrap_or_default(),
            enabled: p.enabled,
            created_at: now,
            updated_at: now,
        };
        profiles::create(&mut *tx, &profile).await?;
        profiles::set_sources(&mut tx, &id, &composition).await?;
        created_profiles.push(id);
        summary.profiles_created += 1;
    }

    tx.commit().await?;

    // The caches are touched only after the commit: an invalidation for a
    // profile the transaction rolled back would evict a live entry for
    // nothing.
    for id in &created_profiles {
        state.caches.invalidate_profile(id).await;
    }

    Ok(summary)
}

/// Return the slug if it is free, otherwise record a warning and yield None.
fn claim_slug(
    slug: Option<String>,
    taken: &mut HashSet<String>,
    name: &str,
    lang: &Lang,
    summary: &mut ImportSummary,
) -> Option<String> {
    let slug = slug.filter(|s| !s.is_empty())?;
    if taken.contains(&slug) {
        summary.warnings.push(
            lang.t("io.warn_slug_collision")
                .replace("{name}", name)
                .replace("{slug}", &slug),
        );
        return None;
    }
    taken.insert(slug.clone());
    Some(slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(reference: &str, name: &str, slug: Option<&str>) -> ExportSource {
        ExportSource {
            reference: reference.into(),
            slug: slug.map(str::to_string),
            name: name.into(),
            url: "https://example.com/sub".into(),
            enabled: true,
            encoding: Encoding::Auto,
            input_format: None,
            protocols: None,
            cache_ttl_seconds: 3600,
            tags: None,
            pipeline: None,
            headers: None,
            ip_family: None,
        }
    }

    fn profile(name: &str, slug: Option<&str>, source_refs: &[&str]) -> ExportProfile {
        ExportProfile {
            slug: slug.map(str::to_string),
            access_token: None,
            name: name.into(),
            output_format: OutputFormat::UriList,
            pipeline: None,
            countries: Vec::new(),
            enabled: true,
            source_refs: source_refs.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Admin state on a throwaway database; the import path itself needs
    /// nothing but the pool, the caches and the config.
    async fn test_state() -> (fumox_core::tempdir_lite::TempDir, AdminState) {
        crate::admin::test_admin_state(Default::default(), Default::default()).await
    }

    #[test]
    fn export_file_round_trips_through_json() {
        let mut s1 = source("srcA0000000", "s1", Some("slug-a"));
        // A pinned IP family rides along and survives the round trip.
        s1.ip_family = Some(IpFamily::Ipv4);
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1_700_000_000,
            sources: vec![s1],
            profiles: vec![profile("p1", Some("prof-a"), &["srcA0000000"])],
        };
        // A country allowlist rides along and survives the round trip;
        // an empty list is omitted from the file entirely.
        let mut p1 = profile("p2", None, &["srcA0000000"]);
        p1.countries = vec!["DE".into(), "US".into()];
        let file = ConfigExport {
            profiles: vec![file.profiles.into_iter().next().unwrap(), p1],
            ..file
        };
        let json = serde_json::to_string(&file).unwrap();
        // The ref key (not "reference") is what lands in the file.
        assert!(json.contains("\"ref\":\"srcA0000000\""));
        assert!(json.contains("\"countries\":[\"DE\",\"US\"]"));
        assert!(json.contains("\"ip_family\":\"ipv4\""));
        let back: ConfigExport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, 1);
        assert_eq!(back.sources.len(), 1);
        assert_eq!(back.sources[0].reference, "srcA0000000");
        assert_eq!(back.sources[0].ip_family, Some(IpFamily::Ipv4));
        assert_eq!(back.profiles[0].source_refs, vec!["srcA0000000"]);
        assert!(back.profiles[0].countries.is_empty());
        assert_eq!(
            back.profiles[1].countries,
            vec!["DE".to_string(), "US".to_string()]
        );
    }

    #[test]
    fn unknown_version_or_garbage_is_rejected() {
        assert!(serde_json::from_str::<ConfigExport>("not json").is_err());
        let v2 = r#"{"version":2,"exported_at":0,"sources":[],"profiles":[]}"#;
        let parsed: ConfigExport = serde_json::from_str(v2).unwrap();
        assert_ne!(parsed.version, SUPPORTED_VERSION);
    }

    #[test]
    fn claim_slug_drops_collisions_and_records_warning() {
        let lang =
            crate::admin::i18n::Locales::load(std::path::Path::new("/nonexistent")).default_lang();
        let mut taken: HashSet<String> = ["taken".to_string()].into_iter().collect();
        let mut summary = ImportSummary::default();

        // A free slug is claimed.
        assert_eq!(
            claim_slug(Some("free".into()), &mut taken, "n", &lang, &mut summary),
            Some("free".into())
        );
        // Reusing it now collides → None + warning.
        assert_eq!(
            claim_slug(Some("free".into()), &mut taken, "n", &lang, &mut summary),
            None
        );
        // A slug taken by the DB also collides.
        assert_eq!(
            claim_slug(Some("taken".into()), &mut taken, "n", &lang, &mut summary),
            None
        );
        assert_eq!(summary.warnings.len(), 2);
    }

    /// F7/F8: import row caps and the
    /// access-token floor are hard errors, nothing is written.
    #[tokio::test]
    async fn import_rejects_row_floods_and_short_tokens() {
        let (_dir, state) =
            crate::admin::test_admin_state(Default::default(), Default::default()).await;
        let lang = state.locales.default_lang();

        // 501 sources trip the row cap before any DNS work happens.
        let flood = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: (0..caps::IMPORT_ROWS + 1)
                .map(|i| source(&format!("ref{i}"), &format!("s{i}"), None))
                .collect(),
            profiles: Vec::new(),
        };
        let errors = validate_import(&state, &lang, &flood).await.errors;
        assert!(!errors.is_empty(), "row cap must fire");

        // A profile with a guessable short token from a third-party file is
        // rejected (the endpoint would be "protected" by a known secret).
        let mut planted = profile("p", None, &[]);
        planted.access_token = Some("123".to_string());
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: Vec::new(),
            profiles: vec![planted],
        };
        let errors = validate_import(&state, &lang, &file).await.errors;
        assert!(!errors.is_empty(), "short imported token must be rejected");

        // A proper-length token passes validation.
        let mut ok = profile("p", None, &[]);
        ok.access_token = Some("a".repeat(32));
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: Vec::new(),
            profiles: vec![ok],
        };
        let errors = validate_import(&state, &lang, &file).await.errors;
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// A third-party token must round-trip unescaped in `?token=…`, so
    /// validation mirrors the profile form's unreserved-ASCII rule.
    #[tokio::test]
    async fn import_rejects_tokens_outside_the_url_charset() {
        let (_dir, state) = test_state().await;
        let lang = state.locales.default_lang();

        // Right length, so only the charset rule can reject these.
        for token in [
            format!("{} ", "a".repeat(caps::TOKEN_MIN)),
            "ё".repeat(caps::TOKEN_MIN),
        ] {
            let mut planted = profile("p", None, &[]);
            planted.access_token = Some(token.clone());
            let file = ConfigExport {
                version: SUPPORTED_VERSION,
                exported_at: 1,
                sources: Vec::new(),
                profiles: vec![planted],
            };
            let errors = validate_import(&state, &lang, &file).await.errors;
            assert!(
                !errors.is_empty(),
                "token {token:?} must be rejected by the charset rule"
            );
        }

        let mut ok = profile("p", None, &[]);
        ok.access_token = Some(format!("{}-_.~", "a".repeat(caps::TOKEN_MIN)));
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: Vec::new(),
            profiles: vec![ok],
        };
        let errors = validate_import(&state, &lang, &file).await.errors;
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// `sources.slug` and `profiles.slug` are two independent UNIQUE
    /// constraints on two tables, and each kind resolves its own only
    /// (`profiles::resolve_token` for `/sub/{id}`, `sources::resolve_token`
    /// for `/src/{id}`). The import must keep the two namespaces apart:
    /// sharing a slug across the two kinds is legal, and collapsing them
    /// into one "taken" set silently strips the profile's slug on a round
    /// trip, repointing every client that was subscribed to `/sub/{slug}`
    /// at `/sub/{id}`.
    #[tokio::test]
    async fn a_source_and_a_profile_may_hold_the_same_slug() {
        let (_dir, state) = test_state().await;
        let pool = state.pool.clone();
        let lang = state.locales.default_lang();

        // The DB itself allows one slug on both tables.
        let now = models::now_ts();
        let existing_source = models::Source {
            id: models::new_id(),
            slug: Some("main".into()),
            name: "s0".into(),
            url: "https://example.com/sub".into(),
            enabled: true,
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
        };
        sources::create(&pool, &existing_source).await.unwrap();
        let existing_profile = models::Profile {
            id: models::new_id(),
            slug: Some("main".into()),
            access_token: None,
            name: "p0".into(),
            output_format: OutputFormat::UriList,
            pipeline: None,
            countries: Vec::new(),
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        profiles::create(&pool, &existing_profile).await.unwrap();

        // Importing the same deployment again: every object collides
        // with its own table's row, so nothing may keep a slug.
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![source("srcB0000000", "s1", Some("main"))],
            profiles: vec![profile("p1", Some("main"), &["srcB0000000"])],
        };
        let summary = apply_import(&state, &lang, file, Vec::new()).await.unwrap();
        assert_eq!(summary.sources_created, 1);
        assert_eq!(summary.profiles_created, 1);

        let rows = profiles::list(&pool, false).await.unwrap();
        let imported = rows.iter().find(|p| p.name == "p1").unwrap();
        assert_eq!(
            imported.slug, None,
            "the profile collides with the stored profile of the same name-space"
        );
        let rows = sources::list(&pool, false).await.unwrap();
        let imported = rows.iter().find(|s| s.name == "s1").unwrap();
        assert_eq!(imported.slug, None, "collides with the stored source");

        // A fresh deployment importing the same file: the source and the
        // profile share a slug, and both must keep it, each in its own
        // table.
        let (_dir, fresh) = test_state().await;
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![source("srcA0000000", "s1", Some("main"))],
            profiles: vec![profile("p1", Some("main"), &["srcA0000000"])],
        };
        apply_import(&fresh, &lang, file, Vec::new()).await.unwrap();

        let stored = profiles::get_by_slug(&fresh.pool, "main").await.unwrap();
        assert!(
            stored.is_some(),
            "the profile must keep its slug: /sub/main would otherwise 404"
        );
        let stored = sources::get_by_slug(&fresh.pool, "main").await.unwrap();
        assert!(stored.is_some(), "the source keeps its slug too");
    }

    /// A profile whose `sources` list names the same reference twice: the
    /// write phase must not abort on the `(profile_id, source_id)` primary
    /// key and leave the already-committed profile row without sources.
    /// `/admin/export` never emits a duplicate ref, so this is the
    /// hand-edited file the import screen accepts.
    #[tokio::test]
    async fn repeated_source_reference_stores_the_source_once() {
        let (_dir, state) = test_state().await;
        let pool = state.pool.clone();
        let lang = state.locales.default_lang();
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![source("srcA0000000", "s1", None)],
            profiles: vec![profile("p1", None, &["srcA0000000", "srcA0000000"])],
        };

        let summary = apply_import(&state, &lang, file, Vec::new())
            .await
            .expect("a repeated source reference must not abort the import");
        assert_eq!(summary.profiles_created, 1);

        let rows = profiles::list(&pool, false).await.unwrap();
        assert_eq!(rows.len(), 1);
        let composition = profiles::get_sources(&pool, &rows[0].id).await.unwrap();
        assert_eq!(composition.len(), 1, "the ref is stored exactly once");
    }

    /// Two *source rows* sharing one `ref`: the write phase keys the fresh
    /// ids by reference, so the second row would overwrite the first in
    /// `ref_to_id` and the profile would bind only that one while the other
    /// source is created and silently orphaned. Validation rejects the
    /// ambiguity instead of picking a winner.
    #[tokio::test]
    async fn duplicate_source_reference_is_rejected() {
        let (_dir, state) = test_state().await;
        let lang = state.locales.default_lang();
        let dup_text = lang.t("val.dup_ref").replace("{ref}", "srcA0000000");

        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![
                source("srcA0000000", "s1", None),
                source("srcA0000000", "s2", None),
            ],
            profiles: vec![profile("p1", None, &["srcA0000000"])],
        };
        let errors = validate_import(&state, &lang, &file).await.errors;
        assert!(
            errors.iter().any(|e| e.contains(&dup_text)),
            "a reference used by two sources must be rejected: {errors:?}"
        );

        // Distinct references stay silent under the same rule, whatever the
        // URLs vet to in this environment.
        let file = ConfigExport {
            sources: vec![
                source("srcA0000000", "s1", None),
                source("srcB0000000", "s2", None),
            ],
            ..file
        };
        let errors = validate_import(&state, &lang, &file).await.errors;
        assert!(
            !errors.iter().any(|e| e.contains(&dup_text)),
            "distinct references must not be flagged: {errors:?}"
        );
    }

    /// The import path applies the same `PIPELINE_BYTES` cap the source and
    /// profile forms do: the stored JSON is re-rendered into every edit form
    /// and recompiled by the preview, so without the cap a file could plant
    /// a pipeline up to the 1 MiB body limit. The rule set here is
    /// semantically valid, so only the size may reject it.
    #[tokio::test]
    async fn imported_pipelines_respect_the_form_size_cap() {
        let (_dir, state) = test_state().await;
        let lang = state.locales.default_lang();

        let rules: Vec<serde_json::Value> = (0..800)
            .map(|i| {
                serde_json::json!({
                    "match": format!("^rule-{i}-{}", "x".repeat(80)),
                    "replace": "r",
                })
            })
            .collect();
        let big = serde_json::json!({ "version": 1, "rename": rules });
        assert!(
            CompiledPipeline::from_json(Some(&big)).is_ok(),
            "the oversized pipeline is semantically valid"
        );
        assert!(pipeline_size(&big) > caps::PIPELINE_BYTES);

        let mut s = source("srcA0000000", "s1", None);
        s.pipeline = Some(big.clone());
        let mut p = profile("p1", None, &["srcA0000000"]);
        p.pipeline = Some(big);
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![s],
            profiles: vec![p],
        };
        let errors = validate_import(&state, &lang, &file).await.errors;
        assert_eq!(
            errors.len(),
            2,
            "source and profile are both refused: {errors:?}"
        );
        assert!(
            errors.iter().all(|e| e.contains("65536")),
            "the cap, not a pipeline semantic, is the reason: {errors:?}"
        );

        // A pipeline inside the cap still imports.
        let mut s = source("srcA0000000", "s1", None);
        s.pipeline = Some(serde_json::json!({ "version": 1 }));
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![s],
            profiles: Vec::new(),
        };
        let errors = validate_import(&state, &lang, &file).await.errors;
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// Rotating the export capability token is audited like every other
    /// admin state change: an info line on the success path, without the
    /// token value itself. The token is the shared secret of both export
    /// links and rotation kills them instantly, so the log line is the
    /// only trace an operator has when a link stops working.
    #[tokio::test]
    async fn rotate_alive_token_is_logged_without_the_token_value() {
        let (_dir, state) = test_state().await;
        let old = state.export_token.current(&state.pool).await.unwrap();

        // The same writer trick the scheduler tests use.
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let make_writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || Captured(std::sync::Arc::clone(&make_writer)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let response = rotate_alive_token(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        // The rotation took effect: a fresh token replaced the old one.
        let new = fumox_core::repo::meta_get(&state.pool, crate::alive_export::TOKEN_KEY)
            .await
            .unwrap()
            .expect("rotation must persist the fresh token");
        assert_ne!(new, old);

        let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("alive-export capability token rotated"),
            "the rotation must be audited: {logs}"
        );
        assert!(
            !logs.contains(&old) && !logs.contains(&new),
            "the token value itself must never be logged: {logs}"
        );
    }

    /// The export is audited like every other admin action: an info line
    /// with the row counts, without the URLs, the tokens or the peer
    /// data. The counts are what an operator needs to reconcile an
    /// export with the panel.
    #[tokio::test]
    async fn the_export_is_logged_with_the_row_counts_only() {
        let (_dir, state) = test_state().await;
        let pool = state.pool.clone();
        let now = models::now_ts();
        let source = models::Source {
            id: models::new_id(),
            slug: Some("s0".into()),
            name: "s0".into(),
            url: "https://secret-host.example/sub".into(),
            enabled: true,
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
        };
        sources::create(&pool, &source).await.unwrap();

        // The same writer trick the scheduler tests use.
        struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let make_writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || Captured(std::sync::Arc::clone(&make_writer)))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let response = export_config(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::OK);

        let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("configuration exported"),
            "the export must be audited: {logs}"
        );
        assert!(
            logs.contains("sources=1") && logs.contains("profiles=0"),
            "the line carries the counts: {logs}"
        );
        assert!(
            !logs.contains("secret-host.example"),
            "the URL must never be logged: {logs}"
        );
    }

    /// The write phase is one transaction: a failure half-way through
    /// leaves the database exactly as it was. A trigger makes the second
    /// profile insert abort, so the source written before it has to be
    /// rolled back with it — a half-imported configuration (a source
    /// without its profile) is worse than no import at all.
    #[tokio::test]
    async fn a_failure_half_way_through_rolls_the_import_back() {
        let (_dir, state) = test_state().await;
        let pool = state.pool.clone();
        let lang = state.locales.default_lang();

        // The second profile insert aborts; the source and the first
        // profile are already written when it happens.
        sqlx::query(
            "CREATE TRIGGER block_p2 BEFORE INSERT ON profiles
             WHEN NEW.name = 'p2'
             BEGIN SELECT RAISE(ABORT, 'the profile insert is denied'); END",
        )
        .execute(&pool)
        .await
        .unwrap();

        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![source("srcA0000000", "s1", None)],
            profiles: vec![
                profile("p1", None, &["srcA0000000"]),
                profile("p2", None, &["srcA0000000"]),
            ],
        };
        let err = apply_import(&state, &lang, file, Vec::new())
            .await
            .expect_err("the trigger must abort the import");
        assert!(
            err.to_string().contains("denied"),
            "the write error must surface: {err}"
        );

        // Nothing survived the abort: neither the source nor the profile
        // written before it.
        let rows = sources::list(&pool, false).await.unwrap();
        assert!(rows.is_empty(), "the source must be rolled back: {rows:?}");
        let rows = profiles::list(&pool, false).await.unwrap();
        assert!(
            rows.is_empty(),
            "the profiles must be rolled back: {rows:?}"
        );
    }

    /// An export bigger than the import accepts says so in the file
    /// itself: the operator must not download a configuration the import
    /// screen will refuse.
    #[test]
    fn an_export_over_the_import_limits_says_so_in_the_file() {
        // A small file is importable: no marker.
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![source("srcA0000000", "s1", None)],
            profiles: Vec::new(),
        };
        let (body, limit) = serialize_export(&file).unwrap();
        assert!(limit.is_none(), "a small file is importable");
        assert!(!body.contains("import_limit"), "{body}");

        // Too many rows: the row cap is named.
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: (0..caps::IMPORT_ROWS + 1)
                .map(|i| source(&format!("ref{i}"), &format!("s{i}"), None))
                .collect(),
            profiles: Vec::new(),
        };
        let (body, limit) = serialize_export(&file).unwrap();
        let limit = limit.expect("a file over the row cap is not importable");
        assert_eq!(limit.cap, ImportCap::Rows);
        assert_eq!(limit.limit, caps::IMPORT_ROWS);
        assert_eq!(limit.actual, caps::IMPORT_ROWS + 1);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            value["import_limit"]["cap"], "rows",
            "the marker names the cap: {body}"
        );

        // Within the row cap but over the byte cap: the size is named.
        let mut big = source("srcA0000000", "s1", None);
        big.name = "x".repeat(caps::IMPORT_BODY_BYTES);
        let file = ConfigExport {
            version: SUPPORTED_VERSION,
            exported_at: 1,
            sources: vec![big],
            profiles: Vec::new(),
        };
        let (body, limit) = serialize_export(&file).unwrap();
        let limit = limit.expect("a file over the byte cap is not importable");
        assert_eq!(limit.cap, ImportCap::Bytes);
        assert_eq!(limit.limit, caps::IMPORT_BODY_BYTES);
        assert!(limit.actual > caps::IMPORT_BODY_BYTES);
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            value["import_limit"]["cap"], "bytes",
            "the marker names the cap: {body}"
        );
    }
}
