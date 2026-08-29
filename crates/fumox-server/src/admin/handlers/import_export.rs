//! Configuration import/export (ADMIN_PLAN §4.6, Phase 4).
//!
//! Export serializes every source and profile (plus profile composition)
//! into a versioned JSON file; import recreates them. The semantics are
//! **create-new only** (owner decision 2026-08-28): imported objects always
//! receive fresh `nanoid(12)` ids, profile composition is remapped onto the
//! new source ids, and existing rows are never overwritten. Slug collisions
//! with the database (or within the file) drop the slug rather than the
//! object; references to sources absent from the file are excluded from the
//! composition. Both cases surface as warnings, not errors.
//!
//! Validation mirrors the source/profile forms and is all-or-nothing: any
//! hard error yields a 422 with the full list and writes nothing.

use crate::admin::AdminState;
use crate::admin::i18n::{Lang, impl_i18n};
use crate::admin::render_html;
use crate::admin::theme::{self, Theme};
use crate::alive_export::{self, export_date};
use crate::fetcher;
use crate::pipeline::CompiledPipeline;
use askama::Template;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use fumox_core::models::{self, Encoding, InputFormat, IpFamily, OutputFormat, Scheme};
use fumox_core::repo::{profiles, proxies, sources};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Slug format shared with the source/profile forms.
const SLUG_RE: &str = r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$";
/// Only schema version we understand today.
const SUPPORTED_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// `GET /admin/export` — download the whole configuration as JSON.
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
    let body = match serde_json::to_string_pretty(&file) {
        Ok(body) => body,
        Err(err) => return super::server_error(lang, &err),
    };

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

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Outcome of a successful import for the summary panel.
#[derive(Debug, Default)]
struct ImportSummary {
    sources_created: usize,
    profiles_created: usize,
    warnings: Vec<String>,
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
    /// Present only after a successful import.
    summary: Option<ImportSummary>,
    /// Absolute public URL of the «all alive» export link, token included.
    alive_url: String,
    /// Alive+linked proxy count right now (button context).
    alive_count: i64,
}

impl_i18n!(ImportTemplate);

/// Render the import/export screen, filling in the alive-export link data
/// shared by every entry point (fresh page, validation errors, import
/// summary). The token is generated on first visit if startup has not
/// already created it.
async fn render_page(
    state: &AdminState,
    lang: Lang,
    theme: Theme,
    headers: &HeaderMap,
    status: StatusCode,
    errors: Vec<String>,
    summary: Option<ImportSummary>,
) -> Response {
    let token = match alive_export::ensure_token(&state.pool).await {
        Ok(token) => token,
        Err(err) => return super::server_error(lang, &err),
    };
    let alive_count = match proxies::count_alive(&state.pool).await {
        Ok(count) => count,
        Err(err) => return super::server_error(lang, &err),
    };
    let alive_url = format!("{}/export/alive/{}", state.serve_base(headers), token);
    render_html(
        lang.clone(),
        &ImportTemplate {
            lang,
            langs: state.locales.choices().to_vec(),
            theme,
            active: "import",
            csrf: state.csrf_for(headers),
            errors,
            summary,
            alive_url,
            alive_count,
        },
        status,
    )
}

/// `GET /admin/import` — the import/export screen.
pub async fn import_form(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    render_page(
        &state,
        lang,
        theme,
        &headers,
        StatusCode::OK,
        Vec::new(),
        None,
    )
    .await
}

/// `POST /admin/import` — validate then create-new.
pub async fn import_submit(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    let theme = theme::from_headers(&headers);
    let payload = form
        .iter()
        .rev()
        .find(|(k, _)| k == "payload")
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();

    let file: ConfigExport = match serde_json::from_str(&payload) {
        Ok(file) => file,
        Err(err) => {
            let errors = vec![lang.t("io.err_parse").replace("{}", &err.to_string())];
            return render_page(
                &state,
                lang,
                theme,
                &headers,
                StatusCode::UNPROCESSABLE_ENTITY,
                errors,
                None,
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
            lang,
            theme,
            &headers,
            StatusCode::UNPROCESSABLE_ENTITY,
            errors,
            None,
        )
        .await;
    }

    // All-or-nothing validation pass.
    let errors = validate_import(&state, &lang, &file).await;
    if !errors.is_empty() {
        return render_page(
            &state,
            lang,
            theme,
            &headers,
            StatusCode::UNPROCESSABLE_ENTITY,
            errors,
            None,
        )
        .await;
    }

    match apply_import(&state, &lang, file).await {
        Ok(summary) => {
            tracing::info!(
                sources = summary.sources_created,
                profiles = summary.profiles_created,
                "configuration imported"
            );
            render_page(
                &state,
                lang,
                theme,
                &headers,
                StatusCode::OK,
                Vec::new(),
                Some(summary),
            )
            .await
        }
        Err(err) => super::server_error(lang, &err),
    }
}

/// `POST /admin/import/alive-token` — issue a fresh token for the «all
/// alive» export link; the previous link stops working immediately.
pub async fn rotate_alive_token(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    let lang = state.locales.lang_from_headers(&headers);
    match alive_export::rotate_token(&state.pool).await {
        Ok(_) => Redirect::to("/admin/import").into_response(),
        Err(err) => super::server_error(lang, &err),
    }
}

/// Validate every imported object with the same rules as the forms. Returns
/// a (possibly empty) list of localized errors; any error aborts the import.
async fn validate_import(state: &AdminState, lang: &Lang, file: &ConfigExport) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let slug_re = regex::Regex::new(SLUG_RE).expect("valid slug regex");

    for s in &file.sources {
        let ctx = format!("{} «{}»", lang.t("io.source_word"), s.name);
        if s.name.trim().is_empty() {
            errors.push(format!("{ctx}: {}", lang.t("val.required")));
        } else if s.name.chars().count() > 200 {
            errors.push(format!("{ctx}: {}", lang.t("val.name_too_long")));
        }
        if s.url.trim().is_empty() {
            errors.push(format!("{ctx}: {}", lang.t("val.required")));
        } else if let Err(message) = fetcher::vet_url(
            &s.url,
            state.admin.allow_private_urls,
            s.ip_family
                .unwrap_or_else(|| state.fetcher.default_family()),
        )
        .await
        {
            errors.push(format!("{ctx}: {message}"));
        }
        if let Some(slug) = s.slug.as_deref()
            && !slug.is_empty()
            && !slug_re.is_match(slug)
        {
            errors.push(format!("{ctx}: {}", lang.t("val.slug_format")));
        }
        if !(60..=86_400).contains(&s.cache_ttl_seconds) {
            errors.push(format!("{ctx}: {}", lang.t("val.ttl_range")));
        }
        if let Some(pipeline) = s.pipeline.as_ref() {
            for message in CompiledPipeline::from_json(Some(pipeline))
                .err()
                .into_iter()
                .flatten()
            {
                errors.push(format!("{ctx}: {message}"));
            }
        }
    }

    for p in &file.profiles {
        let ctx = format!("{} «{}»", lang.t("io.profile_word"), p.name);
        if p.name.trim().is_empty() {
            errors.push(format!("{ctx}: {}", lang.t("val.required")));
        } else if p.name.chars().count() > 200 {
            errors.push(format!("{ctx}: {}", lang.t("val.name_too_long")));
        }
        if let Some(slug) = p.slug.as_deref()
            && !slug.is_empty()
            && !slug_re.is_match(slug)
        {
            errors.push(format!("{ctx}: {}", lang.t("val.slug_format")));
        }
        if let Some(pipeline) = p.pipeline.as_ref() {
            for message in CompiledPipeline::from_json(Some(pipeline))
                .err()
                .into_iter()
                .flatten()
            {
                errors.push(format!("{ctx}: {message}"));
            }
        }
        for code in &p.countries {
            let upper = code.trim().to_ascii_uppercase();
            if upper.len() != 2 || !upper.chars().all(|c| c.is_ascii_alphabetic()) {
                errors.push(format!(
                    "{ctx}: {}",
                    lang.t("val.country_format").replace("{}", code)
                ));
            }
        }
    }

    errors
}

/// Write phase: create sources (fresh ids), then profiles with composition
/// remapped onto the new ids. Collects warnings for dropped slugs/refs.
async fn apply_import(
    state: &AdminState,
    lang: &Lang,
    file: ConfigExport,
) -> Result<ImportSummary, fumox_core::Error> {
    let mut summary = ImportSummary::default();

    // Slugs already present in the DB or used earlier in this file cannot be
    // reused; the object is still created, just without a slug.
    let mut taken_slugs: HashSet<String> = HashSet::new();
    for s in sources::list(&state.pool, false).await? {
        if let Some(slug) = s.slug {
            taken_slugs.insert(slug);
        }
    }
    for p in profiles::list(&state.pool, false).await? {
        if let Some(slug) = p.slug {
            taken_slugs.insert(slug);
        }
    }

    let now = models::now_ts();
    let mut ref_to_id: HashMap<String, String> = HashMap::new();

    for s in file.sources {
        let id = models::new_id();
        ref_to_id.insert(s.reference.clone(), id.clone());
        let slug = claim_slug(s.slug, &mut taken_slugs, &s.name, lang, &mut summary);
        let source = models::Source {
            id: id.clone(),
            slug,
            name: s.name.clone(),
            url: s.url,
            enabled: s.enabled,
            encoding: s.encoding,
            input_format: s.input_format,
            protocols: s.protocols,
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
        sources::create(&state.pool, &source).await?;
        state.caches.invalidate_source(&id).await;
        summary.sources_created += 1;
    }

    for p in file.profiles {
        let id = models::new_id();
        let slug = claim_slug(p.slug, &mut taken_slugs, &p.name, lang, &mut summary);

        // Remap composition onto the freshly created source ids; references
        // to sources missing from the file are dropped with a warning.
        let mut composition: Vec<(String, i64)> = Vec::new();
        for (position, reference) in p.source_refs.iter().enumerate() {
            match ref_to_id.get(reference) {
                Some(new_id) => composition.push((new_id.clone(), position as i64)),
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
            access_token: p.access_token,
            name: p.name,
            output_format: p.output_format,
            pipeline: p.pipeline,
            countries: p.countries,
            enabled: p.enabled,
            created_at: now,
            updated_at: now,
        };
        profiles::create(&state.pool, &profile).await?;
        profiles::set_sources(&state.pool, &id, &composition).await?;
        state.caches.invalidate_profile(&id).await;
        summary.profiles_created += 1;
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
}
