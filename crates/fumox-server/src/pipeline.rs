//! Processing pipeline JSON v1 (SPEC §5, §5.1).
//!
//! The pipeline configuration is stored as JSON in `sources.pipeline` and
//! `profiles.pipeline`; the profile config overrides matching top-level
//! sections of each source config. Validation is strict: unknown keys are
//! errors, so a future schema v2 can add fields without ambiguity. Regexes
//! are compiled at save time; an uncompilable pattern rejects the form.
//!
//! Step order (SPEC §5): parse → filter → rename → geo-enrich →
//! health-filter → merge+dedup → sort → encode. Parse happens during
//! ingestion, health-filtering is expressed as a status exclusion list for
//! the repository query (and re-applied here defensively), encode lives in
//! the serving layer. Speed-enrich is a stub until Phase 4.

use fumox_core::geo::{GeoResolver, apply_template};
use fumox_core::models::{ProxyEntry, ProxyStatus, Scheme};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::str::FromStr;

/// Default geo name template (SPEC §5.1).
pub(crate) const DEFAULT_GEO_TEMPLATE: &str = "{flag} {country} · {name}";

/// Raw pipeline configuration, deserialized with `deny_unknown_fields` at
/// every level so unknown keys fail validation. `pub(crate)` so the admin
/// pipeline editor's ingest parses JSON with the exact same definitions
/// (PIPELINE.md §4) instead of mirroring them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PipelineConfig {
    /// Schema version; must be `1`.
    pub(crate) version: u8,
    #[serde(default)]
    pub(crate) filter: Option<FilterConfig>,
    #[serde(default)]
    pub(crate) rename: Option<Vec<RenameRule>>,
    #[serde(default)]
    pub(crate) geo: Option<GeoStepConfig>,
    #[serde(default)]
    pub(crate) health: Option<HealthConfig>,
    #[serde(default)]
    pub(crate) dedup: Option<DedupConfig>,
    #[serde(default)]
    pub(crate) sort: Option<SortConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilterConfig {
    #[serde(default)]
    pub(crate) protocols: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) exclude_protocols: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub(crate) normalize_params: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenameRule {
    #[serde(rename = "match")]
    pub(crate) match_pattern: String,
    pub(crate) replace: String,
    #[serde(default)]
    pub(crate) flags: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeoStepConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_geo_template")]
    pub(crate) template: String,
}

fn default_geo_template() -> String {
    DEFAULT_GEO_TEMPLATE.to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HealthConfig {
    #[serde(default = "default_exclude_statuses")]
    pub(crate) exclude_statuses: Vec<String>,
}

/// Default health exclusion (SPEC §8): quarantine and removed are hidden
/// from subscriptions unless the pipeline says otherwise.
pub(crate) fn default_exclude_statuses() -> Vec<String> {
    vec!["quarantine".to_string(), "removed".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DedupConfig {
    #[serde(rename = "by")]
    pub(crate) by: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SortBy {
    Source,
    Name,
    Country,
    Latency,
}

impl SortBy {
    /// Every sort key, in schema order (pipeline editor select options).
    pub(crate) const ALL: [SortBy; 4] = [
        SortBy::Source,
        SortBy::Name,
        SortBy::Country,
        SortBy::Latency,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SortBy::Source => "source",
            SortBy::Name => "name",
            SortBy::Country => "country",
            SortBy::Latency => "latency",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SortConfig {
    #[serde(default = "default_sort_by")]
    pub(crate) by: SortBy,
    #[serde(default)]
    pub(crate) desc: bool,
}

const fn default_sort_by() -> SortBy {
    SortBy::Source
}

/// A rename rule with its regex compiled at validation time.
#[derive(Debug, Clone)]
struct CompiledRename {
    regex: Regex,
    replace: String,
}

/// A fully validated, ready-to-run pipeline.
#[derive(Debug, Clone)]
pub struct CompiledPipeline {
    filter_protocols: Option<Vec<Scheme>>,
    exclude_protocols: Option<Vec<Scheme>>,
    normalize_params: bool,
    rename: Vec<CompiledRename>,
    geo_enabled: bool,
    geo_template: String,
    exclude_statuses: Vec<ProxyStatus>,
    sort_by: SortBy,
    sort_desc: bool,
    /// Whether `sort` was set explicitly (used to pick the sort config when
    /// several pipelines are merged: profile wins, then the first source).
    pub sort_explicit: bool,
}

impl Default for CompiledPipeline {
    /// Pass-through pipeline with the SPEC §5.1 defaults: normalize
    /// insecure-aliases, geo-enrich, drop quarantine/removed, dedup by
    /// fingerprint, keep source order.
    fn default() -> Self {
        Self {
            filter_protocols: None,
            exclude_protocols: None,
            normalize_params: true,
            rename: Vec::new(),
            geo_enabled: true,
            geo_template: DEFAULT_GEO_TEMPLATE.to_string(),
            exclude_statuses: vec![ProxyStatus::Quarantine, ProxyStatus::Removed],
            sort_by: SortBy::Source,
            sort_desc: false,
            sort_explicit: false,
        }
    }
}

/// One pipeline validation problem: a catalog key plus positional `{0}`,
/// `{1}`… arguments. The admin layer renders it with `Lang::t_args` in the
/// panel language (form errors, import validation); the serving layer only
/// logs issues in their debug form.
#[derive(Debug, Clone)]
pub struct PipelineIssue {
    /// Catalog key (`pipeline.*` section of `locales/*.toml`).
    pub key: &'static str,
    /// Positional arguments: field names and offending values. Embedded
    /// diagnostics (serde/regex details) stay technical English — only the
    /// sentence around them is localized.
    pub args: Vec<String>,
}

impl CompiledPipeline {
    /// Compile a pipeline JSON value, collecting every validation error
    /// (field-level issues for the admin form, ADMIN_PLAN §6).
    ///
    /// `NULL` and `{}` mean pass-through with defaults (SPEC §5.1).
    pub fn from_json(value: Option<&serde_json::Value>) -> Result<Self, Vec<PipelineIssue>> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        match value {
            serde_json::Value::Null => return Ok(Self::default()),
            serde_json::Value::Object(map) if map.is_empty() => return Ok(Self::default()),
            _ => {}
        }

        let mut errors = Vec::new();
        let config: PipelineConfig = match serde_json::from_value(value.clone()) {
            Ok(config) => config,
            Err(err) => {
                return Err(vec![PipelineIssue {
                    key: "pipeline.invalid",
                    args: vec![err.to_string()],
                }]);
            }
        };

        if config.version != 1 {
            errors.push(PipelineIssue {
                key: "pipeline.version",
                args: vec![config.version.to_string()],
            });
        }

        let mut compiled = Self::default();

        if let Some(filter) = config.filter {
            compiled.filter_protocols =
                parse_scheme_list(&filter.protocols, "filter.protocols", &mut errors);
            compiled.exclude_protocols = parse_scheme_list(
                &filter.exclude_protocols,
                "filter.exclude_protocols",
                &mut errors,
            );
            compiled.normalize_params = filter.normalize_params;
        }

        if let Some(rules) = config.rename {
            for (idx, rule) in rules.iter().enumerate() {
                let field = format!("rename[{idx}]");
                let mut builder = regex::RegexBuilder::new(&rule.match_pattern);
                for flag in rule.flags.chars() {
                    match flag {
                        'i' => {
                            builder.case_insensitive(true);
                        }
                        'm' => {
                            builder.multi_line(true);
                        }
                        's' => {
                            builder.dot_matches_new_line(true);
                        }
                        other => {
                            errors.push(PipelineIssue {
                                key: "pipeline.unknown_flag",
                                args: vec![field.clone(), other.to_string()],
                            });
                        }
                    }
                }
                match builder.build() {
                    Ok(regex) => compiled.rename.push(CompiledRename {
                        regex,
                        replace: rule.replace.clone(),
                    }),
                    Err(err) => errors.push(PipelineIssue {
                        key: "pipeline.bad_regex",
                        args: vec![field, err.to_string()],
                    }),
                }
            }
        }

        if let Some(geo) = config.geo {
            compiled.geo_enabled = geo.enabled;
            if geo.template.trim().is_empty() {
                errors.push(PipelineIssue {
                    key: "pipeline.empty_template",
                    args: Vec::new(),
                });
            } else {
                compiled.geo_template = geo.template;
            }
        }

        if let Some(health) = config.health {
            let mut statuses = Vec::new();
            for raw in &health.exclude_statuses {
                match ProxyStatus::from_str(raw) {
                    Ok(status) => statuses.push(status),
                    Err(_) => errors.push(PipelineIssue {
                        key: "pipeline.unknown_status",
                        args: vec![raw.clone()],
                    }),
                }
            }
            compiled.exclude_statuses = statuses;
        }

        if let Some(dedup) = config.dedup
            && dedup.by != "fingerprint"
        {
            errors.push(PipelineIssue {
                key: "pipeline.dedup_by",
                args: vec![dedup.by],
            });
        }

        if let Some(sort) = config.sort {
            compiled.sort_by = sort.by;
            compiled.sort_desc = sort.desc;
            compiled.sort_explicit = true;
        }

        if errors.is_empty() {
            Ok(compiled)
        } else {
            Err(errors)
        }
    }

    /// Statuses this pipeline excludes — used by the admin preview and
    /// proxy browser queries.
    #[allow(dead_code)] // consumed by admin handlers in Phase 2.5
    pub fn exclude_statuses(&self) -> &[ProxyStatus] {
        &self.exclude_statuses
    }

    /// Run the full pipeline over candidates already loaded from the DB.
    /// Used by `/src` (single source, one pipeline).
    pub async fn apply(&self, candidates: Vec<Candidate>, geo: &GeoResolver) -> Vec<Candidate> {
        let mut out = self.apply_per_source(candidates, geo).await;
        self.finalize(&mut out);
        out
    }

    /// Per-source steps (SPEC §5 steps 2–6): filter → normalize → rename →
    /// geo-enrich → health-filter. `/sub` runs this for every source with
    /// the merged (source + profile) pipeline, then calls [`Self::finalize`]
    /// once on the merged result.
    pub async fn apply_per_source(
        &self,
        mut candidates: Vec<Candidate>,
        geo: &GeoResolver,
    ) -> Vec<Candidate> {
        // filter
        if let Some(allowed) = &self.filter_protocols {
            candidates.retain(|c| allowed.contains(&c.entry.scheme));
        }
        if let Some(excluded) = &self.exclude_protocols {
            candidates.retain(|c| !excluded.contains(&c.entry.scheme));
        }

        // filter.normalize_params — collapse duplicate/contradicting
        // insecure spellings (SPEC §5 step 2).
        if self.normalize_params {
            for candidate in &mut candidates {
                normalize_insecure_params(&mut candidate.entry.params);
            }
        }

        // rename — rules apply in order.
        for candidate in &mut candidates {
            for rule in &self.rename {
                let renamed = rule
                    .regex
                    .replace_all(&candidate.entry.name, rule.replace.as_str())
                    .into_owned();
                candidate.entry.name = renamed;
            }
        }

        // geo-enrich — rewrite the display name from the template and keep
        // the country code for sorting. No-op when the resolver is inactive.
        if self.geo_enabled && geo.is_active() {
            for candidate in &mut candidates {
                if let Some(info) = geo.resolve(&candidate.entry.host).await {
                    let renamed = apply_template(&self.geo_template, &info, &candidate.entry.name);
                    candidate.entry.name = renamed;
                    candidate.geo_country = info.country_code.clone();
                }
            }
        }

        // health-filter — defensive re-check; the serving layer can load
        // every status and rely on this step for exclusion.
        let excluded: HashSet<ProxyStatus> = self.exclude_statuses.iter().copied().collect();
        candidates.retain(|c| !excluded.contains(&c.status));

        candidates
    }

    /// Post-merge steps (SPEC §5 step 7): dedup by fingerprint — the first
    /// occurrence wins, so the earlier source keeps the name it contributed —
    /// followed by the global sort. Speed-enrich is a stub until Phase 4:
    /// latency comes from probe results already stored on the row.
    pub fn finalize(&self, candidates: &mut Vec<Candidate>) {
        let mut seen = HashSet::new();
        candidates.retain(|c| seen.insert(c.entry.fingerprint()));
        self.sort(candidates);
    }

    fn sort(&self, candidates: &mut [Candidate]) {
        match self.sort_by {
            SortBy::Source => {
                candidates.sort_by_key(|c| c.source_position);
                if self.sort_desc {
                    candidates.reverse();
                }
            }
            SortBy::Name => {
                candidates.sort_by_cached_key(|c| c.entry.name.to_lowercase());
                if self.sort_desc {
                    candidates.reverse();
                }
            }
            SortBy::Country => {
                candidates.sort_by_cached_key(|c| c.geo_country.clone().unwrap_or_default());
                if self.sort_desc {
                    candidates.reverse();
                }
            }
            SortBy::Latency => {
                // NULL latencies always go last, even when descending.
                candidates.sort_by_key(|c| match c.latency_ms {
                    Some(ms) => (0u8, if self.sort_desc { -ms } else { ms }),
                    None => (1u8, 0),
                });
            }
        }
    }
}

/// Merge a source pipeline with the profile override: the profile's
/// top-level sections replace the source's (SPEC §5.1).
pub fn merge_configs(
    source: Option<&serde_json::Value>,
    profile: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    match (source, profile) {
        (None, None) => None,
        (Some(s), None) | (None, Some(s)) => Some(s.clone()),
        (Some(s), Some(p)) => {
            let (Some(s_map), Some(p_map)) = (s.as_object(), p.as_object()) else {
                // Non-object configs are invalid; the profile side wins so
                // the error surfaces against the profile form.
                return Some(p.clone());
            };
            let mut merged = s_map.clone();
            for (key, value) in p_map {
                merged.insert(key.clone(), value.clone());
            }
            Some(serde_json::Value::Object(merged))
        }
    }
}

fn parse_scheme_list(
    raw: &Option<Vec<String>>,
    field: &str,
    errors: &mut Vec<PipelineIssue>,
) -> Option<Vec<Scheme>> {
    let Some(raw) = raw else {
        return None;
    };
    let mut schemes = Vec::new();
    for name in raw {
        match Scheme::from_str(name) {
            Ok(scheme) => schemes.push(scheme),
            Err(_) => errors.push(PipelineIssue {
                key: "pipeline.unknown_protocol",
                args: vec![field.to_string(), name.clone()],
            }),
        }
    }
    Some(schemes)
}

/// Collapse the certificate-verification spellings (`insecure`,
/// `allowInsecure`, `skip-cert-verify`) into a single parameter.
///
/// A lone alias is left untouched (clients expect their protocol's native
/// spelling); only duplicate or contradicting toggles are merged. Any
/// truthy value wins and is written back as `1` under the first spelling
/// present; all-falsy sets keep the first spelling and value.
fn normalize_insecure_params(params: &mut Vec<fumox_core::models::Param>) {
    const ALIASES: [&str; 3] = ["insecure", "allowinsecure", "skip-cert-verify"];

    let positions: Vec<usize> = params
        .iter()
        .enumerate()
        .filter(|(_, p)| ALIASES.contains(&p.key.to_ascii_lowercase().as_str()))
        .map(|(idx, _)| idx)
        .collect();
    if positions.len() <= 1 {
        return;
    }

    let any_truthy = positions.iter().any(|&idx| {
        matches!(
            params[idx].value.trim().to_ascii_lowercase().as_str(),
            "1" | "true"
        )
    });
    let keep = positions[0];
    let (key, value, known) = if any_truthy {
        (
            params[keep].key.clone(),
            "1".to_string(),
            params[keep].known,
        )
    } else {
        (
            params[keep].key.clone(),
            params[keep].value.clone(),
            params[keep].known,
        )
    };
    // Drop every alias occurrence, then re-insert the survivor in place.
    for &idx in positions.iter().rev() {
        params.remove(idx);
    }
    params.insert(
        keep.min(params.len()),
        fumox_core::models::Param { key, value, known },
    );
}

/// One proxy on its way through the pipeline: the entry plus the DB-side
/// context the steps need (status, latency, source order, stored geo).
#[derive(Debug, Clone)]
pub struct Candidate {
    pub entry: ProxyEntry,
    /// `profile_sources.position` — the source order inside the profile.
    pub source_position: i64,
    pub status: ProxyStatus,
    pub latency_ms: Option<i64>,
    /// Country code stored on the proxy row by earlier enrichment.
    pub geo_country: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::models::{Param, Scheme};
    use serde_json::json;

    fn candidate(name: &str, scheme: Scheme, host: &str) -> Candidate {
        Candidate {
            entry: ProxyEntry {
                scheme,
                name: name.to_string(),
                host: host.to_string(),
                port: 443,
                credential: "cred".to_string(),
                params: Vec::new(),
                raw_path: String::new(),
                raw_line: String::new(),
            },
            source_position: 0,
            status: ProxyStatus::Unknown,
            latency_ms: None,
            geo_country: None,
        }
    }

    fn inactive_geo() -> GeoResolver {
        // Explicitly disabled: the default config would open the local
        // mmdb files and rewrite names mid-test.
        let cfg = fumox_core::config::GeoConfig {
            enabled: false,
            ..Default::default()
        };
        GeoResolver::new(&cfg)
    }

    #[test]
    fn null_and_empty_configs_compile_to_defaults() {
        assert!(CompiledPipeline::from_json(None).is_ok());
        assert!(CompiledPipeline::from_json(Some(&json!(null))).is_ok());
        assert!(CompiledPipeline::from_json(Some(&json!({}))).is_ok());
        let compiled = CompiledPipeline::from_json(None).unwrap();
        assert_eq!(
            compiled.exclude_statuses(),
            &[ProxyStatus::Quarantine, ProxyStatus::Removed]
        );
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "bogus": true
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.invalid");
        assert!(err[0].args[0].contains("bogus"), "{err:?}");
    }

    #[test]
    fn wrong_version_is_rejected() {
        let err = CompiledPipeline::from_json(Some(&json!({ "version": 2 }))).unwrap_err();
        assert_eq!(err[0].key, "pipeline.version");
        assert_eq!(err[0].args, vec!["2"]);
    }

    #[test]
    fn unknown_protocol_and_status_are_field_errors() {
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "protocols": ["vless", "quantum"] },
            "health": { "exclude_statuses": ["sleeping"] }
        })))
        .unwrap_err();
        assert!(err
            .iter()
            .any(|e| e.key == "pipeline.unknown_protocol" && e.args.contains(&"quantum".into())));
        assert!(
            err.iter()
                .any(|e| e.key == "pipeline.unknown_status" && e.args.contains(&"sleeping".into()))
        );
    }

    #[test]
    fn bad_regex_is_rejected_at_compile_time() {
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": "(", "replace": "" }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.bad_regex");
        assert_eq!(err[0].args[0], "rename[0]");

        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": "a", "replace": "", "flags": "z" }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.unknown_flag");
        assert_eq!(err[0].args[0], "rename[0]");
        assert_eq!(err[0].args[1], "z");
    }

    #[test]
    fn dedup_by_only_supports_fingerprint() {
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "dedup": { "by": "name" }
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.dedup_by");
        assert_eq!(err[0].args, vec!["name"]);
    }

    #[tokio::test]
    async fn filter_step_keeps_allowed_protocols() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "protocols": ["trojan"] }
        })))
        .unwrap();
        let candidates = vec![
            candidate("a", Scheme::Vless, "h1.example.com"),
            candidate("b", Scheme::Trojan, "h2.example.com"),
        ];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].entry.scheme, Scheme::Trojan);
    }

    #[tokio::test]
    async fn exclude_protocols_step() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "exclude_protocols": ["naive"] }
        })))
        .unwrap();
        let candidates = vec![
            candidate("a", Scheme::Naive, "h1.example.com"),
            candidate("b", Scheme::Trojan, "h2.example.com"),
        ];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].entry.scheme, Scheme::Trojan);
    }

    #[tokio::test]
    async fn rename_rules_apply_in_order_with_captures() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [
                { "match": "^(.*?)\\s*\\|", "replace": "$1" },
                { "match": "free", "replace": "FREE", "flags": "i" }
            ]
        })))
        .unwrap();
        let candidates = vec![candidate("RU | free node", Scheme::Vless, "h.example.com")];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.name, "RU FREE node");
    }

    #[tokio::test]
    async fn geo_step_applies_asn_template_when_db_present() {
        // GeoLite2 files are gitignored, so CI runs without them.
        let db_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
        if !db_dir.join("GeoLite2-ASN.mmdb").exists() {
            eprintln!("skipped: GeoLite2-ASN.mmdb is not present");
            return;
        }
        let cfg = fumox_core::config::GeoConfig {
            enabled: true,
            db: fumox_core::config::GeoDbKind::Asn,
            db_dir,
            ..Default::default()
        };
        let geo = GeoResolver::new(&cfg);
        assert!(geo.is_active());

        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            // ASN-only data (no country) must still rename, not no-op.
            "geo": { "enabled": true, "template": "{asn} · {name}" }
        })))
        .unwrap();
        // Literal IP → no DNS round-trip; 8.8.8.8 is AS15169 (Google).
        let out = compiled
            .apply(vec![candidate("Node-1", Scheme::Vless, "8.8.8.8")], &geo)
            .await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].entry.name, "AS15169 · Node-1");
    }

    #[tokio::test]
    async fn health_filter_drops_quarantine_and_removed_but_passes_unknown() {
        let compiled = CompiledPipeline::from_json(None).unwrap();
        let mut quarantined = candidate("q", Scheme::Vless, "h1.example.com");
        quarantined.status = ProxyStatus::Quarantine;
        let mut removed = candidate("r", Scheme::Vless, "h2.example.com");
        removed.status = ProxyStatus::Removed;
        let unknown = candidate("u", Scheme::Tuic, "h3.example.com"); // unprobeable
        let alive = candidate("a", Scheme::Vless, "h4.example.com");

        let out = compiled
            .apply(vec![quarantined, removed, unknown, alive], &inactive_geo())
            .await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, vec!["u", "a"]);
    }

    #[tokio::test]
    async fn dedup_keeps_first_occurrence() {
        let compiled = CompiledPipeline::from_json(None).unwrap();
        let mut first = candidate("first name", Scheme::Vless, "h.example.com");
        first.source_position = 0;
        let mut duplicate = candidate("other name", Scheme::Vless, "h.example.com");
        duplicate.source_position = 1; // same host/port/credential → same fingerprint
        let out = compiled
            .apply(vec![first, duplicate], &inactive_geo())
            .await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].entry.name, "first name");
    }

    #[tokio::test]
    async fn sort_by_name_and_latency_nulls_last() {
        let by_name = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "sort": { "by": "name" }
        })))
        .unwrap();
        let candidates = vec![
            candidate("beta", Scheme::Vless, "h1.example.com"),
            candidate("Alpha", Scheme::Vless, "h2.example.com"),
        ];
        let out = by_name.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.name, "Alpha");
        assert_eq!(out[1].entry.name, "beta");

        let by_latency = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "sort": { "by": "latency", "desc": true }
        })))
        .unwrap();
        let mut fast = candidate("fast", Scheme::Vless, "h1.example.com");
        fast.latency_ms = Some(50);
        let mut slow = candidate("slow", Scheme::Vless, "h2.example.com");
        slow.latency_ms = Some(300);
        let unmeasured = candidate("unknown", Scheme::Vless, "h3.example.com");
        let out = by_latency
            .apply(vec![fast, slow, unmeasured], &inactive_geo())
            .await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        // Descending, but the NULL latency stays last.
        assert_eq!(names, vec!["slow", "fast", "unknown"]);
    }

    #[test]
    fn profile_sections_override_source_sections() {
        let source = json!({
            "version": 1,
            "filter": { "protocols": ["vless"] },
            "sort": { "by": "name" }
        });
        let profile = json!({
            "version": 1,
            "sort": { "by": "latency" }
        });
        let merged = merge_configs(Some(&source), Some(&profile)).unwrap();
        // Profile replaced sort; source filter survived.
        assert_eq!(merged["sort"]["by"], "latency");
        assert_eq!(merged["filter"]["protocols"][0], "vless");
    }

    #[test]
    fn insecure_normalization_merges_contradictions() {
        let mut params = vec![
            Param {
                key: "sni".into(),
                value: "x".into(),
                known: true,
            },
            Param {
                key: "allowInsecure".into(),
                value: "0".into(),
                known: true,
            },
            Param {
                key: "insecure".into(),
                value: "1".into(),
                known: true,
            },
        ];
        normalize_insecure_params(&mut params);
        let insecure: Vec<_> = params
            .iter()
            .filter(|p| {
                ["insecure", "allowinsecure", "skip-cert-verify"]
                    .contains(&p.key.to_ascii_lowercase().as_str())
            })
            .collect();
        assert_eq!(insecure.len(), 1);
        assert_eq!(insecure[0].key, "allowInsecure"); // first spelling present
        assert_eq!(insecure[0].value, "1"); // truthy wins
        assert!(params.iter().any(|p| p.key == "sni"));
    }

    #[test]
    fn insecure_normalization_leaves_lone_alias_alone() {
        let mut params = vec![Param {
            key: "skip-cert-verify".into(),
            value: "0".into(),
            known: true,
        }];
        let before = params.clone();
        normalize_insecure_params(&mut params);
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].key, before[0].key);
        assert_eq!(params[0].value, before[0].value);
    }
}
