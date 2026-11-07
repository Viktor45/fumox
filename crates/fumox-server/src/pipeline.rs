//! Processing pipeline JSON v1.
//!
//! The pipeline configuration is stored as JSON in `sources.pipeline` and
//! `profiles.pipeline`; the profile config overrides matching top-level
//! sections of each source config. Validation is strict: unknown keys are
//! errors, so a future schema v2 can add fields without ambiguity. Regexes
//! are compiled at save time; an uncompilable pattern rejects the form.
//!
//! Step order: parse → filter → drop → rename → geo-enrich →
//! health-filter → merge+dedup → sort → encode. Parse happens during
//! ingestion, health-filtering is expressed as a status exclusion list for
//! the repository query (and re-applied here defensively), encode lives in
//! the serving layer. The `drop` rules run at ingestion too (the source's
//! own pipeline, via [`CompiledPipeline::drop_entries_with_geo`]), before
//! `rename`, so both sides see the original values. The ASN filters read a
//! fact the row may not carry yet, so [`fill_missing_asns`] completes it
//! before them. The two ASN exclusion mechanisms are deliberately
//! distinct: `filter.exclude_asns` hides matching rows from the output
//! while the rows stay stored, a drop rule with `target: "asn"` keeps them
//! from being stored at all. Speed-enrich is a stub until Phase 4.

use fumox_core::geo::{GEO_LOOKUP_CONCURRENCY, GeoResolver, HostGeo, apply_template};
use fumox_core::models::{ProxyEntry, ProxyStatus, Scheme};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};

/// Default geo name template.
pub(crate) const DEFAULT_GEO_TEMPLATE: &str = "{flag} {country} · {name}";

/// Raw pipeline configuration, deserialized with `deny_unknown_fields` at
/// every level so unknown keys fail validation. `pub(crate)` so the admin
/// pipeline editor's ingest parses JSON with the exact same definitions
/// instead of mirroring them.
///
/// The `Serialize` side carries the builder's omit-defaults emit policy:
/// only non-default values are written (`Option`s when present,
/// booleans and defaulted fields only when they differ from their schema
/// default), so the editor builds a typed [`PipelineConfig`] and
/// serializes it instead of restating every key literal in a hand-rolled
/// writer.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PipelineConfig {
    /// Schema version; must be `1`. A missing key defaults to `0`, which
    /// fails the `pipeline.version` check in [`CompiledPipeline::from_json`]
    /// like any other wrong value: an unversioned document is a localized
    /// field error instead of an opaque serde type error.
    #[serde(default)]
    pub(crate) version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) filter: Option<FilterConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rename: Option<Vec<RenameRule>>,
    /// Discard rules: a proxy matching any rule is never
    /// stored. Applied at ingestion (the source's own pipeline) and again
    /// on serving before `rename`, so both sides see the original values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) drop: Option<Vec<DropRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) geo: Option<GeoStepConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) health: Option<HealthConfig>,
    /// Accepted-but-ignored backward-compatibility key: v1 deduplication
    /// is unconditional (by fingerprint), so any `dedup` section is a
    /// no-op. Accepted rather than rejected by `deny_unknown_fields` so
    /// old exports keep importing; real modes arrive in schema v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dedup: Option<DedupConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sort: Option<SortConfig>,
    /// Output-size cap: keep at most `count` proxies of
    /// the final, deduplicated and sorted list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) limit: Option<LimitConfig>,
}

/// Protocol and ASN gates plus the insecure-TLS switch. `protocols` and
/// `exclude_protocols` compose: when both keys are set, a proxy must pass
/// both checks — the result is the intersection of the two lists.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilterConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) protocols: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) exclude_protocols: Option<Vec<String>>,
    /// AS numbers to keep, bare digits (`"24940"`); the `AS24940` spelling
    /// is accepted and normalized to the number. null = no allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) asns: Option<Vec<String>>,
    /// AS numbers to hide from the output, the same accepted format as
    /// [`Self::asns`]: rows whose ASN matches are filtered at serving and
    /// stay stored otherwise untouched. To prevent storage entirely, use
    /// a drop rule with `target: "asn"` — the two are complementary
    /// ("hide" and "not store"), not interchangeable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) exclude_asns: Option<Vec<String>>,
    /// Drop proxies that allow insecure TLS: any
    /// certificate-verification alias set to a truthy value. Default on.
    /// `normalize_params` is the v1 name of the same switch (serde alias,
    /// accepted forever so old exports keep importing).
    #[serde(
        default = "default_true",
        alias = "normalize_params",
        skip_serializing_if = "is_true"
    )]
    pub(crate) forbid_insecure: bool,
}

const fn default_true() -> bool {
    true
}

/// `skip_serializing_if` predicates backing the omit-defaults emit policy:
/// a field at its schema default is never written, the same rule the
/// builder's emit applies to every section it builds.
fn is_true(value: &bool) -> bool {
    *value
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_default_geo_template(value: &String) -> bool {
    value == DEFAULT_GEO_TEMPLATE
}

fn is_default_exclude_statuses(value: &Vec<String>) -> bool {
    *value == default_exclude_statuses()
}

fn is_default_sort(value: &SortBy) -> bool {
    *value == SortBy::Source
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenameRule {
    #[serde(rename = "match")]
    pub(crate) match_pattern: String,
    pub(crate) replace: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) flags: String,
    /// What the regex rewrites: `name` (default), `host`, `port` or
    /// `param:KEY` (case-insensitive first match). Optional so every
    /// existing v1 config stays valid unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<String>,
}

/// Parse and validate a `target` value. A `param:` selector with an empty
/// key is rejected like every other unknown form.
pub(crate) fn parse_rename_target(
    raw: &Option<String>,
    field: &str,
    errors: &mut Vec<PipelineIssue>,
) -> Option<RenameTarget> {
    let Some(raw) = raw else {
        return Some(RenameTarget::Name);
    };
    let target = match raw.trim() {
        "name" => RenameTarget::Name,
        "host" => RenameTarget::Host,
        "port" => RenameTarget::Port,
        param
            if let Some(key) = param.strip_prefix("param:")
                && !key.trim().is_empty() =>
        {
            RenameTarget::Param(key.trim().to_string())
        }
        other => {
            errors.push(PipelineIssue {
                key: "pipeline.unknown_target",
                args: vec![field.to_string(), other.to_string()],
            });
            return None;
        }
    };
    Some(target)
}

/// Compile one rule's regex (shared by rename and drop rules): the `i`/`m`/`s`
/// flags, then the build. An unknown flag or an uncompilable pattern pushes
/// the field error and yields `None`, the rule is skipped, every other rule
/// still reports.
fn compile_rule_regex(
    pattern: &str,
    flags: &str,
    field: &str,
    errors: &mut Vec<PipelineIssue>,
) -> Option<Regex> {
    let mut builder = regex::RegexBuilder::new(pattern);
    for flag in flags.chars() {
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
            other => errors.push(PipelineIssue {
                key: "pipeline.unknown_flag",
                args: vec![field.to_string(), other.to_string()],
            }),
        }
    }
    match builder.build() {
        Ok(regex) => Some(regex),
        Err(err) => {
            errors.push(PipelineIssue {
                key: "pipeline.bad_regex",
                args: vec![field.to_string(), err.to_string()],
            });
            None
        }
    }
}

/// What a rename rule rewrites. Keys arrive case-insensitively from feeds
/// (`headerType` / `headertype`), so param lookups ignore case everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RenameTarget {
    Name,
    Host,
    Port,
    /// Parameter key as written in the rule (not lower-cased: `Param.key`
    /// keeps its original spelling for byte-faithful serialization).
    Param(String),
}

impl RenameTarget {
    /// The field the rule rewrites, for the logs.
    fn label(&self) -> String {
        match self {
            RenameTarget::Name => "name".to_string(),
            RenameTarget::Host => "host".to_string(),
            RenameTarget::Port => "port".to_string(),
            RenameTarget::Param(key) => format!("param:{key}"),
        }
    }
}

/// A discard rule: a proxy matching any rule is thrown away entirely. The
/// mirror of [`RenameRule`] minus `replace`, the field is absent on purpose
/// (`deny_unknown_fields` rejects a copy-pasted rewrite rule), a drop rule
/// only selects. An ASN-targeted rule prevents storage entirely — the
/// counterpart of `filter.exclude_asns`, which only hides the stored rows
/// from the output; see [`CompiledDrop::Asn`].
///
/// Two flavours share one rule shape:
/// - regex over `name` / `host` / `port` / `param:KEY` (the rename-style
///   selectors), with `match` + optional `flags`;
/// - ASN list against `target: "asn"`, with `asns` carrying the
///   numbers. The two flavours are mutually exclusive at validation time:
///   `match` is meaningless against an ASN and `asns` is meaningless
///   against a regex.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DropRule {
    /// Regex pattern (regex targets only). Required for every non-ASN
    /// target; must be empty (or absent) for `target == "asn"`.
    #[serde(rename = "match", default, skip_serializing_if = "String::is_empty")]
    pub(crate) match_pattern: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) flags: String,
    /// Selector name: `name` (default), `host`, `port`, `param:KEY`,
    /// or `asn` (see `asns`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<String>,
    /// AS numbers for `target: "asn"`. Accepts both bare (`24940`) and
    /// prefixed (`AS24940`) spellings, normalised at validation. Required
    /// when `target == "asn"`; forbidden otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) asns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GeoStepConfig {
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub(crate) enabled: bool,
    #[serde(
        default = "default_geo_template",
        skip_serializing_if = "is_default_geo_template"
    )]
    pub(crate) template: String,
}

fn default_geo_template() -> String {
    DEFAULT_GEO_TEMPLATE.to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HealthConfig {
    #[serde(
        default = "default_exclude_statuses",
        skip_serializing_if = "is_default_exclude_statuses"
    )]
    pub(crate) exclude_statuses: Vec<String>,
}

/// Default health exclusion: quarantine and removed are hidden
/// from subscriptions unless the pipeline says otherwise.
pub(crate) fn default_exclude_statuses() -> Vec<String> {
    vec!["quarantine".to_string(), "removed".to_string()]
}

/// The accepted-but-ignored `dedup` section, see [`PipelineConfig::dedup`]:
/// any `by` value compiles, v1 deduplication is unconditional.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DedupConfig {
    #[serde(rename = "by")]
    pub(crate) by: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SortConfig {
    #[serde(default = "default_sort_by", skip_serializing_if = "is_default_sort")]
    pub(crate) by: SortBy,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) desc: bool,
}

/// Output-size cap. `count` is a raw JSON number so that fractional or
/// out-of-range input fails with the field-level `pipeline.invalid_limit`
/// error in [`CompiledPipeline::from_json`] instead of an opaque serde
/// type error; `null`/missing means "no cap", the explicit-defaults reset
/// of the profile tri-state. Unlike the other fields, `count` serializes
/// even when `None`: `"count": null` is the explicit no-cap reset the
/// builder emits.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LimitConfig {
    #[serde(default)]
    pub(crate) count: Option<serde_json::Number>,
}

const fn default_sort_by() -> SortBy {
    SortBy::Source
}

/// A rename rule with its regex compiled at validation time.
#[derive(Debug, Clone)]
struct CompiledRename {
    regex: Regex,
    replace: String,
    target: RenameTarget,
}

/// A discard rule with its matcher compiled at validation time. The two
/// variants share one position in [`CompiledPipeline::drop`]: a single
/// pipeline can mix regex rules and ASN rules.
#[derive(Debug, Clone)]
enum CompiledDrop {
    /// Regex over a single `ProxyEntry` field (name / host / port / param).
    Regex { regex: Regex, target: RenameTarget },
    /// Discard when the proxy's resolved AS number is in `asns` — the
    /// "never store" counterpart of the serving-side `filter.exclude_asns`
    /// ("hide", see [`FilterConfig::exclude_asns`]). Missing ASN is not a
    /// hit (the same lenient contract as the exclude list).
    Asn { asns: Vec<u32> },
}

/// A fully validated, ready-to-run pipeline.
#[derive(Debug, Clone)]
pub struct CompiledPipeline {
    filter_protocols: Option<Vec<Scheme>>,
    exclude_protocols: Option<Vec<Scheme>>,
    /// AS numbers to keep; a proxy whose stored ASN is missing from the
    /// list is dropped (the same "confirmed facts only" semantics as the
    /// profile country allowlist).
    filter_asns: Option<Vec<u32>>,
    exclude_asns: Option<Vec<u32>>,
    /// Drop any proxy that allows insecure TLS (a truthy
    /// certificate-verification alias, see
    /// [`fumox_core::models::is_insecure_param`]).
    forbid_insecure: bool,
    rename: Vec<CompiledRename>,
    drop: Vec<CompiledDrop>,
    geo_enabled: bool,
    geo_template: String,
    exclude_statuses: Vec<ProxyStatus>,
    sort_by: SortBy,
    sort_desc: bool,
    /// Output-size cap: keep at most this many proxies of the final list
    /// `None` = no cap.
    limit_count: Option<usize>,
    /// Whether `sort` was set explicitly (used to pick the sort config when
    /// several pipelines are merged: profile wins, then the first source).
    /// Read through [`CompiledPipeline::sort_explicit`].
    sort_explicit: bool,
}

impl Default for CompiledPipeline {
    /// Pass-through pipeline with the defaults: drop
    /// insecure-allowing entries, geo-enrich, drop quarantine/removed,
    /// dedup by fingerprint, keep source order. The hidden statuses are
    /// built from the one [`default_exclude_statuses`] source of truth,
    /// parsed through the same `FromStr` the config path uses.
    fn default() -> Self {
        Self {
            filter_protocols: None,
            exclude_protocols: None,
            filter_asns: None,
            exclude_asns: None,
            forbid_insecure: true,
            rename: Vec::new(),
            drop: Vec::new(),
            geo_enabled: true,
            geo_template: DEFAULT_GEO_TEMPLATE.to_string(),
            exclude_statuses: default_exclude_statuses()
                .iter()
                .map(|raw| ProxyStatus::from_str(raw).expect("default statuses parse"))
                .collect(),
            sort_by: SortBy::Source,
            sort_desc: false,
            limit_count: None,
            sort_explicit: false,
        }
    }
}

/// One pipeline validation problem: a catalog key plus positional `{0}`,
/// `{1}`… arguments. The admin layer renders it with `Lang::t_args` in the
/// panel language (form errors, import validation); the serving layer only
/// logs issues in their debug form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineIssue {
    /// Catalog key (`pipeline.*` section of `locales/*.toml`).
    pub key: &'static str,
    /// Positional arguments: field names and offending values. Embedded
    /// diagnostics (serde/regex details) stay technical English, only the
    /// sentence around them is localized.
    pub args: Vec<String>,
}

impl CompiledPipeline {
    /// Compile a pipeline JSON value, collecting every validation error
    /// (field-level issues for the admin form).
    ///
    /// `NULL` and `{}` mean pass-through with defaults.
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
        // Deserialize straight from the reference: `&serde_json::Value` is
        // itself a `Deserializer` (the admin pipeline editor's ingest
        // works the same way), the document does not need to be cloned.
        let config: PipelineConfig = match serde::Deserialize::deserialize(value) {
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
            compiled.filter_asns = parse_asn_list(&filter.asns, "filter.asns", &mut errors);
            compiled.exclude_asns =
                parse_asn_list(&filter.exclude_asns, "filter.exclude_asns", &mut errors);
            compiled.forbid_insecure = filter.forbid_insecure;
        }

        if let Some(rules) = config.rename {
            for (idx, rule) in rules.iter().enumerate() {
                let field = format!("rename[{idx}]");
                let target = parse_rename_target(&rule.target, &field, &mut errors);
                if let Some(regex) =
                    compile_rule_regex(&rule.match_pattern, &rule.flags, &field, &mut errors)
                    && let Some(target) = target
                {
                    // A literal replacement that is itself an invalid
                    // host/port can only produce invalid values wherever
                    // the rule fires; reject it here, instead of silently
                    // skipping the rewrite for every entry at runtime.
                    // Replacements with capture groups (`$1`, `${name}`)
                    // depend on the matched text and stay exempt.
                    let literal_ok = rule.replace.contains('$')
                        || match &target {
                            RenameTarget::Host => valid_rewritten_host(&rule.replace),
                            RenameTarget::Port => rule.replace.parse::<u16>().is_ok(),
                            _ => true,
                        };
                    if literal_ok {
                        compiled.rename.push(CompiledRename {
                            regex,
                            replace: rule.replace.clone(),
                            target,
                        });
                    } else {
                        errors.push(PipelineIssue {
                            key: if matches!(target, RenameTarget::Host) {
                                "pipeline.never_valid_host"
                            } else {
                                "pipeline.never_valid_port"
                            },
                            args: vec![field, rule.replace.clone()],
                        });
                    }
                }
            }
        }

        if let Some(rules) = config.drop {
            for (idx, rule) in rules.iter().enumerate() {
                let field = format!("drop[{idx}]");
                if rule.target.as_deref() == Some("asn") {
                    // ASN target: `match`/`flags` are meaningless, `asns`
                    // is required and non-empty. Each entry must parse
                    // through `asn_number` (the same normaliser the
                    // serving-side `filter.asns` uses).
                    if !rule.match_pattern.is_empty() || !rule.flags.is_empty() {
                        errors.push(PipelineIssue {
                            key: "pipeline.asn_target_rejects_match",
                            args: vec![field.clone()],
                        });
                    }
                    match &rule.asns {
                        Some(raw) if !raw.is_empty() => {
                            let mut parsed_asns = Vec::with_capacity(raw.len());
                            for raw_asn in raw {
                                match asn_number(raw_asn) {
                                    Some(n) => parsed_asns.push(n),
                                    None => errors.push(PipelineIssue {
                                        key: "pipeline.unknown_asn",
                                        args: vec![field.clone(), raw_asn.clone()],
                                    }),
                                }
                            }
                            if parsed_asns.len() == raw.len() {
                                compiled.drop.push(CompiledDrop::Asn { asns: parsed_asns });
                            }
                        }
                        _ => errors.push(PipelineIssue {
                            key: "pipeline.asn_target_requires_asns",
                            args: vec![field],
                        }),
                    }
                } else {
                    // Regex target: existing machinery, with the extra
                    // guard that `asns` is not allowed here.
                    if rule.asns.is_some() {
                        errors.push(PipelineIssue {
                            key: "pipeline.non_asn_target_rejects_asns",
                            args: vec![field.clone()],
                        });
                    }
                    let target = parse_rename_target(&rule.target, &field, &mut errors);
                    if let Some(regex) =
                        compile_rule_regex(&rule.match_pattern, &rule.flags, &field, &mut errors)
                        && let Some(target) = target
                    {
                        compiled.drop.push(CompiledDrop::Regex { regex, target });
                    }
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
                // An unknown placeholder is rendered verbatim, so the operator
                // would see a literal brace in every proxy name.
                for placeholder in fumox_core::geo::unknown_placeholders(&geo.template) {
                    errors.push(PipelineIssue {
                        key: "pipeline.unknown_placeholder",
                        args: vec![placeholder],
                    });
                }
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

        // `dedup` is accepted and ignored: v1 deduplication is
        // unconditional (see [`PipelineConfig::dedup`]), so every `by`
        // value compiles and no validation error exists for it.

        if let Some(sort) = config.sort {
            compiled.sort_by = sort.by;
            compiled.sort_desc = sort.desc;
            compiled.sort_explicit = true;
        }

        if let Some(limit) = config.limit {
            // `null`/missing keeps the cap unset (the profile's explicit
            // "defaults" reset); an integer of at least 1 is the cap —
            // fractional, zero, negative, or beyond the platform `usize`
            // (also anything the JSON number exceeds `i64` with) is a
            // field error, "no cap" is the absent section, not a magic
            // number.
            match limit.count {
                None => {}
                Some(count) => match count.as_i64().and_then(|n| usize::try_from(n).ok()) {
                    Some(count) if count >= 1 => compiled.limit_count = Some(count),
                    _ => errors.push(PipelineIssue {
                        key: "pipeline.invalid_limit",
                        args: vec![count.to_string()],
                    }),
                },
            }
        }

        if errors.is_empty() {
            Ok(compiled)
        } else {
            Err(errors)
        }
    }

    /// [`Self::from_json`] behind the serving-side compile cache: every
    /// render re-compiles the same merged configs (source + profile), and
    /// the compile rebuilds every regex from scratch. The cache key is the
    /// config's serialized form, so an edited config lands on a different
    /// key by construction. Validation errors are not cached: a broken
    /// config keeps failing fast, and the fixed one recompiles.
    pub fn from_json_cached(
        value: Option<&serde_json::Value>,
    ) -> Result<Arc<Self>, Vec<PipelineIssue>> {
        static CACHE: LazyLock<Mutex<HashMap<u64, Arc<CompiledPipeline>>>> =
            LazyLock::new(|| Mutex::new(HashMap::new()));
        let key = config_cache_key(value);
        if let Some(cached) = CACHE.lock().unwrap().get(&key) {
            return Ok(Arc::clone(cached));
        }
        match Self::from_json(value) {
            Ok(compiled) => {
                let compiled = Arc::new(compiled);
                let mut cache = CACHE.lock().unwrap();
                // The key space is the distinct (source, profile) config
                // pairs, small in practice; reset rather than grow without
                // bound if an installation accumulates thousands of them.
                if cache.len() >= 1024 {
                    cache.clear();
                }
                cache.insert(key, Arc::clone(&compiled));
                Ok(compiled)
            }
            Err(errors) => Err(errors),
        }
    }

    /// Run the full pipeline over candidates already loaded from the DB.
    /// Used by `/src` (single source, one pipeline).
    pub async fn apply(&self, candidates: Vec<Candidate>, geo: &GeoResolver) -> Vec<Candidate> {
        let mut out = self.apply_per_source(candidates, geo).await;
        self.finalize(&mut out);
        out
    }

    /// Per-entry verdicts of the drop rules, in input order. `asns` is the
    /// pre-parsed ASN column (the caller parses the stored `AS{n}` spellings
    /// once at its boundary) and may be shorter than `entries` (inactive
    /// resolver): unstamped entries keep their ASN rules unapplied and
    /// survive, zipping the two would truncate the batch. The mismatch is
    /// a WARN only when the pipeline actually carries an ASN rule — that
    /// is the case where a truncation silently changes what gets dropped —
    /// and DEBUG otherwise.
    fn drop_survivors(
        &self,
        entries: &[ProxyEntry],
        asns: &[Option<u32>],
        source_id: &str,
    ) -> Vec<bool> {
        if asns.len() < entries.len() {
            let message = "drop rules: fewer resolved ASNs than entries, unstamped entries keep their ASN drop rules unapplied";
            if self
                .drop
                .iter()
                .any(|rule| matches!(rule, CompiledDrop::Asn { .. }))
            {
                tracing::warn!(
                    source_id,
                    entries = entries.len(),
                    asns = asns.len(),
                    "{message}"
                );
            } else {
                tracing::debug!(
                    source_id,
                    entries = entries.len(),
                    asns = asns.len(),
                    "{message}"
                );
            }
        }
        entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                let asn = asns.get(idx).copied().flatten();
                !self
                    .drop
                    .iter()
                    .any(|rule| drop_rule_hits(rule, entry, asn))
            })
            .collect()
    }

    /// Drop rules, keeping every surviving entry paired with its own geo
    /// stamp. The ASNs arrive pre-parsed (`asns`, the caller's boundary);
    /// `facts` is the stamp column the ingest path persists *and* keeps
    /// index-aligned, and `reconcile_source` pairs the two by index:
    /// returning the survivors alone would silently re-point every stamp
    /// after the first dropped entry at a host one or more positions
    /// earlier, stamping proxies with another host's country and ASN.
    pub fn drop_entries_with_geo(
        &self,
        entries: Vec<ProxyEntry>,
        asns: &[Option<u32>],
        facts: &[Option<fumox_core::repo::proxies::GeoStamp>],
        source_id: &str,
    ) -> (
        Vec<ProxyEntry>,
        Vec<Option<fumox_core::repo::proxies::GeoStamp>>,
    ) {
        if self.drop.is_empty() {
            return (entries, facts.to_vec());
        }
        let survivors = self.drop_survivors(&entries, asns, source_id);
        let mut kept_entries = Vec::with_capacity(entries.len());
        let mut kept_facts = Vec::with_capacity(entries.len());
        for (idx, entry) in entries.into_iter().enumerate() {
            if survivors[idx] {
                kept_entries.push(entry);
                kept_facts.push(facts.get(idx).cloned().flatten());
            }
        }
        (kept_entries, kept_facts)
    }

    /// Whether any `drop` rule is configured. Reconciliation asks before a
    /// fetch: a source with drop rules never keeps lingering
    /// links, so a rule added later cannot be held off by still-alive rows ,
    /// serving-side drop hides them instantly, the next refresh unlinks
    /// them for good.
    pub fn has_drop_rules(&self) -> bool {
        !self.drop.is_empty()
    }

    /// Whether `sort` was set explicitly: the sort contest over the merged
    /// profile reads it (profile wins, then the first source that set one).
    pub fn sort_explicit(&self) -> bool {
        self.sort_explicit
    }

    /// Per-source steps: filter → normalize → rename →
    /// geo-enrich → health-filter. `/sub` runs this for every source with
    /// the merged (source + profile) pipeline, then calls [`Self::finalize`]
    /// once on the merged result.
    pub async fn apply_per_source<G: HostGeo + ?Sized>(
        &self,
        mut candidates: Vec<Candidate>,
        geo: &G,
    ) -> Vec<Candidate> {
        // filter
        if self.filter_protocols.is_some() || self.exclude_protocols.is_some() {
            let before = candidates.len();
            if let Some(allowed) = &self.filter_protocols {
                candidates.retain(|c| allowed.contains(&c.entry.scheme));
            }
            if let Some(excluded) = &self.exclude_protocols {
                candidates.retain(|c| !excluded.contains(&c.entry.scheme));
            }
            log_filter_step("protocols", before, candidates.len());
        }
        // Every step below reads `candidate.geo_asn`, which a row ingested
        // without geo does not carry: complete it before they run. Only the
        // ASN rules need it, so a pipeline without them pays no geo lookup
        // per request; the missing ASNs are filled on the ingest side.
        let needs_asn = self.filter_asns.is_some()
            || self.exclude_asns.is_some()
            || self
                .drop
                .iter()
                .any(|rule| matches!(rule, CompiledDrop::Asn { .. }));
        if needs_asn {
            fill_missing_asns(&mut candidates, geo).await;
        }
        // AS-number filter: the stored ASN, or the one the fill just
        // resolved, is the confirmed fact, the same contract as the
        // profile country allowlist.
        // An allowlist drops proxies without a resolved ASN; an exclude
        // list only removes the named ASNs and keeps the unresolved ones.
        if self.filter_asns.is_some() || self.exclude_asns.is_some() {
            let before = candidates.len();
            if let Some(allowed) = &self.filter_asns {
                candidates.retain(|c| c.geo_asn.is_some_and(|asn| allowed.contains(&asn)));
            }
            if let Some(excluded) = &self.exclude_asns {
                candidates.retain(|c| c.geo_asn.is_none_or(|asn| !excluded.contains(&asn)));
            }
            log_filter_step("asns", before, candidates.len());
        }

        // filter.forbid_insecure, drop proxies that allow insecure TLS in
        // any spelling. Falsy toggles (`insecure=0`) and
        // alias-free entries survive; the DB row is never touched.
        if self.forbid_insecure {
            let before = candidates.len();
            Self::retain_secure(&mut candidates);
            log_filter_step("forbid_insecure", before, candidates.len());
        }

        // drop, discard rules. Deliberately before
        // `rename`: both this serving-side pass and the ingestion-side one
        // must see the original values, or the two would disagree; a
        // rewrite must never decide whether a proxy is stored. Any rule
        // matching discards the proxy (rules are OR-ed). ASN-targeted rules
        // use the candidate's typed `geo_asn`; missing ASN is not a hit
        // (the same lenient contract as `filter.exclude_asns`).
        if !self.drop.is_empty() {
            let before = candidates.len();
            candidates.retain(|c| {
                !self
                    .drop
                    .iter()
                    .any(|rule| drop_rule_hits(rule, &c.entry, c.geo_asn))
            });
            log_filter_step("drop", before, candidates.len());
        }

        // rename, rules apply in order. A rule's `target` picks the field:
        // the name (default, the classic behavior), the host, the port or a
        // parameter. Host/port results are guarded: a replacement that
        // would break the URI structure (empty host, non-numeric or
        // out-of-range port, URI delimiters in the host) is skipped with a
        // WARN, leaving the original intact, a broken rule must not
        // produce a broken subscription line for every proxy at once.
        //
        // The skips are counted per rule and reported once per rule: the
        // per-entry event stays at TRACE, a broken rule would otherwise
        // write a WARN line per proxy.
        let mut skips: Vec<SkippedRewrites> = vec![SkippedRewrites::default(); self.rename.len()];
        for candidate in &mut candidates {
            for (idx, rule) in self.rename.iter().enumerate() {
                if let Rewrite::Rejected(value) = apply_rename_rule(&mut candidate.entry, rule) {
                    skips[idx].record(value);
                }
            }
        }
        for (idx, (rule, skip)) in self.rename.iter().zip(&skips).enumerate() {
            if skip.count > 0 {
                tracing::warn!(
                    rule = idx,
                    target = %rule.target.label(),
                    skipped = skip.count,
                    value = %skip.example,
                    "rename rule produced an invalid value, the original is kept"
                );
            }
        }

        // filter.forbid_insecure, again: the filter must see the final
        // parameters, a rename rule can introduce an insecure switch.
        if self.forbid_insecure {
            let before = candidates.len();
            Self::retain_secure(&mut candidates);
            log_filter_step("forbid_insecure", before, candidates.len());
        }

        // geo-enrich, rewrite the display name from the template and keep
        // the country code for sorting. No-op when the resolver is inactive.
        // The hosts resolve with bounded parallelism (a slow host must not
        // stall the whole pass) and under one wall-clock ceiling, like the
        // ingest pass; on expiry the names stay as stored. The lookups are
        // boxed futures collected up front, so no borrow of the generic
        // resolver rides the stream across the await — the boxes stay
        // `Send` whatever they borrow.
        if self.geo_enabled && geo.is_active() {
            use futures_util::StreamExt;
            let lookups: Vec<_> = candidates
                .iter()
                .map(|c| geo.resolve_host(&c.entry.host))
                .collect();
            let resolved = tokio::time::timeout(
                GEO_PASS_TIMEOUT,
                futures_util::stream::iter(lookups)
                    .buffered(GEO_LOOKUP_CONCURRENCY)
                    .collect::<Vec<Option<_>>>(),
            )
            .await;
            match resolved {
                Ok(infos) => {
                    for (candidate, info) in candidates.iter_mut().zip(infos) {
                        if let Some(info) = info {
                            let renamed =
                                apply_template(&self.geo_template, &info, &candidate.entry.name);
                            candidate.entry.name = renamed;
                            candidate.geo_country = info.country_code.clone();
                        }
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_secs = GEO_PASS_TIMEOUT.as_secs(),
                        "geo-enrich exceeded the pass budget; the names stay as stored"
                    );
                }
            }
        }

        // health-filter, defensive re-check; the serving layer can load
        // every status and rely on this step for exclusion.
        let excluded: HashSet<ProxyStatus> = self.exclude_statuses.iter().copied().collect();
        let before = candidates.len();
        candidates.retain(|c| !excluded.contains(&c.status));
        log_filter_step("health", before, candidates.len());

        candidates
    }

    /// Drop the candidates that allow insecure TLS in any spelling: a
    /// truthy certificate-verification alias. Falsy toggles (`insecure=0`)
    /// and alias-free entries survive.
    fn retain_secure(candidates: &mut Vec<Candidate>) {
        candidates.retain(|c| {
            !c.entry
                .params
                .iter()
                .any(fumox_core::models::is_insecure_param)
        });
    }

    /// Post-merge steps: dedup by fingerprint, the first
    /// occurrence wins, so the earlier source keeps the name it contributed ,
    /// followed by the global sort. Speed-enrich is a stub until Phase 4:
    /// latency comes from probe results already stored on the row.
    pub fn finalize(&self, candidates: &mut Vec<Candidate>) {
        let mut seen = HashSet::new();
        let before = candidates.len();
        candidates.retain(|c| seen.insert(c.entry.fingerprint()));
        log_filter_step("dedup", before, candidates.len());
        self.sort(candidates);
        // Output cap: applied after dedup and sorting, so
        // the list keeps its top in the chosen order, `sort: latency`
        // yields the N fastest, `sort: source` the first N of the feed.
        if let Some(limit) = self.limit_count {
            let before = candidates.len();
            candidates.truncate(limit);
            log_filter_step("limit", before, candidates.len());
        }
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
                // Unknown countries always go last, ascending or
                // descending: an absent fact is not a country code (the
                // same contract as the NULL latency below), so the
                // reversal rides the country comparison, not the
                // known/unknown placement.
                candidates.sort_by(|a, b| match (&a.geo_country, &b.geo_country) {
                    (Some(x), Some(y)) => {
                        let ord = x.cmp(y);
                        if self.sort_desc { ord.reverse() } else { ord }
                    }
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                });
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

/// Wall-clock ceiling for one geo-enrich pass: every uncached host can
/// cost a DNS round-trip, so the batch is bounded in time as well as in
/// concurrency (the same contract as the ingest pass). On expiry the
/// names stay as stored instead of blocking the render.
const GEO_PASS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Give every candidate without a stored ASN the one the resolver can
/// name now: an exclude list keeps what it cannot name, and the resolver
/// caches an "unknown" verdict per host, so a row whose column stayed
/// empty keeps reaching the output even when its host resolves fine.
///
/// The lookup is a cache hit (geo-enrich resolves the same hosts a few
/// lines down), a stored ASN is never overwritten, and this runs before
/// `rename`, so the ASN belongs to the host as stored.
async fn fill_missing_asns<G: HostGeo + ?Sized>(candidates: &mut [Candidate], geo: &G) {
    for candidate in candidates.iter_mut() {
        if candidate.geo_asn.is_some() {
            continue;
        }
        if let Some(info) = geo.resolve_host(&candidate.entry.host).await
            && let Some(asn) = info.asn
        {
            candidate.geo_asn = Some(asn);
        }
    }
}

/// The profile-level country allowlist as one filtering step, the matcher
/// `/sub` applies per source. It runs *before* the pipeline's own steps
/// (`CompiledPipeline::apply`): the allowlist is about confirmed geo facts,
/// not a pipeline rule, so it also runs on the tiers the live-filter would
/// drop later, and its own order is fixed — proxies without a determined
/// country stay out while the filter is active, "only these countries"
/// means confirmed facts, not guesses (the same semantics as
/// `filter_asns`). The country codes come in pre-normalized (uppercase).
pub(crate) fn retain_allowed_countries(
    candidates: &mut Vec<Candidate>,
    allowed: &std::collections::HashSet<String>,
) {
    candidates.retain(|c| {
        c.geo_country
            .as_deref()
            .is_some_and(|code| allowed.contains(&code.to_ascii_uppercase()))
    });
}

/// Merge a source pipeline with the profile override: the profile's
/// top-level sections replace the source's.
pub fn merge_configs(
    source: Option<&serde_json::Value>,
    profile: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    match (source, profile) {
        (None, None) => None,
        (Some(s), None) | (None, Some(s)) => Some(s.clone()),
        (Some(s), Some(p)) => {
            // A `NULL` profile pipeline overrides nothing: the source's
            // sections stay in place. Without this the profile's `null`
            // would replace every section with "nothing configured".
            if *p == serde_json::Value::Null {
                return Some(s.clone());
            }
            let (Some(s_map), Some(p_map)) = (s.as_object(), p.as_object()) else {
                // Non-object configs are invalid, so the merged result
                // fails `from_json` one way or another. The profile side
                // wins, its form gets the error; when the source is the
                // non-object one while the profile is a valid object, a
                // WARN names the source config as the broken side.
                if p.as_object().is_some() {
                    tracing::warn!(
                        source = %s,
                        "pipeline merge: the source config is not an object, \
                         the profile's object replaces it"
                    );
                }
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

/// The outcome of one rewrite: the value was applied, or it was rejected
/// and the original stayed. The rejected value travels back to the caller,
/// which counts the skips per rule instead of logging one line per entry.
enum Rewrite {
    Applied,
    Rejected(String),
}

/// The rejected rewrites of one rule: how many entries kept their original
/// and one example of the rejected value, truncated for the log.
#[derive(Clone, Default)]
struct SkippedRewrites {
    count: usize,
    example: String,
}

impl SkippedRewrites {
    fn record(&mut self, value: String) {
        self.count += 1;
        if self.example.is_empty() {
            self.example = truncate_for_log(&value);
        }
    }
}

/// A log value is truncated: a rejected rewrite can be a whole proxy name,
/// not a field the log has to carry in full.
fn truncate_for_log(value: &str) -> String {
    const LIMIT: usize = 128;
    if value.chars().count() <= LIMIT {
        return value.to_string();
    }
    let mut out: String = value.chars().take(LIMIT).collect();
    out.push('…');
    out
}

/// Whether a drop rule's regex matches its target on the entry. The same
/// selector semantics as [`apply_rename_rule`]: the raw (percent-encoded)
/// stored form, the first parameter on a case-insensitive key. A proxy that
/// matches anywhere is discarded whole, the rule never rewrites anything.
fn matches_target(entry: &ProxyEntry, regex: &Regex, target: &RenameTarget) -> bool {
    match target {
        RenameTarget::Name => regex.is_match(&entry.name),
        RenameTarget::Host => regex.is_match(&entry.host),
        RenameTarget::Port => regex.is_match(&entry.port.to_string()),
        RenameTarget::Param(key) => entry
            .params
            .iter()
            .any(|p| p.key.eq_ignore_ascii_case(key) && regex.is_match(&p.value)),
    }
}

/// Whether one drop rule hits this entry — the single evaluation both drop
/// passes share. The ASN source stays with the caller: the ingest pass
/// reads the pre-parsed stamp column, the serving pass reads the
/// candidate's typed `geo_asn`; a missing ASN is not a hit (the same
/// lenient contract as `filter.exclude_asns`).
fn drop_rule_hits(rule: &CompiledDrop, entry: &ProxyEntry, asn: Option<u32>) -> bool {
    match rule {
        CompiledDrop::Regex { regex, target } => matches_target(entry, regex, target),
        CompiledDrop::Asn { asns } => asn.is_some_and(|n| asns.contains(&n)),
    }
}

/// One filtering step's bookkeeping: a DEBUG event with the in/out counts
/// and the removals, so a subscription that shrank can be traced to the
/// step that shrank it, plus a WARN when the step emptied a non-empty
/// input — a misconfigured rule must not quietly blank the feed.
fn log_filter_step(step: &str, before: usize, after: usize) {
    tracing::debug!(
        step,
        in = before,
        out = after,
        removed = before.saturating_sub(after),
        "pipeline filtering step"
    );
    if before > 0 && after == 0 {
        tracing::warn!(
            step,
            removed = before,
            "pipeline step removed every entry of a non-empty input"
        );
    }
}

/// Apply one rename rule to a proxy entry according to its target.
///
/// Parameter values are stored percent-encoded (byte-faithful round-trip,
/// models.rs `Param.value`); the regex matches that raw form, exactly what
/// the admin sees in the URI, and the replacement is stored raw as well.
/// This keeps `path=%2Fws` rewritable through its encoded spelling only,
/// which is the honest, predictable contract (documented in USERGUIDE).
fn apply_rename_rule(entry: &mut ProxyEntry, rule: &CompiledRename) -> Rewrite {
    let rewritten = |value: &str| -> String {
        rule.regex
            .replace_all(value, rule.replace.as_str())
            .into_owned()
    };
    match &rule.target {
        RenameTarget::Name => {
            entry.name = rewritten(&entry.name);
            Rewrite::Applied
        }
        RenameTarget::Host => {
            let host = rewritten(&entry.host);
            // The host is embedded verbatim into the output URI, so it
            // cannot carry the URI delimiters or whitespace. IPv6 literals
            // stay bracket-free in storage (parse_hostport strips them).
            if valid_rewritten_host(&host) {
                entry.host = host;
                Rewrite::Applied
            } else {
                tracing::trace!(
                    host = %host,
                    fingerprint = entry.fingerprint(),
                    "rename rule produced an invalid host, keeping the original"
                );
                Rewrite::Rejected(host)
            }
        }
        RenameTarget::Port => {
            let port = rewritten(&entry.port.to_string());
            match port.parse::<u16>() {
                // Port 0 is not a dialable endpoint: the parsers drop it and
                // the schema CHECK (migration 0018) refuses the row at the
                // upsert, so a rewrite that produced one is rejected like a
                // junk value instead of failing the whole ingest batch.
                Ok(parsed) if parsed != 0 => {
                    entry.port = parsed;
                    Rewrite::Applied
                }
                _ => {
                    tracing::trace!(
                        port = %port,
                        fingerprint = entry.fingerprint(),
                        "rename rule produced an invalid port, keeping the original"
                    );
                    Rewrite::Rejected(port)
                }
            }
        }
        RenameTarget::Param(key) => {
            // Case-insensitive: feeds mix spellings (headerType/headertype).
            // Only the first occurrence is rewritten, the parser also keeps
            // the first on re-parse, so a rewritten later duplicate would be
            // silently dropped at the next ingest round-trip anyway.
            let Some(param) = entry
                .params
                .iter_mut()
                .find(|p| p.key.eq_ignore_ascii_case(key))
            else {
                return Rewrite::Applied;
            };
            param.value = rewritten(&param.value);
            Rewrite::Applied
        }
    }
}

/// A rewritten host must survive the output URI verbatim: non-empty, no
/// URI delimiters, no whitespace, no percent-encoding (the host is not
/// encoded by the serializer, so a raw `%` would corrupt the address).
/// A colon is legal only as part of an IPv6 literal, hosts are stored
/// unbracketed (`2001:db8::1`), so a colon-bearing rewrite must parse as
/// a plain IPv6 address, not smuggle a port or userinfo in.
fn valid_rewritten_host(host: &str) -> bool {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && !host.contains(|c: char| {
            matches!(c, '/' | '?' | '#' | '@' | '[' | ']' | ':' | '%') || c.is_whitespace()
        })
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

/// The AS number carried by a stored `geo_asn` value (`"AS24940"`), or any
/// `AS{n}` / `24940` spelling accepted from a pipeline config. `pub(crate)`
/// because the DB boundaries (`rows_to_candidates`, the ingest drop pass)
/// parse the column exactly once, on their side.
pub(crate) fn asn_number(raw: &str) -> Option<u32> {
    let digits = raw
        .trim()
        .strip_prefix("AS")
        .or_else(|| raw.trim().strip_prefix("as"))
        .unwrap_or(raw.trim());
    digits.parse::<u32>().ok()
}

/// Validate an ASN list field (`filter.asns` / `filter.exclude_asns`):
/// every entry must be a plain AS number, bare (`24940`) or with the `AS`
/// prefix (`AS24940`). Like [`parse_scheme_list`], `None` means "not set"
/// while an empty array stays empty, an allowlist that keeps nothing.
fn parse_asn_list(
    raw: &Option<Vec<String>>,
    field: &str,
    errors: &mut Vec<PipelineIssue>,
) -> Option<Vec<u32>> {
    let Some(raw) = raw else {
        return None;
    };
    let mut asns = Vec::new();
    for value in raw {
        match asn_number(value) {
            Some(asn) => asns.push(asn),
            None => errors.push(PipelineIssue {
                key: "pipeline.unknown_asn",
                args: vec![field.to_string(), value.clone()],
            }),
        }
    }
    Some(asns)
}

/// One proxy on its way through the pipeline: the entry plus the DB-side
/// context the steps need (status, latency, source order, stored geo).
#[derive(Debug, Clone)]
pub struct Candidate {
    pub entry: ProxyEntry,
    /// `profile_sources.position`, the source order inside the profile.
    pub source_position: i64,
    pub status: ProxyStatus,
    pub latency_ms: Option<i64>,
    /// Country code stored on the proxy row by earlier enrichment.
    pub geo_country: Option<String>,
    /// Autonomous system stored on the proxy row, parsed to its number
    /// once at the DB boundary (`rows_to_candidates`); the filters and
    /// drop rules compare plain numbers, never `AS{n}` strings.
    pub geo_asn: Option<u32>,
}

/// The [`CompiledPipeline::from_json_cached`] cache key: the config's
/// serialized bytes. Identical documents serialize identically, any edit
/// produces different bytes, and a missing config keys apart from an
/// empty one.
fn config_cache_key(value: Option<&serde_json::Value>) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match value {
        None => None::<u8>.hash(&mut hasher),
        Some(value) => serde_json::to_vec(value)
            .expect("serializing a serde_json::Value cannot fail")
            .hash(&mut hasher),
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::geo::GeoInfo;
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
                canonical: None,
            },
            source_position: 0,
            status: ProxyStatus::Unknown,
            latency_ms: None,
            geo_country: None,
            geo_asn: None,
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

    /// The mmdb-backed resolver the geo tests share, or `None` when the
    /// GeoLite2 files are absent (gitignored, so a fresh checkout has
    /// none): the caller skips instead of testing a disabled resolver.
    /// The tests are also marked `#[ignore = "requires GeoLite2 mmdb"]`,
    /// so the skip is explicit even before this guard runs.
    fn active_geo_with_dbs() -> Option<GeoResolver> {
        let db_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config");
        if !db_dir.join("GeoLite2-ASN.mmdb").exists() || !db_dir.join("GeoLite2-City.mmdb").exists()
        {
            eprintln!("skipped: GeoLite2-ASN/City.mmdb not present");
            return None;
        }
        let geo = GeoResolver::new(&fumox_core::config::GeoConfig {
            enabled: true,
            db_dir,
            ..Default::default()
        });
        assert!(geo.is_active());
        Some(geo)
    }

    /// Capture log lines of one scope at `max` level and above: the
    /// observability assertions read them back instead of matching on
    /// internals. Returns the buffer and the subscriber guard, which must
    /// stay alive for the capture to run.
    fn capture_logs(
        max: tracing::Level,
    ) -> (
        std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        tracing::subscriber::DefaultGuard,
    ) {
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
            .with_max_level(max)
            .with_writer(move || Captured(std::sync::Arc::clone(&make_writer)))
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (captured, guard)
    }

    #[test]
    fn null_and_empty_configs_compile_to_defaults() {
        assert!(CompiledPipeline::from_json(None).is_ok());
        assert!(CompiledPipeline::from_json(Some(&json!(null))).is_ok());
        assert!(CompiledPipeline::from_json(Some(&json!({}))).is_ok());
        let compiled = CompiledPipeline::from_json(None).unwrap();
        assert_eq!(
            compiled.exclude_statuses,
            vec![ProxyStatus::Quarantine, ProxyStatus::Removed]
        );
        // No `sort` section: source order is the default, not a choice.
        assert!(!compiled.sort_explicit());
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

    /// A JSON without the `version` key takes the serde default (`0`),
    /// which fails the same localized `pipeline.version` check as any
    /// other wrong value, instead of the opaque serde type error.
    #[test]
    fn a_missing_version_is_a_pipeline_version_error() {
        let err = CompiledPipeline::from_json(Some(&json!({ "filter": {} }))).unwrap_err();
        assert_eq!(err[0].key, "pipeline.version");
        assert_eq!(err[0].args, vec!["0"]);
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

    /// An unknown placeholder is rendered verbatim, so the operator would
    /// see a literal brace in every proxy name: it is a field error.
    #[test]
    fn an_unknown_geo_placeholder_is_rejected() {
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "geo": { "enabled": true, "template": "{flag} {country} {foo} {name}" }
        })))
        .unwrap_err();
        assert!(
            err.iter()
                .any(|e| e.key == "pipeline.unknown_placeholder" && e.args.contains(&"foo".into())),
            "{err:?}"
        );
    }

    /// The known placeholders are accepted.
    #[test]
    fn the_known_geo_placeholders_are_accepted() {
        CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "geo": { "enabled": true, "template": "{flag} {country} {city} {asn} {asn_org} {name}" }
        })))
        .unwrap();
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

    /// The `dedup` section is accepted and ignored: v1 deduplication is
    /// unconditional (by fingerprint), so any `by` value compiles and real
    /// modes arrive in v2 — old exports keep importing either way.
    #[test]
    fn the_dedup_section_is_accepted_and_ignored() {
        for by in ["fingerprint", "name"] {
            CompiledPipeline::from_json(Some(&json!({
                "version": 1,
                "dedup": { "by": by }
            })))
            .unwrap_or_else(|errors| panic!("dedup.by={by} must compile: {errors:?}"));
        }
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

    #[test]
    fn rename_target_must_be_known() {
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": "a", "replace": "b", "target": "bogus" }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.unknown_target");
        assert_eq!(err[0].args[0], "rename[0]");
        assert_eq!(err[0].args[1], "bogus");

        // `param:` with an empty key is the same unknown-form error.
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": "a", "replace": "b", "target": "param: " }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.unknown_target");

        // The four valid spellings (and the absent target) compile. The
        // replacement must be a valid literal of its target: `1` for the
        // port, a plain word for the rest.
        for (target, replace) in [
            (None, "b"),
            (Some("name"), "b"),
            (Some("host"), "b"),
            (Some("port"), "1"),
            (Some("param:fp"), "b"),
        ] {
            let mut rule = json!({ "match": "a", "replace": replace });
            if let Some(target) = target {
                rule["target"] = json!(target);
            }
            assert!(
                CompiledPipeline::from_json(Some(&json!({
                    "version": 1,
                    "rename": [rule]
                })))
                .is_ok()
            );
        }
    }

    fn candidate_with_params(name: &str, host: &str, port: u16, params: Vec<Param>) -> Candidate {
        let mut c = candidate(name, Scheme::Vless, host);
        c.entry.port = port;
        c.entry.params = params;
        c
    }

    /// A candidate carrying stored geo facts, as `rows_to_candidates`
    /// loads them from the DB (the `AS{n}` column parsed to its number at
    /// the boundary). The host is derived from the name so the candidates
    /// differ by fingerprint and survive `finalize`'s dedup.
    fn candidate_with_asn(name: &str, asn: Option<u32>) -> Candidate {
        let mut c = candidate(name, Scheme::Vless, &format!("{name}.example.com"));
        c.geo_asn = asn;
        c
    }

    /// Build a `ProxyEntry` for ingestion-side tests: scheme is fixed,
    /// credential too, the drop rules only look at the chosen fields.
    fn entry(name: &str, host: &str) -> ProxyEntry {
        candidate(name, Scheme::Vless, host).entry
    }

    #[tokio::test]
    async fn asns_allowlist_keeps_only_listed_and_drops_unresolved() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "asns": ["24940", "AS13335"] }
        })))
        .unwrap();
        let candidates = vec![
            candidate_with_asn("hetzner", Some(24940)),
            candidate_with_asn("cloudflare", Some(13335)),
            candidate_with_asn("other", Some(9009)),
            candidate_with_asn("unresolved", None),
        ];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, ["hetzner", "cloudflare"]);
    }

    #[tokio::test]
    async fn exclude_asns_drops_listed_and_keeps_unresolved() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "exclude_asns": ["AS24940"] }
        })))
        .unwrap();
        let candidates = vec![
            candidate_with_asn("hetzner", Some(24940)),
            candidate_with_asn("other", Some(9009)),
            candidate_with_asn("unresolved", None),
        ];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, ["other", "unresolved"]);
    }

    /// The one resolver fake of the pipeline tests, standing in for the
    /// shared [`HostGeo`] seam: it answers one ASN for every host (per-host
    /// overrides first), counts its lookups, tracks how many ran
    /// concurrently, and can report itself inactive — everything the fill,
    /// the exclude list and the geo-enrich assertions need without a
    /// MaxMind database.
    #[derive(Default)]
    struct FakeGeo {
        /// The blanket answer for hosts without a `by_host` override.
        asn: Option<u32>,
        /// Per-host answers, consulted first.
        by_host: std::collections::HashMap<&'static str, u32>,
        active: bool,
        calls: std::sync::atomic::AtomicUsize,
        in_flight: std::sync::atomic::AtomicUsize,
        peak: std::sync::atomic::AtomicUsize,
        sleep_ms: u64,
    }

    impl FakeGeo {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn peak(&self) -> usize {
            self.peak.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl HostGeo for FakeGeo {
        fn is_active(&self) -> bool {
            self.active
        }

        fn resolve_host<'a>(
            &'a self,
            host: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Arc<GeoInfo>>> + Send + 'a>>
        {
            let asn = self.by_host.get(host).copied().or(self.asn);
            let sleep_ms = self.sleep_ms;
            Box::pin(async move {
                self.calls
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // The counter moves inside the future, on its first poll:
                // building a future starts no work, so the peak reflects
                // lookups actually running, not ones merely created.
                let running = self
                    .in_flight
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                self.peak
                    .fetch_max(running, std::sync::atomic::Ordering::Relaxed);
                if sleep_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
                }
                self.in_flight
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                asn.map(|asn| {
                    Arc::new(GeoInfo {
                        asn: Some(asn),
                        ..Default::default()
                    })
                })
            })
        }
    }

    /// The fill writes the canonical `AS{n}` spelling the filters parse, and
    /// only where there is nothing stored to write over.
    #[tokio::test]
    async fn the_fill_names_a_candidate_that_carries_no_asn() {
        let mut candidates = vec![
            candidate_with_asn("missing", None),
            candidate_with_asn("stored", Some(24940)),
        ];
        fill_missing_asns(
            &mut candidates,
            &FakeGeo {
                asn: Some(13335),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(candidates[0].geo_asn, Some(13335));
    }

    /// The stored ASN is the confirmed fact, never overwritten by a lookup
    /// that would disagree.
    #[tokio::test]
    async fn the_fill_never_overwrites_a_stored_asn() {
        let mut candidates = vec![candidate_with_asn("stored", Some(24940))];
        fill_missing_asns(
            &mut candidates,
            &FakeGeo {
                asn: Some(13335),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(candidates[0].geo_asn, Some(24940));
    }

    /// A resolver with no ASN to give (City-only install, or a range the ASN
    /// database does not cover) changes nothing rather than inventing one.
    #[tokio::test]
    async fn a_resolver_without_an_asn_changes_nothing() {
        let mut candidates = vec![candidate_with_asn("no-asn", None)];
        fill_missing_asns(&mut candidates, &FakeGeo::default()).await;
        assert_eq!(candidates[0].geo_asn, None);
    }

    /// The reported failure: the exclude list was honoured for every row
    /// whose ingest stamped an ASN and silently kept the rest, while
    /// geo-enrich printed the excluded AS in the output name. The fake
    /// resolver covers the mechanics without a database; the mmdb variant
    /// below exercises the real resolver end to end.
    #[tokio::test]
    async fn the_exclude_list_drops_a_resolved_asn_without_a_stored_one() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "exclude_asns": ["13335"] },
            // Geo enrichment off: the names stay as stored, the assertion
            // reads them back verbatim.
            "geo": { "enabled": false }
        })))
        .unwrap();
        let geo = FakeGeo {
            by_host: std::collections::HashMap::from([("1.1.1.1", 13335), ("8.8.8.8", 15169)]),
            ..Default::default()
        };
        // Neither candidate carries a stored ASN: the exclude list acts on
        // the ASN the fill just resolved.
        let out = compiled
            .apply_per_source(
                vec![
                    candidate("cloudflare", Scheme::Vless, "1.1.1.1"),
                    candidate("google", Scheme::Vless, "8.8.8.8"),
                ],
                &geo,
            )
            .await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, ["google"], "only the excluded AS is dropped");
    }

    /// The same exclusion against the real resolver: 1.1.1.1 is AS13335
    /// (excluded), 8.8.8.8 is AS15169, and neither candidate carries a
    /// stored ASN.
    #[tokio::test]
    #[ignore = "requires GeoLite2 mmdb"]
    async fn a_proxy_without_a_stored_asn_still_honours_the_exclude_list() {
        let Some(geo) = active_geo_with_dbs() else {
            return;
        };

        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "exclude_asns": ["13335"] },
            "geo": { "enabled": true, "template": "{asn} {name}" }
        })))
        .unwrap();
        let out = compiled
            .apply(
                vec![
                    candidate("cloudflare", Scheme::Vless, "1.1.1.1"),
                    candidate("google", Scheme::Vless, "8.8.8.8"),
                ],
                &geo,
            )
            .await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, ["AS15169 google"], "only the excluded AS is dropped");
    }

    #[test]
    fn invalid_asn_entries_are_rejected_with_field_errors() {
        let errors = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "asns": ["24940", "bogus"], "exclude_asns": ["hetzner"] }
        })))
        .unwrap_err();
        assert_eq!(errors[0].key, "pipeline.unknown_asn");
        assert_eq!(errors[0].args, ["filter.asns", "bogus"]);
        assert_eq!(errors[1].key, "pipeline.unknown_asn");
        assert_eq!(errors[1].args, ["filter.exclude_asns", "hetzner"]);
    }

    #[test]
    fn empty_asns_allowlist_keeps_nothing_and_compiles() {
        // An explicit empty allowlist means "output nothing", a real
        // config, kept (the editor routes it to raw mode).
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "asns": [] }
        })))
        .unwrap();
        assert!(compiled.filter_asns.as_ref().is_some_and(|a| a.is_empty()));
    }

    #[tokio::test]
    async fn rename_rewrites_param_host_and_port() {
        // The rule set from the design: name rewrite plus the parameter,
        // host and port targets.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [
                { "match": "server1", "replace": "server2", "target": "name" },
                { "match": "^chrome$", "replace": "firefox", "target": "param:fp" },
                { "match": "server1\\.tr$", "replace": "invalid.tr", "target": "host" },
                { "match": "^123$", "replace": "456", "target": "port" }
            ]
        })))
        .unwrap();
        let candidates = vec![candidate_with_params(
            "server1",
            "server1.tr",
            123,
            vec![
                Param {
                    key: "fp".into(),
                    value: "chrome".into(),
                    known: true,
                    bare: false,
                },
                Param {
                    key: "sni".into(),
                    value: "s.example.com".into(),
                    known: true,
                    bare: false,
                },
            ],
        )];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.name, "server2");
        assert_eq!(out[0].entry.host, "invalid.tr");
        assert_eq!(out[0].entry.port, 456);
        assert_eq!(out[0].entry.params[0].value, "firefox");
        // An untouched parameter keeps its value.
        assert_eq!(out[0].entry.params[1].value, "s.example.com");
    }

    #[tokio::test]
    async fn rename_param_target_matches_case_insensitive_first_occurrence() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": "ws$", "replace": "wss", "target": "param:path", "flags": "i" }]
        })))
        .unwrap();
        let candidates = vec![candidate_with_params(
            "n",
            "h.example.com",
            443,
            vec![
                // Feeds mix spellings; the rule key must match them all.
                Param {
                    key: "path".into(),
                    value: "/ws".into(),
                    known: true,
                    bare: false,
                },
                Param {
                    key: "PATH".into(),
                    value: "/other".into(),
                    known: true,
                    bare: false,
                },
            ],
        )];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.params[0].value, "/wss");
        assert_eq!(out[0].entry.params[1].value, "/other");
    }

    #[tokio::test]
    async fn rename_host_target_guards_invalid_results() {
        // A literal replacement that is never a valid host is a
        // compile-time field error: wherever the rule fires, the rewrite
        // would be invalid and silently skipped.
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": ".*", "replace": "evil.tr/../../x", "target": "host" }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.never_valid_host");
        assert_eq!(err[0].args, ["rename[0]", "evil.tr/../../x"]);

        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": ".*", "replace": "", "target": "host" }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.never_valid_host");

        // "99999" is a valid host in shape: it compiles and rewrites.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": ".*", "replace": "99999", "target": "host" }]
        })))
        .unwrap();
        let candidates = vec![candidate("n", Scheme::Vless, "h.example.com")];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.host, "99999");

        // A capture-group replacement depends on the matched text, so the
        // guard is the runtime one: a delimiter-bearing result is rejected
        // and the original host kept.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [
                { "match": "(h\\.example\\.com)", "replace": "$1/../../x", "target": "host" }
            ]
        })))
        .unwrap();
        let candidates = vec![candidate("n", Scheme::Vless, "h.example.com")];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.host, "h.example.com");
    }

    #[tokio::test]
    async fn rename_host_target_allows_ipv6_literals_only_as_whole_hosts() {
        // Hosts are stored unbracketed; a colon-bearing rewrite must be a
        // plain IPv6 literal, this one is legal.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [
                { "match": "2001:db8::1", "replace": "2001:db8::2", "target": "host" }
            ]
        })))
        .unwrap();
        let candidates = vec![candidate("n", Scheme::Vless, "2001:db8::1")];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.host, "2001:db8::2");

        // A colon pair that is not an IPv6 address (a smuggled port) is
        // rejected and the original host kept. The rule carries a capture
        // group, so the replacement is only guarded at runtime.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [
                { "match": "(h\\.example\\.com)", "replace": "$1:8443", "target": "host" }
            ]
        })))
        .unwrap();
        let candidates = vec![candidate("n", Scheme::Vless, "h.example.com")];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.host, "h.example.com");
    }

    #[test]
    fn drop_rules_reject_replace_and_unknown_keys() {
        // A copied rewrite rule carries `replace`, the strict schema
        // rejects it: a discard rule only selects, never rewrites.
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "match": "a", "replace": "b" }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.invalid");
        assert!(err[0].args[0].contains("replace"), "{err:?}");

        // Flags/target/bad-regex errors reuse the rename keys, with the
        // drop[i] field name.
        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "match": "(", "flags": "" }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.bad_regex");
        assert_eq!(err[0].args[0], "drop[0]");

        let err = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "match": "a", "target": "bogus" }]
        })))
        .unwrap_err();
        assert_eq!(err[0].key, "pipeline.unknown_target");
        assert_eq!(err[0].args[0], "drop[0]");
    }

    #[tokio::test]
    async fn drop_discards_matching_proxies_on_every_target() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [
                { "match": "free|trial", "flags": "i" },
                { "match": "\\.cn$", "target": "host" },
                { "match": "^80$", "target": "port" },
                { "match": "^chrome$", "target": "param:fp" }
            ]
        })))
        .unwrap();
        let candidates = vec![
            candidate_with_params("paid node", "h1.example.com", 443, vec![]),
            candidate_with_params("FREE node", "h2.example.com", 443, vec![]), // name, i
            candidate_with_params("n", "h3.example.cn", 443, vec![]),          // host
            candidate_with_params("n", "h4.example.com", 80, vec![]),          // port
            candidate_with_params(
                "n",
                "h5.example.com",
                443,
                vec![
                    Param {
                        key: "fp".into(),
                        value: "chrome".into(),
                        known: true,
                        bare: false,
                    }, // param
                ],
            ),
            candidate_with_params(
                "n",
                "h6.example.com",
                443,
                vec![
                    Param {
                        key: "fp".into(),
                        value: "firefox".into(),
                        known: true,
                        bare: false,
                    }, // untouched
                ],
            ),
        ];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        let hosts: Vec<&str> = out.iter().map(|c| c.entry.host.as_str()).collect();
        assert_eq!(hosts, vec!["h1.example.com", "h6.example.com"]);
    }

    #[tokio::test]
    async fn drop_runs_before_rename_so_both_see_original_values() {
        // The same pattern dropped on the name and rewritten by rename: the
        // drop sees the original name (matching), the rename never runs for
        // the discarded proxy. Ingest applies only the drop on the same
        // original value, the two sides cannot disagree.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "match": "^free" }],
            "rename": [{ "match": "free", "replace": "paid", "flags": "i" }]
        })))
        .unwrap();
        let candidates = vec![
            candidate("free node", Scheme::Vless, "h1.example.com"),
            candidate("regular node", Scheme::Vless, "h2.example.com"),
        ];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        // The "free node" matched the drop on its original name and is gone;
        // the survivor is untouched by the rename.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].entry.name, "regular node");
    }

    #[tokio::test]
    async fn drop_param_target_matches_case_insensitive_key_and_raw_value() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "match": "%2Fws", "target": "param:path" }]
        })))
        .unwrap();
        let candidates = vec![
            // Feeds mix spellings; the value stays percent-encoded in
            // storage, the rule matches the raw form, as documented.
            candidate_with_params(
                "a",
                "h1.example.com",
                443,
                vec![Param {
                    key: "Path".into(),
                    value: "%2Fws".into(),
                    known: true,
                    bare: false,
                }],
            ),
            candidate_with_params(
                "b",
                "h2.example.com",
                443,
                vec![Param {
                    key: "path".into(),
                    value: "%2Fother".into(),
                    known: true,
                    bare: false,
                }],
            ),
        ];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].entry.name, "b");
    }

    /// The stamp shorthand the drop tests build on: one resolved ASN, no
    /// other facts.
    fn stamp(asn: &str) -> Option<fumox_core::repo::proxies::GeoStamp> {
        Some(fumox_core::repo::proxies::GeoStamp {
            asn: Some(asn.into()),
            ..Default::default()
        })
    }

    /// The parsed ASN column for a stamp slice, exactly what the ingest
    /// caller (`apply_drop_rules`) hands the drop pass at its boundary.
    fn stamp_asns(stamps: &[Option<fumox_core::repo::proxies::GeoStamp>]) -> Vec<Option<u32>> {
        stamps
            .iter()
            .map(|stamp| {
                stamp
                    .as_ref()
                    .and_then(|stamp| stamp.asn.as_deref())
                    .and_then(asn_number)
            })
            .collect()
    }

    #[test]
    fn drop_by_asn_discards_matching_proxies() {
        // The pipeline-level helper (`drop_entries_with_geo`) runs before
        // any DB interaction, so it is the cheapest place to exercise ASN
        // drop. The ASNs arrive pre-parsed, the stamps ride along
        // index-aligned; an empty stamp is "unknown".
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "target": "asn", "asns": ["24940"] }]
        })))
        .unwrap();
        let entries = vec![
            entry("as24940", "h1.example.com"),
            entry("as13335", "h2.example.com"),
            entry("as24940-via-prefix", "h3.example.com"),
        ];
        let stamps = vec![stamp("AS24940"), stamp("AS13335"), stamp("AS24940")];
        let after = compiled
            .drop_entries_with_geo(
                entries.clone(),
                &stamp_asns(&stamps),
                &stamps,
                "test-source",
            )
            .0;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].host, "h2.example.com");
        // Verify the geometry contract: empty stamps leave entries alone.
        let no_geo: Vec<Option<fumox_core::repo::proxies::GeoStamp>> = vec![None; entries.len()];
        let untouched = compiled
            .drop_entries_with_geo(entries, &stamp_asns(&no_geo), &no_geo, "test-source")
            .0;
        assert_eq!(untouched.len(), 3, "missing ASN is not a hit");
    }

    #[test]
    fn drop_entries_keeps_the_batch_when_the_geo_slice_is_short() {
        // The resolver is inactive (geo disabled, or the `.mmdb` files are
        // missing on disk, the default configuration), so the ingest
        // caller resolves no stamps at all and passes an empty slice. The
        // batch must survive intact: a truncated zip would drop every
        // proxy and make reconcile retire the whole source.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [
                { "match": "\\.cn$", "target": "host" },
                { "target": "asn", "asns": ["24940"] }
            ]
        })))
        .unwrap();
        let entries = vec![
            entry("p1", "h1.example.com"),
            entry("p2", "h2.example.com"),
            entry("p3", "h3.example.com"),
        ];
        let names =
            |kept: Vec<ProxyEntry>| -> Vec<String> { kept.into_iter().map(|e| e.name).collect() };
        assert_eq!(
            names(
                compiled
                    .drop_entries_with_geo(entries.clone(), &[], &[], "test-source")
                    .0
            ),
            ["p1", "p2", "p3"]
        );
        // Regex rules need no stamp, so they still fire on a stamp-less
        // batch: only the ASN lookups are skipped.
        let with_cn = compiled
            .drop_entries_with_geo(
                vec![entry("p1", "h1.example.com"), entry("cn", "h.cn")],
                &[],
                &[],
                "test-source",
            )
            .0;
        assert_eq!(names(with_cn), ["p1"]);
        // A partially resolved slice behaves the same for the tail: the
        // entries past its end are unstamped, not dropped.
        let partial_stamps = vec![stamp("AS13335")];
        let partial = compiled
            .drop_entries_with_geo(
                entries,
                &stamp_asns(&partial_stamps),
                &partial_stamps,
                "test-source",
            )
            .0;
        assert_eq!(names(partial), ["p1", "p2", "p3"]);
    }

    #[test]
    fn drop_by_asn_accepts_both_with_and_without_prefix() {
        // `24940` and `AS24940` in the same `asns` list both match a
        // stored `AS24940`, the validator normalises through
        // `asn_number`.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "target": "asn", "asns": ["24940", "AS13335"] }]
        })))
        .unwrap();
        let entries = vec![
            entry("a", "h1.example.com"),
            entry("b", "h2.example.com"),
            entry("c", "h3.example.com"),
        ];
        let stamps = vec![stamp("AS24940"), stamp("AS13335"), stamp("AS99999")];
        let after = compiled
            .drop_entries_with_geo(entries, &stamp_asns(&stamps), &stamps, "test-source")
            .0;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].host, "h3.example.com");

        // The lowercase spelling compiles too and matches the same stored
        // `AS24940`: `asn_number` strips the prefix in either case.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "target": "asn", "asns": ["as24940"] }]
        })))
        .unwrap();
        let entries = vec![entry("a", "h1.example.com"), entry("b", "h2.example.com")];
        let stamps = vec![stamp("AS24940"), stamp("AS13335")];
        let after = compiled
            .drop_entries_with_geo(entries, &stamp_asns(&stamps), &stamps, "test-source")
            .0;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].host, "h2.example.com");
    }

    #[test]
    fn drop_by_asn_keeps_unresolved_proxies() {
        // Missing ASN stamp is not a hit (matches `filter.exclude_asns`).
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "target": "asn", "asns": ["24940"] }]
        })))
        .unwrap();
        let entries = vec![entry("n", "h.example.com")];
        let stamps: Vec<Option<fumox_core::repo::proxies::GeoStamp>> = vec![None];
        let after = compiled
            .drop_entries_with_geo(entries, &stamp_asns(&stamps), &stamps, "test-source")
            .0;
        assert_eq!(after.len(), 1);
    }

    #[test]
    fn drop_with_text_and_asn_rules_combined() {
        // Regex over `host` plus ASN list, the same `drop` array holds
        // both flavours and both fire on a matching entry.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [
                { "match": "\\.cn$", "target": "host" },
                { "target": "asn", "asns": ["24940"] }
            ]
        })))
        .unwrap();
        let entries = vec![
            entry("china", "h.cn"),
            entry("blocked-asn", "h.example.com"),
            entry("kept", "h.example.com"),
        ];
        let stamps = vec![stamp("AS99999"), stamp("AS24940"), stamp("AS99999")];
        let after = compiled
            .drop_entries_with_geo(entries, &stamp_asns(&stamps), &stamps, "test-source")
            .0;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].host, "h.example.com");
        assert_eq!(after[0].name, "kept");
    }

    #[test]
    fn drop_asn_target_requires_asns() {
        // An ASN rule without `asns` is a field error, never a silent
        // match-all. The compile path fails closed: no `CompiledPipeline`
        // is produced.
        let result = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "target": "asn" }]
        })));
        let issues = result.expect_err("missing asns must fail compile");
        assert!(
            issues
                .iter()
                .any(|i| i.key == "pipeline.asn_target_requires_asns"),
            "expected requires-asns error, got {issues:?}"
        );
    }

    #[test]
    fn drop_asn_target_rejects_match_field() {
        let result = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{
                "target": "asn",
                "match": "x",
                "flags": "i",
                "asns": ["24940"]
            }]
        })));
        let issues = result.expect_err("match/flags on asn rule must fail");
        assert!(
            issues
                .iter()
                .any(|i| i.key == "pipeline.asn_target_rejects_match"),
            "expected rejects-match error, got {issues:?}"
        );
    }

    #[test]
    fn non_asn_target_rejects_asns() {
        let result = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{
                "target": "name",
                "match": "free",
                "asns": ["24940"]
            }]
        })));
        let issues = result.expect_err("asns on non-asn rule must fail");
        assert!(
            issues
                .iter()
                .any(|i| i.key == "pipeline.non_asn_target_rejects_asns"),
            "expected non-asn-rejects-asns error, got {issues:?}"
        );
    }

    #[test]
    fn unknown_target_is_a_field_error() {
        // The validator rejects an unknown target with the shared
        // `pipeline.unknown_target` key; the rendered copy (the `asn`
        // entry in the allowed list) is pinned by the admin/i18n tests.
        let issues = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "target": "foo", "match": "." }]
        })))
        .expect_err("unknown target must fail");
        assert!(
            issues.iter().any(|i| i.key == "pipeline.unknown_target"),
            "unknown_target error must be present: {issues:?}"
        );
    }

    #[test]
    fn drop_by_asn_invalid_asn_number_is_a_field_error() {
        // `asns` accepts only digits with optional `AS` prefix. A typo
        // becomes `pipeline.unknown_asn` and skips the rule rather than
        // partially compiling it.
        let result = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "target": "asn", "asns": ["24940", "not-a-number"] }]
        })));
        let issues = result.expect_err("invalid ASN must fail");
        assert!(
            issues.iter().any(|i| i.key == "pipeline.unknown_asn"),
            "expected unknown_asn error, got {issues:?}"
        );
    }

    #[tokio::test]
    async fn drop_by_asn_applies_on_serving_side_too() {
        // The serving-side drop pass must also fire on ASN-targeted
        // rules. Build candidates with explicit `geo_asn` and check the
        // post-apply list.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "drop": [{ "target": "asn", "asns": ["24940"] }]
        })))
        .unwrap();
        let mut keep = candidate("keep", Scheme::Vless, "h1.example.com");
        keep.geo_asn = Some(99999);
        let mut drop_me = candidate("drop", Scheme::Vless, "h2.example.com");
        drop_me.geo_asn = Some(24940);
        let mut unresolved = candidate("unresolved", Scheme::Vless, "h3.example.com");
        unresolved.geo_asn = None;
        let out = compiled
            .apply(vec![keep, drop_me, unresolved], &inactive_geo())
            .await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, vec!["keep", "unresolved"]);
    }

    #[tokio::test]
    async fn rename_port_target_guards_invalid_results() {
        // A literal replacement that is never a valid port is a
        // compile-time field error: the rewrite could only be skipped for
        // every entry it matches.
        for replace in ["70000", "443:evil"] {
            let err = CompiledPipeline::from_json(Some(&json!({
                "version": 1,
                "rename": [{ "match": ".*", "replace": replace, "target": "port" }]
            })))
            .unwrap_err();
            assert_eq!(err[0].key, "pipeline.never_valid_port", "{replace}");
        }

        // Zero is refused at runtime like any other unusable value: the
        // parsers drop it and the schema CHECK (migration 0018) would
        // reject the row at the upsert. "0" parses as u16, so the rule
        // compiles and the guard is the runtime one.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": ".*", "replace": "0", "target": "port" }]
        })))
        .unwrap();
        let candidates = vec![candidate("n", Scheme::Vless, "h.example.com")];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.port, 443);
    }

    #[tokio::test]
    async fn rename_param_target_without_the_key_is_a_noop() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": "a", "replace": "b", "target": "param:pbk" }]
        })))
        .unwrap();
        let candidates = vec![candidate_with_params(
            "n",
            "h.example.com",
            443,
            vec![Param {
                key: "fp".into(),
                value: "chrome".into(),
                known: true,
                bare: false,
            }],
        )];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out[0].entry.params[0].value, "chrome");
    }

    #[tokio::test]
    #[ignore = "requires GeoLite2 mmdb"]
    async fn geo_step_renders_merged_country_city_and_asn_facts() {
        let Some(geo) = active_geo_with_dbs() else {
            return;
        };

        // The resolver merges every database in db_dir, so one template can
        // draw country and ASN facts at once, the one-database era could
        // not render this. 8.8.8.8 is anycast (no city): the missing city
        // must collapse away, not break the name.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "geo": { "enabled": true, "template": "{country} {city} · {asn} {name}" }
        })))
        .unwrap();
        // Literal IP → no DNS round-trip. The country/city wording is the
        // database's, so the assert pins only the shape: facts merged
        // around the `·` separator, the ASN as `AS<n>` and the original
        // name kept.
        let out = compiled
            .apply(vec![candidate("Node-1", Scheme::Vless, "8.8.8.8")], &geo)
            .await;
        assert_eq!(out.len(), 1);
        let name = &out[0].entry.name;
        let (facts, tail) = name.split_once('·').expect("separator renders");
        assert!(
            facts
                .split_whitespace()
                .chain(tail.split_whitespace())
                .any(|token| token.strip_prefix("AS").is_some_and(
                    |digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
                )),
            "ASN must render as AS<n>: {name:?}"
        );
        assert!(
            tail.contains("Node-1"),
            "the original name is kept: {name:?}"
        );
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

    /// The health exclusion list is the operator's choice, both ways: an
    /// empty list hides nothing (a quarantined proxy is served), a list
    /// that names `unknown` hides the never-probed tier too.
    #[tokio::test]
    async fn health_exclude_statuses_is_the_operators_choice() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "health": { "exclude_statuses": [] }
        })))
        .unwrap();
        let mut quarantined = candidate("q", Scheme::Vless, "h1.example.com");
        quarantined.status = ProxyStatus::Quarantine;
        let out = compiled.apply(vec![quarantined], &inactive_geo()).await;
        assert_eq!(out.len(), 1, "an empty exclusion list hides nothing");

        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "health": { "exclude_statuses": ["quarantine", "removed", "unknown"] }
        })))
        .unwrap();
        let mut unknown = candidate("u", Scheme::Vless, "h2.example.com");
        unknown.status = ProxyStatus::Unknown;
        let out = compiled.apply(vec![unknown], &inactive_geo()).await;
        assert!(out.is_empty(), "a listed status is excluded");
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
        // An explicit `sort` section is the sort contest's "was chosen"
        // marker.
        assert!(by_name.sort_explicit());
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

    /// Unknown countries always sort last, ascending or descending: an
    /// absent fact is not a country code, so a reversed sort must not
    /// float it to the top.
    #[tokio::test]
    async fn sort_by_country_puts_unknown_last_in_both_directions() {
        let mut de = candidate("de", Scheme::Vless, "h1.example.com");
        de.geo_country = Some("DE".into());
        let mut us = candidate("us", Scheme::Vless, "h2.example.com");
        us.geo_country = Some("US".into());
        let unknown = candidate("unknown", Scheme::Vless, "h3.example.com");

        let asc = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "sort": { "by": "country" }
        })))
        .unwrap();
        let out = asc
            .apply(
                vec![us.clone(), unknown.clone(), de.clone()],
                &inactive_geo(),
            )
            .await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, ["de", "us", "unknown"]);

        let desc = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "sort": { "by": "country", "desc": true }
        })))
        .unwrap();
        let out = desc.apply(vec![us, unknown, de], &inactive_geo()).await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, ["us", "de", "unknown"]);
    }

    /// Every filtering step reports its in/out counts in a DEBUG event, and
    /// a step that empties a non-empty input warns — a misconfigured rule
    /// must not quietly blank the feed.
    #[tokio::test]
    async fn filtering_steps_log_their_counts_and_a_full_wipe_warns() {
        let (logs, _guard) = capture_logs(tracing::Level::DEBUG);

        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "protocols": ["vless"] }
        })))
        .unwrap();
        let out = compiled
            .apply(
                vec![
                    candidate("a", Scheme::Vless, "h1.example.com"),
                    candidate("b", Scheme::Trojan, "h2.example.com"),
                ],
                &inactive_geo(),
            )
            .await;
        assert_eq!(out.len(), 1);
        let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains(r#"step="protocols""#),
            "the protocols step must log its counts: {logs}"
        );
        assert!(logs.contains("removed=1"), "{logs}");
        assert!(
            logs.contains(r#"step="health""#),
            "the health step must log its counts: {logs}"
        );
        // `apply` ends with `finalize`: the dedup step logs there too (the
        // limit step only fires with a configured cap).
        assert!(logs.contains(r#"step="dedup""#), "{logs}");
        let warnings = logs.lines().filter(|line| line.contains("WARN")).count();
        assert_eq!(warnings, 0, "a partial removal must not warn: {logs}");

        // A rule that removes everything of a non-empty input warns.
        let (logs, _guard) = capture_logs(tracing::Level::DEBUG);
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "protocols": ["ss"] }
        })))
        .unwrap();
        let out = compiled
            .apply(
                vec![candidate("a", Scheme::Vless, "h1.example.com")],
                &inactive_geo(),
            )
            .await;
        assert!(out.is_empty());
        let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("removed every entry of a non-empty input"),
            "a full wipe must warn: {logs}"
        );
    }

    /// The geo pass resolves hosts with bounded parallelism: more than one
    /// lookup is in flight at a time (the old strictly serial loop peaked
    /// at 1) and the peak stays within [`GEO_LOOKUP_CONCURRENCY`].
    #[tokio::test]
    async fn geo_enrich_resolves_hosts_with_bounded_concurrency() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "geo": { "enabled": true }
        })))
        .unwrap();
        let geo = FakeGeo {
            active: true,
            sleep_ms: 20,
            ..Default::default()
        };
        let candidates: Vec<Candidate> = (0..GEO_LOOKUP_CONCURRENCY * 2)
            .map(|idx| {
                candidate(
                    &format!("n{idx}"),
                    Scheme::Vless,
                    &format!("h{idx}.example.com"),
                )
            })
            .collect();
        let out = compiled.apply_per_source(candidates, &geo).await;
        assert_eq!(out.len(), GEO_LOOKUP_CONCURRENCY * 2);

        let peak = geo.peak();
        assert!(
            peak > 1,
            "lookups must overlap; peak concurrency was {peak}, a serial loop would report 1"
        );
        assert!(
            peak <= GEO_LOOKUP_CONCURRENCY,
            "the concurrency cap must hold, peak was {peak}"
        );
    }

    #[tokio::test]
    async fn limit_truncates_after_sort_to_the_top() {
        // `sort: latency` + `limit: 2` yields the two fastest proxies.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "sort": { "by": "latency" },
            "limit": { "count": 2 }
        })))
        .unwrap();
        let with_latency = |name: &str, host: &str, ms: i64| {
            let mut c = candidate(name, Scheme::Vless, host);
            c.latency_ms = Some(ms);
            c
        };
        let out = compiled
            .apply(
                vec![
                    with_latency("slow", "h1.example.com", 300),
                    with_latency("fast", "h2.example.com", 20),
                    with_latency("mid", "h3.example.com", 100),
                    with_latency("fast2", "h4.example.com", 25),
                ],
                &inactive_geo(),
            )
            .await;
        let names: Vec<&str> = out.iter().map(|c| c.entry.name.as_str()).collect();
        assert_eq!(names, vec!["fast", "fast2"]);
    }

    #[tokio::test]
    async fn limit_null_keeps_everything() {
        // The explicit "defaults" reset (the profile tri-state): a present
        // section with `count: null` must not cap anything.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "limit": { "count": null }
        })))
        .unwrap();
        let candidates = vec![
            candidate("a", Scheme::Vless, "h1.example.com"),
            candidate("b", Scheme::Vless, "h2.example.com"),
            candidate("c", Scheme::Vless, "h3.example.com"),
        ];
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn limit_rejects_zero_and_negative_counts() {
        for count in [0, -5] {
            let errors = CompiledPipeline::from_json(Some(&json!({
                "version": 1,
                "limit": { "count": count }
            })))
            .unwrap_err();
            assert_eq!(errors[0].key, "pipeline.invalid_limit");
            assert_eq!(errors[0].args, [count.to_string()]);
        }
    }

    /// Fractional and beyond-`usize` caps are localized field errors too,
    /// not the opaque serde type error the `i64` field produced for
    /// fractions.
    #[test]
    fn fractional_and_oversized_limit_counts_are_field_errors() {
        for count in [json!(2.5), json!(9_223_372_036_854_775_808u64)] {
            let errors = CompiledPipeline::from_json(Some(&json!({
                "version": 1,
                "limit": { "count": count }
            })))
            .unwrap_err();
            assert_eq!(errors[0].key, "pipeline.invalid_limit", "{count}");
            assert_eq!(errors[0].args, [count.to_string()]);
        }
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

    /// A `NULL` profile pipeline overrides nothing: the source's sections
    /// stay in place. The profile's `null` is "no override", not "every
    /// section reset to nothing configured".
    #[test]
    fn a_null_profile_pipeline_overrides_nothing() {
        let source = json!({
            "version": 1,
            "filter": { "protocols": ["vless"] },
            "sort": { "by": "name" }
        });
        let merged = merge_configs(Some(&source), Some(&serde_json::Value::Null)).unwrap();
        assert_eq!(merged, source);
    }

    /// The merge table: absent sides pass through, a non-object profile
    /// wins so the error surfaces against the profile form, and a
    /// non-object source merged with a valid object profile is replaced
    /// by it — with a WARN naming the source config as the broken side,
    /// since only the source could have caused the mismatch.
    #[test]
    fn merge_configs_table() {
        assert_eq!(merge_configs(None, None), None);
        let source = json!({ "version": 1, "sort": { "by": "name" } });
        let profile = json!({ "version": 1, "limit": { "count": 5 } });

        // (Some(obj), None) → the source, untouched.
        assert_eq!(merge_configs(Some(&source), None), Some(source.clone()));
        // (None, Some(p)) → the profile.
        assert_eq!(merge_configs(None, Some(&profile)), Some(profile.clone()));
        // (Some(obj), Some(non-object)) → the profile wins.
        for broken in [json!("oops"), json!(42)] {
            assert_eq!(
                merge_configs(Some(&source), Some(&broken)),
                Some(broken.clone())
            );
        }
        // (Some(non-object), Some(obj)) → the profile's object, merged
        // over nothing, with a WARN that names the source.
        let (logs, _guard) = capture_logs(tracing::Level::WARN);
        let merged = merge_configs(Some(&json!("oops")), Some(&profile));
        let logs = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert_eq!(merged, Some(profile.clone()));
        assert!(
            logs.contains("source"),
            "the WARN must name the source config as the broken side: {logs}"
        );
    }

    /// The ASN fill is a geo lookup per candidate: only the ASN rules need
    /// it, a pipeline without one resolves nothing.
    #[tokio::test]
    async fn a_pipeline_without_an_asn_rule_resolves_no_asn() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "protocols": ["vless"] }
        })))
        .unwrap();
        let geo = FakeGeo::default();
        let candidates = vec![candidate_with_asn("n", None)];
        let out = compiled.apply_per_source(candidates, &geo).await;
        assert_eq!(out.len(), 1);
        assert_eq!(geo.calls(), 0);

        // With an ASN rule the fill runs.
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "filter": { "asns": ["13335"] }
        })))
        .unwrap();
        let geo = FakeGeo::default();
        let candidates = vec![candidate_with_asn("n", None)];
        let _ = compiled.apply_per_source(candidates, &geo).await;
        assert_eq!(geo.calls(), 1);
    }

    /// The insecure filter sees the final parameters: a rename rule that
    /// introduces an insecure switch drops the proxy.
    #[tokio::test]
    async fn the_insecure_filter_sees_the_renamed_parameters() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": ".*", "replace": "1", "target": "param:insecure" }]
        })))
        .unwrap();
        let mut c = candidate("n", Scheme::Vless, "h.example.com");
        c.entry.params.push(Param {
            key: "insecure".into(),
            value: "0".into(),
            known: true,
            bare: false,
        });
        let out = compiled.apply(vec![c], &inactive_geo()).await;
        assert!(
            out.is_empty(),
            "the renamed proxy allows insecure TLS and must be dropped"
        );
    }

    /// A stored insecure proxy stays dropped even when a rename rule would
    /// rewrite the switch away: the stored row is the fact, the rewrite
    /// only changes the output text.
    #[tokio::test]
    async fn a_stored_insecure_proxy_is_dropped_even_when_a_rename_rewrites_it() {
        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": ".*", "replace": "0", "target": "param:insecure" }]
        })))
        .unwrap();
        let mut c = candidate("n", Scheme::Vless, "h.example.com");
        c.entry.params.push(Param {
            key: "insecure".into(),
            value: "1".into(),
            known: true,
            bare: false,
        });
        let out = compiled.apply(vec![c], &inactive_geo()).await;
        assert!(out.is_empty(), "the stored row allows insecure TLS");
    }

    /// A broken rename rule warns once per rule, not once per proxy: a
    /// thousand proxies must not write a thousand WARN lines. The rule
    /// carries a capture group (so it compiles past the literal-replacement
    /// check) and its runtime results are invalid hosts.
    #[tokio::test]
    async fn a_broken_rename_rule_warns_once_per_rule() {
        let (captured, _guard) = capture_logs(tracing::Level::INFO);

        let compiled = CompiledPipeline::from_json(Some(&json!({
            "version": 1,
            "rename": [{ "match": "(.*)", "replace": "$1:8443", "target": "host" }]
        })))
        .unwrap();
        let candidates: Vec<Candidate> = (0..5)
            .map(|idx| {
                candidate(
                    &format!("n{idx}"),
                    Scheme::Vless,
                    &format!("h{idx}.example.com"),
                )
            })
            .collect();
        let out = compiled.apply(candidates, &inactive_geo()).await;
        assert_eq!(out.len(), 5);
        assert_eq!(out[0].entry.host, "h0.example.com");

        let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        let warnings = logs.lines().filter(|line| line.contains("WARN")).count();
        assert_eq!(warnings, 1, "one WARN per rule, not per entry: {logs}");
        assert!(logs.contains("skipped=5"), "{logs}");
        assert!(logs.contains("target=host"), "{logs}");
    }

    #[tokio::test]
    async fn forbid_insecure_drops_every_truthy_alias_spelling() {
        for (key, value) in [
            ("insecure", "1"),
            ("allowInsecure", "1"),
            ("skip-cert-verify", "true"),
            ("allow_insecure", "1"),
            ("INSECURE", " TRUE "),
            // The yes/on spellings of the one shared toggle vocabulary: a
            // `yes` node must drop like a `1` one, not survive the filter.
            ("allowInsecure", "yes"),
            ("skip-cert-verify", "on"),
        ] {
            let mut c = candidate(key, Scheme::Vless, &format!("{key}.example.com"));
            c.entry.params.push(Param {
                key: key.into(),
                value: value.into(),
                known: true,
                bare: false,
            });
            let out = CompiledPipeline::from_json(None)
                .unwrap()
                .apply(vec![c], &inactive_geo())
                .await;
            assert!(
                out.is_empty(),
                "truthy alias {key}={value} must drop the proxy"
            );
        }
    }

    #[tokio::test]
    async fn forbid_insecure_keeps_falsy_and_alias_free_entries() {
        for key in [
            "insecure",
            "allowInsecure",
            "skip-cert-verify",
            "allow_insecure",
        ] {
            let mut c = candidate(key, Scheme::Vless, &format!("{key}.example.com"));
            c.entry.params.push(Param {
                key: key.into(),
                value: "0".into(),
                known: true,
                bare: false,
            });
            let out = CompiledPipeline::from_json(None)
                .unwrap()
                .apply(vec![c], &inactive_geo())
                .await;
            assert_eq!(out.len(), 1, "falsy {key}=0 must survive");
        }
        // No alias at all, untouched by the filter.
        let plain = candidate("plain", Scheme::Vless, "plain.example.com");
        let out = CompiledPipeline::from_json(None)
            .unwrap()
            .apply(vec![plain], &inactive_geo())
            .await;
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn forbid_insecure_off_keeps_insecure_entries() {
        let config = json!({
            "version": 1,
            "filter": { "forbid_insecure": false }
        });
        let mut c = candidate("insecure one", Scheme::Vless, "insecure.example.com");
        c.entry.params.push(Param {
            key: "allowInsecure".into(),
            value: "1".into(),
            known: true,
            bare: false,
        });
        let out = CompiledPipeline::from_json(Some(&config))
            .unwrap()
            .apply(vec![c], &inactive_geo())
            .await;
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn legacy_normalize_params_name_still_compiles_as_the_same_switch() {
        // Old exports carry "normalize_params": false, the v1 name of the
        // switch, accepted via serde alias so imports keep working.
        let legacy = json!({
            "version": 1,
            "filter": { "normalize_params": false }
        });
        let mut c = candidate("insecure one", Scheme::Vless, "legacy.example.com");
        c.entry.params.push(Param {
            key: "insecure".into(),
            value: "1".into(),
            known: true,
            bare: false,
        });
        let out = CompiledPipeline::from_json(Some(&legacy))
            .unwrap()
            .apply(vec![c], &inactive_geo())
            .await;
        assert_eq!(out.len(), 1, "legacy false must disable the filter");
    }

    #[test]
    fn typed_config_serializes_omitting_defaults() {
        // The Serialize side is the builder emit's policy. A config with
        // every section unset serializes to bare `{"version": 1}`: the
        // JSON that makes the builder emit collapse to NULL.
        let bare = PipelineConfig {
            version: 1,
            filter: None,
            rename: None,
            drop: None,
            geo: None,
            health: None,
            dedup: None,
            sort: None,
            limit: None,
        };
        assert_eq!(
            serde_json::to_value(&bare).unwrap(),
            json!({ "version": 1 })
        );

        // Sections present but carrying only schema defaults serialize to
        // the explicit empty blocks the profile tri-state pins: `{}` for
        // the object sections, `[]` for the rule lists, `{"count": null}`
        // for the cap. Fields at their schema default are never written.
        let defaults = PipelineConfig {
            filter: Some(FilterConfig {
                protocols: None,
                exclude_protocols: None,
                asns: None,
                exclude_asns: None,
                forbid_insecure: true,
            }),
            rename: Some(Vec::new()),
            drop: Some(Vec::new()),
            geo: Some(GeoStepConfig {
                enabled: true,
                template: DEFAULT_GEO_TEMPLATE.to_string(),
            }),
            health: Some(HealthConfig {
                exclude_statuses: default_exclude_statuses(),
            }),
            dedup: None,
            sort: Some(SortConfig {
                by: SortBy::Source,
                desc: false,
            }),
            limit: Some(LimitConfig { count: None }),
            ..bare
        };
        assert_eq!(
            serde_json::to_value(&defaults).unwrap(),
            json!({
                "version": 1,
                "filter": {},
                "rename": [],
                "drop": [],
                "geo": {},
                "health": {},
                "sort": {},
                "limit": { "count": null }
            })
        );
    }

    #[test]
    fn typed_config_round_trips_through_its_own_serialization() {
        // Every section at a non-default value: the serialized document
        // must parse back to a config that serializes identically (no
        // asymmetry between the skip predicates and the deserialize
        // defaults) and must pass the strict validator.
        let full = PipelineConfig {
            version: 1,
            filter: Some(FilterConfig {
                protocols: Some(vec!["vless".into()]),
                exclude_protocols: Some(vec!["ss".into()]),
                asns: Some(vec!["24940".into()]),
                exclude_asns: Some(vec!["AS9009".into()]),
                forbid_insecure: false,
            }),
            rename: Some(vec![RenameRule {
                match_pattern: "^free".into(),
                replace: String::new(),
                flags: "i".into(),
                target: Some("param:fp".into()),
            }]),
            drop: Some(vec![
                DropRule {
                    match_pattern: "\\.cn$".into(),
                    flags: String::new(),
                    target: Some("host".into()),
                    asns: None,
                },
                DropRule {
                    match_pattern: String::new(),
                    flags: String::new(),
                    target: Some("asn".into()),
                    asns: Some(vec!["24940".into()]),
                },
            ]),
            geo: Some(GeoStepConfig {
                enabled: false,
                template: "{country} · {name}".into(),
            }),
            health: Some(HealthConfig {
                exclude_statuses: vec!["removed".into()],
            }),
            dedup: Some(DedupConfig {
                by: "fingerprint".into(),
            }),
            sort: Some(SortConfig {
                by: SortBy::Latency,
                desc: true,
            }),
            limit: Some(LimitConfig {
                count: Some(serde_json::Number::from(100)),
            }),
        };
        let value = serde_json::to_value(&full).unwrap();
        let parsed: PipelineConfig = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        assert!(
            CompiledPipeline::from_json(Some(&value)).is_ok(),
            "{value:?}"
        );
        // `limit: {"count": null}` serializes explicitly (the no-cap
        // reset); `limit: null` deserializes as `None` (no section), not
        // as the reset.
        let no_cap = PipelineConfig {
            limit: Some(LimitConfig { count: None }),
            ..full
        };
        assert_eq!(
            serde_json::to_value(&no_cap).unwrap()["limit"],
            json!({ "count": null })
        );
    }
}
