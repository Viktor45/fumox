//! Pipeline builder state (PIPELINE.md): the server-side half of the admin
//! pipeline editor. `BuilderState` mirrors the widget's form fields; [`emit`]
//! generates the pipeline JSON (validator semantics, only non-default values)
//! and [`ingest`] rebuilds the state from a stored JSON or reports "raw
//! mode". The schema registry (`Schema`) sources every option list from the
//! validator's own enums, so the builder can never offer a value the
//! validator rejects out of hand. The widget itself (modes, presets,
//! preview) renders through [`WidgetFragment`] into the source/profile forms.

use crate::admin::i18n::{Lang, impl_i18n};
use crate::pipeline::{DEFAULT_GEO_TEMPLATE, DropRule, PipelineConfig, RenameRule, SortBy};
use askama::Template;
use fumox_core::models::{ProxyStatus, Scheme};

/// One rename row of the builder (a `rename[]` entry).
///
/// `target` mirrors the rule's `target` field in the compact UI form:
/// `"name"`/`"host"`/`"port"` or `"param:KEY"`. The `param` key part is a
/// separate free-text field in the widget (`_rows.html`), so `target`
/// holds `"param"` and `param_key` the key; [`emit_rename_rule`] recombines
/// them. Keeping them split avoids a regex round-trip between the form and
/// the state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RenameRow {
    pub match_pattern: String,
    pub replace: String,
    pub flags: String,
    pub target: String,
    pub param_key: String,
}

/// The rule's `target` JSON value: the compact UI form recombined. An
/// unknown selector or an empty `param` key is emitted as-is (a `param:`
/// with nothing after the colon) — the builder holds values the validator
/// will flag in the preview, never silently dropping them (PIPELINE.md §4).
/// `name` emits nothing: it is the schema default and stays implicit.
pub(crate) fn emit_rename_target(row: &RenameRow) -> Option<String> {
    match row.target.trim() {
        "" | "name" => None,
        "param" => Some(format!("param:{}", row.param_key.trim())),
        other => Some(other.to_string()),
    }
}

/// One drop row of the builder (a `drop[]` entry). The selector twin of a
/// rename row minus the replacement: the same target select (`name`/
/// `host`/`port`/`param` plus the key field), no `replace` — a discard
/// rule only selects, never rewrites.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DropRow {
    pub match_pattern: String,
    pub flags: String,
    pub target: String,
    pub param_key: String,
}

impl DropRow {
    /// The rule's `target` JSON value — the same recombination semantics
    /// as [`emit_rename_target`].
    fn target_value(&self) -> Option<String> {
        match self.target.trim() {
            "" | "name" => None,
            "param" => Some(format!("param:{}", self.param_key.trim())),
            other => Some(other.to_string()),
        }
    }
}

/// Values of the builder widget, exactly as the form fields carry them.
/// Section toggles (`*_set`) express the administrator's intent; [`emit`]
/// turns a set section into JSON only when it holds at least one value that
/// differs from the SPEC §5.1 defaults.
///
/// The `*_defaults` flags are the profile tri-state (PIPELINE.md §6): a
/// profile section replaces the source's section wholesale, so besides "not
/// set" (inherit the source's rule) and "set" there is "explicit defaults" —
/// an empty section that resets the source's rule to the SPEC defaults.
/// `rename_skip` is the "not set" choice for rename, whose only state
/// besides the rules themselves is the empty `[]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BuilderState {
    pub filter_set: bool,
    pub filter_defaults: bool,
    pub protocols: Vec<String>,
    pub exclude_protocols: Vec<String>,
    pub normalize_params: bool,
    pub rename: Vec<RenameRow>,
    pub rename_skip: bool,
    pub rename_defaults: bool,
    /// The `drop` section — the same tri-state as rename, over `DropRow`s.
    pub drop: Vec<DropRow>,
    pub drop_skip: bool,
    pub drop_defaults: bool,
    pub geo_set: bool,
    pub geo_defaults: bool,
    pub geo_enabled: bool,
    /// Empty means the SPEC default template (never emitted, see [`emit`]).
    pub geo_template: String,
    pub health_set: bool,
    pub health_defaults: bool,
    pub exclude_statuses: Vec<String>,
    pub sort_set: bool,
    pub sort_defaults: bool,
    /// Empty or `"source"` is the default (never emitted).
    pub sort_by: String,
    pub sort_desc: bool,
}

/// Form-field values a section mode control submits: the source form uses a
/// checkbox (`"1"` = set), the profile form a radio triple
/// (`"skip"`/`"defaults"`/`"set"`); no field at all means "not set".
fn mode_flags(value: &str) -> (bool, bool) {
    (value == "1" || value == "set", value == "defaults")
}

/// Ready-made builder states (PIPELINE.md §6); `blank` is the empty state.
pub(crate) fn preset(name: &str) -> BuilderState {
    match name {
        // Output only proxies that passed a probe: drop everything never
        // verified, including the permanently `unknown` unprobeable
        // protocols (SPEC §8.5).
        "workers" => BuilderState {
            health_set: true,
            exclude_statuses: vec!["unknown".into(), "quarantine".into(), "removed".into()],
            ..BuilderState::new()
        },
        // Country-first naming.
        "country" => BuilderState {
            geo_set: true,
            geo_template: "{country} · {name}".into(),
            ..BuilderState::new()
        },
        // Plain list: no geo rewriting, names trimmed at both ends.
        "clean" => BuilderState {
            geo_set: true,
            geo_enabled: false,
            rename: vec![RenameRow {
                match_pattern: r"^\s+|\s+$".into(),
                replace: String::new(),
                flags: String::new(),
                ..RenameRow::default()
            }],
            ..BuilderState::new()
        },
        _ => BuilderState::new(),
    }
}

impl BuilderState {
    /// A fresh state: every section unset, checkboxes at their SPEC defaults.
    pub(crate) fn new() -> Self {
        Self {
            normalize_params: true,
            geo_enabled: true,
            exclude_statuses: crate::pipeline::default_exclude_statuses(),
            ..Default::default()
        }
    }

    /// Parse the builder fields out of a urlencoded form. Multi-value fields
    /// (`ped_filter_protocols`, `ped_filter_exclude`, `ped_health_exclude`)
    /// repeat the name; rename/drop rows carry their index:
    /// `ped_rename_<i>_match|replace|flags|target|key`,
    /// `ped_drop_<i>_match|flags|target|key`; section mode controls submit
    /// `ped_<section>` = `1`/`skip`/`defaults`/`set`. Only `ped_*` fields are
    /// read, so the same form body can carry the rest of the source/profile
    /// form.
    pub(crate) fn from_form(form: &[(String, String)]) -> Self {
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

        // Rows are collected through an index map, so gaps (a dropped row)
        // and out-of-order fields parse identically.
        let mut rename_rows: std::collections::BTreeMap<usize, RenameRow> =
            std::collections::BTreeMap::new();
        let mut drop_rows: std::collections::BTreeMap<usize, DropRow> =
            std::collections::BTreeMap::new();
        for (key, value) in form {
            let (prefix, rows): (&str, bool) = if key.starts_with("ped_rename_") {
                ("ped_rename_", true)
            } else if key.starts_with("ped_drop_") {
                ("ped_drop_", false)
            } else {
                continue;
            };
            let Some((index, field)) = key[prefix.len()..].rsplit_once('_') else {
                continue;
            };
            let Ok(index) = index.parse::<usize>() else {
                continue;
            };
            let value = value.trim().to_string();
            if rows {
                let row = rename_rows.entry(index).or_default();
                match field {
                    "match" => row.match_pattern = value,
                    "replace" => row.replace = value,
                    "flags" => row.flags = value,
                    "target" => row.target = value,
                    "key" => row.param_key = value,
                    _ => {}
                }
            } else {
                let row = drop_rows.entry(index).or_default();
                match field {
                    "match" => row.match_pattern = value,
                    "flags" => row.flags = value,
                    "target" => row.target = value,
                    "key" => row.param_key = value,
                    _ => {}
                }
            }
        }

        let (filter_set, filter_defaults) = mode_flags(&get("ped_filter"));
        let (geo_set, geo_defaults) = mode_flags(&get("ped_geo"));
        let (health_set, health_defaults) = mode_flags(&get("ped_health"));
        let (sort_set, sort_defaults) = mode_flags(&get("ped_sort"));
        let rename_mode = get("ped_rename");
        let drop_mode = get("ped_drop");

        Self {
            filter_set,
            filter_defaults,
            protocols: get_all("ped_filter_protocols"),
            exclude_protocols: get_all("ped_filter_exclude"),
            normalize_params: get("ped_normalize") == "1",
            rename: rename_rows.into_values().collect(),
            rename_skip: rename_mode == "skip",
            rename_defaults: rename_mode == "defaults",
            drop: drop_rows.into_values().collect(),
            drop_skip: drop_mode == "skip",
            drop_defaults: drop_mode == "defaults",
            geo_set,
            geo_defaults,
            geo_enabled: get("ped_geo_enabled") == "1",
            geo_template: get("ped_geo_template"),
            health_set,
            health_defaults,
            exclude_statuses: get_all("ped_health_exclude"),
            sort_set,
            sort_defaults,
            sort_by: get("ped_sort_by"),
            sort_desc: get("ped_sort_desc") == "1",
        }
    }

    /// Generate the pipeline JSON (PIPELINE.md §4): `version` 1 plus only the
    /// values that differ from the SPEC §5.1 defaults. A set section with no
    /// non-default value emits nothing — the preview shows the administrator
    /// the resulting (NULL) configuration, and forcing explicit defaults is
    /// what the `*_defaults` mode is for. `None` means "nothing configured":
    /// the field stores NULL (pass-through defaults), never `{}`.
    pub(crate) fn emit(&self) -> Option<serde_json::Value> {
        let mut map = serde_json::Map::new();
        map.insert("version".into(), serde_json::Value::from(1));

        if self.filter_defaults {
            map.insert(
                "filter".into(),
                serde_json::Value::Object(Default::default()),
            );
        } else if self.filter_set {
            let mut filter = serde_json::Map::new();
            if !self.protocols.is_empty() {
                filter.insert("protocols".into(), strings(&self.protocols));
            }
            if !self.exclude_protocols.is_empty() {
                filter.insert("exclude_protocols".into(), strings(&self.exclude_protocols));
            }
            if !self.normalize_params {
                filter.insert("normalize_params".into(), serde_json::Value::from(false));
            }
            if !filter.is_empty() {
                map.insert("filter".into(), filter.into());
            }
        }

        if self.rename_defaults {
            // An explicit `[]`: a profile resets the source's rename rules.
            map.insert("rename".into(), serde_json::Value::Array(Vec::new()));
        } else if !self.rename_skip {
            // Empty rows (no `match`) are work-in-progress lines of the
            // widget and never reach the JSON.
            let rules: Vec<serde_json::Value> = self
                .rename
                .iter()
                .filter(|row| !row.match_pattern.is_empty())
                .map(|row| {
                    let mut rule = serde_json::Map::new();
                    rule.insert(
                        "match".into(),
                        serde_json::Value::from(row.match_pattern.as_str()),
                    );
                    rule.insert(
                        "replace".into(),
                        serde_json::Value::from(row.replace.as_str()),
                    );
                    if !row.flags.is_empty() {
                        rule.insert("flags".into(), serde_json::Value::from(row.flags.as_str()));
                    }
                    if let Some(target) = emit_rename_target(row) {
                        rule.insert("target".into(), serde_json::Value::from(target));
                    }
                    serde_json::Value::Object(rule)
                })
                .collect();
            if !rules.is_empty() {
                map.insert("rename".into(), serde_json::Value::Array(rules));
            }
        }

        if self.drop_defaults {
            // An explicit `[]`: a profile resets the source's drop rules.
            map.insert("drop".into(), serde_json::Value::Array(Vec::new()));
        } else if !self.drop_skip {
            // Same work-in-progress contract as rename: empty `match` lines
            // never reach the JSON.
            let rules: Vec<serde_json::Value> = self
                .drop
                .iter()
                .filter(|row| !row.match_pattern.is_empty())
                .map(|row| {
                    let mut rule = serde_json::Map::new();
                    rule.insert(
                        "match".into(),
                        serde_json::Value::from(row.match_pattern.as_str()),
                    );
                    if !row.flags.is_empty() {
                        rule.insert("flags".into(), serde_json::Value::from(row.flags.as_str()));
                    }
                    if let Some(target) = row.target_value() {
                        rule.insert("target".into(), serde_json::Value::from(target));
                    }
                    serde_json::Value::Object(rule)
                })
                .collect();
            if !rules.is_empty() {
                map.insert("drop".into(), serde_json::Value::Array(rules));
            }
        }

        if self.geo_defaults {
            map.insert("geo".into(), serde_json::Value::Object(Default::default()));
        } else if self.geo_set {
            let mut geo = serde_json::Map::new();
            if !self.geo_enabled {
                geo.insert("enabled".into(), serde_json::Value::from(false));
            }
            let template = self.geo_template.trim();
            if !template.is_empty() && template != DEFAULT_GEO_TEMPLATE {
                geo.insert("template".into(), serde_json::Value::from(template));
            }
            if !geo.is_empty() {
                map.insert("geo".into(), geo.into());
            }
        }

        if self.health_defaults {
            map.insert(
                "health".into(),
                serde_json::Value::Object(Default::default()),
            );
        } else if self.health_set
            && self.exclude_statuses != crate::pipeline::default_exclude_statuses()
        {
            map.insert(
                "health".into(),
                serde_json::json!({ "exclude_statuses": self.exclude_statuses }),
            );
        }

        if self.sort_defaults {
            map.insert("sort".into(), serde_json::Value::Object(Default::default()));
        } else if self.sort_set {
            let mut sort = serde_json::Map::new();
            let by = SortBy::ALL
                .iter()
                .find(|sort| sort.as_str() == self.sort_by)
                .copied();
            if let Some(by) = by
                && by != SortBy::Source
            {
                sort.insert("by".into(), serde_json::Value::from(by.as_str()));
            }
            if self.sort_desc {
                sort.insert("desc".into(), serde_json::Value::from(true));
            }
            if !sort.is_empty() {
                map.insert("sort".into(), sort.into());
            }
        }

        if map.len() == 1 {
            None // only "version" — nothing configured
        } else {
            Some(serde_json::Value::Object(map))
        }
    }

    /// Canonical round-trip (PIPELINE.md §10): rebuilding the state from the
    /// emitted JSON and emitting again produces the same JSON. Holds for
    /// every state, including degenerate ones (a set section with no
    /// non-default value collapses in the first emit).
    #[cfg(test)]
    fn emit_is_idempotent(&self) -> bool {
        match self.emit() {
            None => true, // NULL stays NULL
            Some(json) => match BuilderState::ingest(Some(&json)) {
                Ingest::Builder(rebuilt) => rebuilt.emit() == Some(json),
                Ingest::Raw => false,
            },
        }
    }
}

/// Result of [`BuilderState::ingest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ingest {
    /// The stored pipeline is fully representable by the builder fields.
    Builder(BuilderState),
    /// Structural parse failed (unknown fields, wrong types), the version is
    /// not 1, or the config means something the widget cannot express — the
    /// widget stays out of the way and the raw JSON is edited by hand;
    /// nothing is reinterpreted silently (PIPELINE.md §2.2).
    Raw,
}

impl BuilderState {
    /// Rebuild builder fields from a stored pipeline value (PIPELINE.md §4).
    /// Structural only: an unknown protocol name or an invalid regex stays in
    /// the fields and is caught by the preview/save validation, exactly as in
    /// raw mode. `NULL` and `{}` produce an empty state.
    ///
    /// Sections that are present but carry only default values map to the
    /// explicit-defaults mode: dropping them would change profile semantics
    /// (an absent section inherits the source's rule, an explicit one resets
    /// it), while emitting `{}` keeps the meaning exactly.
    pub(crate) fn ingest(value: Option<&serde_json::Value>) -> Ingest {
        let Some(value) = value else {
            return Ingest::Builder(Self::new());
        };
        match value {
            serde_json::Value::Null => return Ingest::Builder(Self::new()),
            serde_json::Value::Object(map) if map.is_empty() => {
                return Ingest::Builder(Self::new());
            }
            _ => {}
        }
        let Ok(config) = serde_json::from_value::<PipelineConfig>(value.clone()) else {
            return Ingest::Raw;
        };
        if config.version != 1 {
            return Ingest::Raw;
        }
        // An empty allowlist means "output nothing" and an empty `match`
        // pattern matches everywhere — real configs the widget cannot
        // express, so they stay in raw mode instead of flipping meaning.
        if config
            .filter
            .as_ref()
            .is_some_and(|f| f.protocols.as_ref().is_some_and(|p| p.is_empty()))
        {
            return Ingest::Raw;
        }
        if config
            .rename
            .as_ref()
            .is_some_and(|rules| rules.iter().any(|r| r.match_pattern.is_empty()))
        {
            return Ingest::Raw;
        }
        // Same raw-guard for drop: an empty `match` discards everything —
        // a real rule the widget cannot express (its empty line means
        // "not typed yet").
        if config
            .drop
            .as_ref()
            .is_some_and(|rules| rules.iter().any(|r| r.match_pattern.is_empty()))
        {
            return Ingest::Raw;
        }
        let mut state = Self::new();

        if let Some(filter) = config.filter {
            let has_values = filter.protocols.as_ref().is_some_and(|p| !p.is_empty())
                || filter
                    .exclude_protocols
                    .as_ref()
                    .is_some_and(|p| !p.is_empty())
                || !filter.normalize_params;
            if has_values {
                state.filter_set = true;
                state.protocols = filter.protocols.unwrap_or_default();
                state.exclude_protocols = filter.exclude_protocols.unwrap_or_default();
                state.normalize_params = filter.normalize_params;
            } else {
                state.filter_defaults = true;
            }
        }
        if let Some(rules) = config.rename {
            if rules.is_empty() {
                state.rename_defaults = true;
            } else {
                state.rename = rules
                    .into_iter()
                    .map(|rule: RenameRule| {
                        // Split the `param:KEY` form back into the select
                        // value and the key field; `name` (or the absent
                        // target) is the select's default.
                        let (target, param_key) = match rule.target.as_deref() {
                            None | Some("name") => (String::new(), String::new()),
                            Some(raw) => match raw.strip_prefix("param:") {
                                Some(key) => ("param".to_string(), key.to_string()),
                                None => (raw.to_string(), String::new()),
                            },
                        };
                        RenameRow {
                            match_pattern: rule.match_pattern,
                            replace: rule.replace,
                            flags: rule.flags,
                            target,
                            param_key,
                        }
                    })
                    .collect();
            }
        }
        if let Some(rules) = config.drop {
            if rules.is_empty() {
                state.drop_defaults = true;
            } else {
                state.drop = rules
                    .into_iter()
                    .map(|rule: DropRule| {
                        // The same target split as rename rows.
                        let (target, param_key) = match rule.target.as_deref() {
                            None | Some("name") => (String::new(), String::new()),
                            Some(raw) => match raw.strip_prefix("param:") {
                                Some(key) => ("param".to_string(), key.to_string()),
                                None => (raw.to_string(), String::new()),
                            },
                        };
                        DropRow {
                            match_pattern: rule.match_pattern,
                            flags: rule.flags,
                            target,
                            param_key,
                        }
                    })
                    .collect();
            }
        }
        if let Some(geo) = config.geo {
            let template = geo.template.trim();
            let has_values =
                !geo.enabled || (!template.is_empty() && template != DEFAULT_GEO_TEMPLATE);
            if has_values {
                state.geo_set = true;
                state.geo_enabled = geo.enabled;
                // The SPEC default template is shown as the empty value: the
                // field's placeholder carries it and emit never writes it out.
                if template != DEFAULT_GEO_TEMPLATE {
                    state.geo_template = geo.template;
                }
            } else {
                state.geo_defaults = true;
            }
        }
        if let Some(health) = config.health {
            if health.exclude_statuses != crate::pipeline::default_exclude_statuses() {
                state.health_set = true;
                state.exclude_statuses = health.exclude_statuses;
            } else {
                state.health_defaults = true;
            }
        }
        if let Some(sort) = config.sort {
            if sort.by != SortBy::Source || sort.desc {
                state.sort_set = true;
                state.sort_by = sort.by.as_str().to_string();
                state.sort_desc = sort.desc;
            } else {
                state.sort_defaults = true;
            }
        }
        // `dedup` has no builder field: in v1 it only accepts `by:
        // "fingerprint"`, which is semantically the default, so emit
        // canonicalizes it away.
        Ingest::Builder(state)
    }
}

/// Everything the builder part of the widget renders: the state plus
/// precomputed `(value, is_selected)` option rows so the askama template
/// stays dumb. The list columns may also carry values the validator will
/// reject (an unknown protocol/status typed or imported): they render as
/// extra checked rows instead of silently disappearing — the administrator
/// sees exactly what will be reported and can uncheck or replace it.
#[derive(Debug, Clone)]
pub(crate) struct BuilderView {
    pub state: BuilderState,
    pub protocols: Vec<(String, bool)>,
    pub statuses: Vec<(String, bool)>,
    pub sort_options: Vec<(&'static str, bool)>,
}

impl BuilderView {
    /// Render view for a state; rename rows always show at least one empty
    /// line so the widget offers a place to start typing.
    pub(crate) fn new(state: &BuilderState) -> Self {
        // Schema options first, then any selected value outside the schema —
        // it must stay visible (and stay checked) until the admin acts.
        let mut protocols: Vec<(String, bool)> = Schema::protocols()
            .into_iter()
            .map(|name| (name.to_string(), any_of(&state.protocols, name)))
            .collect();
        append_outsiders(&mut protocols, &state.protocols);
        let mut statuses: Vec<(String, bool)> = Schema::statuses()
            .into_iter()
            .map(|name| (name.to_string(), any_of(&state.exclude_statuses, name)))
            .collect();
        append_outsiders(&mut statuses, &state.exclude_statuses);
        Self {
            protocols,
            statuses,
            sort_options: Schema::sort_options()
                .into_iter()
                .map(|name| (name, state.sort_by == name))
                .collect(),
            state: BuilderState {
                rename: display_rows(&state.rename),
                drop: display_rows(&state.drop),
                ..state.clone()
            },
        }
    }

    /// The SPEC §5.1 geo template, shown as the template field's placeholder:
    /// an empty field means "default" and is never emitted.
    pub(crate) fn default_geo_template(&self) -> &'static str {
        crate::pipeline::DEFAULT_GEO_TEMPLATE
    }

    /// The placeholder registry joined for the template hint (PIPELINE.md
    /// §5): when Phase 4 extends the registry, the hint follows on its own.
    pub(crate) fn geo_placeholders(&self) -> String {
        Schema::geo_placeholders().join(" ")
    }
}

fn any_of(values: &[String], name: &str) -> bool {
    values.iter().any(|v| v == name)
}

/// Append the selected values that are not part of the schema list, so an
/// unknown (validator-rejecting) value stays visible and checked in the
/// widget instead of silently dropping out (PIPELINE.md §4: the builder
/// holds such values; the preview and save report them).
fn append_outsiders(rows: &mut Vec<(String, bool)>, selected: &[String]) {
    for value in selected {
        if !rows.iter().any(|(name, _)| name == value) {
            rows.push((value.clone(), true));
        }
    }
}

/// Rule rows to display: at least one empty line (rename and drop alike).
pub(crate) fn display_rows<Row: Default + Clone>(rows: &[Row]) -> Vec<Row> {
    if rows.is_empty() {
        vec![Row::default()]
    } else {
        rows.to_vec()
    }
}

/// UI descriptor of the pipeline v1 schema (PIPELINE.md §5). Every list is
/// sourced from the validator's own enums.
pub(crate) struct Schema;

impl Schema {
    pub(crate) fn protocols() -> Vec<&'static str> {
        Scheme::all().iter().map(|s| s.as_str()).collect()
    }

    pub(crate) fn statuses() -> Vec<&'static str> {
        ProxyStatus::ALL.iter().map(|s| s.as_str()).collect()
    }

    pub(crate) fn sort_options() -> Vec<&'static str> {
        SortBy::ALL.iter().map(|s| s.as_str()).collect()
    }

    /// Geo template placeholders (SPEC §5.1). Phase 4 extends this registry
    /// with `{city} {asn} {asn_org}` — one constant, no other changes.
    pub(crate) fn geo_placeholders() -> [&'static str; 3] {
        ["{flag}", "{country}", "{name}"]
    }
}

fn strings(values: &[String]) -> serde_json::Value {
    serde_json::Value::Array(
        values
            .iter()
            .map(|value| serde_json::Value::from(value.as_str()))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Widget rendering (PIPELINE.md §3)
// ---------------------------------------------------------------------------

/// `#ped-preview` content: the generated JSON plus its validation outcome
/// (the same `CompiledPipeline::from_json` the save path uses).
#[derive(Template)]
#[template(path = "pipeline/_preview.html")]
pub(crate) struct PreviewFragment {
    pub lang: Lang,
    pub json: Option<String>,
    pub valid: bool,
    pub errors: Vec<String>,
}

impl_i18n!(PreviewFragment);

/// Render the preview body for a state — the preview endpoint's response and
/// the initial content of the widget's preview area share it.
pub(crate) fn preview_body(lang: &Lang, built: &BuilderState) -> String {
    let fragment = match built.emit() {
        None => PreviewFragment {
            lang: lang.clone(),
            json: None,
            valid: false,
            errors: Vec::new(),
        },
        Some(value) => {
            let json = serde_json::to_string_pretty(&value).unwrap_or_default();
            match crate::pipeline::CompiledPipeline::from_json(Some(&value)) {
                Ok(_) => PreviewFragment {
                    lang: lang.clone(),
                    json: Some(json),
                    valid: true,
                    errors: Vec::new(),
                },
                Err(issues) => PreviewFragment {
                    lang: lang.clone(),
                    json: Some(json),
                    valid: false,
                    errors: issues
                        .iter()
                        .map(|issue| lang.t_args(issue.key, &issue.args))
                        .collect(),
                },
            }
        }
    };
    fragment.render().unwrap_or_default()
}

/// `#ped-rows` / `#ped-drop-rows` content: the rule lines of one section
/// after add/remove. `section` is `"rename"` or `"drop"` — the template
/// picks the row set, the field prefix and the section's own container id.
#[derive(Template)]
#[template(path = "pipeline/_rows.html")]
pub(crate) struct RowsFragment {
    pub lang: Lang,
    pub builder: BuilderView,
    pub section: &'static str,
}

impl RowsFragment {
    /// The fragment for a section name, clamped to the two known sections.
    pub(crate) fn for_section(lang: Lang, builder: BuilderView, section: &str) -> Self {
        let section = match section {
            "drop" => "drop",
            _ => "rename",
        };
        Self {
            lang,
            builder,
            section,
        }
    }
}

impl_i18n!(RowsFragment);

/// The whole pipeline widget (PIPELINE.md §3): the mode switch (builder ⇄
/// raw), presets, the builder fields with their preview — or the raw JSON
/// textarea. Rendered into the source/profile forms at construction time and
/// swapped by the `mode`/`preset` endpoints; `pipeline_mode` tells the save
/// path which representation is authoritative.
#[derive(Template)]
#[template(path = "pipeline/_widget.html")]
pub(crate) struct WidgetFragment {
    pub lang: Lang,
    pub builder: BuilderView,
    /// `"builder"` or `"raw"` — the `pipeline_mode` value of the form.
    pub mode: &'static str,
    /// Raw-mode textarea content.
    pub pipeline_value: String,
    pub csrf: String,
    /// Localized pipeline validation error to show next to the fields.
    pub error: Option<String>,
    /// Raw mode was entered because the stored JSON is not representable
    /// (PIPELINE.md §2.2) — the template shows the warning.
    pub raw_warning: bool,
    /// Profile form: tri-state section controls (inherit / defaults / set).
    pub profile: bool,
    /// Pre-rendered `#ped-preview` content (builder mode).
    pub preview_html: String,
}

impl_i18n!(WidgetFragment);

impl WidgetFragment {
    pub(crate) fn builder_mode(
        lang: Lang,
        csrf: &str,
        built: &BuilderState,
        profile: bool,
        error: Option<String>,
    ) -> Self {
        Self {
            preview_html: preview_body(&lang, built),
            builder: BuilderView::new(built),
            mode: "builder",
            pipeline_value: String::new(),
            csrf: csrf.to_string(),
            error,
            raw_warning: false,
            profile,
            lang,
        }
    }

    pub(crate) fn raw_mode(
        lang: Lang,
        csrf: &str,
        pipeline_value: String,
        warning: bool,
        error: Option<String>,
    ) -> Self {
        Self {
            builder: BuilderView::new(&BuilderState::new()),
            mode: "raw",
            pipeline_value,
            csrf: csrf.to_string(),
            error,
            raw_warning: warning,
            profile: false,
            preview_html: String::new(),
            lang,
        }
    }

    /// Rendered widget HTML (embedded into the form via `| safe`; everything
    /// inside is server-generated and escaped by askama).
    pub(crate) fn html(self) -> String {
        self.render().unwrap_or_default()
    }
}

/// Widget HTML for a form: prefill from the stored pipeline when the builder
/// can represent it, otherwise raw mode with the warning (PIPELINE.md §2.2).
pub(crate) fn widget_from_stored(
    lang: Lang,
    csrf: &str,
    stored: Option<&serde_json::Value>,
    raw_value: String,
    profile: bool,
) -> String {
    match BuilderState::ingest(stored) {
        Ingest::Builder(built) => WidgetFragment::builder_mode(lang, csrf, &built, profile, None),
        Ingest::Raw => WidgetFragment::raw_mode(lang, csrf, raw_value, true, None),
    }
    .html()
}

/// Widget HTML for a failed form submission: reopen in the posted mode with
/// the posted values (`pipeline_mode=builder` keeps the builder fields).
pub(crate) fn widget_from_posted(
    lang: Lang,
    csrf: &str,
    form: &[(String, String)],
    profile: bool,
    error: Option<String>,
) -> String {
    let get = |key: &str| {
        form.iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    if get("pipeline_mode") == "builder" {
        WidgetFragment::builder_mode(lang, csrf, &BuilderState::from_form(form), profile, error)
    } else {
        WidgetFragment::raw_mode(lang, csrf, get("pipeline"), false, error)
    }
    .html()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn state() -> BuilderState {
        BuilderState::new()
    }

    fn set(name: &str, values: &[&str]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|v| (name.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_state_emits_none() {
        assert_eq!(state().emit(), None);
        // Only the toggle without any non-default value is still NULL.
        let mut s = state();
        s.filter_set = true;
        s.geo_set = true;
        s.sort_set = true;
        assert_eq!(s.emit(), None);
    }

    #[test]
    fn emit_writes_only_non_default_values() {
        let mut s = state();
        s.filter_set = true;
        s.protocols = vec!["vless".into(), "trojan".into()];
        s.normalize_params = false;
        s.geo_set = true;
        s.geo_enabled = false;
        s.geo_template = "{asn} · {name}".into();
        s.health_set = true;
        s.exclude_statuses = vec!["removed".into()];
        s.sort_set = true;
        s.sort_by = "latency".into();
        s.sort_desc = true;

        assert_eq!(
            s.emit(),
            Some(json!({
                "version": 1,
                "filter": {
                    "protocols": ["vless", "trojan"],
                    "normalize_params": false
                },
                "geo": { "enabled": false, "template": "{asn} · {name}" },
                "health": { "exclude_statuses": ["removed"] },
                "sort": { "by": "latency", "desc": true }
            }))
        );
        // Everything the emit produced must pass the real validator.
        assert!(crate::pipeline::CompiledPipeline::from_json(s.emit().as_ref()).is_ok());
    }

    #[test]
    fn emit_skips_default_equal_values_and_empty_rename_rows() {
        let mut s = state();
        s.filter_set = true;
        s.protocols = vec!["ss".into()];
        s.normalize_params = true; // default — not emitted
        s.geo_set = true;
        s.geo_template = "{flag} {country} · {name}".into(); // default — not emitted
        s.rename = vec![
            RenameRow::default(), // empty — skipped
            RenameRow {
                match_pattern: "^free".into(),
                replace: String::new(),
                flags: "i".into(),
                ..RenameRow::default()
            },
        ];
        assert_eq!(
            s.emit(),
            Some(json!({
                "version": 1,
                "filter": { "protocols": ["ss"] },
                "rename": [{ "match": "^free", "replace": "", "flags": "i" }]
            }))
        );
    }

    #[test]
    fn emit_writes_the_target_and_ingest_splits_it_back() {
        let mut s = state();
        s.rename = vec![
            // name stays implicit — the schema default, never emitted.
            RenameRow {
                match_pattern: "a".into(),
                replace: "b".into(),
                target: "name".into(),
                param_key: String::new(),
                flags: String::new(),
            },
            RenameRow {
                match_pattern: "server1\\.tr$".into(),
                replace: "invalid.tr".into(),
                target: "host".into(),
                param_key: String::new(),
                flags: String::new(),
            },
            RenameRow {
                match_pattern: "^chrome$".into(),
                replace: "firefox".into(),
                target: "param".into(),
                param_key: "fp".into(),
                flags: String::new(),
            },
        ];
        assert_eq!(
            s.emit(),
            Some(json!({
                "version": 1,
                "rename": [
                    { "match": "a", "replace": "b" },
                    { "match": "server1\\.tr$", "replace": "invalid.tr", "target": "host" },
                    { "match": "^chrome$", "replace": "firefox", "target": "param:fp" }
                ]
            }))
        );
        // …and the emitted JSON rebuilds the same split form — `name`, the
        // schema default, comes back as the select's implicit value ("").
        let Some(json) = s.emit() else {
            panic!("must emit")
        };
        let Ingest::Builder(rebuilt) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse")
        };
        assert_eq!(
            rebuilt.rename[0],
            RenameRow {
                match_pattern: "a".into(),
                replace: "b".into(),
                target: String::new(),
                param_key: String::new(),
                flags: String::new(),
            }
        );
        assert_eq!(rebuilt.rename[1], s.rename[1]);
        assert_eq!(rebuilt.rename[2], s.rename[2]);
    }

    #[test]
    fn emit_holds_values_the_validator_flags() {
        // A param row without a key and an unknown selector both emit as-is:
        // the preview reports them, nothing is silently reinterpreted.
        let mut s = state();
        s.rename = vec![
            RenameRow {
                match_pattern: "a".into(),
                replace: "b".into(),
                target: "param".into(),
                param_key: String::new(),
                flags: String::new(),
            },
            RenameRow {
                match_pattern: "c".into(),
                replace: "d".into(),
                target: "bogus".into(),
                param_key: String::new(),
                flags: String::new(),
            },
        ];
        let json = s.emit().unwrap();
        assert_eq!(json["rename"][0]["target"], json!("param:"));
        assert_eq!(json["rename"][1]["target"], json!("bogus"));
        assert!(crate::pipeline::CompiledPipeline::from_json(Some(&json)).is_err());
    }

    #[test]
    fn from_form_parses_the_target_fields() {
        let form: Vec<(String, String)> = [
            ("ped_rename_0_match".into(), "chrome".into()),
            ("ped_rename_0_replace".into(), "firefox".into()),
            ("ped_rename_0_target".into(), "param".into()),
            ("ped_rename_0_key".into(), "fp".into()),
            ("ped_rename_1_match".into(), "server1".into()),
            ("ped_rename_1_replace".into(), "server2".into()),
            ("ped_rename_1_target".into(), "host".into()),
        ]
        .into_iter()
        .collect();
        let s = BuilderState::from_form(&form);
        assert_eq!(
            s.rename,
            vec![
                RenameRow {
                    match_pattern: "chrome".into(),
                    replace: "firefox".into(),
                    target: "param".into(),
                    param_key: "fp".into(),
                    flags: String::new(),
                },
                RenameRow {
                    match_pattern: "server1".into(),
                    replace: "server2".into(),
                    target: "host".into(),
                    param_key: String::new(),
                    flags: String::new(),
                },
            ]
        );
        assert_eq!(
            s.emit(),
            Some(json!({
                "version": 1,
                "rename": [
                    { "match": "chrome", "replace": "firefox", "target": "param:fp" },
                    { "match": "server1", "replace": "server2", "target": "host" }
                ]
            }))
        );
    }

    #[test]
    fn drop_section_emits_and_ingests_back() {
        let mut s = state();
        s.drop = vec![
            DropRow {
                match_pattern: "free|trial".into(),
                target: String::new(), // name — implicit
                param_key: String::new(),
                flags: "i".into(),
            },
            DropRow {
                match_pattern: "\\.cn$".into(),
                target: "host".into(),
                param_key: String::new(),
                flags: String::new(),
            },
        ];
        assert_eq!(
            s.emit(),
            Some(json!({
                "version": 1,
                "drop": [
                    { "match": "free|trial", "flags": "i" },
                    { "match": "\\.cn$", "target": "host" }
                ]
            }))
        );
        let Some(json) = s.emit() else {
            panic!("must emit")
        };
        let Ingest::Builder(rebuilt) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert_eq!(rebuilt.drop, s.drop);
        assert!(crate::pipeline::CompiledPipeline::from_json(Some(&json)).is_ok());
    }

    #[test]
    fn drop_explicit_defaults_and_tri_state_round_trip() {
        // `drop: []` in a profile resets the source's rules — the same
        // profile semantics as rename.
        let mut s = state();
        s.drop_defaults = true;
        let Some(json) = s.emit() else {
            panic!("must emit")
        };
        assert_eq!(json["drop"], json!([]));
        let Ingest::Builder(rebuilt) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert!(rebuilt.drop_defaults && rebuilt.drop.is_empty());

        // The tri-state radios parse the same way as rename's.
        let form = vec![("ped_drop".into(), "skip".into())];
        let s = BuilderState::from_form(&form);
        assert!(s.drop_skip && !s.drop_defaults);
    }

    #[test]
    fn from_form_parses_drop_rows_with_gaps_and_unknown_selector() {
        let form: Vec<(String, String)> = [
            ("ped_drop_1_match".into(), "\\.cn$".into()),
            ("ped_drop_1_target".into(), "host".into()),
            ("ped_drop_0_match".into(), "free".into()),
            ("ped_drop_0_flags".into(), "i".into()),
            ("ped_drop_0_target".into(), "param".into()),
            ("ped_drop_0_key".into(), "fp".into()),
            ("ped_rename_0_match".into(), "unrelated".into()),
        ]
        .into_iter()
        .collect();
        let s = BuilderState::from_form(&form);
        assert_eq!(
            s.drop,
            vec![
                DropRow {
                    match_pattern: "free".into(),
                    flags: "i".into(),
                    target: "param".into(),
                    param_key: "fp".into(),
                },
                DropRow {
                    match_pattern: "\\.cn$".into(),
                    flags: String::new(),
                    target: "host".into(),
                    param_key: String::new(),
                },
            ]
        );
        // The rename rows are untouched by the drop fields.
        assert_eq!(s.rename.len(), 1);
        assert_eq!(s.rename[0].match_pattern, "unrelated");
        let emitted = s.emit().unwrap();
        assert_eq!(
            emitted["drop"],
            json!([
                { "match": "free", "flags": "i", "target": "param:fp" },
                { "match": "\\.cn$", "target": "host" }
            ])
        );
    }

    #[test]
    fn ingest_sends_drop_rules_with_empty_match_to_raw_mode() {
        // An empty `match` discards everything — a real config the widget
        // cannot express; raw mode keeps it editable as JSON.
        let json = json!({ "version": 1, "drop": [{ "match": "" }] });
        assert_eq!(BuilderState::ingest(Some(&json)), Ingest::Raw);
    }

    #[test]
    fn emit_dedup_default_sort_and_health_stay_silent() {
        let mut s = state();
        s.health_set = true;
        s.exclude_statuses = vec!["quarantine".into(), "removed".into()]; // == default
        s.sort_set = true;
        s.sort_by = "source".into();
        s.sort_desc = false;
        assert_eq!(s.emit(), None);
    }

    #[test]
    fn emit_explicit_defaults_for_profiles() {
        let mut s = state();
        s.filter_defaults = true;
        s.rename_defaults = true;
        s.geo_defaults = true;
        s.health_defaults = true;
        s.sort_defaults = true;
        assert_eq!(
            s.emit(),
            Some(json!({
                "version": 1,
                "filter": {},
                "rename": [],
                "geo": {},
                "health": {},
                "sort": {}
            }))
        );
        // Every empty section is valid for the real validator.
        assert!(crate::pipeline::CompiledPipeline::from_json(s.emit().as_ref()).is_ok());
    }

    #[test]
    fn emit_rename_skip_ignores_the_rows() {
        let mut s = state();
        s.rename_skip = true;
        s.rename = vec![RenameRow {
            match_pattern: "x".into(),
            replace: "y".into(),
            flags: String::new(),
            ..RenameRow::default()
        }];
        s.filter_set = true;
        s.protocols = vec!["vless".into()];
        assert_eq!(
            s.emit(),
            Some(json!({ "version": 1, "filter": { "protocols": ["vless"] } }))
        );
    }

    #[test]
    fn from_form_parses_every_field() {
        let form: Vec<(String, String)> = [
            set("ped_filter", &["1"]),
            set("ped_filter_protocols", &["vless", "trojan"]),
            set("ped_filter_exclude", &["naive"]),
            vec![("ped_normalize".to_string(), "1".to_string())],
            vec![
                ("ped_rename_1_match".to_string(), "b".to_string()),
                ("ped_rename_1_replace".to_string(), "B".to_string()),
            ],
            vec![
                ("ped_rename_0_match".to_string(), "a".to_string()),
                ("ped_rename_0_flags".to_string(), "i".to_string()),
            ],
            set("ped_geo", &["1"]),
            vec![("ped_geo_template".to_string(), "{asn} · {name}".to_string())],
            set("ped_health", &["1"]),
            set("ped_health_exclude", &["alive"]),
            set("ped_sort", &["1"]),
            vec![("ped_sort_by".to_string(), "country".to_string())],
            set("ped_sort_desc", &["1"]),
            vec![("name".to_string(), "не поле конструктора".to_string())],
        ]
        .into_iter()
        .flatten()
        .collect();

        let s = BuilderState::from_form(&form);
        assert!(s.filter_set && !s.filter_defaults);
        assert_eq!(s.protocols, ["vless", "trojan"]);
        assert_eq!(s.exclude_protocols, ["naive"]);
        assert!(s.normalize_params);
        // Rows are ordered by index, not by form order; missing fields are empty.
        assert_eq!(
            s.rename,
            vec![
                RenameRow {
                    match_pattern: "a".into(),
                    replace: String::new(),
                    flags: "i".into(),
                    ..RenameRow::default()
                },
                RenameRow {
                    match_pattern: "b".into(),
                    replace: "B".into(),
                    flags: String::new(),
                    ..RenameRow::default()
                },
            ]
        );
        assert!(s.geo_set && !s.geo_enabled);
        assert_eq!(s.geo_template, "{asn} · {name}");
        assert!(s.health_set);
        assert_eq!(s.exclude_statuses, ["alive"]);
        assert!(s.sort_set && s.sort_desc);
        assert_eq!(s.sort_by, "country");
    }

    #[test]
    fn from_form_parses_the_tri_state_radios() {
        let form: Vec<(String, String)> = [
            vec![("ped_filter".into(), "defaults".into())],
            vec![("ped_geo".into(), "set".into())],
            vec![("ped_health".into(), "skip".into())],
            vec![
                ("ped_sort".into(), "set".into()),
                ("ped_sort_by".into(), "name".into()),
            ],
            vec![("ped_rename".into(), "defaults".into())],
        ]
        .into_iter()
        .flatten()
        .collect();

        let s = BuilderState::from_form(&form);
        assert!(s.filter_defaults && !s.filter_set);
        assert!(s.geo_set && !s.geo_defaults);
        assert!(!s.health_set && !s.health_defaults, "skip = inherit");
        assert!(s.sort_set && s.sort_by == "name");
        assert!(s.rename_defaults && !s.rename_skip);
    }

    #[test]
    fn from_form_without_fields_is_a_clean_slate() {
        // No `ped_*` fields at all: every checkbox unchecked, every list
        // empty — the emit is NULL, exactly like an untouched widget.
        let s = BuilderState::from_form(&[("name".into(), "x".into())]);
        assert!(!s.filter_set && !s.geo_set && !s.health_set && !s.sort_set);
        assert!(!s.normalize_params && !s.geo_enabled && !s.sort_desc);
        assert!(s.rename.is_empty());
        assert_eq!(s.emit(), None);
        // A rendered widget starts from different defaults — the SPEC ones.
        let fresh = BuilderState::new();
        assert!(fresh.normalize_params && fresh.geo_enabled);
        assert_eq!(fresh.exclude_statuses, ["quarantine", "removed"]);
    }

    #[test]
    fn ingest_empty_values_are_an_empty_state() {
        for value in [None, Some(&json!(null)), Some(&json!({}))] {
            let ingest = BuilderState::ingest(value);
            assert_eq!(ingest, Ingest::Builder(BuilderState::new()), "{value:?}");
        }
    }

    #[test]
    fn ingest_rebuilds_every_section() {
        let json = json!({
            "version": 1,
            "filter": { "protocols": ["vless"], "exclude_protocols": ["ss"], "normalize_params": false },
            "rename": [{ "match": "^x", "replace": "y", "flags": "im" }],
            "geo": { "enabled": false, "template": "{asn} · {name}" },
            "health": { "exclude_statuses": ["alive", "unknown"] },
            "sort": { "by": "name", "desc": true }
        });
        let Ingest::Builder(s) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert!(s.filter_set);
        assert_eq!(s.protocols, ["vless"]);
        assert_eq!(s.exclude_protocols, ["ss"]);
        assert!(!s.normalize_params);
        assert_eq!(s.rename.len(), 1);
        assert_eq!(s.rename[0].match_pattern, "^x");
        assert_eq!(s.rename[0].flags, "im");
        assert!(s.geo_set && !s.geo_enabled);
        assert_eq!(s.geo_template, "{asn} · {name}");
        assert!(s.health_set);
        assert_eq!(s.exclude_statuses, ["alive", "unknown"]);
        assert!(s.sort_set && s.sort_desc);
        assert_eq!(s.sort_by, "name");

        // And the rebuilt state emits the same JSON back.
        assert_eq!(s.emit().unwrap(), json);
    }

    #[test]
    fn ingest_maps_default_valued_sections_to_explicit_defaults() {
        // `{}` and sections carrying only default values must survive a
        // profile round-trip: dropping them would make the profile inherit
        // the source's rule instead of resetting it (PIPELINE.md §6).
        let json = json!({
            "version": 1,
            "filter": {},
            "rename": [],
            "geo": { "enabled": true, "template": "{flag} {country} · {name}" },
            "health": { "exclude_statuses": ["quarantine", "removed"] },
            "sort": { "by": "source" }
        });
        let Ingest::Builder(s) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert!(s.filter_defaults && !s.filter_set);
        assert!(s.rename_defaults);
        assert!(s.geo_defaults && !s.geo_set);
        assert!(s.health_defaults && !s.health_set);
        assert!(s.sort_defaults && !s.sort_set);
        // Emitting produces the canonical form: same effective values (the
        // defaults the sections carried), without spelling them out.
        assert_eq!(
            s.emit().unwrap(),
            json!({
                "version": 1,
                "filter": {},
                "rename": [],
                "geo": {},
                "health": {},
                "sort": {}
            })
        );
    }

    #[test]
    fn ingest_hides_the_default_template_inside_a_set_section() {
        let json = json!({
            "version": 1,
            "geo": { "enabled": false, "template": "{flag} {country} · {name}" }
        });
        let Ingest::Builder(s) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert!(s.geo_set && !s.geo_enabled);
        assert_eq!(s.geo_template, "");
        assert_eq!(
            s.emit().unwrap(),
            json!({ "version": 1, "geo": { "enabled": false } })
        );
    }

    #[test]
    fn ingest_unknown_structure_falls_back_to_raw() {
        let unknown_field = json!({ "version": 1, "bogus": true });
        assert_eq!(BuilderState::ingest(Some(&unknown_field)), Ingest::Raw);

        let bad_type = json!({ "version": 1, "filter": { "protocols": "vless" } });
        assert_eq!(BuilderState::ingest(Some(&bad_type)), Ingest::Raw);

        let version2 = json!({ "version": 2 });
        assert_eq!(BuilderState::ingest(Some(&version2)), Ingest::Raw);

        let bad_rename = json!({ "version": 1, "rename": [{ "match": "x" }] }); // no replace
        assert_eq!(BuilderState::ingest(Some(&bad_rename)), Ingest::Raw);
    }

    #[test]
    fn ingest_rejects_configs_the_builder_cannot_represent() {
        // An empty allowlist means "output nothing"; dropping it would allow
        // everything — raw mode instead of silent reinterpretation.
        let empty_allowlist = json!({ "version": 1, "filter": { "protocols": [] } });
        assert_eq!(BuilderState::ingest(Some(&empty_allowlist)), Ingest::Raw);

        // An empty `match` pattern matches everywhere — a real rule the
        // widget cannot express (its empty row means "not typed yet").
        let empty_pattern = json!({ "version": 1, "rename": [{ "match": "", "replace": "x" }] });
        assert_eq!(BuilderState::ingest(Some(&empty_pattern)), Ingest::Raw);
    }

    #[test]
    fn ingest_keeps_values_the_validator_will_flag() {
        // Unknown names are structural strings — the builder holds them and
        // the preview/save validation reports them (PIPELINE.md §4).
        let json = json!({
            "version": 1,
            "filter": { "protocols": ["quantum"] },
            "health": { "exclude_statuses": ["sleeping"] },
            "rename": [{ "match": "(", "replace": "" }]
        });
        let Ingest::Builder(s) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert_eq!(s.protocols, ["quantum"]);
        assert_eq!(s.exclude_statuses, ["sleeping"]);
        assert_eq!(s.rename[0].match_pattern, "(");
        // Emitting them back produces the same JSON, which the validator rejects.
        let emitted = s.emit().unwrap();
        assert!(crate::pipeline::CompiledPipeline::from_json(Some(&emitted)).is_err());
    }

    #[test]
    fn ingest_canonicalizes_dedup_away() {
        let json = json!({ "version": 1, "dedup": { "by": "fingerprint" } });
        let Ingest::Builder(s) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert_eq!(s, BuilderState::new()); // nothing to configure
        assert_eq!(s.emit(), None); // NULL is the equivalent config
    }

    #[test]
    fn round_trip_ingest_emit_is_idempotent_for_every_state() {
        let mut states = Vec::new();
        states.push(state());

        let mut filter_only = state();
        filter_only.filter_set = true;
        states.push(filter_only);

        let mut degenerate = state();
        degenerate.filter_set = true;
        degenerate.geo_set = true; // toggled, but no non-default values
        degenerate.health_set = true;
        degenerate.rename = vec![RenameRow::default()];
        states.push(degenerate);

        let mut tri_state = state();
        tri_state.filter_defaults = true;
        tri_state.health_set = true;
        tri_state.exclude_statuses = vec!["alive".into()];
        tri_state.sort_defaults = true;
        states.push(tri_state);

        let mut everything = state();
        everything.filter_set = true;
        everything.protocols = vec!["vless".into()];
        everything.exclude_protocols = vec!["ss".into()];
        everything.normalize_params = false;
        everything.rename = vec![RenameRow {
            match_pattern: "^(.*?)\\s*\\|".into(),
            replace: "$1".into(),
            flags: "i".into(),
            ..RenameRow::default()
        }];
        everything.geo_set = true;
        everything.geo_enabled = false;
        everything.geo_template = "{country} · {name}".into();
        everything.health_set = true;
        everything.exclude_statuses = vec!["alive".into()];
        everything.sort_set = true;
        everything.sort_by = "country".into();
        everything.sort_desc = true;
        states.push(everything);

        for s in &states {
            assert!(s.emit_is_idempotent(), "{s:?}");
        }
    }

    #[test]
    fn round_trip_through_ingest_returns_the_state() {
        // For states whose set sections carry non-default values the
        // rebuild is exact.
        let mut s = state();
        s.filter_set = true;
        s.protocols = vec!["vless".into()];
        s.normalize_params = false;
        s.rename = vec![RenameRow {
            match_pattern: "free".into(),
            replace: "FREE".into(),
            flags: String::new(),
            ..RenameRow::default()
        }];
        s.geo_set = true;
        s.geo_enabled = false;
        s.health_set = true;
        s.exclude_statuses = vec!["alive".into()];
        s.sort_set = true;
        s.sort_by = "latency".into();

        let Some(json) = s.emit() else {
            panic!("must emit");
        };
        let Ingest::Builder(rebuilt) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert_eq!(rebuilt, s);
    }

    #[test]
    fn round_trip_keeps_explicit_defaults() {
        let mut s = state();
        s.filter_defaults = true;
        s.health_set = true;
        s.exclude_statuses = vec!["alive".into()];
        s.rename_defaults = true;

        let Some(json) = s.emit() else {
            panic!("must emit");
        };
        let Ingest::Builder(rebuilt) = BuilderState::ingest(Some(&json)) else {
            panic!("must parse");
        };
        assert_eq!(rebuilt, s);
    }

    #[test]
    fn presets_produce_valid_builder_states() {
        let workers = preset("workers");
        assert!(workers.health_set);
        assert_eq!(
            workers.exclude_statuses,
            ["unknown", "quarantine", "removed"]
        );
        assert!(crate::pipeline::CompiledPipeline::from_json(workers.emit().as_ref()).is_ok());

        let country = preset("country");
        assert!(country.geo_set);
        assert_eq!(country.geo_template, "{country} · {name}");

        let clean = preset("clean");
        assert!(clean.geo_set && !clean.geo_enabled);
        assert_eq!(clean.rename.len(), 1);

        assert_eq!(preset("blank"), BuilderState::new());
        assert_eq!(preset("nope"), BuilderState::new());
    }

    #[test]
    fn schema_lists_match_the_validator_enums() {
        assert_eq!(
            Schema::protocols(),
            [
                "vless",
                "vmess",
                "trojan",
                "ss",
                "hysteria2",
                "tuic",
                "mieru",
                "socks5",
                "naive"
            ]
        );
        assert_eq!(
            Schema::statuses(),
            ["unknown", "alive", "quarantine", "removed"]
        );
        assert_eq!(
            Schema::sort_options(),
            ["source", "name", "country", "latency"]
        );
        assert_eq!(
            Schema::geo_placeholders(),
            ["{flag}", "{country}", "{name}"]
        );
    }

    #[test]
    fn view_prefills_selections_and_always_shows_a_rename_line() {
        let mut s = state();
        s.protocols = vec!["trojan".into()];
        s.sort_by = "name".into();
        s.exclude_statuses = vec!["removed".into()];
        let view = BuilderView::new(&s);

        let trojan = view
            .protocols
            .iter()
            .find(|(name, _)| *name == "trojan")
            .unwrap();
        assert!(trojan.1);
        let vless = view
            .protocols
            .iter()
            .find(|(name, _)| *name == "vless")
            .unwrap();
        assert!(!vless.1);
        assert_eq!(
            view.statuses.iter().filter(|(_, sel)| *sel).count(),
            1,
            "only 'removed' selected"
        );
        assert_eq!(view.state.rename.len(), 1, "an empty typing line is shown");
    }

    #[test]
    fn rows_render_the_target_selector() {
        // A row with every target variant renders its select and the param
        // key field; an unknown selector stays visible as its own option.
        let lang = test_lang();
        let s = BuilderState {
            rename: vec![
                RenameRow {
                    match_pattern: "a".into(),
                    replace: "b".into(),
                    target: String::new(),
                    param_key: String::new(),
                    flags: String::new(),
                },
                RenameRow {
                    match_pattern: "chrome".into(),
                    replace: "firefox".into(),
                    target: "param".into(),
                    param_key: "fp".into(),
                    flags: String::new(),
                },
                RenameRow {
                    match_pattern: "x".into(),
                    replace: "y".into(),
                    target: "bogus".into(),
                    param_key: String::new(),
                    flags: String::new(),
                },
            ],
            drop: vec![DropRow {
                match_pattern: "\\.cn$".into(),
                target: "host".into(),
                param_key: String::new(),
                flags: String::new(),
            }],
            ..BuilderState::new()
        };
        let html = RowsFragment::for_section(lang.clone(), BuilderView::new(&s), "rename")
            .render()
            .unwrap_or_default();

        // Row 0: the implicit name default.
        assert!(html.contains(r#"<option value="name" selected"#), "{html}");
        // Row 1: param selected, its key carried in the adjacent field.
        assert!(html.contains(r#"<option value="param" selected"#), "{html}");
        assert!(html.contains(r#"value="fp""#), "{html}");
        // Row 2: an unknown selector survives as a visible option.
        assert!(html.contains(r#"<option value="bogus" selected"#), "{html}");
        // The key fields submit under the row-indexed names.
        assert!(html.contains(r#"name="ped_rename_0_target""#), "{html}");
        assert!(html.contains(r#"name="ped_rename_1_key""#), "{html}");
        assert!(html.contains(r#"name="ped_rename_2_target""#), "{html}");
        // The rename fragment never carries drop fields.
        assert!(!html.contains("ped_drop_"), "{html}");

        // The drop fragment renders its own rows: no `replace` field, the
        // drop-prefixed names, its own remove endpoint.
        let html = RowsFragment::for_section(lang, BuilderView::new(&s), "drop")
            .render()
            .unwrap_or_default();
        assert!(html.contains(r#"<option value="host" selected"#), "{html}");
        assert!(html.contains(r#"name="ped_drop_0_match""#), "{html}");
        assert!(html.contains("section=drop&amp;remove=0"), "{html}");
        assert!(!html.contains("ped_rename_"), "{html}");
        assert!(!html.contains("replace"), "{html}");
    }

    #[test]
    fn widget_builder_mode_renders_with_preview_and_raw_mode_with_warning() {
        let lang = test_lang();
        let mut s = state();
        s.filter_set = true;
        s.protocols = vec!["vless".into()];
        let widget = WidgetFragment::builder_mode(lang.clone(), "csrf-token", &s, false, None);
        let html = widget.html();
        assert!(html.contains(r#"value="builder""#), "{html}");
        assert!(html.contains("ped_filter_protocols"), "{html}");
        assert!(html.contains("Сгенерированный pipeline JSON"), "{html}");
        assert!(
            html.contains("hx-post=\"/admin/pipeline/preview\""),
            "{html}"
        );
        assert!(!html.contains(r#"value="raw""#), "{html}");

        let widget =
            WidgetFragment::raw_mode(lang, "csrf-token", "{\"version\": 1}".into(), true, None);
        let html = widget.html();
        assert!(html.contains(r#"value="raw""#), "{html}");
        assert!(html.contains("id=\"pipeline-field\""), "{html}");
        assert!(html.contains("конструктор не представляет"), "{html}");
        assert!(!html.contains("ped_filter_protocols"), "{html}");
    }

    #[test]
    fn widget_from_posted_restores_the_posted_mode() {
        let lang = test_lang();
        let form = vec![
            ("pipeline_mode".into(), "builder".into()),
            ("ped_filter".into(), "1".into()),
            ("ped_filter_protocols".into(), "trojan".into()),
            ("pipeline".into(), "stale".into()),
        ];
        let html = widget_from_posted(lang.clone(), "c", &form, false, None);
        assert!(html.contains(r#"value="builder""#), "{html}");
        assert!(
            html.contains(r#"value="trojan" id="ped-proto-trojan" checked"#),
            "{html}"
        );

        let form = vec![
            ("pipeline_mode".into(), "raw".into()),
            ("pipeline".into(), "{\"version\": 1}".into()),
        ];
        let html = widget_from_posted(lang, "c", &form, false, None);
        assert!(html.contains(r#"value="raw""#), "{html}");
        assert!(html.contains(r#"{&#34;version&#34;: 1}"#), "{html}");
    }

    fn test_lang() -> Lang {
        // Embedded catalogs load without a directory; ru is the default.
        crate::admin::i18n::Locales::load(Path::new("/nonexistent-fumox-locales")).default_lang()
    }
}
