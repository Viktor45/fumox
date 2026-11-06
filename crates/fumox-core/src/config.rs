//! Application configuration.
//!
//! Layered configuration: built-in defaults → TOML file
//! (`config/app.toml` by default) → environment variables with the
//! `FUMOX_` prefix and `__` as the section separator
//! (e.g. `FUMOX_ADMIN__TOKEN=secret`).
//!
//! Every key has a default so the service runs out of the box.
//! Unknown keys are rejected to catch typos early.
//!
//! Environment values arrive as strings and are fed to each key's
//! deserializer unchanged, so a list-valued key needs a JSON array, not a
//! comma-separated string: `FUMOX_SERVER__TRUST_PROXY_IPS='["10.0.0.0/8"]'`.
//! The same rule covers every `Vec` key (`admin.trust_proxy_ips`,
//! `server.allowed_hosts`, `admin.allowed_hosts`,
//! `probe.recheck_delays_secs`). The one exception is `[meow].test_url`,
//! whose deserializer also splits a comma-separated string into URLs.
//!
//! The TOML file itself is located by (strongest first): the `--config`
//! CLI flag, the `FUMOX_CONFIG` environment variable, then the default
//! `config/app.toml` resolved against the CWD.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::models::IpFamily;

/// Default location of the TOML config file, resolved against the CWD.
pub const DEFAULT_CONFIG_PATH: &str = "config/app.toml";

/// Environment variable pointing at the TOML config file, the middle
/// layer between the `--config` flag (strongest) and the default location.
pub const CONFIG_PATH_ENV: &str = "FUMOX_CONFIG";

/// Prefix of every environment variable the loader reads.
pub const ENV_PREFIX: &str = "FUMOX_";

/// `FUMOX_*` variables that are not configuration keys.
///
/// They belong to the deployment around the binary: the compose file
/// reads them for the port mapping and the build cache, and the loader
/// reads one of them itself. A variable in this list is ignored
/// without a word; every other unknown name is refused, because the
/// commonest cause is a typo in a section or a key name, and a
/// silently ignored variable is a setting that never takes effect.
pub const NON_CONFIG_ENV_VARS: &[&str] = &[
    CONFIG_PATH_ENV,
    // Compose: how the config directory is mounted into the container.
    "FUMOX_CONFIG_ACCESS",
    // Compose: the host-side port mapping and the admin bind address.
    "FUMOX_PUBLIC_PORT",
    "FUMOX_ADMIN_PORT",
    "FUMOX_ADMIN_BIND",
    // Compose: the buildkit cache mode.
    "FUMOX_BUILD_CACHE",
];

/// Top-level application configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub fetch: FetchConfig,
    #[serde(default)]
    pub ingest: IngestConfig,
    #[serde(default)]
    pub geo: GeoConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub probe: ProbeConfig,
    #[serde(default)]
    pub meow: MeowConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub log: LogConfig,
}

/// Where the TOML config file was looked for, as resolved by
/// [`load`], lets the binaries log the truth (the loader
/// itself cannot: the tracing subscriber is not installed until after the
/// config, which carries the log level, is loaded).
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedConfigPath {
    /// The file at this path was merged into the configuration.
    Loaded(PathBuf),
    /// No file anywhere, the service runs on built-in defaults plus env
    /// overrides. The default location may legitimately be absent
    /// (out-of-the-box run), so this is not an error.
    Missing,
}

/// Resolve the TOML file location by priority: the explicit `path` (the
/// `--config` flag) → [`CONFIG_PATH_ENV`] → [`DEFAULT_CONFIG_PATH`] against
/// the CWD. An explicitly requested file (flag or env) must exist, a typo
/// must fail loudly, not silently fall back to defaults. An empty env
/// value counts as unset.
pub fn resolve_config_path(path: Option<&Path>) -> crate::Result<ResolvedConfigPath> {
    match path {
        Some(p) => {
            if p.is_file() {
                Ok(ResolvedConfigPath::Loaded(p.to_path_buf()))
            } else {
                Err(crate::Error::Config(format!(
                    "config file not found: {}",
                    p.display()
                )))
            }
        }
        None => {
            // No CLI flag, the env pointer, if set, wins over the default
            // location. An empty value counts as unset.
            let from_env = std::env::var(CONFIG_PATH_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .map(PathBuf::from);
            let file = from_env
                .as_deref()
                .unwrap_or(Path::new(DEFAULT_CONFIG_PATH));
            if !file.is_file() {
                if from_env.is_some() {
                    return Err(crate::Error::Config(format!(
                        "config file set via {CONFIG_PATH_ENV} not found: {}",
                        file.display()
                    )));
                }
                // The default location being absent is the out-of-the-box
                // run, not an error.
                return Ok(ResolvedConfigPath::Missing);
            }
            Ok(ResolvedConfigPath::Loaded(file.to_path_buf()))
        }
    }
}

impl AppConfig {
    /// Carry a key that moved to another section over to its new home.
    ///
    /// `[probe].refresh_check_limit` became `[ingest].refresh_check_limit`
    /// when the priority queue became the scheduler's. A config file from
    /// the previous release still carries the old name, and a struct with
    /// `deny_unknown_fields` refuses it — so an upgrade would turn into a
    /// refusal to start. The old name is accepted for one release: its
    /// value is carried over when the new key still holds its default,
    /// and a warning names the key to rename.
    ///
    /// The new key wins when it was set explicitly, even to the default
    /// value: an operator who set both meant the new one.
    fn apply_moved_keys(&mut self) {
        let Some(old) = self.probe.refresh_check_limit.take() else {
            return;
        };
        let carried = self.ingest.refresh_check_limit == defaults::refresh_check_limit();
        if carried {
            self.ingest.refresh_check_limit = old;
        }
        tracing::warn!(
            old_value = old,
            new_value = self.ingest.refresh_check_limit,
            "probe.refresh_check_limit moved to ingest.refresh_check_limit: \
             rename the key in your config file"
        );
    }

    /// The DNS timeout of the SSRF pipeline: the dedicated
    /// `[network].dns_timeout_secs` when it is set, `[geo].dns_timeout_secs`
    /// otherwise, never below one second.
    ///
    /// The two consumers of the address policy (the probe's dial gate and
    /// the server's fetcher) read the bound from here, so a change to it
    /// reaches both.
    pub fn ssrf_dns_timeout(&self) -> std::time::Duration {
        let secs = if self.network.dns_timeout_secs > 0 {
            self.network.dns_timeout_secs
        } else {
            self.geo.dns_timeout_secs
        };
        std::time::Duration::from_secs(secs.max(1))
    }

    /// Cross-field checks serde cannot express on individual fields.
    fn validate(&self) -> crate::Result<()> {
        // The range table first: the checks below divide by a value it
        // guarantees to be non-zero.
        self.validate_bounds()?;
        if self.meow.backoff_max_secs < self.meow.backoff_initial_secs {
            return Err(crate::Error::Config(format!(
                "meow.backoff_max_secs ({}) must be >= meow.backoff_initial_secs ({})",
                self.meow.backoff_max_secs, self.meow.backoff_initial_secs
            )));
        }
        // An explicitly enabled panel that still carries the shipped
        // placeholder and listens on a non-loopback address is a
        // misconfiguration with a security consequence, not a default.
        // On loopback the placeholder merely disables the panel, which the
        // operator can still reach through a tunnel.
        if self.admin.enabled
            && self.admin.uses_placeholder_token()
            && !self.admin.bind.ip().is_loopback()
        {
            return Err(crate::Error::Config(format!(
                "admin.token is the placeholder \"{}\" while admin.bind is {}: \
                 set admin.token (or FUMOX_ADMIN__TOKEN) to a secret value, \
                 or set admin.enabled = false",
                PLACEHOLDER_ADMIN_TOKEN, self.admin.bind
            )));
        }
        self.validate_trust_proxy_ips()?;
        self.validate_meow_test_urls()?;
        self.validate_probe_queue()?;
        Ok(())
    }

    /// The T2 test URL is fetched by meow-rs, on the proxy's side of the
    /// tunnel, so the probe's own address gate never sees it. A literal
    /// loopback, link-local or RFC1918 host in `[meow].test_url` turns the
    /// tunnel check into a request to an internal service , which is the
    /// SSRF the probe's gate exists to prevent. The flag that opens the
    /// probe's dial targets opens these too.
    fn validate_meow_test_urls(&self) -> crate::Result<()> {
        if self.probe.allow_private_targets {
            return Ok(());
        }
        for entry in &self.meow.test_url {
            let Ok(parsed) = url::Url::parse(entry) else {
                // Already refused by the deserializer.
                continue;
            };
            let ip = match parsed.host() {
                Some(url::Host::Ipv4(addr)) => std::net::IpAddr::V4(addr),
                Some(url::Host::Ipv6(addr)) => std::net::IpAddr::V6(addr),
                // A name is resolved by meow-rs where the probe cannot vet
                // it, so only literals are checked here.
                Some(url::Host::Domain(_)) | None => continue,
            };
            if let Err(reason) = crate::ssrf::vet_addr(ip, false) {
                return Err(crate::Error::Config(format!(
                    "meow.test_url entry '{entry}' points at {ip} ({reason}): \
                     set probe.allow_private_targets = true to allow it"
                )));
            }
        }
        Ok(())
    }

    /// Every numeric setting is checked against the range the admin
    /// editor advertises, so a value the panel would refuse is refused
    /// at startup too. The message names the key and the bound: an
    /// operator who typed the value has to be able to find it.
    fn validate_bounds(&self) -> crate::Result<()> {
        for (path, value) in self.numeric_settings() {
            let Some(range) = bounds::range_of(path) else {
                continue;
            };
            if range.contains(value) {
                continue;
            }
            return Err(crate::Error::Config(format!(
                "{path} = {value} is outside the accepted range {}..={}",
                range.min, range.max
            )));
        }
        Ok(())
    }

    /// The numeric settings of this config, each under the dotted path
    /// the range table uses. A rate limit is composite: the table bounds
    /// the count under a `.limit` suffix, and the window is fixed to one
    /// of four units by the parser.
    fn numeric_settings(&self) -> Vec<(&'static str, u64)> {
        vec![
            (
                "server.export_max_rows",
                u64::from(self.server.export_max_rows),
            ),
            (
                "server.rate_limit.limit",
                u64::from(self.server.rate_limit.limit),
            ),
            (
                "server.auth_fail_rate_limit.limit",
                u64::from(self.server.auth_fail_rate_limit.limit),
            ),
            (
                "database.busy_timeout_ms",
                u64::from(self.database.busy_timeout_ms),
            ),
            (
                "database.max_connections",
                u64::from(self.database.max_connections),
            ),
            (
                "fetch.connect_timeout_secs",
                self.fetch.connect_timeout_secs,
            ),
            ("fetch.read_timeout_secs", self.fetch.read_timeout_secs),
            ("fetch.max_response_bytes", self.fetch.max_response_bytes),
            ("fetch.max_concurrency", self.fetch.max_concurrency as u64),
            ("fetch.max_retries", u64::from(self.fetch.max_retries)),
            (
                "fetch.retry_base_backoff_ms",
                self.fetch.retry_base_backoff_ms,
            ),
            (
                "ingest.refresh_check_limit",
                u64::from(self.ingest.refresh_check_limit),
            ),
            ("geo.cache_max_entries", self.geo.cache_max_entries),
            ("geo.cache_ttl_secs", self.geo.cache_ttl_secs),
            ("geo.dns_timeout_secs", self.geo.dns_timeout_secs),
            (
                "geo.startup_download_budget_secs",
                self.geo.startup_download_budget_secs,
            ),
            ("network.dns_timeout_secs", self.network.dns_timeout_secs),
            (
                "admin.session_ttl_hours",
                u64::from(self.admin.session_ttl_hours),
            ),
            (
                "admin.rate_limit.limit",
                u64::from(self.admin.rate_limit.limit),
            ),
            (
                "admin.login_rate_limit.limit",
                u64::from(self.admin.login_rate_limit.limit),
            ),
            ("probe.cycle_interval_secs", self.probe.cycle_interval_secs),
            ("probe.sample_size", u64::from(self.probe.sample_size)),
            ("probe.fail_limit", u64::from(self.probe.fail_limit)),
            (
                "probe.connect_timeout_secs",
                self.probe.connect_timeout_secs,
            ),
            ("probe.tls_timeout_secs", self.probe.tls_timeout_secs),
            ("probe.concurrency", self.probe.concurrency as u64),
            (
                "probe.heartbeat_interval_secs",
                self.probe.heartbeat_interval_secs,
            ),
            (
                "probe.second_chance_min_hours",
                self.probe.second_chance_min_hours,
            ),
            (
                "probe.second_chance_spread_hours",
                self.probe.second_chance_spread_hours,
            ),
            ("probe.queue_stale_days", self.probe.queue_stale_days),
            (
                "probe.retention_interval_secs",
                self.probe.retention_interval_secs,
            ),
            (
                "probe.backlog_target_drain_minutes",
                self.probe.backlog_target_drain_minutes,
            ),
            ("meow.timeout_secs", self.meow.timeout_secs),
            ("meow.backoff_initial_secs", self.meow.backoff_initial_secs),
            ("meow.backoff_max_secs", self.meow.backoff_max_secs),
            (
                "retention.probe_results_days",
                u64::from(self.retention.probe_results_days),
            ),
            (
                "retention.fetch_log_days",
                u64::from(self.retention.fetch_log_days),
            ),
        ]
    }

    /// The trusted-proxy lists are the operator's statement about which
    /// peers may speak for a client (`X-Forwarded-For`). A `/0` entry
    /// trusts every peer on the internet, which turns the per-IP rate
    /// limit into a no-op: any caller can name its own address. Such an
    /// entry is a config error, not a warning.
    fn validate_trust_proxy_ips(&self) -> crate::Result<()> {
        for (path, list) in [
            ("server.trust_proxy_ips", &self.server.trust_proxy_ips),
            ("admin.trust_proxy_ips", &self.admin.trust_proxy_ips),
        ] {
            for entry in list {
                let Some(net) = parse_trusted_cidr(entry) else {
                    return Err(crate::Error::Config(format!(
                        "{path} entry {entry:?} is not a CIDR or an IP address"
                    )));
                };
                if net.prefix_len() == 0 {
                    return Err(crate::Error::Config(format!(
                        "{path} entry {entry:?} covers every address: it would let \
                         any client name its own address in X-Forwarded-For"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The priority queue holds the freshly ingested proxies, and the
    /// probe drains it at the rate it checks proxies: `sample_size` per
    /// `cycle_interval_secs`. A queue that grows faster than it is
    /// drained never empties, and the proxies an operator waits for sit
    /// at the back of it for ever.
    fn validate_probe_queue(&self) -> crate::Result<()> {
        // The divisor is at least 1: the range table bounds the cycle
        // interval to a second or more, and `validate_bounds` ran.
        let per_hour =
            u64::from(self.probe.sample_size) * (3600 / self.probe.cycle_interval_secs.max(1));
        if u64::from(self.ingest.refresh_check_limit) > per_hour {
            return Err(crate::Error::Config(format!(
                "ingest.refresh_check_limit = {} is larger than what the probe drains in an \
                 hour (probe.sample_size = {} every probe.cycle_interval_secs = {} s): the \
                 priority queue would grow without bound",
                self.ingest.refresh_check_limit,
                self.probe.sample_size,
                self.probe.cycle_interval_secs
            )));
        }
        Ok(())
    }
}

/// Parse one entry of a trusted-proxy list: a CIDR (`10.0.0.0/8`) or a
/// bare address, which counts as a host prefix. `None` when the entry
/// is neither.
pub fn parse_trusted_cidr(entry: &str) -> Option<ipnet::IpNet> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
        return Some(net);
    }
    // A bare address is a host prefix: the admin editor writes them
    // back verbatim, and the startup parser reads them the same way.
    let addr = trimmed.parse::<std::net::IpAddr>().ok()?;
    Some(match addr {
        std::net::IpAddr::V4(_) => ipnet::IpNet::new(addr, 32).ok()?,
        std::net::IpAddr::V6(_) => ipnet::IpNet::new(addr, 128).ok()?,
    })
}

/// Result of [`load`]: the merged configuration together with the file
/// that was actually read. The path is what the admin panel uses as the
/// round-trip target for the *Edit settings* page, see
/// [`crate::config_writer`].
#[derive(Debug)]
pub struct LoadedConfig {
    pub config: AppConfig,
    pub path: ResolvedConfigPath,
}

/// Loads configuration from defaults, an optional TOML file and the
/// environment.
///
/// The file location is resolved by [`resolve_config_path`]: the
/// explicit `path` (the `--config` flag) → the [`CONFIG_PATH_ENV`]
/// environment variable → [`DEFAULT_CONFIG_PATH`] against the CWD.
/// Every key has a default, so a missing default file runs the
/// service out of the box.
///
/// The precedence is one direction and one direction only: the
/// environment wins over the file, the file wins over the built-in
/// defaults. `--print-config` on both binaries prints the result, so
/// the operator can see which value is in force.
pub fn load(path: Option<&Path>) -> crate::Result<LoadedConfig> {
    let mut figment = Figment::from(Serialized::defaults(AppConfig::default()));
    let resolved = resolve_config_path(path)?;

    if let ResolvedConfigPath::Loaded(file) = &resolved {
        figment = figment.merge(Toml::file(file));
    }

    // Environment overrides: FUMOX_SECTION__KEY (double underscore splits
    // the section path). The layer is restricted to the paths the
    // configuration actually has, so a variable that names no key
    // cannot shadow something else; `check_env_vars` turns such a name
    // into an error instead of letting it pass unnoticed.
    let mut paths = config_paths();
    paths.extend(DEPRECATED_PATHS.iter().map(|p| (*p).to_string()));
    let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    figment = figment.merge(Env::prefixed(ENV_PREFIX).split("__").only(&path_refs));

    check_env_vars(&paths)?;

    let mut config: AppConfig = figment.extract()?;
    config.apply_moved_keys();
    config.validate()?;
    Ok(LoadedConfig {
        config,
        path: resolved,
    })
}

/// Config paths that exist only for backward compatibility: the key
/// moved to another section, and the old name is still read so a config
/// file from the previous release keeps loading.
const DEPRECATED_PATHS: &[&str] = &["probe.refresh_check_limit"];

/// The dotted paths the configuration has (`server.bind`, `admin.token`),
/// lower-cased.
///
/// The env layer's whitelist: `FUMOX_SERVER__BIND` maps to
/// `server.bind`, and a variable naming no path here names no
/// configuration key.
pub fn config_paths() -> Vec<String> {
    let value = serde_json::to_value(AppConfig::default()).expect("the default config serializes");
    let mut paths = Vec::new();
    collect_paths("", &value, &mut paths);
    paths.sort();
    paths
}

/// The configuration paths the environment currently overrides.
///
/// The env layer wins over the file, so a setting named here cannot be
/// changed through the config file: the environment keeps the value no
/// matter what the file says. The admin panel uses the list to render
/// those fields read-only and to leave them out of the write.
///
/// The paths are the dotted config keys (`admin.token`), the same
/// shape [`config_paths`] returns. A `FUMOX_*` variable that names no
/// config key is not reported: [`check_env_vars`] refuses the start
/// instead.
pub fn env_overridden_paths() -> Vec<String> {
    let known = config_paths();
    let mut overridden: Vec<String> = Vec::new();
    for (name, _) in std::env::vars_os() {
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(ENV_PREFIX) || NON_CONFIG_ENV_VARS.contains(&name) {
            continue;
        }
        let Some(path) = env_var_path(name) else {
            continue;
        };
        if known.contains(&path) && !overridden.contains(&path) {
            overridden.push(path);
        }
    }
    overridden.sort();
    overridden
}

/// Flatten a JSON value into dotted leaf paths (`admin.rate_limit`).
/// Arrays count as one leaf so `meow.test_url` stays a single key.
fn collect_paths(prefix: &str, value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                collect_paths(&path, nested, out);
            }
        }
        _ => out.push(prefix.to_string()),
    }
}

/// The dotted path a `FUMOX_*` name names: the prefix is dropped, `__`
/// becomes `.` and the rest is lower-cased, exactly as the figment env
/// provider maps it.
fn env_var_path(name: &str) -> Option<String> {
    let rest = name.strip_prefix(ENV_PREFIX)?;
    if rest.is_empty() {
        return None;
    }
    Some(rest.replace("__", ".").to_ascii_lowercase())
}

/// Refuse a `FUMOX_*` variable that names no configuration key.
///
/// The deployment variables of [`NON_CONFIG_ENV_VARS`] are expected and
/// ignored. Every other unknown name is a mistake — a typo in the
/// section, a key that moved, a variable of another project — and the
/// mistake is invisible otherwise: the variable is simply not applied
/// and the setting keeps the value the file gave it. The error names
/// the variable and the closest key, because the operator has to be
/// able to fix it without reading the source.
fn check_env_vars(paths: &[String]) -> crate::Result<()> {
    let mut unknown: Vec<String> = Vec::new();
    for (name, _) in std::env::vars_os() {
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(ENV_PREFIX) || NON_CONFIG_ENV_VARS.contains(&name) {
            continue;
        }
        let Some(path) = env_var_path(name) else {
            continue;
        };
        if paths.contains(&path) {
            continue;
        }
        unknown.push(name.to_string());
    }
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort();

    let mut message = format!(
        "{} environment variable(s) name no configuration key and were not applied: {}",
        unknown.len(),
        unknown.join(", ")
    );
    for name in &unknown {
        let Some(path) = env_var_path(name) else {
            continue;
        };
        let leaf = path.rsplit('.').next().unwrap_or_default();
        let suggestions: Vec<&str> = paths
            .iter()
            .filter(|known| known.rsplit('.').next() == Some(leaf))
            .map(String::as_str)
            .collect();
        if suggestions.is_empty() {
            message.push_str(&format!(
                "\n  {name}: no configuration key ends in `{leaf}`"
            ));
        } else {
            message.push_str(&format!(
                "\n  {name}: did you mean {}?",
                suggestions
                    .iter()
                    .map(|s| format!("`{s}`"))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ));
        }
    }
    message.push_str(
        "\nEnvironment variables are FUMOX_<SECTION>__<KEY>, with a double underscore; \
         the sections are admin, database, fetch, geo, ingest, log, meow, probe, \
         retention and server.",
    );
    Err(crate::Error::Config(message))
}

/// Shorthand for callers that only need the merged config and do not
/// care which file (if any) was loaded, tests and one-shot helpers.
pub fn load_config(path: Option<&Path>) -> crate::Result<AppConfig> {
    Ok(load(path)?.config)
}

/// What the config dump writes instead of the admin token.
pub const REDACTED_ADMIN_TOKEN: &str = "<redacted>";

/// The resolved configuration as TOML, with the admin token redacted.
///
/// This is what `--print-config` prints: the effective value of every
/// key after the file and the environment were merged, so the operator
/// can see which value is in force and which one the file would give
/// without the environment. The admin token is a credential, and the
/// dump lands in terminals, CI logs and bug reports, so it is replaced
/// by a placeholder.
pub fn dump(config: &AppConfig) -> crate::Result<String> {
    let mut redacted = config.clone();
    if !redacted.admin.token.is_empty() {
        redacted.admin.token = REDACTED_ADMIN_TOKEN.to_string();
    }
    toml::to_string(&redacted)
        .map_err(|err| crate::Error::Config(format!("cannot render the configuration: {err}")))
}

/// Parse a config document body over the built-in defaults and run the
/// same cross-field validation the loader runs, without the environment
/// layer.
///
/// The admin panel writes the file verbatim, so the document it
/// assembles is checked with the rules the binaries enforce at startup:
/// a file the loader refuses aborts both of them, so a success toast
/// for such a file would be a lie.
///
/// The environment layer is deliberately left out. `FUMOX_*` may shadow
/// a broken value in the file for as long as the variable is set, but
/// the file is what the next start without those variables reads.
pub fn parse_document(text: &str) -> crate::Result<AppConfig> {
    let mut config: AppConfig = Figment::from(Serialized::defaults(AppConfig::default()))
        .merge(Toml::string(text))
        .extract()?;
    config.apply_moved_keys();
    config.validate()?;
    Ok(config)
}
/// Which forwarding header the trusted reverse proxy writes.
///
/// The declaration is the contract: a header the operator has not named
/// is never honored, whoever sent it. Without the declaration a client
/// picks its own rate-limit key: it sends `X-Forwarded-For: 9.9.9.9` and
/// `Forwarded: for=9.9.9.9` beside a proxy that writes one header and
/// passes the other through, and the pair agrees, so the forged address
/// looks confirmed. `None` (the default) resolves every forwarded header
/// to the peer address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustedHeader {
    /// Honor no forwarding header: the peer address is the client.
    #[default]
    None,
    /// Honor `X-Forwarded-For` only.
    Xff,
    /// Honor RFC 7239 `Forwarded` only.
    Forwarded,
    /// Honor both, and only when they name the same address.
    Both,
}

impl TrustedHeader {
    /// The name the configuration file and the settings form use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Xff => "xff",
            Self::Forwarded => "forwarded",
            Self::Both => "both",
        }
    }

    /// True when the `X-Forwarded-*` headers are trusted.
    pub fn honors_xff(self) -> bool {
        matches!(self, Self::Xff | Self::Both)
    }

    /// True when the RFC 7239 `Forwarded` header is trusted.
    pub fn honors_forwarded(self) -> bool {
        matches!(self, Self::Forwarded | Self::Both)
    }
}

/// Public HTTP listener serving `/sub/{id}` and `/src/{id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket for the public subscription endpoints.
    #[serde(default = "defaults::server_bind")]
    pub bind: SocketAddr,
    /// Per-IP fixed-window limit for every public request (`/sub`, `/src`,
    /// `/export/alive`), a generous ceiling against scraping and floods.
    #[serde(default = "defaults::public_rate_limit")]
    pub rate_limit: RateLimit,
    /// Per-IP limit fed by failed access-token checks (HTTP 403 on `/sub`) ,
    /// the brute-force signal for protected profiles.
    #[serde(default = "defaults::auth_fail_rate_limit")]
    pub auth_fail_rate_limit: RateLimit,
    /// CIDRs of reverse proxies whose `X-Forwarded-For` (or RFC 7239
    /// `Forwarded: for=…`) is honored for the per-IP rate-limit key. Empty
    /// = never honor forwarded headers (any caller can otherwise spoof the
    /// key).
    #[serde(default = "defaults::trust_proxy_ips")]
    pub trust_proxy_ips: Vec<String>,
    /// Which forwarding header the trusted proxy writes. Only the named
    /// header is honored; `none` (the default) honors none, so the peer
    /// address is the client even when `trust_proxy_ips` names a proxy.
    #[serde(default)]
    pub trust_proxy_header: TrustedHeader,
    /// Hostnames / IPs allowed to reach the public listener. Empty = accept
    /// any host (today's behavior); setting this locks the
    /// alive-export endpoint to the operator's own hostname.
    #[serde(default = "defaults::allowed_hosts")]
    pub allowed_hosts: Vec<String>,
    /// Hard ceiling on the rows one `/export/alive` / `/export/ready` body
    /// may carry, applied as `LIMIT ?` in the backing query. Unlike `/sub`
    /// and `/src`, which a profile's `limit.count` and a source pipeline
    /// already bound, the two export links have no upstream cap, so without
    /// one a large pool would turn one public request into an unbounded
    /// read, render and body. An operator whose tier exceeds the ceiling
    /// raises it here; the admin badge stays uncapped, so a truncated
    /// export is always visible as smaller than the tier.
    #[serde(default = "defaults::export_max_rows")]
    pub export_max_rows: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: defaults::server_bind(),
            rate_limit: defaults::public_rate_limit(),
            auth_fail_rate_limit: defaults::auth_fail_rate_limit(),
            trust_proxy_ips: defaults::trust_proxy_ips(),
            trust_proxy_header: defaults::trust_proxy_header(),
            allowed_hosts: defaults::allowed_hosts(),
            export_max_rows: defaults::export_max_rows(),
        }
    }
}

/// Source ingestion of `fumox-server`'s scheduler (fetch → parse →
/// reconcile). Owns the knobs of the reconcile pass that are
/// not per-source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestConfig {
    /// How many newly inserted `unknown` proxies of one source refresh are
    /// enqueued for priority checking (0 disables the queue). The probe
    /// drains the queue at the start of its next cycle, newest first.
    #[serde(default = "defaults::refresh_check_limit")]
    pub refresh_check_limit: u32,
    /// Whether pipeline `drop` rules switch off the alive-linger link
    /// policy for their source. `true` (the default): an alive proxy of
    /// a source with drop rules leaves on the next refresh after the rule
    /// catches it. `false`: the probe alone retires proxies, every source
    /// lingers, even ones with drop rules, so a rule added later only
    /// stops new matches, never stored ones.
    #[serde(default = "defaults::drop_gate")]
    pub drop_gate: bool,
    /// Revive a `removed` proxy the feed still carries: on the next
    /// refresh of a source containing it, the row resets to the pristine
    /// `unknown` state (fail_count and quarantine schedules cleared, same
    /// as the admin "reset status" action) and re-enters the probe cycle.
    /// `false` (the default) keeps `removed` terminal, the only ways back
    /// are the admin "reset status" action or «purge removed» followed by
    /// a re-insert from a fetch.
    #[serde(default = "defaults::removed_as_unknown")]
    pub removed_as_unknown: bool,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            refresh_check_limit: defaults::refresh_check_limit(),
            drop_gate: defaults::drop_gate(),
            removed_as_unknown: defaults::removed_as_unknown(),
        }
    }
}

/// SQLite durability level. `Normal` survives a process crash; `Full`
/// also survives an OS crash or a power loss, at the cost of an fsync
/// per commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SynchronousMode {
    /// Recommended for WAL: survives a process crash, not a power loss.
    Normal,
    /// Every commit is fsynced: survives a power loss.
    Full,
}

/// SQLite connection settings. SQLite (WAL) is the single source of truth;
/// `busy_timeout` is required on every connection (DATABASE, exploitation
/// notes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Path to the SQLite database file.
    #[serde(default = "defaults::database_path")]
    pub path: PathBuf,
    /// `busy_timeout` in milliseconds applied to every connection.
    #[serde(default = "defaults::busy_timeout_ms")]
    pub busy_timeout_ms: u32,
    /// Maximum number of connections in the pool.
    #[serde(default = "defaults::max_connections")]
    pub max_connections: u32,
    /// Durability level handed to SQLite. The default (`normal`) is the
    /// recommended mode for WAL.
    #[serde(default = "defaults::synchronous")]
    pub synchronous: SynchronousMode,
    /// Whether a migration whose stored checksum no longer matches the
    /// file on disk may be re-stamped in place at startup.
    ///
    /// Off by default. sqlx hashes the whole migration file, so a
    /// comment edit and a DDL edit are indistinguishable from here, and a
    /// silent re-stamp hides a schema that fell behind the files. With
    /// the flag off the boot stops and names the version; the operator
    /// then runs the `repair_migration_checksums` example, or turns the
    /// flag on for that run.
    #[serde(default = "defaults::allow_checksum_repair")]
    pub allow_checksum_repair: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: defaults::database_path(),
            busy_timeout_ms: defaults::busy_timeout_ms(),
            max_connections: defaults::max_connections(),
            synchronous: defaults::synchronous(),
            allow_checksum_repair: defaults::allow_checksum_repair(),
        }
    }
}

/// Source fetcher behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchConfig {
    /// TCP connect timeout.
    #[serde(default = "defaults::connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// Whole-request read timeout.
    #[serde(default = "defaults::read_timeout_secs")]
    pub read_timeout_secs: u64,
    /// Hard cap on the (decompressed) response size; guards against
    /// decompression bombs.
    #[serde(default = "defaults::max_response_bytes")]
    pub max_response_bytes: u64,
    /// Number of sources fetched concurrently (semaphore size).
    #[serde(default = "defaults::max_concurrency")]
    pub max_concurrency: usize,
    /// Retries for recoverable error classes (`network`, `http_server`).
    #[serde(default = "defaults::max_retries")]
    pub max_retries: u32,
    /// Base backoff between retries; grows exponentially.
    #[serde(default = "defaults::retry_base_backoff_ms")]
    pub retry_base_backoff_ms: u64,
    /// Default `User-Agent` unless a source overrides it via `headers`.
    #[serde(default = "defaults::user_agent")]
    pub user_agent: String,
    /// Default IP protocol family for fetching source URLs. A source
    /// without its own `ip_family` inherits this. `any` = dual-stack (first
    /// IPv4 wins, IPv6 fallback); `ipv4` / `ipv6` are strict, no address of
    /// that family means the fetch fails.
    #[serde(default)]
    pub ip_family: IpFamily,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            connect_timeout_secs: defaults::connect_timeout_secs(),
            read_timeout_secs: defaults::read_timeout_secs(),
            max_response_bytes: defaults::max_response_bytes(),
            max_concurrency: defaults::max_concurrency(),
            max_retries: defaults::max_retries(),
            retry_base_backoff_ms: defaults::retry_base_backoff_ms(),
            user_agent: defaults::user_agent(),
            ip_family: IpFamily::default(),
        }
    }
}

/// Geo enrichment via MaxMind GeoLite2. Every database found in
/// `db_dir` is opened and all of them contribute facts, a name template
/// can mix `{country}`, `{city}` and `{asn}` placeholders freely.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoConfig {
    /// Master switch for geo enrichment.
    #[serde(default = "defaults::geo_enabled")]
    pub enabled: bool,
    /// Legacy selector from the one-database era. No longer affects
    /// resolution (every database in `db_dir` is merged) and is not read
    /// by any code; the key is still accepted so existing config files
    /// keep parsing, and it no longer round-trips into saved config.
    /// `doc(hidden)`: the field is public only so struct literals with
    /// `..Default::default()` compile outside this crate: there is
    /// nothing to do with a value of type `()`.
    #[doc(hidden)]
    #[serde(default, skip_serializing, deserialize_with = "de_ignore_legacy")]
    pub db: (),
    /// Directory containing the `.mmdb` files (never committed).
    #[serde(default = "defaults::geo_db_dir")]
    pub db_dir: PathBuf,
    /// Upper bound for the host→geo in-memory cache.
    #[serde(default = "defaults::geo_cache_max_entries")]
    pub cache_max_entries: u64,
    /// How long a host→geo verdict (a positive one and a no-record one
    /// alike) stays cached, in seconds. Six hours by default, matching
    /// the periodic geo backfill's cadence; entries expire, so a host
    /// that comes back is resolved again without a restart.
    #[serde(default = "defaults::geo_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Timeout for the async DNS resolution step.
    #[serde(default = "defaults::dns_timeout_secs")]
    pub dns_timeout_secs: u64,
    /// Upper bound on how long startup waits for the GeoLite2 download
    /// before the listeners bind. The same budget bounds the background
    /// backfill of the geo columns that runs after it: both are startup
    /// work the public surface should not wait on. Past the budget the
    /// download keeps running in the background (the file is installed by
    /// an atomic rename) and this run simply runs without geo enrichment
    /// until the next start.
    #[serde(default = "defaults::geo_startup_download_budget_secs")]
    pub startup_download_budget_secs: u64,
    /// Whether the databases are downloaded at all. Off means the operator
    /// provides the `.mmdb` files by hand (a MaxMind mirror, an internal
    /// copy, a read-only volume) and fumox never writes into `db_dir`.
    #[serde(default = "defaults::geo_auto_download")]
    pub auto_download: bool,
    /// Mirror URLs per database file name (`GeoLite2-City.mmdb` → URL).
    /// The built-in values point at the public release assets; an operator
    /// points them at another mirror by name, which is an operational
    /// decision rather than a release.
    #[serde(default = "defaults::geo_download_urls")]
    pub download_urls: BTreeMap<String, String>,
    /// Expected SHA-256 per database file name. A file whose checksum is
    /// listed here is installed only when the download matches it; a file
    /// without a listed checksum is installed on the format check alone.
    #[serde(default)]
    pub sha256: BTreeMap<String, String>,
}

/// Serde landing place for config keys the code no longer reads (the
/// legacy `[geo].db`): any value is accepted and discarded, so old
/// config files keep parsing and a saved file never carries the key.
///
/// An empty value is the historical "unset" spelling and passes without a
/// word. A non-empty one is a setting the operator wrote, and a silently
/// ignored setting is one that never takes effect: it gets a warning
/// naming where the geo data really comes from now.
fn de_ignore_legacy<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    let empty = match &value {
        serde_json::Value::Null => true,
        serde_json::Value::String(text) => text.is_empty(),
        _ => false,
    };
    if !empty {
        tracing::warn!(
            key = "geo.db",
            value = %value,
            "legacy [geo].db key is ignored; geo facts come from every .mmdb in [geo].db_dir"
        );
    }
    Ok(())
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            enabled: defaults::geo_enabled(),
            db: (),
            db_dir: defaults::geo_db_dir(),
            cache_max_entries: defaults::geo_cache_max_entries(),
            cache_ttl_secs: defaults::geo_cache_ttl_secs(),
            dns_timeout_secs: defaults::dns_timeout_secs(),
            startup_download_budget_secs: defaults::geo_startup_download_budget_secs(),
            auto_download: defaults::geo_auto_download(),
            download_urls: defaults::geo_download_urls(),
            sha256: BTreeMap::new(),
        }
    }
}

impl GeoConfig {
    /// Centralized `u64 → Duration` conversion so the SSRF vet, fetcher and
    /// geo enrichment all consume the same bound instead of duplicating the
    /// conversion at each call site.
    pub fn dns_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.dns_timeout_secs)
    }

    /// How long startup may block on the GeoLite2 download before the
    /// listeners bind without geo enrichment.
    ///
    /// Capped at [`MAX_STARTUP_DOWNLOAD_BUDGET_SECS`]: the budget is the
    /// time the public surface is unavailable, and no mirror is worth five
    /// minutes of that. A hand-edited config file above the cap is clamped
    /// rather than rejected, so an existing installation still starts.
    pub fn startup_download_budget(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.startup_download_budget_secs
                .min(MAX_STARTUP_DOWNLOAD_BUDGET_SECS),
        )
    }
}

/// The upper bound of `[geo].startup_download_budget_secs`.
///
/// The budget is the time the public surface waits for the GeoLite2
/// download. Five minutes is already far more than a mirror needs, and
/// every second of it is a second in which the instance answers no
/// request.
pub const MAX_STARTUP_DOWNLOAD_BUDGET_SECS: u64 = 300;

/// Settings of the address policy, the gate every untrusted host passes
/// before it may be dialed.
///
/// The section exists because the SSRF pipeline resolves a feed-supplied
/// host before the probe or the fetcher may connect to it, and that
/// resolution belongs to the address policy, not to the geo enrichment
/// (which resolves the same names for a different reason: to label them).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Upper bound for the DNS resolution step of the SSRF pipeline.
    ///
    /// `0` = follow `[geo].dns_timeout_secs`. The effective bound is never
    /// below one second: a zero timeout would fail every resolution
    /// instantly, which is a misconfiguration, not a policy.
    #[serde(default = "defaults::network_dns_timeout_secs")]
    pub dns_timeout_secs: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            dns_timeout_secs: defaults::network_dns_timeout_secs(),
        }
    }
}

/// Selectable GeoLite2 database kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoDbKind {
    #[default]
    Country,
    City,
    Asn,
}

impl GeoDbKind {
    /// Canonical `.mmdb` file name for this database kind.
    pub fn file_name(self) -> &'static str {
        match self {
            GeoDbKind::Country => "GeoLite2-Country.mmdb",
            GeoDbKind::City => "GeoLite2-City.mmdb",
            GeoDbKind::Asn => "GeoLite2-ASN.mmdb",
        }
    }
}

/// Admin panel settings. An empty `token` disables the
/// admin listener entirely (it answers 404).
/// Built-in default of `[admin].token` is the empty string: the panel
/// stays off until an operator sets a token explicitly.
pub const DEFAULT_ADMIN_TOKEN: &str = "change-me";

/// Placeholder value that shipped in older releases. It is treated as
/// "panel disabled" exactly like an empty token, so an upgrade that keeps
/// the old config file cannot expose the panel with a guessable secret.
pub const PLACEHOLDER_ADMIN_TOKEN: &str = DEFAULT_ADMIN_TOKEN;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Master switch; `false` or an empty `token` disables the panel.
    #[serde(default = "defaults::admin_enabled")]
    pub enabled: bool,
    /// Login secret. Empty string = admin disabled.
    #[serde(default = "defaults::admin_token")]
    pub token: String,
    /// Separate loopback listener.
    #[serde(default = "defaults::admin_bind")]
    pub bind: SocketAddr,
    /// HMAC session cookie lifetime.
    #[serde(default = "defaults::session_ttl_hours")]
    pub session_ttl_hours: u32,
    /// When `false`, source URLs must not resolve to loopback / RFC1918 /
    /// link-local / metadata addresses (SSRF protection).
    #[serde(default)]
    pub allow_private_urls: bool,
    /// Soft limit for `/admin/*` routes (per IP).
    #[serde(default = "defaults::admin_rate_limit")]
    pub rate_limit: RateLimit,
    /// Hard limit for `POST /admin/login` (per IP).
    #[serde(default = "defaults::login_rate_limit")]
    pub login_rate_limit: RateLimit,
    /// Add `; Secure` to the admin session cookie. Enable when the panel is
    /// reached through an HTTPS front (reverse proxy); a plain-HTTP
    /// deployment must keep it off, or browsers will drop the cookie.
    #[serde(default)]
    pub secure_cookies: bool,
    /// Directory with UI translation catalogs (`<code>.toml`); relative to
    /// the working directory. Missing directory falls back to the catalogs
    /// embedded in the binary.
    #[serde(default = "defaults::admin_locales_dir")]
    pub locales_dir: String,
    /// CIDRs of reverse proxies whose `X-Forwarded-For` (or RFC 7239
    /// `Forwarded: for=…`) is honored for the admin per-IP rate-limit key.
    /// Empty = never honor forwarded headers.
    #[serde(default = "defaults::trust_proxy_ips")]
    pub trust_proxy_ips: Vec<String>,
    /// Which forwarding header the trusted proxy writes. Only the named
    /// header is honored; `none` (the default) honors none, so the peer
    /// address is the client even when `trust_proxy_ips` names a proxy.
    #[serde(default)]
    pub trust_proxy_header: TrustedHeader,
    /// Hostnames / IPs allowed to reach the admin listener. Empty = accept
    /// any host (today's behavior).
    #[serde(default = "defaults::allowed_hosts")]
    pub allowed_hosts: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: defaults::admin_enabled(),
            token: defaults::admin_token(),
            bind: defaults::admin_bind(),
            session_ttl_hours: defaults::session_ttl_hours(),
            allow_private_urls: false,
            rate_limit: defaults::admin_rate_limit(),
            login_rate_limit: defaults::login_rate_limit(),
            secure_cookies: false,
            locales_dir: defaults::admin_locales_dir(),
            trust_proxy_ips: defaults::trust_proxy_ips(),
            trust_proxy_header: defaults::trust_proxy_header(),
            allowed_hosts: defaults::allowed_hosts(),
        }
    }
}

impl fmt::Debug for AdminConfig {
    /// A hand-written `Debug` impl, because the token is a credential and
    /// the derived one would print it: `{:?}` of the whole [`AppConfig`]
    /// and of [`LoadedConfig`] delegate to the fields' `Debug`, so the
    /// secret never reaches a debug log or a panic message any more than
    /// it reaches `--print-config` (see [`dump`]).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminConfig")
            .field("enabled", &self.enabled)
            .field("token", &REDACTED_ADMIN_TOKEN)
            .field("bind", &self.bind)
            .field("session_ttl_hours", &self.session_ttl_hours)
            .field("allow_private_urls", &self.allow_private_urls)
            .field("rate_limit", &self.rate_limit)
            .field("login_rate_limit", &self.login_rate_limit)
            .field("secure_cookies", &self.secure_cookies)
            .field("locales_dir", &self.locales_dir)
            .field("trust_proxy_ips", &self.trust_proxy_ips)
            .field("trust_proxy_header", &self.trust_proxy_header)
            .field("allowed_hosts", &self.allowed_hosts)
            .finish()
    }
}

impl AdminConfig {
    /// The panel is active only when enabled and a real token is set.
    ///
    /// Both an empty token and the historical `"change-me"` placeholder
    /// count as "no token": the listener is not started and the panel
    /// answers 404.
    pub fn is_active(&self) -> bool {
        self.enabled && !self.token.is_empty() && self.token != PLACEHOLDER_ADMIN_TOKEN
    }

    /// True when the operator explicitly left the placeholder in place.
    /// The server refuses to start on such a config when the panel is
    /// bound to a non-loopback address.
    pub fn uses_placeholder_token(&self) -> bool {
        self.token == PLACEHOLDER_ADMIN_TOKEN
    }

    /// True when the panel is live, reachable from outside the host, and
    /// sends its session cookie without the `Secure` attribute.
    ///
    /// A cookie without `Secure` travels in clear text on every request,
    /// so anyone on the path can read the session token. The check is a
    /// warning and not an error: a plain-HTTP deployment is legitimate
    /// when the panel sits behind a TLS-terminating proxy that the
    /// browser reaches over HTTPS, and forcing `Secure` there would
    /// make the browser drop the cookie and lock the operator out.
    pub fn insecure_cookies_on_a_public_bind(&self) -> bool {
        self.is_active() && !self.secure_cookies && !self.bind.ip().is_loopback()
    }
}

/// Probe daemon behaviour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    /// Scheduling cycle period; each cycle probes a random sample.
    #[serde(default = "defaults::cycle_interval_secs")]
    pub cycle_interval_secs: u64,
    /// Random sample size per cycle (spreads load, avoids bursts).
    #[serde(default = "defaults::sample_size")]
    pub sample_size: u32,
    /// Consecutive failures before quarantine.
    #[serde(default = "defaults::fail_limit")]
    pub fail_limit: u32,
    /// When `false` (the default), the daemon refuses to dial proxy hosts
    /// that resolve to loopback / RFC1918 / link-local (cloud metadata) /
    /// CGNAT / unique-local addresses:
    /// proxy hosts come from remote feeds, and without this gate a hostile
    /// feed turns the probe into an internal port scanner. A refusal is
    /// journaled as a *failed check*, so a
    /// blocked target walks the ordinary fail ladder instead of clogging
    /// the queues. Mirrors `[admin].allow_private_urls` of the fetcher.
    #[serde(default)]
    pub allow_private_targets: bool,
    /// TCP connect timeout for T1 checks.
    #[serde(default = "defaults::probe_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// TLS handshake timeout for T1 checks.
    #[serde(default = "defaults::probe_tls_timeout_secs")]
    pub tls_timeout_secs: u64,
    /// Concurrent probe tasks.
    #[serde(default = "defaults::probe_concurrency")]
    pub concurrency: usize,
    /// Heartbeat period for the `probe_heartbeat` meta key.
    #[serde(default = "defaults::heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
    /// Lower bound of the second-chance window: `quarantined_at + N hours`.
    #[serde(default = "defaults::second_chance_min_hours")]
    pub second_chance_min_hours: u64,
    /// Width of the uniform jitter added on top of the minimum, giving the
    /// `[12h, 16h)` window by default.
    #[serde(default = "defaults::second_chance_spread_hours")]
    pub second_chance_spread_hours: u64,
    /// Quarantine recheck ladder: delays in seconds between
    /// consecutive rechecks after a failed second chance. Failing recheck
    /// `N` schedules recheck `N+1` after `recheck_delays_secs[N-1]`;
    /// failing the last entry removes the proxy. An empty list removes the
    /// proxy right after the failed second chance. The ladder length is
    /// arbitrary (the schedule lives in the generic `ladder_at`/`ladder_step`
    /// columns), capped at 16 steps of at most 30 days.
    #[serde(
        default = "defaults::recheck_delays_secs",
        deserialize_with = "de_recheck_delays"
    )]
    pub recheck_delays_secs: Vec<i64>,
    /// `probe_requests` entries older than this many days are purged (the
    /// priority queue holds rows for proxies that may never be re-checked).
    #[serde(default = "defaults::queue_stale_days")]
    pub queue_stale_days: u64,
    /// How often the retention rotation task runs.
    #[serde(default = "defaults::retention_interval_secs")]
    pub retention_interval_secs: u64,
    /// Target drain time (minutes) used by the `/admin/probe` backlog
    /// banner when computing suggested `[probe]` values. Range 5..=1440
    /// (5 min..=24 h). Default 60.
    #[serde(default = "defaults::backlog_target_drain_minutes")]
    pub backlog_target_drain_minutes: u64,
    /// The key moved to `[ingest].refresh_check_limit`: the queue is the
    /// scheduler's, the probe only drains it. The old name is accepted
    /// for one release so an upgrade from a config that still carries it
    /// does not turn into a refusal to start: the value is carried over
    /// to the new key when the new key still holds its default, and a
    /// warning names the key to rename. `skip_serializing` keeps the
    /// dead knob out of a written config.
    #[doc(hidden)]
    #[serde(default, skip_serializing)]
    pub refresh_check_limit: Option<u32>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            cycle_interval_secs: defaults::cycle_interval_secs(),
            sample_size: defaults::sample_size(),
            fail_limit: defaults::fail_limit(),
            allow_private_targets: false,
            connect_timeout_secs: defaults::probe_connect_timeout_secs(),
            tls_timeout_secs: defaults::probe_tls_timeout_secs(),
            concurrency: defaults::probe_concurrency(),
            heartbeat_interval_secs: defaults::heartbeat_interval_secs(),
            second_chance_min_hours: defaults::second_chance_min_hours(),
            second_chance_spread_hours: defaults::second_chance_spread_hours(),
            recheck_delays_secs: defaults::recheck_delays_secs(),
            queue_stale_days: defaults::queue_stale_days(),
            retention_interval_secs: defaults::retention_interval_secs(),
            backlog_target_drain_minutes: defaults::backlog_target_drain_minutes(),
            refresh_check_limit: None,
        }
    }
}

/// meow-rs integration for T2 checks. meow-rs runs as a separate
/// system service; Fumox only talks to its REST API and reloads its config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeowConfig {
    /// meow-rs REST API address (`host:port`).
    #[serde(default = "defaults::meow_api_addr")]
    pub api_addr: String,
    /// Bearer token for the meow-rs external-controller.
    ///
    /// The controller can reconfigure the proxy kernel and read its
    /// state, so it is only safe on a network nobody else reaches. A
    /// non-empty value makes it answer `401` to a request without the
    /// matching `Authorization: Bearer <token>` header, which is the
    /// difference between "reachable" and "usable" for anyone who gets
    /// past the network boundary. Empty (the default) keeps the
    /// controller unauthenticated, which is only acceptable when the
    /// port is not published at all.
    #[serde(default = "defaults::meow_api_token")]
    pub api_token: String,
    /// Clash YAML config path generated by the probe and reloaded via
    /// `PUT /configs`.
    #[serde(default = "defaults::meow_config_path")]
    pub config_path: PathBuf,
    /// Test URL(s) for delay/healthcheck requests (configurable because the
    /// defaults may be blocked in some regions). Accepts a single URL, a
    /// TOML array, or a comma-separated string; every entry has to be an
    /// absolute `http(s)` URL. The probe draws one of them per cycle and
    /// uses it for every check of that cycle.
    #[serde(default = "defaults::meow_test_url", deserialize_with = "de_test_urls")]
    pub test_url: Vec<String>,
    /// Per-check timeout.
    #[serde(default = "defaults::meow_timeout_secs")]
    pub timeout_secs: u64,
    /// Initial delay before retrying meow-rs after it answered
    /// `ServiceUnavailable`; doubles on every consecutive failure.
    #[serde(default = "defaults::meow_backoff_initial_secs")]
    pub backoff_initial_secs: u64,
    /// Upper bound of the meow-rs retry backoff.
    #[serde(default = "defaults::meow_backoff_max_secs")]
    pub backoff_max_secs: u64,
    /// Resolve the T2 test URL over IPv4 only (meow-rs' own default).
    ///
    /// Only the *test URL* host is resolved through meow (proxy servers
    /// are pinned to an IP literal), so this matters solely on IPv6-only
    /// egress or an AAAA-only test URL.
    #[serde(default = "defaults::meow_ipv6")]
    pub ipv6: bool,
}

impl Default for MeowConfig {
    fn default() -> Self {
        Self {
            api_addr: defaults::meow_api_addr(),
            api_token: defaults::meow_api_token(),
            config_path: defaults::meow_config_path(),
            test_url: defaults::meow_test_url(),
            timeout_secs: defaults::meow_timeout_secs(),
            backoff_initial_secs: defaults::meow_backoff_initial_secs(),
            backoff_max_secs: defaults::meow_backoff_max_secs(),
            ipv6: defaults::meow_ipv6(),
        }
    }
}

/// History rotation; enforced by a daily task in
/// the probe daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// Keep `probe_results` rows for this many days.
    #[serde(default = "defaults::probe_results_days")]
    pub probe_results_days: u32,
    /// Keep `fetch_log` rows for this many days.
    #[serde(default = "defaults::fetch_log_days")]
    pub fetch_log_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            probe_results_days: defaults::probe_results_days(),
            fetch_log_days: defaults::fetch_log_days(),
        }
    }
}

/// Console log level (`[log]` section). `RUST_LOG` with full `EnvFilter`
/// directives still wins when set (see `logging::init_tracing`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

/// Per-binary console levels. Both processes read the same `app.toml`, so
/// each takes its own key: `server` for fumox-server, `probe` for
/// fumox-probe.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Console level of `fumox-server`.
    #[serde(default)]
    pub server: LogLevel,
    /// Console level of `fumox-probe`.
    #[serde(default)]
    pub probe: LogLevel,
}

/// `[meow].test_url`: a single URL, a comma-separated string, or a sequence
/// of URLs. Blank entries are dropped, and the list must not end up empty ,
/// the T2 check has nothing to fetch otherwise. Every entry has to be an
/// absolute `http(s)` URL with a host: meow-rs fetches it on the proxy's
/// side, so a `file://` entry or a hostless path would turn the tunnel
/// check into a request nobody asked for.
fn de_test_urls<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a URL or a list of URLs")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            finish(split_urls(value).collect())
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut urls = Vec::new();
            while let Some(item) = seq.next_element::<String>()? {
                urls.extend(split_urls(&item));
            }
            finish(urls)
        }
    }

    // Comma-splitting applies to array items too, so `FUMOX_MEOW__TEST_URL`
    // overrides stay possible with several endpoints (env values are strings).
    fn split_urls(value: &str) -> impl Iterator<Item = String> + '_ {
        value
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(str::to_string)
    }

    fn finish<E: serde::de::Error>(urls: Vec<String>) -> Result<Vec<String>, E> {
        if urls.is_empty() {
            return Err(E::custom("meow.test_url must contain at least one URL"));
        }
        urls.into_iter()
            .map(|entry| check_test_url::<E>(&entry))
            .collect()
    }

    deserializer.deserialize_any(Visitor)
}

/// Validate one `[meow].test_url` entry: an absolute `http(s)` URL with a
/// host. Returns the entry unchanged, so the stored value stays exactly
/// what the operator wrote.
fn check_test_url<E: serde::de::Error>(entry: &str) -> Result<String, E> {
    let parsed = url::Url::parse(entry).map_err(|e| {
        E::custom(format!(
            "meow.test_url entry '{entry}' is not a valid URL: {e}"
        ))
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(E::custom(format!(
                "meow.test_url entry '{entry}' uses the '{other}' scheme: only http and https are allowed"
            )));
        }
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(E::custom(format!(
            "meow.test_url entry '{entry}' has no host"
        )));
    }
    Ok(entry.to_string())
}

/// `[probe].recheck_delays_secs`: the quarantine recheck ladder. Bounded to
/// 16 steps of at most 30 days each so a typo cannot schedule rechecks
/// years out or build an unbounded ladder; an empty list is legal and means
/// «remove right after the failed second chance».
fn de_recheck_delays<'de, D>(deserializer: D) -> Result<Vec<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let delays = Vec::<i64>::deserialize(deserializer)?;
    const MAX_STEPS: usize = bounds::RECHECK_MAX_STEPS;
    const MAX_DELAY_SECS: i64 = bounds::RECHECK_MAX_DELAY_SECS;
    if delays.len() > MAX_STEPS {
        return Err(serde::de::Error::custom(format!(
            "recheck_delays_secs: at most {MAX_STEPS} steps are supported (got {})",
            delays.len()
        )));
    }
    for delay in &delays {
        if !(1..=MAX_DELAY_SECS).contains(delay) {
            return Err(serde::de::Error::custom(format!(
                "recheck_delays_secs: each delay must be 1..={MAX_DELAY_SECS} seconds (got {delay})"
            )));
        }
    }
    Ok(delays)
}

/// A rate limit expressed as a number of requests per time window.
///
/// Serialized form is `"N/unit"` where unit is one of `sec`/`min`/`hour`/
/// `day` (single-letter abbreviations accepted when parsing). A window that
/// is none of those four is printed as `"N/<seconds>sec"` and parsed back
/// the same way, so `parse(display(x)) == x` holds for every window. A bare
/// integer is interpreted as requests per minute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub limit: u32,
    pub window: Duration,
}

impl RateLimit {
    pub const fn new(limit: u32, window: Duration) -> Self {
        Self { limit, window }
    }
}

impl FromStr for RateLimit {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        // A bare integer means "requests per minute", the same reading the
        // deserializer gives a TOML integer.
        if let Ok(limit) = s.parse::<u32>() {
            return Ok(Self::new(limit, Duration::from_secs(60)));
        }
        let (num, unit) = s
            .split_once('/')
            .ok_or_else(|| format!("rate limit must look like 'N/unit', got '{s}'"))?;
        let limit: u32 = num
            .trim()
            .parse()
            .map_err(|e| format!("invalid rate limit count '{num}': {e}"))?;
        let unit = unit.trim().to_ascii_lowercase();
        let secs: u64 = match unit.as_str() {
            "s" | "sec" | "second" => 1,
            "m" | "min" | "minute" => 60,
            "h" | "hour" => 3600,
            "d" | "day" => 86400,
            // The seconds form `N/<n>sec` is what `Display` prints for a
            // window that is none of the four canonical ones, so it has to
            // parse back to the same window.
            other => other
                .strip_suffix("sec")
                .and_then(|n| n.trim().parse::<u64>().ok())
                .ok_or_else(|| format!("unknown rate limit unit '{other}'"))?,
        };
        if secs == 0 {
            return Err("rate limit window must be at least one second".to_string());
        }
        Ok(Self::new(limit, Duration::from_secs(secs)))
    }
}

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unit = match self.window.as_secs() {
            1 => "sec",
            60 => "min",
            3600 => "hour",
            86400 => "day",
            n => return write!(f, "{}/{}sec", self.limit, n),
        };
        write!(f, "{}/{}", self.limit, unit)
    }
}

impl Serialize for RateLimit {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RateLimit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = RateLimit;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string like \"120/min\" or an integer (per minute)")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<RateLimit, E> {
                v.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<RateLimit, E> {
                let limit = u32::try_from(v).map_err(serde::de::Error::custom)?;
                Ok(RateLimit::new(limit, Duration::from_secs(60)))
            }

            // figment's TOML pipeline delivers integers as `i64`, not `u64`
            // like serde_json: without this a bare `rate_limit = 300` broke boot.
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<RateLimit, E> {
                let v = u64::try_from(v).map_err(serde::de::Error::custom)?;
                self.visit_u64(v)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// The value range one numeric setting accepts.
///
/// These bounds are what the *editor* enforces, what the settings form
/// advertises and what the loader refuses at startup, not a promise
/// about what the running code can survive. They live here, next to the
/// config they describe, because they used to live in three places at
/// once: as literal arguments in the save handler, as `min`/`max`
/// attributes in the template, and as prose in `config/app.toml`. One
/// table, three consumers.
///
/// **Composite fields.** A setting the config stores as one string but
/// the form edits as two inputs (a rate limit: `N/unit`) appears under
/// the path of the *edited* input with a `.limit` suffix:
/// `server.rate_limit.limit`. The stored key is `server.rate_limit`;
/// the suffix names the half of the pair the bound applies to. The
/// editor and the loader both read the table through this convention,
/// so a bound and the field it guards cannot drift apart.
pub mod bounds {
    /// Ceiling on `[fetch].max_response_bytes`: 256 MiB.
    ///
    /// The fetcher buffers the body of a subscription page in memory, so
    /// an unbounded value is an unbounded allocation, and the editor
    /// writes integers into a TOML document, so the value has to
    /// survive an `i64` with room to spare. 256 MiB is far above any
    /// real subscription page and far below the memory a single fetch
    /// may take.
    pub const MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

    /// Steps of the quarantine recheck ladder. Past this the ladder is
    /// a config error rather than a longer queue, so a typo cannot
    /// schedule rechecks years out.
    pub const RECHECK_MAX_STEPS: usize = 16;

    /// Longest single recheck delay, 30 days.
    pub const RECHECK_MAX_DELAY_SECS: i64 = 30 * 24 * 60 * 60;

    /// Accepted range of a numeric setting, inclusive on both ends.
    /// Every numeric setting has one: a setting without a ceiling is a
    /// setting nobody checked.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Range {
        pub min: u64,
        pub max: u64,
    }

    impl Range {
        pub const fn new(min: u64, max: u64) -> Self {
            Self { min, max }
        }

        pub fn contains(self, value: u64) -> bool {
            value >= self.min && value <= self.max
        }
    }

    /// Every bounded numeric setting, keyed by its dotted config path.
    /// A key missing from this table is either not a number or not
    /// editable in the admin panel; the template test enforces that
    /// every number input resolves here, and the loader test enforces
    /// that every row here is a config key the loader checks.
    pub const RANGES: &[(&str, Range)] = &[
        ("database.busy_timeout_ms", Range::new(100, 60_000)),
        ("database.max_connections", Range::new(1, 1024)),
        ("fetch.connect_timeout_secs", Range::new(1, 600)),
        ("fetch.read_timeout_secs", Range::new(1, 3600)),
        (
            "fetch.max_response_bytes",
            Range::new(1024, MAX_RESPONSE_BYTES),
        ),
        ("fetch.max_concurrency", Range::new(1, 1024)),
        ("fetch.max_retries", Range::new(0, 16)),
        ("fetch.retry_base_backoff_ms", Range::new(0, 60_000)),
        ("ingest.refresh_check_limit", Range::new(0, 10_000)),
        ("geo.cache_max_entries", Range::new(0, 10_000_000)),
        // One second .. 30 days; a zero TTL would expire every entry
        // immediately and turn the cache off without saying so.
        ("geo.cache_ttl_secs", Range::new(1, 30 * 24 * 3600)),
        ("geo.dns_timeout_secs", Range::new(1, 60)),
        (
            "geo.startup_download_budget_secs",
            Range::new(0, super::MAX_STARTUP_DOWNLOAD_BUDGET_SECS),
        ),
        // 0 = follow [geo].dns_timeout_secs.
        ("network.dns_timeout_secs", Range::new(0, 60)),
        ("admin.session_ttl_hours", Range::new(1, 24 * 365)),
        ("admin.rate_limit.limit", Range::new(1, 1_000_000)),
        ("admin.login_rate_limit.limit", Range::new(1, 1_000_000)),
        ("probe.fail_limit", Range::new(1, 32)),
        ("probe.second_chance_min_hours", Range::new(0, 24 * 365)),
        ("probe.second_chance_spread_hours", Range::new(0, 24 * 365)),
        ("probe.queue_stale_days", Range::new(0, 365)),
        (
            "probe.retention_interval_secs",
            Range::new(60, 7 * 24 * 3600),
        ),
        ("probe.cycle_interval_secs", Range::new(1, 24 * 3600)),
        ("probe.sample_size", Range::new(1, 100_000)),
        ("probe.connect_timeout_secs", Range::new(1, 600)),
        ("probe.tls_timeout_secs", Range::new(1, 600)),
        // Every in-flight check holds its sockets for the connect + TLS
        // window, so the concurrent tasks multiply the file descriptors
        // the process needs. Past a few hundred the default ulimit -n
        // (1024) is the real ceiling, and a config the daemon cannot
        // honor is worse than one it refuses.
        ("probe.concurrency", Range::new(1, 128)),
        ("probe.heartbeat_interval_secs", Range::new(1, 24 * 3600)),
        ("probe.backlog_target_drain_minutes", Range::new(5, 24 * 60)),
        ("meow.timeout_secs", Range::new(1, 600)),
        ("meow.backoff_initial_secs", Range::new(1, 24 * 3600)),
        ("meow.backoff_max_secs", Range::new(1, 24 * 3600)),
        ("retention.probe_results_days", Range::new(1, 3650)),
        ("retention.fetch_log_days", Range::new(1, 3650)),
        ("server.export_max_rows", Range::new(1, 10_000_000)),
        ("server.rate_limit.limit", Range::new(1, 1_000_000)),
        (
            "server.auth_fail_rate_limit.limit",
            Range::new(1, 1_000_000),
        ),
    ];

    /// The accepted range of `dotted_key`, or `None` when the setting
    /// is not a bounded number.
    pub fn range_of(dotted_key: &str) -> Option<Range> {
        RANGES
            .iter()
            .find(|(key, _)| *key == dotted_key)
            .map(|(_, range)| *range)
    }

    /// `min` rendered for an HTML attribute. A setting with no range
    /// yields an empty string rather than a made-up zero.
    pub fn min_attr(dotted_key: &str) -> String {
        range_of(dotted_key)
            .map(|r| r.min.to_string())
            .unwrap_or_default()
    }

    /// `max` rendered for an HTML attribute. A setting with no range
    /// yields an empty string rather than a made-up number.
    pub fn max_attr(dotted_key: &str) -> String {
        range_of(dotted_key)
            .map(|r| r.max.to_string())
            .unwrap_or_default()
    }

    /// The range as an operator reads it: `1..=86400`.
    pub fn display(dotted_key: &str) -> Option<String> {
        let range = range_of(dotted_key)?;
        Some(format!("{}..={}", range.min, range.max))
    }
}

/// Built-in default values. Every config key has one.
///
/// Most defaults live in the functions below and are named in each
/// field's `serde(default = ...)` attribute. The exceptions are the
/// fields with an implicit default, and each of them is deliberate:
/// `admin.allow_private_urls`, `admin.secure_cookies` and
/// `probe.allow_private_targets` default to `false` — the safe side of
/// each security toggle, turning a protection on is never the fallback —
/// `fetch.ip_family` defaults to `IpFamily::default()` (`any`), and the
/// `[log]` levels default to `LogLevel::default()` (`info`), all via
/// `#[serde(default)]` on the field or the `Default` impl of the section.
mod defaults {
    use super::*;

    pub fn server_bind() -> SocketAddr {
        "0.0.0.0:8080".parse().expect("valid socket address")
    }

    /// The drop gate is on by default: a source that carries drop rules
    /// detaches the proxies those rules would have discarded. The probe
    /// alone owns the lifecycle of the proxies no rule touches.
    pub const fn drop_gate() -> bool {
        true
    }
    pub fn database_path() -> PathBuf {
        PathBuf::from("fumox.db")
    }
    pub const fn busy_timeout_ms() -> u32 {
        30000
    }
    pub const fn max_connections() -> u32 {
        8
    }
    pub const fn synchronous() -> SynchronousMode {
        SynchronousMode::Normal
    }
    /// The checksum repair is opt-in: a re-stamp hides a DDL divergence
    /// the same way it hides a comment edit, so the operator has to say
    /// that the edit was harmless.
    pub const fn allow_checksum_repair() -> bool {
        false
    }
    pub const fn connect_timeout_secs() -> u64 {
        10
    }
    pub const fn read_timeout_secs() -> u64 {
        30
    }
    pub const fn max_response_bytes() -> u64 {
        10 * 1024 * 1024
    }
    pub const fn max_concurrency() -> usize {
        4
    }
    pub const fn max_retries() -> u32 {
        2
    }
    pub const fn retry_base_backoff_ms() -> u64 {
        500
    }
    pub fn user_agent() -> String {
        format!("fumox/{}", env!("CARGO_PKG_VERSION"))
    }
    pub const fn geo_enabled() -> bool {
        true
    }
    pub fn geo_db_dir() -> PathBuf {
        PathBuf::from("config")
    }
    pub const fn geo_cache_max_entries() -> u64 {
        16384
    }
    /// Six hours: a verdict outlives a feed's repeat window and expires
    /// before the next periodic geo backfill pass.
    pub const fn geo_cache_ttl_secs() -> u64 {
        6 * 3600
    }
    pub const fn dns_timeout_secs() -> u64 {
        5
    }
    /// The SSRF pipeline follows the geo timeout until an operator gives it
    /// its own bound.
    pub const fn network_dns_timeout_secs() -> u64 {
        0
    }
    pub const fn geo_startup_download_budget_secs() -> u64 {
        60
    }
    pub const fn geo_auto_download() -> bool {
        true
    }
    /// The public release assets the databases are fetched from when the
    /// operator names no mirror of their own.
    pub fn geo_download_urls() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "GeoLite2-ASN.mmdb".to_string(),
                "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
                    .to_string(),
            ),
            (
                "GeoLite2-City.mmdb".to_string(),
                "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-City.mmdb"
                    .to_string(),
            ),
        ])
    }
    pub const fn admin_enabled() -> bool {
        true
    }
    pub fn admin_token() -> String {
        String::new()
    }
    pub fn admin_bind() -> SocketAddr {
        "127.0.0.1:8081".parse().expect("valid socket address")
    }
    pub const fn session_ttl_hours() -> u32 {
        168
    }
    pub fn admin_rate_limit() -> RateLimit {
        RateLimit::new(120, Duration::from_secs(60))
    }
    pub fn login_rate_limit() -> RateLimit {
        RateLimit::new(5, Duration::from_secs(60))
    }
    pub fn public_rate_limit() -> RateLimit {
        RateLimit::new(300, Duration::from_secs(60))
    }
    pub fn auth_fail_rate_limit() -> RateLimit {
        RateLimit::new(30, Duration::from_secs(60))
    }
    pub fn admin_locales_dir() -> String {
        "locales".to_string()
    }
    /// Empty by default, fumox is exposed directly without a reverse proxy
    /// in most deployments, so honoring `X-Forwarded-For` would let any
    /// caller spoof the per-IP rate-limit key.
    pub fn trust_proxy_ips() -> Vec<String> {
        Vec::new()
    }
    /// No forwarding header is honored until the operator names one: a
    /// header nobody declared is text the client chose.
    pub const fn trust_proxy_header() -> TrustedHeader {
        TrustedHeader::None
    }
    /// Empty by default, the Host header is accepted verbatim, matching the
    /// historical behavior. Operators behind a reverse proxy that rewrites
    /// Host should enumerate the expected hosts here to lock the
    /// alive-export endpoint to the proxy's own hostname.
    pub fn allowed_hosts() -> Vec<String> {
        Vec::new()
    }
    /// Row ceiling of one alive/ready export body. Generous for a normal
    /// pool, finite because the export link is public, cacheable and has
    /// no upstream cap of its own.
    pub const fn export_max_rows() -> u32 {
        50_000
    }
    pub const fn cycle_interval_secs() -> u64 {
        60
    }
    pub const fn sample_size() -> u32 {
        50
    }
    pub const fn refresh_check_limit() -> u32 {
        50
    }
    pub const fn removed_as_unknown() -> bool {
        false
    }
    pub const fn fail_limit() -> u32 {
        3
    }
    pub const fn probe_connect_timeout_secs() -> u64 {
        10
    }
    pub const fn probe_tls_timeout_secs() -> u64 {
        10
    }
    pub const fn probe_concurrency() -> usize {
        8
    }
    pub const fn heartbeat_interval_secs() -> u64 {
        30
    }
    pub const fn second_chance_min_hours() -> u64 {
        12
    }
    pub const fn second_chance_spread_hours() -> u64 {
        4
    }
    pub const fn retention_interval_secs() -> u64 {
        86400
    }
    pub fn recheck_delays_secs() -> Vec<i64> {
        // defaults: +15m, +30m, +1h after the failed second chance.
        vec![15 * 60, 30 * 60, 60 * 60]
    }
    pub const fn queue_stale_days() -> u64 {
        7
    }
    /// Target drain time used by the `/admin/probe` backlog banner when
    /// computing recommended `[probe]` values. 60 minutes by default ,
    /// 5..=1440 minutes (5 min..=24 h).
    pub const fn backlog_target_drain_minutes() -> u64 {
        60
    }
    pub const fn meow_backoff_initial_secs() -> u64 {
        60
    }
    pub const fn meow_backoff_max_secs() -> u64 {
        15 * 60
    }
    /// meow-rs' own `ipv6` default (mihomo parity): IPv4-only resolution.
    pub const fn meow_ipv6() -> bool {
        false
    }
    pub fn meow_api_addr() -> String {
        "127.0.0.1:9090".to_string()
    }
    pub fn meow_api_token() -> String {
        String::new()
    }
    pub fn meow_config_path() -> PathBuf {
        PathBuf::from("config/meow.yaml")
    }
    pub fn meow_test_url() -> Vec<String> {
        // One endpoint, not a list. The probe draws the URL once per cycle
        // (see `fumox-probe`'s `cycle_test_url`), so a list only ever
        // widened the ways a whole cycle could fail; seven addresses of one
        // vendor made that worse, because a region where that vendor is
        // blocked failed every proxy at once. This endpoint answers 204
        // and is not tied to one account; operators whose egress cannot
        // reach it set `[meow].test_url` to a URL of their own.
        //
        // HTTPS, not HTTP: the request is made by the proxy under test,
        // so a hostile proxy could answer a plaintext request itself and
        // the check would read that forgery as a working tunnel. Over TLS
        // the answer has to come from the real endpoint.
        vec!["https://www.gstatic.com/generate_204".to_string()]
    }
    pub const fn meow_timeout_secs() -> u64 {
        10
    }
    pub const fn probe_results_days() -> u32 {
        14
    }
    pub const fn fetch_log_days() -> u32 {
        30
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admin writer checks the document it assembles with this
    /// parser, and the operator has to learn which key is wrong: an
    /// error that only says "invalid config" sends them looking
    /// through the whole file.
    #[test]
    fn parse_document_names_the_offending_key() {
        let err = parse_document("[server]\nbynd = \"0.0.0.0:8080\"\n")
            .expect_err("an unknown key must be refused");
        let message = err.to_string();
        assert!(
            message.contains("bynd"),
            "the error must name the offending key: {message}"
        );
    }

    /// A document the loader accepts must survive the parser too: the
    /// writer refuses everything this parser refuses, so a drift here
    /// would refuse every save.
    #[test]
    fn parse_document_accepts_what_the_loader_accepts() {
        let cfg = parse_document("[server]\nbind = \"127.0.0.1:9999\"\n")
            .expect("a valid document must parse");
        assert_eq!(cfg.server.bind.to_string(), "127.0.0.1:9999");
    }

    #[test]
    fn defaults_load_without_file() {
        // The env-pointer must not leak from other tests into this one:
        // `defaults_load_without_file` asserts the built-in defaults.
        let _guard = env_mutex().lock();
        // SAFETY: every touch of FUMOX_CONFIG across the test suite is
        // serialized by `env_mutex`; other threads read the variable only
        // through the same lock.
        unsafe { std::env::remove_var(CONFIG_PATH_ENV) };

        let cfg = load_config(None).expect("defaults must load");
        assert_eq!(cfg.admin.bind.to_string(), "127.0.0.1:8081");
        assert_eq!(cfg.database.busy_timeout_ms, 30000);
        assert_eq!(cfg.retention.probe_results_days, 14);
        assert_eq!(cfg.retention.fetch_log_days, 30);
        assert_eq!(cfg.log.server, LogLevel::Info);
        assert_eq!(cfg.log.probe, LogLevel::Info);
        // The built-in defaults carry no admin token: the panel is off
        // until an operator sets one explicitly.
        assert_eq!(cfg.admin.token, "");
        assert!(!cfg.admin.is_active());
        assert!(cfg.admin.enabled);
        // Ingest defaults: the drop gate is on (a source with drop rules
        // detaches what its rules would have discarded) and the
        // priority-probe queue is enabled.
        assert!(cfg.ingest.drop_gate);
        assert_eq!(cfg.ingest.refresh_check_limit, 50);
    }

    #[test]
    fn ingest_section_owns_drop_gate_and_refresh_check_limit() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-ingest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(
            &file,
            "[ingest]\ndrop_gate = true\nrefresh_check_limit = 10\n",
        )
        .unwrap();
        let cfg = load_config_isolated(Some(&file)).expect("ingest section must load");
        assert!(cfg.ingest.drop_gate);
        assert_eq!(cfg.ingest.refresh_check_limit, 10);

        // The keys moved house. `drop_gate` has no old spelling left, so
        // the old section still refuses it. `refresh_check_limit` keeps
        // its old name for one release: the value is carried over
        // instead of the file being refused, so an upgrade does not turn
        // into a server that will not start.
        std::fs::write(&file, "[server]\ndrop_gate = true\n").unwrap();
        assert!(load_config_isolated(Some(&file)).is_err());
        std::fs::write(&file, "[probe]\nrefresh_check_limit = 10\n").unwrap();
        let cfg = load_config_isolated(Some(&file)).expect("the old spelling must still load");
        assert_eq!(cfg.ingest.refresh_check_limit, 10);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn log_levels_are_per_binary_and_validated() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[log]\nserver = \"warn\"\nprobe = \"debug\"\n").unwrap();

        let cfg = load_config_isolated(Some(&file)).expect("log levels must load");
        assert_eq!(cfg.log.server, LogLevel::Warn);
        assert_eq!(cfg.log.probe, LogLevel::Debug);

        std::fs::write(&file, "[log]\nserver = \"loud\"\n").unwrap();
        let err = load_config_isolated(Some(&file)).unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)));

        std::fs::write(&file, "[log]\nlevel = \"warn\"\n").unwrap();
        let err = load_config_isolated(Some(&file)).unwrap_err();
        assert!(
            matches!(err, crate::Error::Config(_)),
            "unknown key rejected"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_explicit_path_is_an_error() {
        let err = load_config_isolated(Some(Path::new("/nonexistent/app.toml"))).unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)));
    }

    /// Serializes the tests that touch `FUMOX_CONFIG`: the process
    /// environment is shared by every test thread, so two of them
    /// manipulating the variable concurrently would race.
    fn env_mutex() -> &'static std::sync::Mutex<()> {
        static MUTEX: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        MUTEX.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// [`load_config`] with the process environment held still.
    ///
    /// The loader reads `FUMOX_*` from the environment, and the
    /// environment belongs to the whole process: a test that sets one of
    /// those variables leaks it into every test that runs next, whether
    /// that test asked for it or not. A leaked `FUMOX_SERVER__BIND`
    /// changes what the next test believes it loaded.
    ///
    /// The lock is not reentrant, so a test that manipulates the
    /// environment itself takes the guard and calls [`load_config`]
    /// directly.
    fn load_config_isolated(path: Option<&Path>) -> crate::Result<AppConfig> {
        let _guard = env_mutex().lock();
        load_config(path)
    }

    /// `FUMOX_CONFIG` points the loader at the TOML file when no CLI flag
    /// is given; the flag keeps priority over the variable, and a set
    /// variable whose file is missing is an error, not a silent fallback.
    #[test]
    fn env_pointed_config_file_is_loaded_and_validated() {
        let _guard = env_mutex().lock();
        let dir = std::env::temp_dir().join(format!("fumox-cfg-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("env.toml");
        std::fs::write(&file, "[retention]\nprobe_results_days = 7\n").unwrap();

        // SAFETY: every touch of FUMOX_CONFIG across the test suite is
        // serialized by `env_mutex`; other threads read the variable only
        // through the same lock.
        unsafe { std::env::set_var(CONFIG_PATH_ENV, &file) };
        let cfg = load_config(None).expect("env-pointed file must load");
        assert_eq!(cfg.retention.probe_results_days, 7);
        assert_eq!(
            cfg.retention.fetch_log_days, 30,
            "untouched keys keep defaults"
        );

        // The explicit flag outranks the variable.
        let flag_file = dir.join("flag.toml");
        std::fs::write(&flag_file, "[retention]\nprobe_results_days = 5\n").unwrap();
        let cfg = load_config(Some(&flag_file)).expect("the flag must outrank the env pointer");
        assert_eq!(cfg.retention.probe_results_days, 5);

        // A variable naming a missing file is an operator typo, loud.
        // SAFETY: see above.
        let missing = dir.join("missing.toml");
        unsafe { std::env::set_var(CONFIG_PATH_ENV, &missing) };
        let err = load_config(None).unwrap_err();
        assert!(
            err.to_string().contains(CONFIG_PATH_ENV),
            "the error names the variable: {err}"
        );

        // Empty (or whitespace) value counts as unset, the default
        // location applies again, exactly like without the variable.
        // SAFETY: see above.
        unsafe { std::env::set_var(CONFIG_PATH_ENV, "   ") };
        let cfg = load_config(None).expect("empty pointer behaves as unset");
        assert_eq!(cfg.retention.probe_results_days, 14);

        // SAFETY: see above.
        unsafe {
            std::env::remove_var(CONFIG_PATH_ENV);
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn rate_limit_parsing() {
        let rl: RateLimit = "120/min".parse().unwrap();
        assert_eq!(rl, RateLimit::new(120, Duration::from_secs(60)));
        assert_eq!(rl.to_string(), "120/min");

        assert_eq!(
            "5/m".parse::<RateLimit>().unwrap(),
            RateLimit::new(5, Duration::from_secs(60))
        );
        assert_eq!(
            "10/hour".parse::<RateLimit>().unwrap(),
            RateLimit::new(10, Duration::from_secs(3600))
        );
        // A bare integer means "per minute", the same reading the
        // deserializer gives a TOML integer.
        assert_eq!(
            "120".parse::<RateLimit>().unwrap(),
            RateLimit::new(120, Duration::from_secs(60))
        );
        assert!("x/min".parse::<RateLimit>().is_err());
        assert!("5/lightyear".parse::<RateLimit>().is_err());
        assert!("5/0sec".parse::<RateLimit>().is_err());
    }

    /// `Display` and `FromStr` have to be mutually inverse: a config the
    /// admin panel wrote has to load back into the same value.
    #[test]
    fn rate_limit_survives_a_display_parse_round_trip() {
        for limit in [
            RateLimit::new(120, Duration::from_secs(60)),
            RateLimit::new(5, Duration::from_secs(1)),
            RateLimit::new(30, Duration::from_secs(3600)),
            RateLimit::new(7, Duration::from_secs(86400)),
            // A window that is none of the four canonical ones is printed
            // in the seconds form and has to parse back.
            RateLimit::new(5, Duration::from_secs(30)),
        ] {
            let text = limit.to_string();
            assert_eq!(
                text.parse::<RateLimit>().unwrap(),
                limit,
                "'{text}' must parse back into the same rate limit"
            );
        }
    }

    #[test]
    fn rate_limit_deserializes_from_int_or_string() {
        let from_str: RateLimit = serde_json::from_str("\"5/min\"").unwrap();
        assert_eq!(from_str, RateLimit::new(5, Duration::from_secs(60)));
        let from_int: RateLimit = serde_json::from_str("42").unwrap();
        assert_eq!(from_int, RateLimit::new(42, Duration::from_secs(60)));
    }

    /// Regression: figment's TOML pipeline hands the visitor `i64`, not
    /// `u64` like serde_json, so a bare `rate_limit = 300` aborted boot.
    #[test]
    fn rate_limit_deserializes_from_bare_toml_integer() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-rl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");

        std::fs::write(&file, "[server]\nrate_limit = 300\n").unwrap();
        let cfg =
            load_config_isolated(Some(&file)).expect("bare TOML integer rate limit must load");
        assert_eq!(
            cfg.server.rate_limit,
            RateLimit::new(300, Duration::from_secs(60))
        );

        std::fs::write(&file, "[server]\nrate_limit = -1\n").unwrap();
        assert!(
            load_config_isolated(Some(&file)).is_err(),
            "a negative rate limit must be rejected"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn meow_test_url_accepts_string_array_and_csv() {
        let single: MeowConfig =
            serde_json::from_str(r#"{"test_url": "http://www.gstatic.com/generate_204"}"#).unwrap();
        assert_eq!(single.test_url, ["http://www.gstatic.com/generate_204"]);

        // A plain string may carry several URLs comma-separated, this is how
        // the FUMOX_MEOW__TEST_URL env override can configure rotation.
        let csv: MeowConfig =
            serde_json::from_str(r#"{"test_url": "http://a/204, http://b/204 ,http://c/204"}"#)
                .unwrap();
        assert_eq!(
            csv.test_url,
            ["http://a/204", "http://b/204", "http://c/204"]
        );

        let array: MeowConfig =
            serde_json::from_str(r#"{"test_url": ["http://a/204", "http://b/204"]}"#).unwrap();
        assert_eq!(array.test_url, ["http://a/204", "http://b/204"]);

        // Items of an array may also be comma-separated.
        let mixed: MeowConfig =
            serde_json::from_str(r#"{"test_url": ["http://a/204", "http://b/204, http://c/204"]}"#)
                .unwrap();
        assert_eq!(
            mixed.test_url,
            ["http://a/204", "http://b/204", "http://c/204"]
        );

        let defaults: MeowConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults.test_url.len(), 1);
        assert!(
            defaults.test_url[0].starts_with("http"),
            "the default test URL is an http endpoint: {:?}",
            defaults.test_url
        );

        for empty in [
            "{\"test_url\": \"\"}",
            "{\"test_url\": []}",
            "{\"test_url\": \" , \"}",
        ] {
            let err = serde_json::from_str::<MeowConfig>(empty).unwrap_err();
            assert!(
                err.to_string().contains("at least one URL"),
                "{empty}: {err}"
            );
        }
    }

    /// The test URL is fetched by meow-rs, so a scheme other than http(s)
    /// or an entry without a host is refused at the door.
    #[test]
    fn meow_test_url_refuses_a_non_http_scheme_or_a_hostless_entry() {
        for entry in [
            "file:///etc/passwd",
            "ftp://example.com/generate_204",
            "gopher://example.com/",
            "http://",
            "/generate_204",
            "not a url",
        ] {
            let err = serde_json::from_str::<MeowConfig>(&format!("{{\"test_url\": \"{entry}\"}}"))
                .unwrap_err();
            let text = err.to_string();
            assert!(text.contains("meow.test_url entry"), "{entry}: {text}");
        }
    }

    /// A literal loopback or link-local test URL is the SSRF the probe's
    /// own address gate exists to prevent; only the operator's explicit
    /// `allow_private_targets` opens it.
    #[test]
    fn meow_test_url_refuses_a_private_address_unless_the_flag_is_set() {
        for entry in [
            "http://127.0.0.1/generate_204",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/generate_204",
            "http://10.0.0.1/generate_204",
        ] {
            let mut config = AppConfig::default();
            config.meow.test_url = vec![entry.to_string()];
            let err = config
                .validate()
                .expect_err("a private test URL must be refused");
            let text = err.to_string();
            assert!(text.contains("meow.test_url entry"), "{entry}: {text}");
            assert!(text.contains("allow_private_targets"), "{entry}: {text}");

            // The flag opens it.
            config.probe.allow_private_targets = true;
            config
                .validate()
                .expect("allow_private_targets opens the private test URL");
        }
    }

    #[test]
    fn toml_file_overrides_defaults() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(
            &file,
            r#"
[server]
bind = "127.0.0.1:9999"

[admin]
token = ""

[retention]
probe_results_days = 7
"#,
        )
        .unwrap();

        let cfg = load_config_isolated(Some(&file)).expect("toml must load");
        assert_eq!(cfg.server.bind.to_string(), "127.0.0.1:9999");
        assert!(!cfg.admin.is_active(), "empty token disables the admin");
        assert_eq!(cfg.retention.probe_results_days, 7);
        assert_eq!(
            cfg.retention.fetch_log_days, 30,
            "untouched keys keep defaults"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn placeholder_admin_token_disables_the_panel() {
        let mut admin = AdminConfig {
            token: PLACEHOLDER_ADMIN_TOKEN.to_string(),
            ..AdminConfig::default()
        };
        assert!(!admin.is_active(), "the placeholder is not a token");
        assert!(admin.uses_placeholder_token());

        admin.token = String::new();
        assert!(!admin.is_active(), "an empty token is not a token either");

        admin.token = "a-real-secret".to_string();
        assert!(admin.is_active());
        assert!(!admin.uses_placeholder_token());

        admin.enabled = false;
        assert!(!admin.is_active(), "the master switch still wins");
    }

    #[test]
    fn placeholder_admin_token_on_a_public_bind_refuses_to_start() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-ph-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(
            &file,
            "[admin]\nenabled = true\ntoken = \"change-me\"\nbind = \"0.0.0.0:8081\"\n",
        )
        .unwrap();

        let err = load_config_isolated(Some(&file)).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("change-me"),
            "the error must name the placeholder: {message}"
        );
        assert!(
            message.contains("admin.token"),
            "the error must name the key to fix: {message}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn placeholder_admin_token_on_a_loopback_bind_still_loads() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-phl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(
            &file,
            "[admin]\nenabled = true\ntoken = \"change-me\"\nbind = \"127.0.0.1:8081\"\n",
        )
        .unwrap();

        let cfg = load_config_isolated(Some(&file)).expect("a loopback placeholder must load");
        assert!(!cfg.admin.is_active());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[admin]\ntokn = \"oops\"\n").unwrap();

        let err = load_config_isolated(Some(&file)).unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Keys the reference file deliberately does not declare. Empty since
    /// the inert one-database-era `[geo].db` selector was dropped from the
    /// struct (old files still parse: the key is accepted and ignored,
    /// but it is no longer a config key, so the shipped file that promises
    /// "every available key" must not declare it either).
    const REFERENCE_FILE_OMISSIONS: &[&str] = &[];

    /// The bounds table is a lookup, so a duplicate key is not a
    /// compile error: `range_of` would silently return the first one and
    /// the second would read as a live row that no field ever uses. The
    /// server-side test proves every row is rendered; this proves there
    /// is only one row per key, and that no range is inverted.
    #[test]
    fn bounds_rows_are_unique_and_ordered() {
        let mut seen = std::collections::BTreeSet::new();
        for (key, range) in bounds::RANGES {
            assert!(seen.insert(*key), "duplicate bounds row for {key}");
            assert!(
                range.min <= range.max,
                "{key}: min {} above max {}",
                range.min,
                range.max
            );
        }
    }

    /// Every bounds key has to be a real config path. The table is keyed
    /// by the *form field* name, which for the four rate-limit inputs is
    /// `<path>.limit` (the number half of a number-plus-unit pair)
    /// while the config itself stores one `RateLimit` under `<path>`.
    /// That suffix is the only place the two naming schemes differ, so
    /// it is stripped here rather than pretended away.
    #[test]
    fn bounds_keys_are_real_config_paths() {
        for (key, _) in bounds::RANGES {
            let path = key.strip_suffix(".limit").unwrap_or(key);
            let (section, leaf) = path.split_once('.').expect("bounds key is section.leaf");
            let json = serde_json::to_value(AppConfig::default()).unwrap();
            let found = json
                .get(section)
                .and_then(|s| s.get(leaf))
                .is_some_and(|v| !v.is_null());
            assert!(found, "{key} is bounded but AppConfig has no such key");
        }
    }

    /// The bounds table and the list of settings the loader checks are
    /// two tables. A setting in one and missing from the other is a
    /// setting nobody bounds: the editor refuses it, the loader accepts
    /// it, and the operator gets two different answers about the same
    /// key depending on where the value came from.
    #[test]
    fn every_bounded_setting_is_checked_by_the_loader() {
        let checked: std::collections::BTreeSet<&str> = AppConfig::default()
            .numeric_settings()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let bounded: std::collections::BTreeSet<&str> =
            bounds::RANGES.iter().map(|(k, _)| *k).collect();
        let unbounded: Vec<_> = bounded.difference(&checked).collect();
        assert!(
            unbounded.is_empty(),
            "these settings have a range but the loader never checks them: {unbounded:?}"
        );
        let unchecked: Vec<_> = checked.difference(&bounded).collect();
        assert!(
            unchecked.is_empty(),
            "these settings are checked by the loader but have no range: {unchecked:?}"
        );
        assert_eq!(
            checked.len(),
            bounds::RANGES.len(),
            "the two tables must have the same size: {checked:?} vs {bounded:?}"
        );
    }

    /// A value outside its range fails at startup, and the message names
    /// the key and the bound: an operator who typed the value has to be
    /// able to find it without reading the source.
    #[test]
    fn an_out_of_range_value_fails_at_startup() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-range-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");

        std::fs::write(&file, "[probe]\nfail_limit = 0\n").unwrap();
        let err = load_config_isolated(Some(&file)).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("probe.fail_limit"),
            "the error must name the key: {message}"
        );
        assert!(
            message.contains("1..=32"),
            "the error must name the bound: {message}"
        );

        // The zero values the range table forbids.
        for (section, body) in [
            ("probe", "sample_size = 0\n"),
            ("admin", "session_ttl_hours = 0\n"),
            ("server", "export_max_rows = 0\n"),
            ("database", "busy_timeout_ms = 0\n"),
        ] {
            std::fs::write(&file, format!("[{section}]\n{body}")).unwrap();
            let err = load_config_isolated(Some(&file)).unwrap_err();
            assert!(
                matches!(err, crate::Error::Config(_)),
                "[{section}] {body} must be refused: {err}"
            );
        }

        // The response-size ceiling: an unbounded body limit is an
        // unbounded allocation.
        std::fs::write(&file, "[fetch]\nmax_response_bytes = 1073741824\n").unwrap();
        let err = load_config_isolated(Some(&file)).unwrap_err();
        assert!(
            err.to_string().contains("fetch.max_response_bytes"),
            "the error must name the key: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A trusted-proxy entry that covers the whole internet is a config
    /// error: the per-IP rate limit would key on a value the caller
    /// chooses, which is the same as having no per-IP limit at all.
    #[test]
    fn a_trust_proxy_entry_that_covers_everything_is_refused() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-cidr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");

        for entry in ["0.0.0.0/0", "::/0"] {
            std::fs::write(
                &file,
                format!("[server]\ntrust_proxy_ips = [\"{entry}\"]\n"),
            )
            .unwrap();
            let err = load_config_isolated(Some(&file)).unwrap_err();
            assert!(
                err.to_string().contains("trust_proxy_ips"),
                "{entry} must be refused: {err}"
            );
        }

        // An entry that is not an address at all.
        std::fs::write(&file, "[server]\ntrust_proxy_ips = [\"not-an-address\"]\n").unwrap();
        assert!(load_config_isolated(Some(&file)).is_err());

        // A plain host prefix and a real CIDR are both fine.
        for entry in ["10.0.0.1", "10.0.0.0/8", "::1"] {
            std::fs::write(
                &file,
                format!("[server]\ntrust_proxy_ips = [\"{entry}\"]\n"),
            )
            .unwrap();
            assert!(
                load_config_isolated(Some(&file)).is_ok(),
                "{entry} must be accepted"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The priority queue drains at the rate the probe checks proxies.
    /// A queue that grows faster than it drains never empties, and the
    /// proxies an operator waits for sit at the back of it for ever.
    #[test]
    fn a_refresh_limit_the_probe_cannot_drain_is_refused() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-queue-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");

        // 60 per minute = 3600 per hour, so a limit of 3600 fits and
        // 3601 does not.
        std::fs::write(
            &file,
            "[probe]\ncycle_interval_secs = 60\nsample_size = 60\n\
             [ingest]\nrefresh_check_limit = 3600\n",
        )
        .unwrap();
        assert!(load_config_isolated(Some(&file)).is_ok());

        std::fs::write(
            &file,
            "[probe]\ncycle_interval_secs = 60\nsample_size = 60\n\
             [ingest]\nrefresh_check_limit = 3601\n",
        )
        .unwrap();
        let err = load_config_isolated(Some(&file)).unwrap_err();
        assert!(
            err.to_string().contains("ingest.refresh_check_limit"),
            "the error must name the key: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The shipped `config/app.toml` is the full reference of every available
    /// key at its default value (owner request 2026-08-30). Guard it against
    /// rot: whenever a config struct gains a field, the file must gain the
    /// key too, or this test fails. Values are intentionally not compared ,
    /// the file doubles as a working deployment config and may override them.
    ///
    /// The key set is read from the file **as TOML text**, not through
    /// `extract::<AppConfig>()`: every field carries a serde default, so a
    /// deserialized struct is the default set by construction and a key
    /// deleted from the file reappears filled from that default, the diff
    /// was empty whatever the file said.
    #[test]
    fn shipped_app_toml_covers_every_key() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/app.toml");
        assert!(
            path.is_file(),
            "the reference config must be part of the checkout: {}",
            path.display()
        );

        let text = std::fs::read_to_string(&path).expect("config/app.toml must be readable");
        let doc: toml_edit::DocumentMut = text
            .parse()
            .expect("config/app.toml must be valid TOML on its own");

        let mut file_keys = std::collections::BTreeSet::new();
        for (key, item) in doc.iter() {
            toml_leaf_paths(key, item, &mut file_keys);
        }
        let mut default_keys = std::collections::BTreeSet::new();
        for path in config_paths() {
            default_keys.insert(path);
        }
        for omitted in REFERENCE_FILE_OMISSIONS {
            assert!(
                default_keys.remove(*omitted),
                "{omitted} is not a config key any more, drop it from REFERENCE_FILE_OMISSIONS"
            );
        }

        let missing: Vec<_> = default_keys.difference(&file_keys).collect();
        assert!(
            missing.is_empty(),
            "config/app.toml is missing keys (add them at their default values): {missing:?}"
        );
        let unknown: Vec<_> = file_keys.difference(&default_keys).collect();
        assert!(
            unknown.is_empty(),
            "config/app.toml declares keys AppConfig does not know (typo, or a renamed key): {unknown:?}"
        );

        // The file is also the deployment config the image ships, so it
        // has to survive the loader's own checks: a value outside its
        // range, an unknown key or an unparsable trust list would stop
        // the server at the first start.
        load_config_isolated(Some(&path)).expect("the shipped config must load");
    }

    /// Dotted leaf paths of a parsed TOML document (`server.allowed_hosts`):
    /// tables recurse, everything else is a single key so an array stays one
    /// leaf, matching how [`config_paths`] flattens the serialized struct.
    fn toml_leaf_paths(
        prefix: &str,
        item: &toml_edit::Item,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        match item {
            toml_edit::Item::Table(table) => {
                for (key, nested) in table.iter() {
                    let path = if prefix.is_empty() {
                        key.to_string()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    toml_leaf_paths(&path, nested, out);
                }
            }
            _ => {
                out.insert(prefix.to_string());
            }
        }
    }

    #[test]
    fn geo_dns_timeout_returns_duration_from_secs() {
        let cfg = GeoConfig {
            dns_timeout_secs: 7,
            ..Default::default()
        };
        assert_eq!(cfg.dns_timeout(), std::time::Duration::from_secs(7));
    }

    /// The SSRF pipeline has its own DNS bound: the dedicated
    /// `[network].dns_timeout_secs` when it is set, the geo key otherwise,
    /// and never below one second (a zero timeout would fail every
    /// resolution instantly).
    #[test]
    fn the_ssrf_dns_timeout_follows_the_geo_key_until_it_is_set() {
        let mut cfg = AppConfig::default();
        assert_eq!(cfg.geo.dns_timeout_secs, 5);
        assert_eq!(cfg.ssrf_dns_timeout(), std::time::Duration::from_secs(5));

        cfg.network.dns_timeout_secs = 9;
        assert_eq!(cfg.ssrf_dns_timeout(), std::time::Duration::from_secs(9));

        // The geo key stays the geo enrichment's own bound.
        cfg.geo.dns_timeout_secs = 3;
        assert_eq!(cfg.ssrf_dns_timeout(), std::time::Duration::from_secs(9));
        assert_eq!(cfg.geo.dns_timeout(), std::time::Duration::from_secs(3));

        // A zero bound is clamped to one second, never to "no wait".
        cfg.network.dns_timeout_secs = 0;
        cfg.geo.dns_timeout_secs = 0;
        assert_eq!(cfg.ssrf_dns_timeout(), std::time::Duration::from_secs(1));
    }

    /// A `FUMOX_*` variable that names no configuration key is a
    /// mistake, and a silent one: the variable is simply not applied
    /// and the setting keeps the value the file gave it. The loader
    /// refuses it and names the key it probably meant.
    #[test]
    fn a_typo_in_an_env_var_is_refused() {
        let _guard = env_mutex().lock();

        // SAFETY: every touch of FUMOX_* across the test suite is
        // serialized by `env_mutex`; other threads read the variable only
        // through the same lock.
        unsafe { std::env::set_var("FUMOX_ADMNI__TOKEN", "secret") };
        let err = load_config(None).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("FUMOX_ADMNI__TOKEN"),
            "the error must name the variable: {message}"
        );
        assert!(
            message.contains("admin.token"),
            "the error must suggest the key it meant: {message}"
        );
        // SAFETY: see above.
        unsafe { std::env::remove_var("FUMOX_ADMNI__TOKEN") };

        assert!(
            load_config(None).is_ok(),
            "the variable is gone, the load must succeed again"
        );
    }

    /// The deployment variables of the compose file are not config keys.
    /// They must not stop the server from starting.
    #[test]
    fn the_compose_only_variables_are_ignored() {
        let _guard = env_mutex().lock();

        // `FUMOX_CONFIG` is the file pointer, not a setting: it is
        // covered by `env_pointed_config_file_is_loaded_and_validated`.
        for name in NON_CONFIG_ENV_VARS
            .iter()
            .filter(|n| **n != CONFIG_PATH_ENV)
        {
            // SAFETY: every touch of FUMOX_* across the test suite is
            // serialized by `env_mutex`; other threads read the variable
            // only through the same lock.
            unsafe { std::env::set_var(name, "1") };
        }
        let loaded = load_config(None);
        for name in NON_CONFIG_ENV_VARS
            .iter()
            .filter(|n| **n != CONFIG_PATH_ENV)
        {
            // SAFETY: see above.
            unsafe { std::env::remove_var(name) };
        }
        loaded.expect("the compose variables must not stop the load");
    }

    /// The whitelist is the configuration's own key set, so a key that
    /// exists is applied and a key that does not is refused.
    #[test]
    fn the_env_whitelist_is_the_config_key_set() {
        let paths = config_paths();
        assert!(paths.contains(&"server.bind".to_string()));
        assert!(paths.contains(&"admin.token".to_string()));
        assert!(paths.contains(&"meow.test_url".to_string()));
        assert!(
            !paths.iter().any(|p| p.contains("..") || p.ends_with('.')),
            "the paths must be plain dotted names: {paths:?}"
        );
    }

    /// The dump shows the effective values and never the token: it
    /// lands in terminals, CI logs and bug reports.
    #[test]
    fn the_config_dump_redacts_the_admin_token() {
        let config = AppConfig {
            admin: AdminConfig {
                token: "a-real-secret".to_string(),
                ..AdminConfig::default()
            },
            ..AppConfig::default()
        };
        let text = dump(&config).expect("the config must render");
        assert!(
            !text.contains("a-real-secret"),
            "the token must not appear in the dump: {text}"
        );
        assert!(
            text.contains(REDACTED_ADMIN_TOKEN),
            "the placeholder must be there instead: {text}"
        );

        // An empty token stays empty: the placeholder would suggest a
        // token is set when none is.
        let config = AppConfig::default();
        let text = dump(&config).expect("the config must render");
        assert!(!text.contains(REDACTED_ADMIN_TOKEN), "{text}");
    }

    /// The legacy `[geo].db` selector no longer exists as a config field:
    /// old files that still carry the key must keep loading (any value,
    /// even one the old enum would have refused), and a serialized
    /// config must not re-emit the dead knob. A non-empty value is a
    /// setting the operator wrote, so it draws a warning instead of a
    /// silent ignore; the empty historical "unset" spelling stays silent.
    #[test]
    fn legacy_geo_db_key_is_accepted_and_ignored() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-geodb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        // A value the old `GeoDbKind` would still have accepted…
        std::fs::write(&file, "[geo]\ndb = \"city\"\n").unwrap();
        assert!(load_config_isolated(Some(&file)).is_ok());
        // …and one it would not: the key is ignored wholesale now.
        std::fs::write(&file, "[geo]\ndb = 42\n").unwrap();
        assert!(load_config_isolated(Some(&file)).is_ok());
        // The empty spelling counts as unset and stays warning-free.
        std::fs::write(&file, "[geo]\ndb = \"\"\n").unwrap();
        assert!(load_config_isolated(Some(&file)).is_ok());
        std::fs::remove_dir_all(&dir).ok();

        // The key must not round-trip back into written config.
        let json = serde_json::to_value(GeoConfig::default()).unwrap();
        assert!(
            json.get("db").is_none(),
            "the dead [geo].db knob must not serialize: {json}"
        );
    }

    /// `[probe].refresh_check_limit` moved to `[ingest].refresh_check_limit`
    /// when the priority queue became the scheduler's. A config file from
    /// the release that still carries the old key must keep loading: an
    /// upgrade that refuses to start is the worst possible outcome of a
    /// rename. The value comes along, so the queue depth the operator
    /// chose survives the upgrade too.
    #[test]
    fn the_moved_refresh_check_limit_key_is_accepted_and_carried_over() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-moved-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");

        std::fs::write(&file, "[probe]\nrefresh_check_limit = 7\n").unwrap();
        let loaded = load_config_isolated(Some(&file)).expect("the old key must still load");
        assert_eq!(loaded.ingest.refresh_check_limit, 7);

        // The new key wins when the operator set both: the old name is
        // the leftover, the new one is the intent.
        std::fs::write(
            &file,
            "[probe]\nrefresh_check_limit = 7\n[ingest]\nrefresh_check_limit = 3\n",
        )
        .unwrap();
        let loaded = load_config_isolated(Some(&file)).expect("both keys must load");
        assert_eq!(loaded.ingest.refresh_check_limit, 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The old name must not come back: a config written from the model
    /// carries the key in its new home only, so the warning stops once
    /// the operator renamed it.
    #[test]
    fn the_moved_key_does_not_round_trip_into_a_written_config() {
        let json = serde_json::to_value(ProbeConfig::default()).unwrap();
        assert!(
            json.get("refresh_check_limit").is_none(),
            "the moved [probe].refresh_check_limit knob must not serialize: {json}"
        );
    }

    /// The environment variable of the old name is accepted too: an
    /// operator who set `FUMOX_PROBE__REFRESH_CHECK_LIMIT` would
    /// otherwise hit the "names no configuration key" refusal.
    #[test]
    fn the_old_environment_variable_is_still_accepted() {
        let _guard = env_mutex().lock();
        let dir = std::env::temp_dir().join(format!("fumox-cfg-moved-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[server]\nbind = \"127.0.0.1:8080\"\n").unwrap();

        // SAFETY: every touch of FUMOX_* across the test suite is
        // serialized by `env_mutex`; other threads read the variable only
        // through the same lock.
        unsafe { std::env::set_var("FUMOX_PROBE__REFRESH_CHECK_LIMIT", "9") };
        let loaded = load_config(Some(&file)).expect("the old variable must still be accepted");
        assert_eq!(loaded.ingest.refresh_check_limit, 9);
        // SAFETY: see above.
        unsafe { std::env::remove_var("FUMOX_PROBE__REFRESH_CHECK_LIMIT") };

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The startup budget is operator-tunable, not a constant baked into
    /// the server binary: a mirror that needs longer than the default (or an
    /// operator willing to boot without geo) must be able to say so in
    /// `app.toml` or via `FUMOX_GEO__STARTUP_DOWNLOAD_BUDGET_SECS`.
    #[test]
    fn geo_startup_download_budget_is_configurable() {
        let _guard = env_mutex().lock();

        assert_eq!(
            GeoConfig::default().startup_download_budget(),
            std::time::Duration::from_secs(60)
        );
        let cfg = GeoConfig {
            startup_download_budget_secs: 5,
            ..Default::default()
        };
        assert_eq!(
            cfg.startup_download_budget(),
            std::time::Duration::from_secs(5)
        );

        let dir = std::env::temp_dir().join(format!("fumox-cfg-geobudget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[geo]\nstartup_download_budget_secs = 15\n").unwrap();
        let loaded = load_config(Some(&file)).unwrap();
        assert_eq!(
            loaded.geo.startup_download_budget(),
            std::time::Duration::from_secs(15)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The startup budget is capped: the public surface waits for it, and
    /// no mirror is worth minutes of an unavailable instance. A value
    /// above the cap (a hand-edited file) is clamped, not rejected: an
    /// existing installation still starts.
    #[test]
    fn the_geo_startup_budget_is_capped() {
        let cfg = GeoConfig {
            startup_download_budget_secs: 3_600,
            ..Default::default()
        };
        assert_eq!(
            cfg.startup_download_budget(),
            std::time::Duration::from_secs(MAX_STARTUP_DOWNLOAD_BUDGET_SECS)
        );
        assert_eq!(
            bounds::range_of("geo.startup_download_budget_secs")
                .unwrap()
                .max,
            MAX_STARTUP_DOWNLOAD_BUDGET_SECS
        );
    }

    /// The alive/ready export row ceiling is a setting, like the geo
    /// startup budget above: an operator with a tier larger than the
    /// shipped 50 000 rows raises it in `config/app.toml` or via
    /// `FUMOX_SERVER__EXPORT_MAX_ROWS`, and the env override still
    /// outranks the file. A config missing the key keeps the shipped
    /// number, so no existing deployment changes behavior.
    #[test]
    fn server_export_max_rows_is_configurable() {
        let _guard = env_mutex().lock();

        assert_eq!(
            ServerConfig::default().export_max_rows,
            50_000,
            "the default must be the number the hard-coded constant used"
        );

        let dir = std::env::temp_dir().join(format!("fumox-cfg-exportcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");

        // A config that does not mention the key keeps the default.
        std::fs::write(&file, "[server]\nbind = \"0.0.0.0:8080\"\n").unwrap();
        assert_eq!(
            load_config(Some(&file)).unwrap().server.export_max_rows,
            50_000
        );

        // The file raises it.
        std::fs::write(&file, "[server]\nexport_max_rows = 200000\n").unwrap();
        assert_eq!(
            load_config(Some(&file)).unwrap().server.export_max_rows,
            200_000
        );

        // The env outranks the file, as for every other key.
        // SAFETY: every touch of FUMOX_SERVER__EXPORT_MAX_ROWS across the
        // test suite is serialized by `env_mutex`.
        unsafe { std::env::set_var("FUMOX_SERVER__EXPORT_MAX_ROWS", "7") };
        assert_eq!(
            load_config(Some(&file)).unwrap().server.export_max_rows,
            7,
            "FUMOX_SERVER__EXPORT_MAX_ROWS must outrank the file value"
        );

        // SAFETY: see above.
        unsafe {
            std::env::remove_var("FUMOX_SERVER__EXPORT_MAX_ROWS");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// `FUMOX_ADMIN__TOKEN` must outrank the value written to
    /// `config/app.toml`, env overrides are how operators rotate the
    /// admin token without editing the file (regression for the
    /// figment-merge case that silently left the file value in place).
    #[test]
    fn env_admin_token_overrides_file() {
        let _guard = env_mutex().lock();

        let dir = std::env::temp_dir().join(format!("fumox-cfg-envtoken-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[admin]\ntoken = \"from-file\"\n").unwrap();

        // SAFETY: every touch of FUMOX_ADMIN__TOKEN across the test suite is
        // serialized by `env_mutex`; other threads read the variable only
        // through the same lock.
        unsafe { std::env::set_var("FUMOX_ADMIN__TOKEN", "from-env") };
        let cfg = load_config(Some(&file)).expect("env override must load");
        assert_eq!(
            cfg.admin.token, "from-env",
            "FUMOX_ADMIN__TOKEN must outrank [admin].token from the file"
        );

        // SAFETY: see above.
        unsafe {
            std::env::remove_var("FUMOX_ADMIN__TOKEN");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// Env must override the file for every type the loader handles ,
    /// not just `String`. `Env::split` in figment 0.10 does a string
    /// replace, so the merge path is the same for every leaf, but
    /// guarding each type catches regressions in a single place.
    /// `Vec<String>` overrides need a JSON array (figment's default
    /// sequence deserializer), not a comma-separated string, that
    /// comma-split support lives in `de_test_urls` and is opt-in.
    #[test]
    fn env_overrides_file_for_every_type() {
        let _guard = env_mutex().lock();

        let dir = std::env::temp_dir().join(format!("fumox-cfg-envtypes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(
            &file,
            "[admin]\ntoken = \"file-token\"\n\
             [ingest]\ndrop_gate = false\n\
             [probe]\ncycle_interval_secs = 60\n\
             [server]\ntrust_proxy_ips = [\"10.9.0.0/16\"]\n",
        )
        .unwrap();

        // SAFETY: every touch of FUMOX_* across the test suite is
        // serialized by `env_mutex`; other threads read the variable only
        // through the same lock.
        unsafe {
            std::env::set_var("FUMOX_ADMIN__TOKEN", "env-token");
            std::env::set_var("FUMOX_INGEST__DROP_GATE", "true");
            std::env::set_var("FUMOX_PROBE__CYCLE_INTERVAL_SECS", "7");
            std::env::set_var("FUMOX_SERVER__TRUST_PROXY_IPS", "[\"10.8.0.0/16\"]");
        }
        let cfg = load_config(Some(&file)).expect("env overrides must load");
        assert_eq!(cfg.admin.token, "env-token");
        assert!(cfg.ingest.drop_gate);
        assert_eq!(cfg.probe.cycle_interval_secs, 7);
        assert_eq!(cfg.server.trust_proxy_ips, ["10.8.0.0/16"]);

        // SAFETY: see above.
        unsafe {
            std::env::remove_var("FUMOX_ADMIN__TOKEN");
            std::env::remove_var("FUMOX_INGEST__DROP_GATE");
            std::env::remove_var("FUMOX_PROBE__CYCLE_INTERVAL_SECS");
            std::env::remove_var("FUMOX_SERVER__TRUST_PROXY_IPS");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// The list of settings the environment overrides is what the admin
    /// panel renders read-only: a field named here cannot be changed
    /// through the file, because the env layer wins over it.
    #[test]
    fn the_env_overridden_paths_name_the_settings_the_environment_wins() {
        let _guard = env_mutex().lock();

        // SAFETY: every touch of FUMOX_* across the test suite is
        // serialized by `env_mutex`; other threads read the variable only
        // through the same lock.
        unsafe {
            std::env::set_var("FUMOX_INGEST__DROP_GATE", "true");
            std::env::set_var("FUMOX_ADMIN__TOKEN", "env-token");
            // A deployment variable, not a setting.
            std::env::set_var("FUMOX_CONFIG_ACCESS", "rw");
        }
        let overridden = env_overridden_paths();
        assert!(
            overridden.contains(&"ingest.drop_gate".to_string()),
            "the bool the env overrides must be listed: {overridden:?}"
        );
        assert!(
            overridden.contains(&"admin.token".to_string()),
            "the token the env overrides must be listed: {overridden:?}"
        );
        assert!(
            !overridden.iter().any(|path| path.starts_with("config")),
            "a deployment variable is not a setting: {overridden:?}"
        );
        // Sorted and free of duplicates: the panel renders the list as
        // it stands, and a repeated entry would read as a mistake.
        let mut sorted = overridden.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, overridden, "the list must be sorted and unique");

        // SAFETY: see above.
        unsafe {
            std::env::remove_var("FUMOX_INGEST__DROP_GATE");
            std::env::remove_var("FUMOX_ADMIN__TOKEN");
            std::env::remove_var("FUMOX_CONFIG_ACCESS");
        }
        let after = env_overridden_paths();
        assert!(
            !after.contains(&"ingest.drop_gate".to_string()),
            "the list must empty out with the environment: {after:?}"
        );
        assert!(
            !after.contains(&"admin.token".to_string()),
            "the list must empty out with the environment: {after:?}"
        );
    }

    /// [`load`] reports which config file it actually read: an existing
    /// explicit path comes back as [`ResolvedConfigPath::Loaded`], a
    /// missing one is an operator typo and fails loudly, and no file
    /// anywhere is the out-of-the-box [`ResolvedConfigPath::Missing`]
    /// (the crate directory the tests run in has no `config/app.toml`).
    #[test]
    fn load_reports_which_config_file_it_read() {
        let _guard = env_mutex().lock();
        let dir = std::env::temp_dir().join(format!("fumox-cfg-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[retention]\nprobe_results_days = 7\n").unwrap();

        // An existing explicit path is loaded and named.
        let loaded = load(Some(&file)).expect("the explicit file must load");
        assert_eq!(loaded.path, ResolvedConfigPath::Loaded(file.clone()));
        assert_eq!(loaded.config.retention.probe_results_days, 7);

        // A missing explicit path is an error, not a fallback.
        let missing = dir.join("missing.toml");
        let err = load(Some(&missing)).unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)), "{err}");
        assert!(err.to_string().contains("missing.toml"), "{err}");

        // Without any pointer and without a config/app.toml next to the
        // crate, the loader runs on built-in defaults.
        // SAFETY: every touch of FUMOX_CONFIG across the test suite is
        // serialized by `env_mutex`.
        unsafe { std::env::set_var(CONFIG_PATH_ENV, "   ") };
        let defaults = load(None).expect("defaults must load");
        assert_eq!(
            defaults.path,
            ResolvedConfigPath::Missing,
            "no config/app.toml next to the crate"
        );

        // SAFETY: see above.
        unsafe {
            std::env::remove_var(CONFIG_PATH_ENV);
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// `[fetch].ip_family` parses from the file and from the environment
    /// into the three families, defaults to `IpFamily::Any`, and refuses
    /// a value that is none of them.
    #[test]
    fn fetch_ip_family_parses_from_toml_and_env() {
        assert_eq!(IpFamily::default(), IpFamily::Any);
        assert_eq!(FetchConfig::default().ip_family, IpFamily::Any);

        let dir = std::env::temp_dir().join(format!("fumox-cfg-ipfam-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        for (text, expected) in [
            ("\"any\"", IpFamily::Any),
            ("\"ipv4\"", IpFamily::Ipv4),
            ("\"ipv6\"", IpFamily::Ipv6),
        ] {
            std::fs::write(&file, format!("[fetch]\nip_family = {text}\n")).unwrap();
            let cfg = load_config_isolated(Some(&file)).expect("a known family must load");
            assert_eq!(cfg.fetch.ip_family, expected, "{text}");
        }

        std::fs::write(&file, "[fetch]\nip_family = \"dual\"\n").unwrap();
        let err = load_config_isolated(Some(&file)).unwrap_err();
        assert!(
            matches!(err, crate::Error::Config(_)),
            "an unknown family must be refused: {err}"
        );

        // The environment override: `FUMOX_FETCH__IP_FAMILY` wins over
        // the file, exactly like for every other key.
        // SAFETY: every touch of FUMOX_* across the test suite is
        // serialized by `env_mutex`.
        let _guard = env_mutex().lock();
        unsafe { std::env::set_var("FUMOX_FETCH__IP_FAMILY", "ipv6") };
        let cfg = load(Some(&file)).expect("the env override must load");
        assert_eq!(
            cfg.config.fetch.ip_family,
            IpFamily::Ipv6,
            "FUMOX_FETCH__IP_FAMILY must apply"
        );
        // SAFETY: see above.
        unsafe { std::env::remove_var("FUMOX_FETCH__IP_FAMILY") };

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The host→geo verdict lifetime is a config key: six hours by
    /// default, readable from the file and overridable from the
    /// environment like every other key.
    #[test]
    fn geo_cache_ttl_is_configurable() {
        assert_eq!(
            GeoConfig::default().cache_ttl_secs,
            6 * 3600,
            "the shipped default is six hours"
        );

        let dir = std::env::temp_dir().join(format!("fumox-cfg-ttl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[geo]\ncache_ttl_secs = 600\n").unwrap();
        let loaded = load(Some(&file)).expect("the ttl key must load");
        assert_eq!(loaded.config.geo.cache_ttl_secs, 600);

        // SAFETY: every touch of FUMOX_* across the test suite is
        // serialized by `env_mutex`.
        let _guard = env_mutex().lock();
        unsafe { std::env::set_var("FUMOX_GEO__CACHE_TTL_SECS", "120") };
        let loaded = load(Some(&file)).expect("the env override must load");
        assert_eq!(
            loaded.config.geo.cache_ttl_secs, 120,
            "FUMOX_GEO__CACHE_TTL_SECS must outrank the file"
        );
        // SAFETY: see above.
        unsafe { std::env::remove_var("FUMOX_GEO__CACHE_TTL_SECS") };

        // A zero TTL would expire every entry immediately: refused.
        // `load_config` directly: the guard is already held and the
        // helper's lock is not reentrant.
        std::fs::write(&file, "[geo]\ncache_ttl_secs = 0\n").unwrap();
        assert!(load_config(Some(&file)).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The token is a credential: it must not appear in the `Debug` output
    /// of the admin section, of the whole config, or of the loaded result
    /// — the placeholder takes its place, like in `--print-config`.
    #[test]
    fn the_admin_token_is_redacted_in_debug_output() {
        let config = AppConfig {
            admin: AdminConfig {
                token: "a-real-secret".to_string(),
                ..AdminConfig::default()
            },
            ..AppConfig::default()
        };
        let text = format!("{config:?}");
        assert!(
            !text.contains("a-real-secret"),
            "the token must not appear in AppConfig debug: {text}"
        );
        assert!(
            text.contains(&format!("token: \"{REDACTED_ADMIN_TOKEN}\"")),
            "the placeholder must be there instead: {text}"
        );

        let loaded = LoadedConfig {
            config: config.clone(),
            path: ResolvedConfigPath::Missing,
        };
        let text = format!("{loaded:?}");
        assert!(
            !text.contains("a-real-secret"),
            "the token must not appear in LoadedConfig debug: {text}"
        );

        let text = format!("{:?}", config.admin);
        assert!(
            !text.contains("a-real-secret") && text.contains(REDACTED_ADMIN_TOKEN),
            "the admin section debug redacts too: {text}"
        );
    }

    /// The cross-field check names both values: an operator who typed
    /// them has to see which one is the wrong one.
    #[test]
    fn the_meow_backoff_check_names_both_values() {
        let mut config = AppConfig::default();
        config.meow.backoff_initial_secs = 300;
        config.meow.backoff_max_secs = 60;
        let err = config.validate().expect_err("max below initial is refused");
        let message = err.to_string();
        assert!(
            message.contains("meow.backoff_max_secs (60)")
                && message.contains("meow.backoff_initial_secs (300)"),
            "the error must contain both actual values: {message}"
        );
    }

    /// The concurrency ceiling is the file-descriptor budget, not an
    /// arbitrary number: a config above it is refused at startup, and the
    /// range the admin editor advertises is the same table.
    #[test]
    fn the_probe_concurrency_ceiling_is_enforced() {
        assert_eq!(
            bounds::range_of("probe.concurrency"),
            Some(bounds::Range::new(1, 128)),
            "the ceiling keeps the in-flight sockets under a default ulimit -n"
        );
        let dir = std::env::temp_dir().join(format!("fumox-cfg-conc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[probe]\nconcurrency = 129\n").unwrap();
        let err = load_config_isolated(Some(&file)).unwrap_err();
        assert!(
            err.to_string().contains("probe.concurrency"),
            "the error must name the key: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
