//! Application configuration.
//!
//! Layered configuration (SPEC §12): built-in defaults → TOML file
//! (`config/app.toml` by default) → environment variables with the
//! `FUMOX_` prefix and `__` as the section separator
//! (e.g. `FUMOX_ADMIN__TOKEN=secret`).
//!
//! Every key has a default so the service runs out of the box (PLAN, gap 13).
//! Unknown keys are rejected to catch typos early.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Default location of the TOML config file, resolved against the CWD.
pub const DEFAULT_CONFIG_PATH: &str = "config/app.toml";

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
    pub geo: GeoConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub probe: ProbeConfig,
    #[serde(default)]
    pub meow: MeowConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
}

impl AppConfig {
    /// Loads configuration from defaults, an optional TOML file and the
    /// environment.
    ///
    /// When `path` is given explicitly the file must exist; when it is
    /// `None`, the default location is used if present and silently skipped
    /// otherwise (out-of-the-box run with built-in defaults).
    pub fn load(path: Option<&Path>) -> crate::Result<Self> {
        let mut figment = Figment::from(Serialized::defaults(Self::default()));

        match path {
            Some(p) => {
                if !p.is_file() {
                    return Err(crate::Error::Config(format!(
                        "config file not found: {}",
                        p.display()
                    )));
                }
                figment = figment.merge(Toml::file(p));
            }
            None => {
                let default_path = Path::new(DEFAULT_CONFIG_PATH);
                if default_path.is_file() {
                    figment = figment.merge(Toml::file(default_path));
                } else {
                    tracing::info!(
                        path = DEFAULT_CONFIG_PATH,
                        "config file not found, using built-in defaults"
                    );
                }
            }
        }

        // Environment overrides: FUMOX_SECTION__KEY (double underscore splits
        // the section path).
        figment = figment.merge(Env::prefixed("FUMOX_").split("__"));

        Ok(figment.extract()?)
    }
}

/// Public HTTP listener serving `/sub/{id}` and `/src/{id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket for the public subscription endpoints.
    #[serde(default = "defaults::server_bind")]
    pub bind: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: defaults::server_bind(),
        }
    }
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
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: defaults::database_path(),
            busy_timeout_ms: defaults::busy_timeout_ms(),
            max_connections: defaults::max_connections(),
        }
    }
}

/// Source fetcher behaviour (PLAN, gaps 4–5, 12).
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
        }
    }
}

/// Geo enrichment via MaxMind GeoLite2 (SPEC §6). The Country database is
/// the default; City and ASN are reserved for the future.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoConfig {
    /// Master switch for geo enrichment.
    #[serde(default = "defaults::geo_enabled")]
    pub enabled: bool,
    /// Which GeoLite2 database to use.
    #[serde(default)]
    pub db: GeoDbKind,
    /// Directory containing the `.mmdb` files (never committed).
    #[serde(default = "defaults::geo_db_dir")]
    pub db_dir: PathBuf,
    /// Upper bound for the host→geo in-memory cache.
    #[serde(default = "defaults::geo_cache_max_entries")]
    pub cache_max_entries: u64,
    /// Timeout for the async DNS resolution step.
    #[serde(default = "defaults::dns_timeout_secs")]
    pub dns_timeout_secs: u64,
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            enabled: defaults::geo_enabled(),
            db: GeoDbKind::default(),
            db_dir: defaults::geo_db_dir(),
            cache_max_entries: defaults::geo_cache_max_entries(),
            dns_timeout_secs: defaults::dns_timeout_secs(),
        }
    }
}

impl GeoConfig {
    /// Full path of the configured `.mmdb` file.
    pub fn db_path(&self) -> PathBuf {
        self.db_dir.join(self.db.file_name())
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

/// Admin panel settings (ADMIN_PLAN §2–3). An empty `token` disables the
/// admin listener entirely (it answers 404).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Master switch; `false` or an empty `token` disables the panel.
    #[serde(default = "defaults::admin_enabled")]
    pub enabled: bool,
    /// Login secret. Empty string = admin disabled.
    #[serde(default = "defaults::admin_token")]
    pub token: String,
    /// Separate loopback listener (ADMIN_PLAN §2).
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
    /// Directory with UI translation catalogs (`<code>.toml`); relative to
    /// the working directory. Missing directory falls back to the catalogs
    /// embedded in the binary.
    #[serde(default = "defaults::admin_locales_dir")]
    pub locales_dir: String,
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
            locales_dir: defaults::admin_locales_dir(),
        }
    }
}

impl AdminConfig {
    /// The panel is active only when enabled, and a non-empty token is set.
    pub fn is_active(&self) -> bool {
        self.enabled && !self.token.is_empty()
    }
}

/// Probe daemon behaviour (SPEC §8).
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
    /// `[24h, 48h)` window by default (SPEC §8.3a).
    #[serde(default = "defaults::second_chance_spread_hours")]
    pub second_chance_spread_hours: u64,
    /// How often the retention rotation task runs.
    #[serde(default = "defaults::retention_interval_secs")]
    pub retention_interval_secs: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            cycle_interval_secs: defaults::cycle_interval_secs(),
            sample_size: defaults::sample_size(),
            fail_limit: defaults::fail_limit(),
            connect_timeout_secs: defaults::probe_connect_timeout_secs(),
            tls_timeout_secs: defaults::probe_tls_timeout_secs(),
            concurrency: defaults::probe_concurrency(),
            heartbeat_interval_secs: defaults::heartbeat_interval_secs(),
            second_chance_min_hours: defaults::second_chance_min_hours(),
            second_chance_spread_hours: defaults::second_chance_spread_hours(),
            retention_interval_secs: defaults::retention_interval_secs(),
        }
    }
}

/// meow-rs integration for T2 checks (SPEC §8.2). meow-rs runs as a separate
/// system service; Fumox only talks to its REST API and reloads its config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeowConfig {
    /// meow-rs REST API address (`host:port`).
    #[serde(default = "defaults::meow_api_addr")]
    pub api_addr: String,
    /// Clash YAML config path generated by the probe and reloaded via
    /// `PUT /configs`.
    #[serde(default = "defaults::meow_config_path")]
    pub config_path: PathBuf,
    /// Test URL for delay/healthcheck requests (configurable because the
    /// default may be blocked in some regions).
    #[serde(default = "defaults::meow_test_url")]
    pub test_url: String,
    /// Per-check timeout.
    #[serde(default = "defaults::meow_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for MeowConfig {
    fn default() -> Self {
        Self {
            api_addr: defaults::meow_api_addr(),
            config_path: defaults::meow_config_path(),
            test_url: defaults::meow_test_url(),
            timeout_secs: defaults::meow_timeout_secs(),
        }
    }
}

/// History rotation (SPEC §12 `[retention]`); enforced by a daily task in
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

/// A rate limit expressed as a number of requests per time window.
///
/// Serialized form is `"N/unit"` where unit is one of `sec`/`min`/`hour`/
/// `day` (single-letter abbreviations accepted when parsing). A bare integer
/// is interpreted as requests per minute.
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
        let (num, unit) = s
            .split_once('/')
            .ok_or_else(|| format!("rate limit must look like 'N/unit', got '{s}'"))?;
        let limit: u32 = num
            .trim()
            .parse()
            .map_err(|e| format!("invalid rate limit count '{num}': {e}"))?;
        let secs = match unit.trim().to_ascii_lowercase().as_str() {
            "s" | "sec" | "second" => 1,
            "m" | "min" | "minute" => 60,
            "h" | "hour" => 3600,
            "d" | "day" => 86400,
            other => return Err(format!("unknown rate limit unit '{other}'")),
        };
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
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// Built-in default values. Every config key has one (PLAN, gap 13).
mod defaults {
    use super::*;

    pub fn server_bind() -> SocketAddr {
        "0.0.0.0:8080".parse().expect("valid socket address")
    }
    pub fn database_path() -> PathBuf {
        PathBuf::from("fumox.db")
    }
    pub const fn busy_timeout_ms() -> u32 {
        5000
    }
    pub const fn max_connections() -> u32 {
        8
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
    pub const fn dns_timeout_secs() -> u64 {
        5
    }
    pub const fn admin_enabled() -> bool {
        true
    }
    pub fn admin_token() -> String {
        "change-me".to_string()
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
    pub fn admin_locales_dir() -> String {
        "locales".to_string()
    }
    pub const fn cycle_interval_secs() -> u64 {
        60
    }
    pub const fn sample_size() -> u32 {
        50
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
        24
    }
    pub const fn second_chance_spread_hours() -> u64 {
        24
    }
    pub const fn retention_interval_secs() -> u64 {
        86400
    }
    pub fn meow_api_addr() -> String {
        "127.0.0.1:9090".to_string()
    }
    pub fn meow_config_path() -> PathBuf {
        PathBuf::from("config/meow.yaml")
    }
    pub fn meow_test_url() -> String {
        "http://www.gstatic.com/generate_204".to_string()
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

    #[test]
    fn defaults_load_without_file() {
        let cfg = AppConfig::load(None).expect("defaults must load");
        assert_eq!(cfg.admin.bind.to_string(), "127.0.0.1:8081");
        assert_eq!(cfg.database.busy_timeout_ms, 5000);
        assert_eq!(cfg.retention.probe_results_days, 14);
        assert_eq!(cfg.retention.fetch_log_days, 30);
        assert!(cfg.admin.is_active());
        assert_eq!(cfg.geo.db_path(), Path::new("config/GeoLite2-Country.mmdb"));
    }

    #[test]
    fn missing_explicit_path_is_an_error() {
        let err = AppConfig::load(Some(Path::new("/nonexistent/app.toml"))).unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)));
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
        assert!("120".parse::<RateLimit>().is_err());
        assert!("x/min".parse::<RateLimit>().is_err());
        assert!("5/lightyear".parse::<RateLimit>().is_err());
    }

    #[test]
    fn rate_limit_deserializes_from_int_or_string() {
        let from_str: RateLimit = serde_json::from_str("\"5/min\"").unwrap();
        assert_eq!(from_str, RateLimit::new(5, Duration::from_secs(60)));
        let from_int: RateLimit = serde_json::from_str("42").unwrap();
        assert_eq!(from_int, RateLimit::new(42, Duration::from_secs(60)));
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

        let cfg = AppConfig::load(Some(&file)).expect("toml must load");
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
    fn unknown_keys_are_rejected() {
        let dir = std::env::temp_dir().join(format!("fumox-cfg-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.toml");
        std::fs::write(&file, "[admin]\ntokn = \"oops\"\n").unwrap();

        let err = AppConfig::load(Some(&file)).unwrap_err();
        assert!(matches!(err, crate::Error::Config(_)));

        std::fs::remove_dir_all(&dir).ok();
    }
}
