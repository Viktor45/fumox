//! Geo enrichment (MaxMind GeoLite2) ,
//!
//! Pipeline: `host` → (async DNS if it is a domain) → IP → MaxMind lookup →
//! merged geo facts (country + city from City, ASN from ASN, every unique
//! database present in `[geo].db_dir` contributes; the Country database is
//! redundant, City carries all of its facts, and is not read) applied to
//! the display name through a template (default `"{flag} {country} ·
//! {name}"`, placeholders `{flag} {country} {city} {asn} {asn_org}
//! {name}`).
//!
//! The DNS step goes through the shared SSRF resolver
//! ([`crate::ssrf::lookup_with_timeout`]), so the geo lookup runs under the
//! same concurrency cap as the rest of the process, and the address it
//! looks up is the one the dial path would pick
//! ([`crate::ssrf::pick_vetted`]): the facts then describe the server that
//! is actually contacted, not a sibling address of the same name.
//!
//! Facts are cached per host (hosts repeat heavily in subscription feeds).
//! The three outcomes are kept apart, because they say different things
//! about a host: a name that did not resolve says nothing about the host,
//! an address no database knows is a fact about it, and a database read
//! that failed is a fault of this process. A failed name resolution is
//! cached separately and briefly ([`NEGATIVE_TTL`]), a resolved address
//! without a record like any other verdict ([`CACHE_TTL`]). Entries expire,
//! so a host that comes back is resolved without a restart.
//!
//! The `.mmdb` files are never committed. They are opened once per
//! directory per process and shared (see [`Backends`]), so the admin
//! panel's on-demand resolution does not re-read ~80 MB per request. When
//! no database file can be opened the resolver degrades to a no-op with a
//! warning, geo enrichment is an optional enhancement, not a startup
//! requirement.

use crate::config::{GeoConfig, GeoDbKind};
use crate::models::IpFamily;
use crate::ssrf;
use maxminddb::Reader;
use moka::future::Cache;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

/// Geo facts resolved for one proxy host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoInfo {
    /// The IP the host resolved to (or the host itself when it is literal).
    pub ip: String,
    /// ISO-3166-1 alpha-2 code, e.g. `"DE"`.
    pub country_code: Option<String>,
    /// English country name, e.g. `"Germany"`.
    pub country_name: Option<String>,
    /// City name (City database only).
    pub city_name: Option<String>,
    /// Autonomous system number (ASN database only).
    pub asn: Option<u32>,
    /// AS organization (ASN database only).
    pub asn_org: Option<String>,
}

impl GeoInfo {
    /// Whether the resolver learned anything about the host at all.
    ///
    /// Every fact counts, not just the country: a row that only carries an
    /// ASN (the City database is silent for whole address blocks) is still
    /// enriched and must not be rendered as if nothing was known.
    pub fn has_facts(&self) -> bool {
        self.country_code.is_some()
            || self.country_name.is_some()
            || self.city_name.is_some()
            || self.asn.is_some()
            || self.asn_org.is_some()
    }
}

/// Convert an ISO-3166-1 alpha-2 code into a flag emoji.
///
/// Each letter maps onto a Unicode regional indicator symbol
/// (`A` → U+1F1E6). Input is upper-cased; non-two-letter codes yield `None`.
pub fn flag_emoji(iso_code: &str) -> Option<String> {
    let code = iso_code.trim().to_ascii_uppercase();
    let bytes = code.as_bytes();
    if bytes.len() != 2 || !bytes.iter().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let mut out = String::with_capacity(8);
    for b in bytes {
        out.push(char::from_u32(0x1F1E6 + (b - b'A') as u32)?);
    }
    Some(out)
}

/// The canonical `AS{n}` text of an AS number.
pub fn asn_text(asn: u32) -> String {
    format!("AS{asn}")
}

/// The canonical `AS{n}` text of an autonomous-system number.
///
/// The operator-facing forms are `24940` and `AS24940`; the `geo_asn`
/// column stores the canonical `AS{n}` text. Normalising once, here, is
/// what keeps the paths that compare the column in agreement: a caller
/// that spelled the number `as24940` matched no row at all, and a
/// caller that passed the bare number to a path that expected the
/// prefixed form matched none either.
///
/// `None` for anything that is not an AS number: the digits have to be
/// there, they have to be digits, and an AS number is at most ten digits
/// long.
pub fn canonical_asn(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let digits = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
        .unwrap_or(trimmed);
    if !digits.is_empty() && digits.len() <= 10 && digits.bytes().all(|b| b.is_ascii_digit()) {
        Some(format!("AS{digits}"))
    } else {
        None
    }
}

/// The placeholders the geo name template understands.
pub const TEMPLATE_PLACEHOLDERS: [&str; 6] = ["flag", "country", "city", "asn", "asn_org", "name"];

/// The placeholders in `template` the renderer does not know.
///
/// An unknown placeholder is rendered verbatim (`{foo}` stays `{foo}`), so
/// the admin panel and the config loader reject it instead of leaving the
/// operator with a literal brace in every proxy name.
pub fn unknown_placeholders(template: &str) -> Vec<String> {
    let mut unknown: Vec<String> = Vec::new();
    for candidate in template.split('{').skip(1) {
        let Some(end) = candidate.find('}') else {
            continue;
        };
        let key = candidate[..end].trim();
        if key.is_empty() || TEMPLATE_PLACEHOLDERS.contains(&key) {
            continue;
        }
        if !unknown.iter().any(|seen| seen == key) {
            unknown.push(key.to_string());
        }
    }
    unknown
}

/// Apply the rename template.
///
/// Placeholders: `{flag}`, `{country}`, `{city}`, `{asn}`, `{asn_org}`,
/// `{name}`. The original name is returned unchanged only when there is no
/// geo data at all (no country, no city, no ASN), a template with empty
/// substitutions would only produce dangling separators. Individual missing
/// values substitute as empty strings, and the result is then collapsed
/// (whitespace runs → single space, trimmed), so `"{flag} {country} {city} ·
/// {name}"` without a city still renders cleanly.
///
/// A template without `{name}` gets the original name appended: the name
/// identifies the proxy in every output format, and a template that drops
/// it makes two different servers indistinguishable. An empty template
/// renders the name alone.
pub fn apply_template(template: &str, geo: &GeoInfo, name: &str) -> String {
    if !geo.has_facts() {
        return name.to_string();
    }
    let template = template.trim();
    if template.is_empty() {
        return name.to_string();
    }
    let flag = geo
        .country_code
        .as_deref()
        .and_then(flag_emoji)
        .unwrap_or_default();
    let country = geo
        .country_name
        .clone()
        .or_else(|| geo.country_code.clone())
        .unwrap_or_default();
    let city = geo.city_name.as_deref().unwrap_or_default();
    let asn_org = geo.asn_org.as_deref().unwrap_or_default();
    let asn = geo.asn.map(asn_text).unwrap_or_default();
    let mut rendered = template
        .replace("{flag}", &flag)
        .replace("{country}", &country)
        .replace("{city}", city)
        // {asn_org} before {asn}: the shorter placeholder is a prefix of it.
        .replace("{asn_org}", asn_org)
        .replace("{asn}", &asn)
        .replace("{name}", name)
        .to_string();
    if !template.contains("{name}") {
        rendered.push(' ');
        rendered.push_str(name);
    }
    collapse_whitespace(&rendered)
}

/// Collapse whitespace runs into single spaces and trim the ends.
fn collapse_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

/// Every GeoLite2 database that carries unique facts and is found in
/// `[geo].db_dir`: City (country + city) and ASN (autonomous system). The
/// Country database is deliberately not read, City carries every fact it
/// has (a leftover `GeoLite2-Country.mmdb` is simply ignored). Missing
/// kinds contribute no facts; a directory with only `GeoLite2-ASN.mmdb`
/// still resolves AS numbers.
struct Backends {
    city: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

/// Size and modification time of one database file, the stamp that says
/// whether the opened copy is still the file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    size: u64,
    modified: Option<SystemTime>,
}

impl FileStamp {
    fn of(path: &Path) -> Self {
        match std::fs::metadata(path) {
            Ok(meta) => Self {
                size: meta.len(),
                modified: meta.modified().ok(),
            },
            Err(_) => Self {
                size: 0,
                modified: None,
            },
        }
    }
}

/// The opened databases of one directory.
struct RegistryEntry {
    /// The stamp of the files when they were opened.
    stamp: Vec<FileStamp>,
    /// The opened databases, `None` when the directory holds none.
    backends: Option<Arc<Backends>>,
}

/// The databases opened in this process, keyed by their directory.
///
/// Opening a database reads the whole file (~80 MB for the City
/// database), so each file is read once per directory per process and
/// every resolver shares the result: the admin panel's on-demand
/// resolution must not re-read the databases per request. A file that
/// changed since it was opened (the downloader installs a fresh copy by
/// rename) is read again on the next lookup, so a database that arrived
/// after startup is picked up without a restart.
static BACKENDS: OnceLock<Mutex<HashMap<PathBuf, RegistryEntry>>> = OnceLock::new();

impl Backends {
    /// The shared backends of `dir`, opening the files on the first call
    /// and re-opening them when a file changed.
    fn shared(dir: &Path) -> Option<Arc<Backends>> {
        let registry = BACKENDS.get_or_init(|| Mutex::new(HashMap::new()));
        let stamp = vec![
            FileStamp::of(&dir.join(GeoDbKind::City.file_name())),
            FileStamp::of(&dir.join(GeoDbKind::Asn.file_name())),
        ];
        let mut guard = registry.lock().unwrap_or_else(|err| err.into_inner());
        if let Some(entry) = guard.get(dir)
            && entry.stamp == stamp
        {
            return entry.backends.clone();
        }
        let backends = Arc::new(Backends::from_dir(dir));
        let opened = (!backends.is_empty()).then(|| Arc::clone(&backends));
        guard.insert(
            dir.to_path_buf(),
            RegistryEntry {
                stamp,
                backends: opened.clone(),
            },
        );
        opened
    }

    fn from_dir(dir: &std::path::Path) -> Self {
        let open = |kind: GeoDbKind| {
            let path = dir.join(kind.file_name());
            match Reader::open_readfile(&path) {
                Ok(reader) => Some(reader),
                // missing file, contributing no facts is the documented
                // behavior for an absent database, not an error
                Err(_) if !path.exists() => None,
                Err(err) => {
                    tracing::warn!(
                        file = kind.file_name(),
                        error = %err,
                        "GeoLite2 database unreadable; its facts are skipped"
                    );
                    None
                }
            }
        };
        Self {
            city: open(GeoDbKind::City),
            asn: open(GeoDbKind::Asn),
        }
    }

    fn is_empty(&self) -> bool {
        self.city.is_none() && self.asn.is_none()
    }

    fn mask(&self) -> GeoFactMask {
        GeoFactMask {
            country: self.city.is_some(),
            asn: self.asn.is_some(),
        }
    }
}

/// Which stored geo facts the loaded databases can produce at all.
///
/// A missing fact is only worth retrying when a database could answer it:
/// chasing one that cannot be filled re-walks the table every pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GeoFactMask {
    /// A City database is loaded, so `geo_country` is obtainable.
    pub country: bool,
    /// An ASN database is loaded, so `geo_asn` is obtainable.
    pub asn: bool,
}

/// The geo enrichment state of this installation.
///
/// Geo is an optional enhancement, so a missing database is not a fault of
/// the process. It is still worth telling the operator which of the three
/// situations they are in: enrichment switched off, switched on but with
/// nothing to read, or reading only part of the facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoState {
    /// Geo enrichment is switched off (`[geo].enabled = false`).
    Disabled,
    /// Geo is on, but no database could be opened.
    NoDatabases,
    /// A database is open, but not the one carrying the country: the names
    /// carry an AS number and no country.
    Degraded,
    /// The City database is open, so the country and the city are known.
    Ready,
}

impl GeoState {
    /// The state as it appears in the health answer and in the log.
    pub const fn as_str(self) -> &'static str {
        match self {
            GeoState::Disabled => "off",
            GeoState::NoDatabases => "no databases",
            GeoState::Degraded => "degraded",
            GeoState::Ready => "ready",
        }
    }

    /// Whether the country facts are obtainable. A country allowlist and
    /// the country filters need them: without them they match nothing.
    pub const fn has_country(self) -> bool {
        matches!(self, GeoState::Ready)
    }
}

/// How long a host→geo verdict stays cached.
///
/// Without a lifetime the "unknown" answer for a host whose DNS failed
/// once survives until the process restarts, and the ASN filters keep
/// whatever they cannot name. Six hours matches the periodic geo
/// backfill's cadence.
const CACHE_TTL: Duration = Duration::from_secs(6 * 3600);

/// How long a *failed name resolution* stays cached.
///
/// A name that did not resolve says nothing about the host: the record
/// may be published minutes later, and a dead name in a feed is common.
/// The short lifetime keeps a host from being written off for hours, the
/// long [`CACHE_TTL`] of the facts themselves is for verdicts that are
/// facts.
const NEGATIVE_TTL: Duration = Duration::from_secs(10 * 60);

/// Window in which at most one line per outcome is logged.
const LOG_WINDOW_SECS: u64 = 60;

/// Names that did not resolve.
static DNS_FAILED: AtomicU64 = AtomicU64::new(0);
/// Database reads that failed.
static LOOKUP_ERRORS: AtomicU64 = AtomicU64::new(0);
/// Addresses no loaded database knows.
static NO_DATA: AtomicU64 = AtomicU64::new(0);

/// The geo resolution counters of this process.
///
/// The three outcomes are distinct on purpose: a name that does not
/// resolve says nothing about the host, an address without a record is a
/// fact about it, and a database read that failed is a fault of this
/// process. Merging them into one "unresolved" number hides which of the
/// three an operator has to fix.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GeoStats {
    /// Host names that did not resolve.
    pub dns_failed: u64,
    /// Database lookups that failed.
    pub lookup_errors: u64,
    /// Addresses no loaded database has a record for.
    pub no_data: u64,
}

/// The geo counters of this process.
pub fn geo_stats() -> GeoStats {
    GeoStats {
        dns_failed: DNS_FAILED.load(Ordering::Relaxed),
        lookup_errors: LOOKUP_ERRORS.load(Ordering::Relaxed),
        no_data: NO_DATA.load(Ordering::Relaxed),
    }
}

/// Logs at most one line per window, so a feed full of dead names does
/// not drown the log.
struct Throttle {
    last: AtomicU64,
}

impl Throttle {
    const fn new() -> Self {
        Self {
            last: AtomicU64::new(0),
        }
    }

    /// Whether a line may be logged now.
    fn allow(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0);
        let last = self.last.load(Ordering::Relaxed);
        if now.saturating_sub(last) < LOG_WINDOW_SECS {
            return false;
        }
        self.last.store(now, Ordering::Relaxed);
        true
    }
}

static DNS_LOG: Throttle = Throttle::new();
static NO_DATA_LOG: Throttle = Throttle::new();
static LOOKUP_ERROR_LOG: Throttle = Throttle::new();

/// What one resolution produced.
#[derive(Debug, Clone)]
pub enum GeoOutcome {
    /// The host resolved and the databases know the address.
    Facts(Arc<GeoInfo>),
    /// The host resolved, but no loaded database has a record for the
    /// address (or the database read failed).
    NoRecord,
    /// The host name did not resolve.
    DnsFailed(String),
}

/// Host → geo resolver with an in-memory cache. Cheap to clone/share: the
/// internals are `Arc`-wrapped.
#[derive(Clone)]
pub struct GeoResolver {
    /// Directory the databases live in. The resolver asks the
    /// process-wide registry for them on every lookup instead of holding
    /// one copy, so a database that arrives after the startup (the
    /// downloader installs it) is picked up without a restart.
    db_dir: Option<std::path::PathBuf>,
    /// Resolved facts per host. `None` is a cached verdict: the host
    /// resolved, but no loaded database knows the address.
    facts: Cache<String, Option<Arc<GeoInfo>>>,
    /// Names that did not resolve, with the reason. Kept apart from the
    /// facts because it expires much sooner ([`NEGATIVE_TTL`]).
    dns_failures: Cache<String, String>,
    dns_timeout: Duration,
}

impl GeoResolver {
    /// Build a resolver from config. Every GeoLite2 database found in
    /// `[geo].db_dir` is opened and all of them contribute facts, a name
    /// template can mix `{country}`, `{city}` and `{asn}` freely. The
    /// files that opened are named in one startup info line; a missing
    /// kind gets its own warn (only while geo is enabled, its facts are
    /// simply skipped). Returns a no-op resolver (with a warning logged)
    /// when geo is disabled or no database file could be opened.
    pub fn new(cfg: &GeoConfig) -> Self {
        Self::with_cache_ttl(cfg, CACHE_TTL)
    }

    /// [`Self::new`] with an explicit cache lifetime, so a test can watch an
    /// entry expire without waiting out the production TTL.
    fn with_cache_ttl(cfg: &GeoConfig, ttl: Duration) -> Self {
        let facts = Cache::builder()
            .max_capacity(cfg.cache_max_entries)
            .time_to_live(ttl)
            .build();
        let dns_failures = Cache::builder()
            .max_capacity(cfg.cache_max_entries)
            .time_to_live(ttl.min(NEGATIVE_TTL))
            .build();
        let dns_timeout = cfg.dns_timeout();
        if !cfg.enabled {
            return Self {
                db_dir: None,
                facts,
                dns_failures,
                dns_timeout,
            };
        }
        let resolver = Self {
            db_dir: Some(cfg.db_dir.clone()),
            facts,
            dns_failures,
            dns_timeout,
        };
        match resolver.backends() {
            Some(backends) => {
                let kinds = [
                    (GeoDbKind::City, backends.city.is_some()),
                    (GeoDbKind::Asn, backends.asn.is_some()),
                ];
                let opened: Vec<&str> = kinds
                    .iter()
                    .filter(|(_, loaded)| *loaded)
                    .map(|(kind, _)| kind.file_name())
                    .collect();
                for (kind, loaded) in kinds {
                    if !loaded {
                        // Debug while another backend is open: a deliberate
                        // ASN-only or City-only setup is a supported
                        // configuration, and warning about it on every
                        // start would drown the warning below, which is
                        // the one that means geo is off.
                        tracing::debug!(
                            file = kind.file_name(),
                            dir = %cfg.db_dir.display(),
                            "GeoLite2 database missing; its facts are skipped"
                        );
                    }
                }
                tracing::info!(
                    dir = %cfg.db_dir.display(),
                    files = opened.join(", "),
                    "geo enrichment enabled"
                );
            }
            None => {
                tracing::warn!(
                    dir = %cfg.db_dir.display(),
                    "no GeoLite2 database could be opened yet; geo enrichment stays off \
                     until one appears"
                );
            }
        }
        resolver
    }

    /// The databases this installation can read, opened once per directory
    /// per process and re-opened when a file changed (the downloader
    /// installs a fresh copy by rename).
    fn backends(&self) -> Option<Arc<Backends>> {
        self.db_dir.as_deref().and_then(Backends::shared)
    }

    /// Whether this resolver can actually enrich (at least one database
    /// loaded).
    pub fn is_active(&self) -> bool {
        self.backends().is_some()
    }

    /// The geo state of this installation, asked on every call: the
    /// databases are re-read when a file changed, so a database the
    /// downloader installed after the startup is seen without a restart.
    pub fn state(&self) -> GeoState {
        if self.db_dir.is_none() {
            return GeoState::Disabled;
        }
        match self.backends() {
            None => GeoState::NoDatabases,
            Some(backends) if backends.city.is_some() => GeoState::Ready,
            Some(_) => GeoState::Degraded,
        }
    }

    /// Which stored geo facts this installation can fill in. Empty mask: no
    /// database opened, nothing obtainable.
    pub fn fact_mask(&self) -> GeoFactMask {
        self.backends().map(|b| b.mask()).unwrap_or_default()
    }

    /// Resolve geo information for a proxy host (domain or literal IP).
    /// Returns `None` when the resolver is inactive, DNS fails, or no loaded
    /// database has data for the address.
    pub async fn resolve(&self, host: &str) -> Option<Arc<GeoInfo>> {
        match self.resolve_detailed(host).await {
            GeoOutcome::Facts(info) => Some(info),
            GeoOutcome::NoRecord | GeoOutcome::DnsFailed(_) => None,
        }
    }

    /// [`Self::resolve`] with the outcome kept apart: a name that did not
    /// resolve and an address without a record are different facts about
    /// the host and are counted separately.
    pub async fn resolve_detailed(&self, host: &str) -> GeoOutcome {
        let Some(backends) = self.backends() else {
            return GeoOutcome::NoRecord;
        };
        let key = host.to_ascii_lowercase();
        if let Some(hit) = self.facts.get(&key).await {
            return match hit {
                Some(info) => GeoOutcome::Facts(info),
                None => GeoOutcome::NoRecord,
            };
        }
        if let Some(reason) = self.dns_failures.get(&key).await {
            return GeoOutcome::DnsFailed(reason);
        }
        // Single-flight: moka resolves the init future once per key, the
        // concurrent callers wait for that one answer instead of starting
        // a DNS query each.
        let dns_failures = self.dns_failures.clone();
        let host = host.to_string();
        let cache_key = key.clone();
        let dns_timeout = self.dns_timeout;
        let value = self
            .facts
            .get_with(key.clone(), async move {
                resolve_once(&backends, &dns_failures, &host, &cache_key, dns_timeout).await
            })
            .await;
        match value {
            Some(info) => GeoOutcome::Facts(info),
            None => {
                // The attempt either hit "no record" (cached like any
                // other verdict) or the name did not resolve (cached
                // briefly and separately).
                if let Some(reason) = self.dns_failures.get(&key).await {
                    // The negative verdict must not outlive the short DNS
                    // failure lifetime: drop it, so the next attempt after
                    // the failure expires resolves the name again.
                    self.facts.invalidate(&key).await;
                    return GeoOutcome::DnsFailed(reason);
                }
                GeoOutcome::NoRecord
            }
        }
    }
}

/// One resolution attempt, as the cache stores it.
async fn resolve_once(
    backends: &Arc<Backends>,
    dns_failures: &Cache<String, String>,
    host: &str,
    key: &str,
    dns_timeout: Duration,
) -> Option<Arc<GeoInfo>> {
    match resolve_uncached(backends, host, dns_timeout).await {
        Resolved::Facts(info) => Some(Arc::new(info)),
        Resolved::NoRecord => None,
        Resolved::DnsFailed(reason) => {
            dns_failures.insert(key.to_string(), reason).await;
            None
        }
    }
}

/// What one uncached attempt produced.
enum Resolved {
    Facts(GeoInfo),
    /// The host resolved, no loaded database knows the address.
    NoRecord,
    /// The name did not resolve.
    DnsFailed(String),
}

/// Merge the facts of every loaded database for one IP: City
/// contributes country + city, ASN the autonomous system on top.
async fn resolve_uncached(backends: &Backends, host: &str, dns_timeout: Duration) -> Resolved {
    let ip = match ssrf::parse_ip_literal(host) {
        Some(ip) => ip,
        None => match ssrf::lookup_with_timeout(host, dns_timeout).await {
            Ok(addrs) => match ssrf::pick_vetted(&addrs, IpFamily::Any) {
                Some(ip) => ip,
                None => {
                    NO_DATA.fetch_add(1, Ordering::Relaxed);
                    if NO_DATA_LOG.allow() {
                        tracing::debug!(
                            host,
                            "geo: the host name resolved to no address the dial path could use"
                        );
                    }
                    return Resolved::NoRecord;
                }
            },
            Err(reason) => {
                DNS_FAILED.fetch_add(1, Ordering::Relaxed);
                if DNS_LOG.allow() {
                    tracing::warn!(host, reason, "geo: the host name did not resolve");
                }
                return Resolved::DnsFailed(reason);
            }
        },
    };
    let mut info = GeoInfo {
        ip: ip.to_string(),
        ..Default::default()
    };
    let mut any = false;
    if let Some(reader) = &backends.city
        && let Some(city) = lookup_city(reader, ip)
    {
        info.country_code = info.country_code.or(city.country_code);
        info.country_name = info.country_name.or(city.country_name);
        info.city_name = info.city_name.or(city.city_name);
        any = true;
    }
    if let Some(reader) = &backends.asn
        && let Some(asn) = lookup_asn(reader, ip)
    {
        info.asn = asn.asn;
        info.asn_org = asn.asn_org;
        any = true;
    }
    if !any {
        NO_DATA.fetch_add(1, Ordering::Relaxed);
        if NO_DATA_LOG.allow() {
            tracing::debug!(host = %host, ip = %ip, "geo: no database knows this address");
        }
        return Resolved::NoRecord;
    }
    Resolved::Facts(info)
}

/// On-demand enrichment over **every** GeoLite2 database found in
/// `[geo].db_dir` (admin proxy-card "resolve City/ASN" action). Same
/// resolution semantics as [`GeoResolver`], both open and merge all
/// databases, kept as a thin wrapper so the admin panel can hold its own
/// resolver instance (with its own cache) next to the pipeline one.
pub struct FullResolver {
    inner: GeoResolver,
}

impl FullResolver {
    /// Open every database present in `db_dir`, regardless of
    /// `[geo].enabled`, which gates the pipeline's own resolver (the card
    /// enrichment is independent of the pipeline). Missing files are
    /// skipped silently: the caller decides what to report when nothing
    /// resolved.
    pub fn from_dir(cfg: &GeoConfig) -> Self {
        let mut cfg = cfg.clone();
        cfg.enabled = true;
        Self {
            inner: GeoResolver::new(&cfg),
        }
    }

    /// Whether any database loaded at all, `false` means there is nothing
    /// to enrich with and the UI should not offer the action.
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }

    /// Resolve a host against every loaded database and merge the facts:
    /// Country/City contribute the country (+ city for City), ASN the
    /// autonomous system. `None` when the host does not resolve to an IP
    /// or no database knows the address.
    pub async fn resolve(&self, host: &str) -> Option<GeoInfo> {
        self.inner.resolve(host).await.map(|info| (*info).clone())
    }
}

/// The country, city and (with the ASN database) the autonomous system of
/// one address.
///
/// The country MaxMind believes the address is in is `country`; when that
/// is empty the `registered_country` (where the ISP registered the
/// block) is the next best answer. A record that carries only a city is
/// kept as well: the country of a block MaxMind has no opinion on is not
/// a reason to throw the city away.
fn lookup_city(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<GeoInfo> {
    use maxminddb::geoip2;
    let record: geoip2::City = match reader.lookup(ip) {
        Ok(result) => match result.decode() {
            Ok(Some(record)) => record,
            Ok(None) => return None,
            Err(err) => {
                count_lookup_error(&err);
                return None;
            }
        },
        Err(err) => {
            count_lookup_error(&err);
            return None;
        }
    };
    let country = if record.country.is_empty() {
        &record.registered_country
    } else {
        &record.country
    };
    let country_code = country.iso_code.map(str::to_string);
    let country_name = english_name(&country.names);
    let city_name = english_name(&record.city.names);
    if country_code.is_none() && country_name.is_none() && city_name.is_none() {
        return None;
    }
    Some(GeoInfo {
        country_code,
        country_name,
        city_name,
        ..Default::default()
    })
}

fn lookup_asn(reader: &Reader<Vec<u8>>, ip: IpAddr) -> Option<GeoInfo> {
    use maxminddb::geoip2;
    let record: geoip2::Asn = match reader.lookup(ip) {
        Ok(result) => match result.decode() {
            Ok(Some(record)) => record,
            Ok(None) => return None,
            Err(err) => {
                count_lookup_error(&err);
                return None;
            }
        },
        Err(err) => {
            count_lookup_error(&err);
            return None;
        }
    };
    Some(GeoInfo {
        asn: record.autonomous_system_number,
        asn_org: record.autonomous_system_organization.map(str::to_string),
        ..Default::default()
    })
}

/// Count a failed database read. A read that fails is a fault of this
/// process (a truncated or unreadable file), not a fact about the
/// address, so it is counted apart from the "no record" case.
fn count_lookup_error(error: &maxminddb::MaxMindDbError) {
    LOOKUP_ERRORS.fetch_add(1, Ordering::Relaxed);
    if LOOKUP_ERROR_LOG.allow() {
        tracing::warn!(error = %error, "geo: the database lookup failed");
    }
}

/// Since maxminddb 0.27 the geoip2 model exposes names as a typed struct
/// instead of a locale map: prefer English, then fall back to any other
/// available language.
fn english_name(names: &maxminddb::geoip2::Names<'_>) -> Option<String> {
    names
        .english
        .or(names.german)
        .or(names.spanish)
        .or(names.french)
        .or(names.russian)
        .or(names.japanese)
        .or(names.brazilian_portuguese)
        .or(names.simplified_chinese)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GeoConfig;

    /// The workspace `config/` directory with the gitignored GeoLite2 files
    /// (tests skip themselves when it is empty, CI runs without them).
    fn workspace_db_dir() -> Option<std::path::PathBuf> {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config");
        let has_any = [GeoDbKind::City, GeoDbKind::Asn]
            .iter()
            .any(|kind| dir.join(kind.file_name()).is_file());
        has_any.then(|| dir.canonicalize().unwrap())
    }

    fn full_resolver() -> Option<FullResolver> {
        let dir = workspace_db_dir()?;
        let resolver = FullResolver::from_dir(&GeoConfig {
            db_dir: dir,
            ..Default::default()
        });
        resolver.is_active().then_some(resolver)
    }

    /// Positives and negatives expire alike: an "unknown" answer for a host
    /// whose DNS was down must not outlive the process. Skipped without the
    /// .mmdb files.
    #[tokio::test]
    async fn a_cached_verdict_expires_so_a_failed_host_is_retried() {
        let Some(dir) = workspace_db_dir() else {
            eprintln!("skipping: no GeoLite2 databases in workspace config/");
            return;
        };
        let geo = GeoResolver::with_cache_ttl(
            &GeoConfig {
                enabled: true,
                db_dir: dir,
                ..Default::default()
            },
            Duration::from_millis(50),
        );

        geo.resolve("8.8.8.8").await.expect("8.8.8.8 is known");
        assert!(geo.resolve("nx.invalid").await.is_none());
        assert!(
            geo.dns_failures.get("nx.invalid").await.is_some(),
            "a failed name resolution is cached too"
        );

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(geo.facts.get("8.8.8.8").await.is_none(), "positive expired");
        assert!(
            geo.dns_failures.get("nx.invalid").await.is_none(),
            "negative expired"
        );
        assert!(
            geo.resolve("8.8.8.8").await.is_some(),
            "an expired host is looked up again"
        );
    }

    /// All databases found in the directory answer at once: the merged facts
    /// carry country, city and ASN for a known address. Skipped without the
    /// .mmdb files.
    #[tokio::test]
    async fn full_resolver_merges_city_and_asn_facts() {
        let Some(resolver) = full_resolver() else {
            eprintln!("skipping: no GeoLite2 databases in workspace config/");
            return;
        };
        let info = resolver.resolve("8.8.8.8").await.expect("8.8.8.8 is known");
        assert_eq!(info.country_code.as_deref(), Some("US"));
        assert_eq!(info.ip, "8.8.8.8");
        // Whichever of City/ASN loaded contributes its fact. 8.8.8.8 is anycast
        // Google DNS, the City database legitimately has no city for it, so
        // the ASN database is the one carrying a fact here.
        if workspace_db_dir()
            .unwrap()
            .join(GeoDbKind::Asn.file_name())
            .is_file()
        {
            assert_eq!(info.asn, Some(15169), "Google ASN expected: {info:?}");
            assert_eq!(info.asn_org.as_deref(), Some("Google LLC"));
        }
        // A residential-looking address the City database does know: the
        // merge must pick the city up alongside the country.
        if let Some(info) = resolver.resolve("81.19.44.10").await
            && info.country_code.is_some()
        {
            // only assert the shape, the specific city varies by build
            assert!(info.city_name.is_some() || info.asn.is_some());
        }
    }

    /// A literal-IP host needs no DNS; a bogus host resolves to nothing
    /// rather than panicking.
    #[tokio::test]
    async fn full_resolver_without_databases_is_inactive() {
        let resolver = FullResolver::from_dir(&GeoConfig {
            db_dir: std::path::PathBuf::from("/nonexistent-geo-dir"),
            ..Default::default()
        });
        assert!(!resolver.is_active());
        assert!(resolver.resolve("8.8.8.8").await.is_none());
    }

    /// The pipeline resolver merges every unique database found in `db_dir`
    /// (regression guard for the one-database era: a template can mix
    /// country, city and ASN facts at once). Skipped without the files.
    #[tokio::test]
    async fn pipeline_resolver_merges_all_databases() {
        let Some(resolver) = resolver_for(GeoDbKind::City) else {
            eprintln!("skipping: GeoLite2-City.mmdb not present");
            return;
        };
        let info = resolver.resolve("8.8.8.8").await.expect("8.8.8.8 known");
        assert_eq!(info.country_code.as_deref(), Some("US"));
        // 8.8.8.8 is anycast Google DNS: City has no city for it, but when
        // the ASN database is present its facts must merge in alongside the
        // country, impossible in the one-database era.
        if mmdb_path(GeoDbKind::Asn).is_some() {
            assert_eq!(info.asn, Some(15169), "Google ASN expected: {info:?}");
            assert_eq!(info.asn_org.as_deref(), Some("Google LLC"));
        }
    }

    /// The merged facts flow through a mixed template: country, city and
    /// ASN together in one name. Skipped without the files.
    #[tokio::test]
    async fn merged_template_renders_country_city_and_asn_at_once() {
        let Some(resolver) = resolver_for(GeoDbKind::City) else {
            eprintln!("skipping: GeoLite2-City.mmdb not present");
            return;
        };
        // Literal IP: no DNS round-trip. 8.8.8.8 is US/AS15169 with no
        // city (anycast), the template must render country and ASN in one
        // pass, with the missing city collapsing away.
        let info = resolver.resolve("8.8.8.8").await.expect("8.8.8.8 known");
        assert_eq!(info.country_code.as_deref(), Some("US"));
        if mmdb_path(GeoDbKind::Asn).is_some() {
            assert_eq!(
                apply_template(
                    "{flag} {country} {city} · {asn} {asn_org} · {name}",
                    &info,
                    "Node-1"
                ),
                "🇺🇸 United States · AS15169 Google LLC · Node-1"
            );
        }
    }

    /// The address the geo step looks up is the one the dial path picks:
    /// a host with two A records must be geo-resolved through the address
    /// the fetcher dials, not through its sibling.
    #[test]
    fn the_geo_step_picks_the_same_address_as_the_dial_path() {
        let addrs = vec![
            "2606:4700::1".parse::<IpAddr>().unwrap(),
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "2.2.2.2".parse::<IpAddr>().unwrap(),
        ];
        assert_eq!(
            ssrf::pick_vetted(&addrs, IpFamily::Any),
            Some("1.1.1.1".parse().unwrap())
        );
    }

    #[test]
    fn flag_emoji_from_iso_codes() {
        assert_eq!(flag_emoji("DE").as_deref(), Some("🇩🇪"));
        assert_eq!(flag_emoji("us").as_deref(), Some("🇺🇸"));
        assert_eq!(flag_emoji(" NL ").as_deref(), Some("🇳🇱"));
        assert_eq!(flag_emoji("D"), None);
        assert_eq!(flag_emoji("DEU"), None);
        assert_eq!(flag_emoji("D1"), None);
        assert_eq!(flag_emoji(""), None);
    }

    fn german_geo() -> GeoInfo {
        GeoInfo {
            ip: "1.2.3.4".into(),
            country_code: Some("DE".into()),
            country_name: Some("Germany".into()),
            ..Default::default()
        }
    }

    #[test]
    fn template_substitution() {
        let geo = german_geo();
        assert_eq!(
            apply_template("{flag} {country} · {name}", &geo, "Node-1"),
            "🇩🇪 Germany · Node-1"
        );
        assert_eq!(
            apply_template("{name} [{country}]", &geo, "Node-1"),
            "Node-1 [Germany]"
        );
    }

    #[test]
    fn template_falls_back_to_name_without_country() {
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            ..Default::default()
        };
        assert_eq!(
            apply_template("{flag} {country} · {name}", &geo, "Node-1"),
            "Node-1"
        );
    }

    #[test]
    fn template_uses_iso_code_when_name_missing() {
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            country_code: Some("DE".into()),
            ..Default::default()
        };
        assert_eq!(
            apply_template("{flag} {country} · {name}", &geo, "Node-1"),
            "🇩🇪 DE · Node-1"
        );
    }

    #[test]
    fn template_city_placeholder() {
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            country_code: Some("DE".into()),
            country_name: Some("Germany".into()),
            city_name: Some("Berlin".into()),
            ..Default::default()
        };
        assert_eq!(
            apply_template("{flag} {city} · {name}", &geo, "Node-1"),
            "🇩🇪 Berlin · Node-1"
        );
        assert_eq!(
            apply_template("{country} {city} | {name}", &geo, "Node-1"),
            "Germany Berlin | Node-1"
        );
    }

    #[test]
    fn template_asn_placeholders() {
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            asn: Some(24940),
            asn_org: Some("Hetzner Online GmbH".into()),
            ..Default::default()
        };
        // ASN-only data (no country) must not be a no-op.
        assert_eq!(
            apply_template("{asn} {asn_org} · {name}", &geo, "Node-1"),
            "AS24940 Hetzner Online GmbH · Node-1"
        );
        assert_eq!(
            apply_template("[{asn}] {name}", &geo, "Node-1"),
            "[AS24940] Node-1"
        );
    }

    #[test]
    fn template_missing_values_collapse_whitespace() {
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            country_code: Some("DE".into()),
            country_name: Some("Germany".into()),
            ..Default::default()
        };
        // No city in the database → the gap and dangling separator vanish.
        assert_eq!(
            apply_template("{flag} {country} {city} · {name}", &geo, "Node-1"),
            "🇩🇪 Germany · Node-1"
        );
        // No ASN org → only the number renders.
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            asn: Some(24940),
            ..Default::default()
        };
        assert_eq!(
            apply_template("{asn} {asn_org} · {name}", &geo, "Node-1"),
            "AS24940 · Node-1"
        );
    }

    #[test]
    fn template_noop_only_without_any_geo_data() {
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            ..Default::default()
        };
        assert_eq!(
            apply_template("{flag} {country} {city} {asn} · {name}", &geo, "Node-1"),
            "Node-1"
        );
    }

    /// A fact is a fact: a country without an ISO code (some databases
    /// carry only the name) must still enrich the name. The old condition
    /// looked at the ISO code alone and dropped the row's only fact.
    #[test]
    fn template_renders_country_name_when_iso_code_missing() {
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            country_name: Some("Germany".into()),
            ..Default::default()
        };
        assert!(geo.has_facts(), "a country name alone is a fact");
        assert_eq!(
            apply_template("{country} · {name}", &geo, "Node-1"),
            "Germany · Node-1"
        );
    }

    /// The AS organization alone is a fact too (an ASN database without
    /// the number would be odd, but a name without an organization is
    /// still enrichment).
    #[test]
    fn template_renders_an_asn_organization_without_a_number() {
        let geo = GeoInfo {
            ip: "1.2.3.4".into(),
            asn_org: Some("Example Networks".into()),
            ..Default::default()
        };
        assert!(geo.has_facts());
        assert_eq!(
            apply_template("{asn_org} · {name}", &geo, "Node-1"),
            "Example Networks · Node-1"
        );
    }

    /// The name identifies the proxy: a template that does not carry it
    /// gets it appended instead of dropping it silently.
    #[test]
    fn a_template_without_the_name_keeps_the_name() {
        let geo = german_geo();
        assert_eq!(
            apply_template("{flag} {country}", &geo, "Node-1"),
            "🇩🇪 Germany Node-1"
        );
        // A template that names it is left alone.
        assert_eq!(
            apply_template("{name} [{country}]", &geo, "Node-1"),
            "Node-1 [Germany]"
        );
    }

    /// An empty template renders the name alone: the pipeline editor
    /// rejects one, but a stored pipeline from an older version must not
    /// blank every proxy name.
    #[test]
    fn an_empty_template_renders_the_name() {
        let geo = german_geo();
        assert_eq!(apply_template("", &geo, "Node-1"), "Node-1");
        assert_eq!(apply_template("   ", &geo, "Node-1"), "Node-1");
    }

    /// A placeholder the renderer does not know would end up in every
    /// proxy name as a literal brace, so the loader and the admin panel
    /// reject it.
    #[test]
    fn unknown_placeholders_are_reported() {
        assert!(unknown_placeholders("{flag} {country} · {name}").is_empty());
        assert!(unknown_placeholders("{asn_org} {city}").is_empty());
        assert_eq!(
            unknown_placeholders("{flag} {foo} {name}"),
            vec!["foo".to_string()]
        );
        assert_eq!(
            unknown_placeholders("{foo} {bar} {foo}"),
            vec!["foo".to_string(), "bar".to_string()]
        );
        // A stray brace is not a placeholder.
        assert!(unknown_placeholders("{unclosed").is_empty());
    }

    /// A name that does not resolve and an address no database knows are
    /// different facts, and the resolver keeps them apart: the first is a
    /// transient condition of the name, the second a verdict about the
    /// address.
    #[tokio::test]
    async fn a_failed_name_and_an_unknown_address_are_different_outcomes() {
        let Some(resolver) = resolver_for(GeoDbKind::City) else {
            eprintln!("skipped: GeoLite2-City.mmdb not present");
            return;
        };
        // A name that cannot resolve.
        let failed = resolver.resolve_detailed("nx.invalid").await;
        assert!(
            matches!(failed, GeoOutcome::DnsFailed(_)),
            "a name that does not resolve is a DNS failure, got {failed:?}"
        );
        // An address that resolves but that no database knows.
        let unknown = resolver.resolve_detailed("192.0.2.1").await;
        assert!(
            matches!(unknown, GeoOutcome::NoRecord),
            "an address without a record is no record, got {unknown:?}"
        );
    }

    /// The databases of one directory are opened once per process: the
    /// admin panel's on-demand resolver must not re-read ~80 MB per
    /// request.
    #[test]
    fn the_databases_of_one_directory_are_opened_once() {
        let dir = std::path::PathBuf::from("/nonexistent-geo-dir-shared");
        assert!(
            Backends::shared(&dir).is_none(),
            "no database in that directory"
        );
        assert!(
            Backends::shared(&dir).is_none(),
            "the empty verdict is cached, the directory is not re-read"
        );
        let registry = BACKENDS.get().expect("registry initialized");
        let guard = registry.lock().unwrap();
        assert!(guard.contains_key(&dir), "the directory has one entry");
    }

    #[test]
    fn disabled_resolver_is_inactive() {
        let cfg = GeoConfig {
            enabled: false,
            ..Default::default()
        };
        let resolver = GeoResolver::new(&cfg);
        assert!(!resolver.is_active());
    }

    #[test]
    fn missing_database_degrades_to_noop() {
        let cfg = GeoConfig {
            enabled: true,
            db_dir: std::path::PathBuf::from("/nonexistent-dir"),
            ..Default::default()
        };
        let resolver = GeoResolver::new(&cfg);
        assert!(!resolver.is_active());
    }

    /// The state tells the three situations apart: enrichment off, on but
    /// with nothing to read, and reading the facts.
    #[test]
    fn the_state_names_the_geo_situation() {
        let off = GeoResolver::new(&GeoConfig {
            enabled: false,
            ..Default::default()
        });
        assert_eq!(off.state(), GeoState::Disabled);
        assert_eq!(off.state().as_str(), "off");

        let without_db = GeoResolver::new(&GeoConfig {
            enabled: true,
            db_dir: std::path::PathBuf::from("/nonexistent-dir"),
            ..Default::default()
        });
        assert_eq!(without_db.state(), GeoState::NoDatabases);
        assert_eq!(without_db.state().as_str(), "no databases");
        assert!(
            !without_db.state().has_country(),
            "without the City database the country facts are unobtainable"
        );

        // A resolver over the workspace directory: the City database makes
        // it ready, an ASN-only setup is degraded.
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config");
        let resolver = GeoResolver::new(&GeoConfig {
            enabled: true,
            db_dir: dir,
            ..Default::default()
        });
        match resolver.state() {
            GeoState::Ready => assert!(resolver.state().has_country()),
            GeoState::Degraded => assert!(!resolver.state().has_country()),
            other => panic!("unexpected state {other:?}"),
        }
    }

    /// Path to a GeoLite2 database if present in the workspace `config/`
    /// directory (the files are gitignored, so tests skip without them).
    fn mmdb_path(kind: GeoDbKind) -> Option<std::path::PathBuf> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config")
            .join(kind.file_name());
        path.exists().then_some(path)
    }

    /// A resolver over the workspace `config/` directory, active only when
    /// at least the given database kind is present (CI runs without any).
    fn resolver_for(kind: GeoDbKind) -> Option<GeoResolver> {
        let db_dir = mmdb_path(kind)?.parent().unwrap().to_path_buf();
        let resolver = GeoResolver::new(&GeoConfig {
            enabled: true,
            db_dir,
            ..Default::default()
        });
        resolver.is_active().then_some(resolver)
    }

    #[tokio::test]
    async fn country_lookup_for_literal_ip() {
        let Some(resolver) = resolver_for(GeoDbKind::City) else {
            eprintln!("skipped: GeoLite2-City.mmdb not present");
            return;
        };
        // 8.8.8.8 is Google's DNS, reliably geo-tagged as US.
        let info = resolver
            .resolve("8.8.8.8")
            .await
            .expect("8.8.8.8 must resolve");
        assert_eq!(info.ip, "8.8.8.8");
        assert_eq!(info.country_code.as_deref(), Some("US"));
        assert!(info.country_name.is_some());
    }

    #[tokio::test]
    async fn results_are_cached_including_negative() {
        let Some(resolver) = resolver_for(GeoDbKind::City) else {
            eprintln!("skipped: GeoLite2-City.mmdb not present");
            return;
        };
        // TEST-NET-1 address: valid IP, typically without geo data, the
        // negative result must be cached and stable across calls.
        let first = resolver.resolve("192.0.2.1").await;
        let second = resolver.resolve("192.0.2.1").await;
        assert_eq!(first, second);

        // Positive results are cached identically (case-insensitive keys).
        let a = resolver.resolve("8.8.8.8").await;
        let b = resolver.resolve("8.8.8.8").await;
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[tokio::test]
    async fn city_lookup_resolves_country() {
        let Some(resolver) = resolver_for(GeoDbKind::City) else {
            eprintln!("skipped: GeoLite2-City.mmdb not present");
            return;
        };
        // The City backend must at least carry country data. A city name is
        // data-dependent (anycast addresses like 8.8.8.8 often have none),
        // so it is asserted softly rather than required.
        let info = resolver
            .resolve("8.8.8.8")
            .await
            .expect("8.8.8.8 must resolve");
        assert_eq!(info.country_code.as_deref(), Some("US"));
        if let Some(city) = &info.city_name {
            eprintln!("city for 8.8.8.8: {city}");
        }
    }

    #[tokio::test]
    async fn asn_lookup_returns_asn() {
        let Some(resolver) = resolver_for(GeoDbKind::Asn) else {
            eprintln!("skipped: GeoLite2-ASN.mmdb not present");
            return;
        };
        let info = resolver
            .resolve("8.8.8.8")
            .await
            .expect("8.8.8.8 must resolve");
        assert_eq!(info.asn, Some(15169)); // Google LLC
        assert!(info.asn_org.is_some());
    }

    #[tokio::test]
    async fn dns_resolution_for_domain_host() {
        let Some(resolver) = resolver_for(GeoDbKind::City) else {
            eprintln!("skipped: GeoLite2-City.mmdb not present");
            return;
        };
        // Requires network; treated as a skip when the sandbox is offline.
        match resolver.resolve("one.one.one.one").await {
            Some(info) => {
                assert!(!info.ip.is_empty());
                assert!(info.ip.parse::<IpAddr>().is_ok());
                eprintln!("one.one.one.one -> {} ({:?})", info.ip, info.country_code);
            }
            None => eprintln!("skipped: DNS resolution unavailable (offline?)"),
        }
    }
}
