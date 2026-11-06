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
//! without a record like any other verdict (`[geo].cache_ttl_secs`).
//! Entries expire,
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
/// geo data at all (no country, no city, no ASN). Individual missing
/// values substitute as empty strings, and the result is then collapsed
/// (whitespace runs → single space, trimmed), so `"{flag} {country} {city} ·
/// {name}"` without a city still renders cleanly.
///
/// Two substitutions have a canonical spelling: `{asn}` renders the
/// `AS{n}` text ([`asn_text`], the same form the `geo_asn` column
/// stores), and `{country}` falls back to the ISO code when the database
/// carries no English name for the block.
///
/// A pure-separator fragment (` · `, ` | `, the spaces around one)
/// between two substitutions that both rendered empty is dropped, so an
/// ASN-only record renders `{flag} {country} · {name}` as the plain name
/// instead of `· Node-1`. A separator with rendered content on both sides
/// survives: `{asn} {asn_org} · {name}` without an organization still
/// reads `AS24940 · Node-1`.
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
    let substitution = |key: &str| -> String {
        match key {
            "flag" => geo
                .country_code
                .as_deref()
                .and_then(flag_emoji)
                .unwrap_or_default(),
            "country" => geo
                .country_name
                .clone()
                .or_else(|| geo.country_code.clone())
                .unwrap_or_default(),
            "city" => geo.city_name.clone().unwrap_or_default(),
            // {asn_org} before {asn}: the shorter placeholder is a prefix of it.
            "asn" => geo.asn.map(asn_text).unwrap_or_default(),
            "asn_org" => geo.asn_org.clone().unwrap_or_default(),
            "name" => name.to_string(),
            // A placeholder the renderer does not know stays verbatim, so
            // the loader and the admin panel reject it instead of the
            // operator finding a literal brace in every proxy name.
            other => format!("{{{other}}}"),
        }
    };
    // Split the template into literal fragments and resolved slots. The
    // render pass needs the whole sequence to tell a separator whose
    // neighbours both vanished from one that still joins two facts.
    enum Segment {
        Text(String),
        Slot(String),
    }
    let mut segments: Vec<Segment> = Vec::new();
    let mut has_name = false;
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        if start > 0 {
            segments.push(Segment::Text(rest[..start].to_string()));
        }
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let key = after[..end].trim();
                has_name |= key == "name";
                segments.push(Segment::Slot(substitution(key)));
                rest = &after[end + 1..];
            }
            // No closing brace: the rest is verbatim text, the same
            // stray-brace case `unknown_placeholders` ignores.
            None => {
                segments.push(Segment::Text(format!("{{{}", after)));
                rest = "";
            }
        }
    }
    if !rest.is_empty() {
        segments.push(Segment::Text(rest.to_string()));
    }
    let renders_content = |segment: &Segment| match segment {
        Segment::Text(text) => text.chars().any(|c| !c.is_whitespace()),
        Segment::Slot(value) => !value.is_empty(),
    };
    // Suffix tables: whether anything renders after a position, and
    // whether an empty slot still renders after it.
    let mut content_after = vec![false; segments.len() + 1];
    let mut empty_slot_after = vec![false; segments.len() + 1];
    for i in (0..segments.len()).rev() {
        content_after[i] = content_after[i + 1] || renders_content(&segments[i]);
        empty_slot_after[i] = empty_slot_after[i + 1]
            || matches!(&segments[i], Segment::Slot(value) if value.is_empty());
    }
    let mut rendered = String::new();
    let mut empty_slot_before = false;
    for (i, segment) in segments.iter().enumerate() {
        match segment {
            Segment::Slot(value) => {
                empty_slot_before |= value.is_empty();
                if !value.is_empty() {
                    rendered.push_str(value);
                }
            }
            Segment::Text(text) => {
                // Dangling on the left: an empty slot preceded the
                // fragment and nothing has rendered since. Dangling on
                // the right: an empty slot follows and nothing renders
                // beyond it. Either way a pure-separator fragment has
                // nothing left to separate.
                let dangling_before =
                    empty_slot_before && !rendered.chars().any(|c| !c.is_whitespace());
                let dangling_after = empty_slot_after[i + 1] && !content_after[i + 1];
                let separator = !text.chars().any(char::is_alphabetic);
                if !(separator && (dangling_before || dangling_after)) {
                    rendered.push_str(text);
                }
            }
        }
    }
    if !has_name {
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
                        dir = %dir.display(),
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

/// How long a *failed name resolution* stays cached.
///
/// A name that did not resolve says nothing about the host: the record
/// may be published minutes later, and a dead name in a feed is common.
/// The short lifetime keeps a host from being written off for hours, the
/// long `[geo].cache_ttl_secs` of the facts themselves (six hours by
/// default) is for verdicts that are facts.
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
    /// address (or the database read failed). The address it resolved to
    /// is kept so a caller can still record it (`proxies.resolved_ip`):
    /// a no-record answer is a fact about the address, not a failure to
    /// resolve it. `None` when the name resolved to no address the dial
    /// path could use, or when the resolver is inactive.
    NoRecord { ip: Option<String> },
    /// The host name did not resolve.
    DnsFailed(String),
}

/// The cached verdict of one host.
#[derive(Clone)]
enum Verdict {
    /// The databases know the address.
    Facts(Arc<GeoInfo>),
    /// No loaded database knows the address. The address is kept so the
    /// outcome of a fresh lookup can hand it to the caller even when the
    /// verdict is served from the cache.
    NoRecord { ip: Option<String> },
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
    /// Resolved verdicts per host.
    facts: Cache<String, Verdict>,
    /// Names that did not resolve, with the reason. Kept apart from the
    /// facts because it expires much sooner ([`NEGATIVE_TTL`]).
    dns_failures: Cache<String, String>,
    dns_timeout: Duration,
}

impl GeoResolver {
    /// Build a resolver from config. Every GeoLite2 database found in
    /// `[geo].db_dir` is opened and all of them contribute facts, a name
    /// template can mix `{country}`, `{city}` and `{asn}` freely. The
    /// opened files are named in one startup info line; a kind that did
    /// not open logs at debug while another database is open (a
    /// deliberate ASN-only or City-only setup is supported), and the warn
    /// — geo enrichment stays off until a database appears — is reserved
    /// for the case where nothing opened at all. Geo disabled builds a
    /// no-op resolver without any logging.
    pub fn new(cfg: &GeoConfig) -> Self {
        Self::construct(cfg, Duration::from_secs(cfg.cache_ttl_secs), true)
    }

    /// [`Self::new`] with an explicit cache lifetime, so a test can watch an
    /// entry expire without waiting out the production TTL.
    #[cfg(test)]
    fn with_cache_ttl(cfg: &GeoConfig, ttl: Duration) -> Self {
        Self::construct(cfg, ttl, true)
    }

    /// The constructor body. `log_startup` silences the startup lines for
    /// the admin panel's on-demand resolver ([`FullResolver::from_dir`]),
    /// which opens the same databases without reporting on them: whether
    /// geo applies is the caller's decision, read from [`Self::state`]
    /// and [`Self::fact_mask`].
    fn construct(cfg: &GeoConfig, ttl: Duration, log_startup: bool) -> Self {
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
        let Some(backends) = resolver.backends() else {
            if log_startup {
                tracing::warn!(
                    dir = %cfg.db_dir.display(),
                    "no GeoLite2 database could be opened yet; geo enrichment stays off \
                     until one appears"
                );
            }
            return resolver;
        };
        if log_startup {
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
                    // start would drown the warn above, which is
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
            GeoOutcome::NoRecord { .. } | GeoOutcome::DnsFailed(_) => None,
        }
    }

    /// [`Self::resolve`] with the outcome kept apart: a name that did not
    /// resolve and an address without a record are different facts about
    /// the host and are counted separately. The no-record outcome carries
    /// the address the host resolved to.
    pub async fn resolve_detailed(&self, host: &str) -> GeoOutcome {
        let Some(backends) = self.backends() else {
            return GeoOutcome::NoRecord { ip: None };
        };
        // The cache key and the DNS query both see the normalized host:
        // case and a trailing dot are the same name, and an IPv6 literal
        // loses its URI brackets, so `[2001:db8::1]` is parsed as the
        // address it is instead of being sent to the resolver as a name.
        let key = crate::fingerprint::normalize_host(host);
        if let Some(verdict) = self.facts.get(&key).await {
            return match verdict {
                Verdict::Facts(info) => GeoOutcome::Facts(info),
                Verdict::NoRecord { ip } => GeoOutcome::NoRecord { ip },
            };
        }
        if let Some(reason) = self.dns_failures.get(&key).await {
            return GeoOutcome::DnsFailed(reason);
        }
        // Single-flight: moka resolves the init future once per key, the
        // concurrent callers wait for that one answer instead of starting
        // a DNS query each.
        let dns_failures = self.dns_failures.clone();
        let host = key.clone();
        let cache_key = key.clone();
        let dns_timeout = self.dns_timeout;
        let value = self
            .facts
            .get_with(key.clone(), async move {
                resolve_once(&backends, &dns_failures, &host, &cache_key, dns_timeout).await
            })
            .await;
        match value {
            Verdict::Facts(info) => GeoOutcome::Facts(info),
            Verdict::NoRecord { ip } => {
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
                GeoOutcome::NoRecord { ip }
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
) -> Verdict {
    match resolve_uncached(backends, host, dns_timeout).await {
        Resolved::Facts(info) => Verdict::Facts(Arc::new(info)),
        Resolved::NoRecord { ip } => Verdict::NoRecord { ip },
        Resolved::DnsFailed(reason) => {
            dns_failures.insert(key.to_string(), reason).await;
            Verdict::NoRecord { ip: None }
        }
    }
}

/// What one uncached attempt produced.
enum Resolved {
    Facts(GeoInfo),
    /// The host resolved (or is a literal), but no loaded database knows
    /// the address. The address is kept for the outcome; `None` when the
    /// name resolved to no address the dial path could use.
    NoRecord {
        ip: Option<String>,
    },
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
                    return Resolved::NoRecord { ip: None };
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
        return Resolved::NoRecord {
            ip: Some(ip.to_string()),
        };
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
    ///
    /// Constructed without the pipeline's startup logging: the admin path
    /// opens the same databases without the "geo enrichment enabled" line
    /// and without the missing-database warns, and reports its situation
    /// through [`GeoState`](GeoResolver::state) and
    /// [`GeoFactMask`](GeoResolver::fact_mask) instead.
    pub fn from_dir(cfg: &GeoConfig) -> Self {
        let mut cfg = cfg.clone();
        cfg.enabled = true;
        Self {
            inner: GeoResolver::construct(&cfg, Duration::from_secs(cfg.cache_ttl_secs), false),
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

    /// [`Self::resolve`] with the outcome kept apart: a name that did not
    /// resolve and an address without a record are different facts, and
    /// the no-record outcome carries the address the host resolved to,
    /// which the caller can still record as `proxies.resolved_ip`.
    pub async fn resolve_detailed(&self, host: &str) -> GeoOutcome {
        self.inner.resolve_detailed(host).await
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

    /// Encodes a MaxMind DB control byte with its payload size. Types
    /// above 7 (`uint64`, `array`, ...) are extended: the control byte
    /// carries the type-0 marker and the next byte names the real type,
    /// with the size in the five control bits unchanged. Plain types take
    /// the one- or two-byte-extension forms for the sizes the control
    /// byte cannot carry (the long ASN keys).
    fn mmdb_header(out: &mut Vec<u8>, data_type: usize, size: usize) {
        if data_type >= 8 {
            assert!(size < 29, "the fixture extended data fits five bits");
            out.push(size as u8);
            out.push((data_type - 7) as u8);
            return;
        }
        let prefix = (data_type << 5) as u8;
        match size {
            s if s < 29 => out.push(prefix | s as u8),
            s if s < 285 => {
                out.push(prefix | 29);
                out.push((s - 29) as u8);
            }
            s => {
                out.push(prefix | 30);
                out.extend_from_slice(&u16::try_from(s - 285).unwrap().to_be_bytes());
            }
        }
    }

    /// A UTF-8 string datum.
    fn mmdb_string(value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        mmdb_header(&mut out, 2, value.len());
        out.extend_from_slice(value.as_bytes());
        out
    }

    /// A minimal big-endian unsigned datum (`uint16`/`uint32`/`uint64`
    /// share the shape: control byte, byte count, the bytes themselves).
    fn mmdb_uint(data_type: usize, value: u64) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let mut out = Vec::new();
        mmdb_header(&mut out, data_type, bytes.len() - first);
        out.extend_from_slice(&bytes[first..]);
        out
    }

    /// A map datum from pre-encoded key/value pairs.
    fn mmdb_map(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
        let mut out = Vec::new();
        mmdb_header(&mut out, 7, entries.len());
        for (key, value) in entries {
            out.extend_from_slice(&key);
            out.extend_from_slice(&value);
        }
        out
    }

    /// An array datum from pre-encoded items.
    fn mmdb_array(items: Vec<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        mmdb_header(&mut out, 11, items.len());
        for item in items {
            out.extend_from_slice(&item);
        }
        out
    }

    /// The City record of the fixture: Germany/Berlin for one /24.
    fn city_record() -> Vec<u8> {
        let names = |en: &str| mmdb_map(vec![(mmdb_string("en"), mmdb_string(en))]);
        let country = |code: &str, name: &str| {
            mmdb_map(vec![
                (mmdb_string("iso_code"), mmdb_string(code)),
                (mmdb_string("names"), names(name)),
            ])
        };
        mmdb_map(vec![
            (
                mmdb_string("city"),
                mmdb_map(vec![(mmdb_string("names"), names("Berlin"))]),
            ),
            (mmdb_string("country"), country("DE", "Germany")),
            (mmdb_string("registered_country"), country("DE", "Germany")),
        ])
    }

    /// The ASN record of the fixture: AS15169 Google LLC for one /24.
    fn asn_record() -> Vec<u8> {
        mmdb_map(vec![
            (mmdb_string("autonomous_system_number"), mmdb_uint(6, 15169)),
            (
                mmdb_string("autonomous_system_organization"),
                mmdb_string("Google LLC"),
            ),
        ])
    }

    /// The bytes of a minimal valid `.mmdb` that routes one /24 (the
    /// first three octets of `prefix`) to one record. Every off-path
    /// branch is the no-record terminal, so any other address looks up as
    /// "not found" — the smallest file the real reader accepts, so the
    /// resolver tests run without the (never-committed) GeoLite2 files.
    fn fixture_mmdb(prefix: [u8; 3], record: &[u8], database_type: &str) -> Vec<u8> {
        let record_24 = |value: u32| [(value >> 16) as u8, (value >> 8) as u8, value as u8];
        // One node per prefix bit; search-tree records are 3 bytes
        // (record_size 24), a node is 6.
        let node_count: u32 = 24;
        let mut tree = vec![0u8; node_count as usize * 6];
        for node in 0..node_count {
            let (left, right) = if node + 1 == node_count {
                // The last node hands both host bits to the record: the
                // /24 covers the remaining eight bits. The data pointer
                // is node_count + 16 (the separator size) + offset 0.
                let pointer = record_24(node_count + 16);
                (pointer, pointer)
            } else {
                let child = record_24(node + 1);
                let empty = record_24(node_count);
                let bit = (prefix[node as usize / 8] >> (7 - node % 8)) & 1;
                if bit == 0 {
                    (child, empty)
                } else {
                    (empty, child)
                }
            };
            let base = node as usize * 6;
            tree[base..base + 3].copy_from_slice(&left);
            tree[base + 3..base + 6].copy_from_slice(&right);
        }
        let mut out = tree;
        // The separator between the search tree and the data section; the
        // data pointers resolve against the offset after it.
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(record);
        out.extend_from_slice(&[0xAB, 0xCD, 0xEF]);
        out.extend_from_slice(b"MaxMind.com");
        out.extend_from_slice(&mmdb_map(vec![
            (mmdb_string("binary_format_major_version"), mmdb_uint(5, 2)),
            (mmdb_string("binary_format_minor_version"), mmdb_uint(5, 0)),
            (mmdb_string("build_epoch"), mmdb_uint(9, 1_700_000_000)),
            (mmdb_string("database_type"), mmdb_string(database_type)),
            (
                mmdb_string("description"),
                mmdb_map(vec![(mmdb_string("en"), mmdb_string("fumox test fixture"))]),
            ),
            (mmdb_string("ip_version"), mmdb_uint(5, 4)),
            (
                mmdb_string("languages"),
                mmdb_array(vec![mmdb_string("en")]),
            ),
            (
                mmdb_string("node_count"),
                mmdb_uint(6, u64::from(node_count)),
            ),
            (mmdb_string("record_size"), mmdb_uint(5, 24)),
        ]));
        out
    }

    /// Writes the fixture databases under their canonical names into a
    /// fresh temp directory and returns it, so a resolver can be built on
    /// them like on the real `db_dir`.
    fn fixture_db_dir(tag: &str) -> std::path::PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "fumox-geo-fixture-{}-{tag}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("fixture directory");
        std::fs::write(
            dir.join(GeoDbKind::City.file_name()),
            fixture_mmdb([81, 19, 44], &city_record(), "GeoLite2-City"),
        )
        .expect("city fixture");
        std::fs::write(
            dir.join(GeoDbKind::Asn.file_name()),
            fixture_mmdb([8, 8, 8], &asn_record(), "GeoLite2-ASN"),
        )
        .expect("asn fixture");
        dir
    }

    /// The fixture builder produces databases the real reader accepts:
    /// the records decode with exactly the facts the fixture wrote, and
    /// addresses outside the fixture network have no record.
    #[test]
    fn lookup_city_and_lookup_asn_read_a_fixture_database() {
        let city = Reader::from_source(fixture_mmdb([81, 19, 44], &city_record(), "GeoLite2-City"))
            .expect("the fixture must be a valid database");
        let record =
            lookup_city(&city, "81.19.44.10".parse().unwrap()).expect("the /24 has a record");
        assert_eq!(record.country_code.as_deref(), Some("DE"));
        assert_eq!(record.country_name.as_deref(), Some("Germany"));
        assert_eq!(record.city_name.as_deref(), Some("Berlin"));
        assert!(
            lookup_city(&city, "8.8.8.8".parse().unwrap()).is_none(),
            "no record outside the fixture network"
        );

        let asn = Reader::from_source(fixture_mmdb([8, 8, 8], &asn_record(), "GeoLite2-ASN"))
            .expect("the fixture must be a valid database");
        let record = lookup_asn(&asn, "8.8.8.8".parse().unwrap()).expect("the /24 has a record");
        assert_eq!(record.asn, Some(15169));
        assert_eq!(record.asn_org.as_deref(), Some("Google LLC"));
    }

    /// `english_name` prefers English and falls back to any other
    /// language, the behavior the merged name rendering relies on.
    #[test]
    fn english_name_prefers_english_then_any_language() {
        use maxminddb::geoip2;
        let names = geoip2::Names {
            english: Some("Germany"),
            ..Default::default()
        };
        assert_eq!(english_name(&names).as_deref(), Some("Germany"));
        let names = geoip2::Names {
            german: Some("Deutschland"),
            ..Default::default()
        };
        assert_eq!(english_name(&names).as_deref(), Some("Deutschland"));
        assert_eq!(english_name(&geoip2::Names::default()), None);
    }

    /// City and ASN facts merge into one verdict on the fixture
    /// databases; a partial record (only one database knows the address)
    /// still enriches.
    #[tokio::test]
    async fn the_fixture_resolver_merges_city_and_asn_facts() {
        let resolver = GeoResolver::new(&GeoConfig {
            enabled: true,
            db_dir: fixture_db_dir("merge"),
            ..Default::default()
        });
        let info = resolver
            .resolve("81.19.44.10")
            .await
            .expect("the fixture address is known");
        assert_eq!(info.ip, "81.19.44.10");
        assert_eq!(info.country_code.as_deref(), Some("DE"));
        assert_eq!(info.country_name.as_deref(), Some("Germany"));
        assert_eq!(info.city_name.as_deref(), Some("Berlin"));
        assert_eq!(info.asn, None, "81.19.44.x has no ASN record");

        // The ASN-only address: partial facts, still enrichment.
        let info = resolver
            .resolve("8.8.8.8")
            .await
            .expect("the fixture address is known");
        assert_eq!(info.asn, Some(15169));
        assert_eq!(info.asn_org.as_deref(), Some("Google LLC"));
        assert_eq!(info.country_code, None, "8.8.8.x has no City record");
        assert!(info.has_facts(), "an ASN-only record is still enrichment");
    }

    /// A no-record answer is a fact about the address: the outcome keeps
    /// the IP the host resolved to, so a caller can record it as
    /// `proxies.resolved_ip` even when no database knows the address.
    #[tokio::test]
    async fn a_no_record_outcome_keeps_the_resolved_ip() {
        let resolver = GeoResolver::new(&GeoConfig {
            enabled: true,
            db_dir: fixture_db_dir("norecord"),
            ..Default::default()
        });
        // TEST-NET-1: a valid address the fixture databases do not know.
        for attempt in 0..2 {
            match resolver.resolve_detailed("192.0.2.1").await {
                GeoOutcome::NoRecord { ip } => {
                    assert_eq!(
                        ip.as_deref(),
                        Some("192.0.2.1"),
                        "the resolved ip survives, attempt {attempt}"
                    );
                }
                other => panic!("expected a no-record outcome, got {other:?}"),
            }
        }
    }

    /// The cache lifetime is the configured one: positives and negatives
    /// expire alike, and an expired host is looked up again.
    #[tokio::test]
    async fn the_fixture_cache_expires_after_the_configured_ttl() {
        let resolver = GeoResolver::with_cache_ttl(
            &GeoConfig {
                enabled: true,
                db_dir: fixture_db_dir("ttl"),
                ..Default::default()
            },
            Duration::from_millis(50),
        );
        resolver.resolve("81.19.44.10").await.expect("known");
        resolver.resolve("192.0.2.1").await;
        assert!(resolver.facts.get("81.19.44.10").await.is_some());
        assert!(
            resolver.dns_failures.get("192.0.2.1").await.is_none(),
            "a no-record verdict is a fact, not a DNS failure"
        );

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            resolver.facts.get("81.19.44.10").await.is_none(),
            "the positive verdict expired"
        );
        assert!(
            resolver.resolve("81.19.44.10").await.is_some(),
            "an expired host is looked up again"
        );
    }

    /// The cache key and the DNS query see the normalized host: case, a
    /// trailing dot and the URI brackets of an IPv6 literal are the same
    /// host, so both spellings share one verdict.
    #[tokio::test]
    async fn the_cache_key_and_the_dns_query_use_the_normalized_host() {
        let resolver = GeoResolver::new(&GeoConfig {
            enabled: true,
            db_dir: fixture_db_dir("normalize"),
            ..Default::default()
        });
        let first = resolver.resolve("81.19.44.10").await.expect("known");
        let second = resolver
            .resolve("81.19.44.10.")
            .await
            .expect("a trailing dot is the same zone");
        assert_eq!(first, second, "one verdict for both spellings");
        assert!(
            resolver.dns_failures.get("81.19.44.10").await.is_none(),
            "an address is never sent to the DNS resolver"
        );
        assert!(
            resolver.dns_failures.get("81.19.44.10.").await.is_none(),
            "the normalized spelling is the cached key, the raw one is not"
        );
    }

    /// The admin panel's resolver constructs without the startup lines:
    /// no "geo enrichment enabled", no missing-database warns. Whether
    /// geo applies is the caller's decision, read from `state()` and
    /// `fact_mask()`, not from log output.
    #[test]
    fn full_resolver_from_dir_constructs_without_startup_logging() {
        #[derive(Clone, Default)]
        struct SharedBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for SharedBuf {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
            type Writer = Self;

            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let capture = |run: &dyn Fn()| {
            let buffer = SharedBuf::default();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(buffer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
            String::from_utf8(buffer.0.lock().unwrap().clone()).expect("log output is utf-8")
        };

        let cfg = GeoConfig {
            enabled: true,
            db_dir: fixture_db_dir("quiet"),
            ..Default::default()
        };
        let quiet = capture(&|| {
            let resolver = FullResolver::from_dir(&cfg);
            assert!(resolver.is_active(), "the fixture databases loaded");
        });
        assert!(
            !quiet.contains("geo enrichment enabled"),
            "the admin path must stay quiet: {quiet}"
        );
        assert!(
            !quiet.contains("GeoLite2"),
            "no database warn on the admin path: {quiet}"
        );

        // The pipeline constructor still reports, proving the capture
        // sees the line the quiet one must not print.
        let loud = capture(&|| {
            GeoResolver::new(&cfg);
        });
        assert!(
            loud.contains("geo enrichment enabled"),
            "the pipeline constructor reports the opened databases: {loud}"
        );
    }

    /// Partial facts must not render a dangling separator: an ASN-only
    /// record under `{flag} {country} · {name}` is the plain name, while
    /// a record with the facts on both sides keeps the separator.
    #[test]
    fn a_partial_facts_template_renders_without_a_dangling_separator() {
        let asn_only = GeoInfo {
            ip: "8.8.8.8".into(),
            asn: Some(15169),
            asn_org: Some("Google LLC".into()),
            ..Default::default()
        };
        assert_eq!(
            apply_template("{flag} {country} · {name}", &asn_only, "Node-1"),
            "Node-1"
        );
        assert_eq!(
            apply_template("{flag} {country} · {asn} {asn_org}", &asn_only, "Node-1"),
            "AS15169 Google LLC Node-1"
        );
        // A trailing separator with nothing after it drops too.
        assert_eq!(
            apply_template("{name} · {country}", &asn_only, "Node-1"),
            "Node-1"
        );
        // Content on both sides keeps the separator.
        assert_eq!(
            apply_template("{flag} {country} · {name}", &german_geo(), "Node-1"),
            "🇩🇪 Germany · Node-1"
        );
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
            matches!(unknown, GeoOutcome::NoRecord { .. }),
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
    /// Built on [`workspace_db_dir`], the single source of the path.
    fn mmdb_path(kind: GeoDbKind) -> Option<std::path::PathBuf> {
        let path = workspace_db_dir()?.join(kind.file_name());
        path.is_file().then_some(path)
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
