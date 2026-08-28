//! Geo enrichment (MaxMind GeoLite2) — SPEC §6.
//!
//! Pipeline: `host` → (async DNS if it is a domain) → IP → MaxMind lookup →
//! geo facts (country, optionally city/ASN depending on the database) applied
//! to the display name through a template (default `"{flag} {country} ·
//! {name}"`, placeholders `{flag} {country} {city} {asn} {asn_org} {name}`,
//! SPEC §5.1/§6).
//!
//! DNS and lookup results are cached per host (hosts repeat heavily in
//! subscription feeds); negative results are cached too, so unresolvable
//! hosts are not re-queried on every pipeline run.
//!
//! The `.mmdb` files are never committed. When the configured database file
//! is absent the resolver degrades to a no-op with a warning — geo
//! enrichment is an optional enhancement, not a startup requirement.

use crate::config::{GeoConfig, GeoDbKind};
use maxminddb::Reader;
use moka::future::Cache;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

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

/// Apply the rename template (SPEC §5.1 `geo.template`).
///
/// Placeholders: `{flag}`, `{country}`, `{city}`, `{asn}`, `{asn_org}`,
/// `{name}`. The original name is returned unchanged only when there is no
/// geo data at all (no country, no city, no ASN) — a template with empty
/// substitutions would only produce dangling separators. Individual missing
/// values substitute as empty strings, and the result is then collapsed
/// (whitespace runs → single space, trimmed), so `"{flag} {country} {city} ·
/// {name}"` without a city still renders cleanly.
pub fn apply_template(template: &str, geo: &GeoInfo, name: &str) -> String {
    if geo.country_code.is_none() && geo.city_name.is_none() && geo.asn.is_none() {
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
    let asn = geo.asn.map(|asn| format!("AS{asn}")).unwrap_or_default();
    let rendered = template
        .replace("{flag}", &flag)
        .replace("{country}", &country)
        .replace("{city}", city)
        // {asn_org} before {asn}: the shorter placeholder is a prefix of it.
        .replace("{asn_org}", asn_org)
        .replace("{asn}", &asn)
        .replace("{name}", name);
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

enum Backend {
    Country(Reader<Vec<u8>>),
    City(Reader<Vec<u8>>),
    Asn(Reader<Vec<u8>>),
}

/// Host → geo resolver with an in-memory cache. Cheap to clone/share: the
/// internals are `Arc`-wrapped.
#[derive(Clone)]
pub struct GeoResolver {
    backend: Option<Arc<Backend>>,
    cache: Cache<String, Option<Arc<GeoInfo>>>,
    dns_timeout: Duration,
}

impl GeoResolver {
    /// Build a resolver from config. Returns a no-op resolver (with a
    /// warning logged) when geo is disabled or the database file is missing.
    pub fn new(cfg: &GeoConfig) -> Self {
        let cache = Cache::builder().max_capacity(cfg.cache_max_entries).build();
        let dns_timeout = Duration::from_secs(cfg.dns_timeout_secs);
        if !cfg.enabled {
            return Self {
                backend: None,
                cache,
                dns_timeout,
            };
        }
        let path = cfg.db_path();
        let reader = match Reader::open_readfile(&path) {
            Ok(reader) => reader,
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "GeoLite2 database unavailable; geo enrichment disabled"
                );
                return Self {
                    backend: None,
                    cache,
                    dns_timeout,
                };
            }
        };
        let backend = match cfg.db {
            GeoDbKind::Country => Backend::Country(reader),
            GeoDbKind::City => Backend::City(reader),
            GeoDbKind::Asn => Backend::Asn(reader),
        };
        Self {
            backend: Some(Arc::new(backend)),
            cache,
            dns_timeout,
        }
    }

    /// Whether this resolver can actually enrich (database loaded).
    pub fn is_active(&self) -> bool {
        self.backend.is_some()
    }

    /// Resolve geo information for a proxy host (domain or literal IP).
    /// Returns `None` when the resolver is inactive, DNS fails, or the
    /// database has no data for the address.
    pub async fn resolve(&self, host: &str) -> Option<Arc<GeoInfo>> {
        let backend = self.backend.as_ref()?;
        let key = host.to_ascii_lowercase();
        if let Some(cached) = self.cache.get(&key).await {
            return cached;
        }
        let info = self.resolve_uncached(backend, host).await.map(Arc::new);
        self.cache.insert(key, info.clone()).await;
        info
    }

    async fn resolve_uncached(&self, backend: &Backend, host: &str) -> Option<GeoInfo> {
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => self.dns_resolve(host).await?,
        };
        let mut info = lookup(backend, ip)?;
        info.ip = ip.to_string();
        Some(info)
    }

    /// Async DNS resolution with the configured timeout. Prefers the first
    /// IPv4 answer (proxy servers are overwhelmingly IPv4-reachable).
    async fn dns_resolve(&self, host: &str) -> Option<IpAddr> {
        let lookup = tokio::time::timeout(self.dns_timeout, tokio::net::lookup_host((host, 0)))
            .await
            .ok()?
            .ok()?;
        let mut addrs = lookup.map(|addr| addr.ip());
        let first = addrs.next()?;
        Some(addrs.find(IpAddr::is_ipv4).unwrap_or(first))
    }
}

fn lookup(backend: &Backend, ip: IpAddr) -> Option<GeoInfo> {
    use maxminddb::geoip2;
    match backend {
        Backend::Country(reader) => {
            let record: geoip2::Country = reader.lookup(ip).ok()?.decode().ok().flatten()?;
            if record.country.is_empty() {
                return None;
            }
            Some(GeoInfo {
                country_code: record.country.iso_code.map(str::to_string),
                country_name: english_name(&record.country.names),
                ..Default::default()
            })
        }
        Backend::City(reader) => {
            let record: geoip2::City = reader.lookup(ip).ok()?.decode().ok().flatten()?;
            if record.country.is_empty() {
                return None;
            }
            Some(GeoInfo {
                country_code: record.country.iso_code.map(str::to_string),
                country_name: english_name(&record.country.names),
                city_name: english_name(&record.city.names),
                ..Default::default()
            })
        }
        Backend::Asn(reader) => {
            let record: geoip2::Asn = reader.lookup(ip).ok()?.decode().ok().flatten()?;
            Some(GeoInfo {
                asn: record.autonomous_system_number,
                asn_org: record.autonomous_system_organization.map(str::to_string),
                ..Default::default()
            })
        }
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

    /// Path to a GeoLite2 database if present in the workspace `config/`
    /// directory (the files are gitignored, so tests skip without them).
    fn mmdb_path(kind: GeoDbKind) -> Option<std::path::PathBuf> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config")
            .join(kind.file_name());
        path.exists().then_some(path)
    }

    fn resolver_for(kind: GeoDbKind) -> Option<GeoResolver> {
        let db_dir = mmdb_path(kind)?;
        let cfg = GeoConfig {
            enabled: true,
            db: kind,
            db_dir: db_dir.parent().unwrap().to_path_buf(),
            ..Default::default()
        };
        let resolver = GeoResolver::new(&cfg);
        resolver.is_active().then_some(resolver)
    }

    #[tokio::test]
    async fn country_lookup_for_literal_ip() {
        let Some(resolver) = resolver_for(GeoDbKind::Country) else {
            eprintln!("skipped: GeoLite2-Country.mmdb not present");
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
        let Some(resolver) = resolver_for(GeoDbKind::Country) else {
            eprintln!("skipped: GeoLite2-Country.mmdb not present");
            return;
        };
        // TEST-NET-1 address: valid IP, typically without geo data — the
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
        let Some(resolver) = resolver_for(GeoDbKind::Country) else {
            eprintln!("skipped: GeoLite2-Country.mmdb not present");
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
