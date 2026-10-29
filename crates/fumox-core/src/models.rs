//! Domain models shared by `fumox-server` and `fumox-probe`.
//!
//! The types mirror the SQLite schema. The
//! persistence mapping itself lives in the repository layer; these structs
//! stay database-agnostic so parsers and the pipeline can work with them
//! without a database handle.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Proxy protocol scheme (`proxies.scheme`).
///
/// Serialized as the lower-case wire name used in subscription URIs and in
/// the database. `naive` covers both `naive+https` and `naive+quic` origins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Vless,
    Vmess,
    Trojan,
    Ss,
    Hysteria2,
    Tuic,
    Mieru,
    Socks5,
    Naive,
    /// Snell (v1-v6), an obfuscated TCP proxy. meow-rs gained v6 in
    /// 0.22.0 (`default`/`unshaped`/`unsafe-raw` record modes, pooled
    /// connections); older servers keep their own version in `params`.
    Snell,
    /// AnyTLS, a TLS-shaped proxy that pads to traffic shape. Native in
    /// meow-rs since 0.21.x.
    AnyTls,
}

impl Scheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Scheme::Vless => "vless",
            Scheme::Vmess => "vmess",
            Scheme::Trojan => "trojan",
            Scheme::Ss => "ss",
            Scheme::Hysteria2 => "hysteria2",
            Scheme::Tuic => "tuic",
            Scheme::Mieru => "mieru",
            Scheme::Socks5 => "socks5",
            Scheme::Naive => "naive",
            Scheme::Snell => "snell",
            Scheme::AnyTls => "anytls",
        }
    }

    /// Every accepted spelling of this scheme, the canonical wire name
    /// first.
    ///
    /// The table is the single source of truth: [`FromStr`] and the
    /// `Deserialize` impl both read it, so a spelling one of them accepts
    /// the other accepts too. `hy2` is the spelling subscription feeds
    /// actually use for `hysteria2`.
    pub const fn aliases(self) -> &'static [&'static str] {
        match self {
            Scheme::Vless => &["vless"],
            Scheme::Vmess => &["vmess"],
            Scheme::Trojan => &["trojan"],
            Scheme::Ss => &["ss"],
            Scheme::Hysteria2 => &["hysteria2", "hy2"],
            Scheme::Tuic => &["tuic"],
            Scheme::Mieru => &["mieru"],
            Scheme::Socks5 => &["socks5"],
            Scheme::Naive => &["naive"],
            Scheme::Snell => &["snell"],
            Scheme::AnyTls => &["anytls"],
        }
    }

    /// All schemes the MVP parsers accept, in parse-priority order.
    pub const fn all() -> &'static [Scheme] {
        &[
            Scheme::Vless,
            Scheme::Vmess,
            Scheme::Trojan,
            Scheme::Ss,
            Scheme::Hysteria2,
            Scheme::Tuic,
            Scheme::Mieru,
            Scheme::Socks5,
            Scheme::Naive,
            Scheme::Snell,
            Scheme::AnyTls,
        ]
    }

    /// Whether the probe daemon can actively health-check this scheme.
    ///
    /// tuic and mieru are UDP-only with no T2 support, so they stay
    /// permanently `unknown` and pass health filters.
    pub const fn is_probeable(self) -> bool {
        !matches!(self, Scheme::Tuic | Scheme::Mieru)
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Scheme {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for scheme in Scheme::all() {
            if scheme.aliases().contains(&s) {
                return Ok(*scheme);
            }
        }
        Err(crate::Error::Parse(format!("unknown scheme: {s:?}")))
    }
}

/// The wire format reads the same alias table as [`FromStr`]: a config or
/// an import file that spells a scheme `hy2` parses exactly like the string
/// `"hy2"` does.
impl<'de> Deserialize<'de> for Scheme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse::<Scheme>().map_err(serde::de::Error::custom)
    }
}

/// The wire name of a scheme is its canonical alias, the spelling the
/// database and the subscription URIs use.
impl Serialize for Scheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Proxy lifecycle status (`proxies.status`).
///
/// `ready` is the tunnel-verified tier: it is
/// assigned only while the latest T2 check succeeded and demoted back to
/// `alive` by any failed T2 outcome. The tiers do not overlap, `alive`
/// means T1-alive without a fresh successful T2, `ready` means alive plus
/// the confirmed tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyStatus {
    Unknown,
    Alive,
    Ready,
    Quarantine,
    Removed,
}

impl ProxyStatus {
    /// Every status in schema order, the source for the admin UI option
    /// lists (pipeline editor health filter), the proxy filter whitelist
    /// and the status badge map.
    pub const fn all() -> &'static [ProxyStatus] {
        &[
            ProxyStatus::Unknown,
            ProxyStatus::Alive,
            ProxyStatus::Ready,
            ProxyStatus::Quarantine,
            ProxyStatus::Removed,
        ]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            ProxyStatus::Unknown => "unknown",
            ProxyStatus::Alive => "alive",
            ProxyStatus::Ready => "ready",
            ProxyStatus::Quarantine => "quarantine",
            ProxyStatus::Removed => "removed",
        }
    }
}

impl fmt::Display for ProxyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProxyStatus {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let status = match s {
            "unknown" => ProxyStatus::Unknown,
            "alive" => ProxyStatus::Alive,
            "ready" => ProxyStatus::Ready,
            "quarantine" => ProxyStatus::Quarantine,
            "removed" => ProxyStatus::Removed,
            other => {
                return Err(crate::Error::Parse(format!(
                    "unknown proxy status: {other:?}"
                )));
            }
        };
        Ok(status)
    }
}

/// Fetch error classification (`sources.error_class`, `fetch_log.error_class`).
/// This is the only permitted vocabulary, the legacy
/// `stale|unreachable|…` set is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Network,
    HttpServer,
    HttpClient,
    ParseError,
    /// The fetch succeeded, but the payload could not be stored: the
    /// database rejected the write. Unlike the other classes this one
    /// says nothing about the upstream — the feed was fine and this
    /// process failed — so it must not be reported as a fetch error.
    Storage,
}

impl ErrorClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorClass::Network => "network",
            ErrorClass::HttpServer => "http_server",
            ErrorClass::HttpClient => "http_client",
            ErrorClass::ParseError => "parse_error",
            ErrorClass::Storage => "storage",
        }
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ErrorClass {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let class = match s {
            "network" => ErrorClass::Network,
            "http_server" => ErrorClass::HttpServer,
            "http_client" => ErrorClass::HttpClient,
            "parse_error" => ErrorClass::ParseError,
            "storage" => ErrorClass::Storage,
            other => {
                return Err(crate::Error::Parse(format!(
                    "unknown error class: {other:?}"
                )));
            }
        };
        Ok(class)
    }
}

/// A single protocol parameter kept in its original position.
///
/// Order matters for byte-faithful round-trip serialization of URI schemes,
/// so parameters are stored as an ordered list rather than a map. `known`
/// records whether the parser recognized the key for this scheme; unknown
/// parameters pass through untouched and are persisted into
/// `proxies.unknown_params`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Param {
    pub key: String,
    /// Raw value exactly as it appeared in the source (still percent-encoded
    /// for URI schemes). Decoding happens at use time, never in storage, so
    /// serialization can emit the original bytes.
    pub value: String,
    pub known: bool,
}

/// Certificate-verification toggle spellings seen across the wire formats:
/// the URI families ship `insecure` / `allowInsecure` / `skip-cert-verify`,
/// sing-box links (tuic) the underscore `allow_insecure`. One list shared by
/// every consumer, the fingerprint normalisation, the output writers and the
/// forbid-insecure pipeline filter, so a feed spelling the toggle
/// differently is never missed by one of them and two spellings of the same
/// node collapse onto one deduplication key.
pub const INSECURE_ALIASES: [&str; 4] = [
    "insecure",
    "allowinsecure",
    "skip-cert-verify",
    "allow_insecure",
];

/// Whether `value` spells a truthy toggle (`1` / `true` / `yes` / `on`,
/// trimmed and case-insensitive). The one vocabulary shared by every toggle
/// consumer: the certificate-verification aliases (the fingerprint
/// normalisation, the output writers, the forbid-insecure filter), the
/// parsers' Clash booleans and the writers' `param_truthy`. Splitting it
/// made `allowInsecure=yes` keep a node that `allowInsecure=1` dropped and
/// let the fingerprint merge a `yes` row with the secure variant.
pub(crate) fn is_truthy_toggle(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Whether `value` spells a falsy toggle (`0` / `false` / `no` / `off`,
/// trimmed and case-insensitive).
///
/// The counterpart of [`is_truthy_toggle`]: an explicit switch that says
/// "off" has to be honoured, otherwise a stated `tls: false` would be
/// overruled by the SNI-implies-TLS rule.
pub(crate) fn is_falsy_toggle(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Whether the parameter switches certificate verification off: one of the
/// [`INSECURE_ALIASES`] spellings carrying a truthy value.
pub fn is_insecure_param(param: &Param) -> bool {
    INSECURE_ALIASES.contains(&param.key.to_ascii_lowercase().as_str())
        && is_truthy_toggle(&param.value)
}

/// A parsed, normalized proxy record, the unit of deduplication and of the
/// processing pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub scheme: Scheme,
    /// Display name (URI fragment or vmess `ps`). Excluded from the
    /// fingerprint; may be rewritten by the rename stage of the pipeline.
    pub name: String,
    pub host: String,
    pub port: u16,
    /// uuid / password / `method:pass` / `user:pass`, scheme-dependent.
    ///
    /// A secret: it never leaves the server in a serialised form.
    #[serde(skip_serializing)]
    pub credential: String,
    /// All parameters in original order (query pairs for URI schemes, JSON
    /// fields for vmess).
    pub params: Vec<Param>,
    /// Raw path segment between the authority and the query ("" or "/"),
    /// preserved verbatim for round-trip fidelity.
    pub raw_path: String,
    /// The exact source line this entry was parsed from (debugging and
    /// recovery; `proxies.raw_line`). It carries the credential, so it is
    /// a secret too.
    #[serde(skip_serializing)]
    pub raw_line: String,
}

impl ProxyEntry {
    /// First parameter value with the exact key, if present.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.key == key)
            .map(|p| p.value.as_str())
    }

    /// First parameter value matching the key case-insensitively.
    ///
    /// Real-world feeds mix spellings (`headerType` / `headertype`), so any
    /// semantic lookup must ignore case.
    pub fn param_ignore_case(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|p| p.key.eq_ignore_ascii_case(key))
            .map(|p| p.value.as_str())
    }

    /// Recognized parameters as a JSON object for `proxies.params`.
    ///
    /// On duplicate keys the first occurrence wins; order is not guaranteed
    /// in the stored JSON (the ordered list stays the round-trip source).
    pub fn known_params_json(&self) -> serde_json::Map<String, serde_json::Value> {
        Self::split_params_json(&self.params, true)
    }

    /// Unrecognized parameters as a JSON object for `proxies.unknown_params`.
    pub fn unknown_params_json(&self) -> serde_json::Map<String, serde_json::Value> {
        Self::split_params_json(&self.params, false)
    }

    fn split_params_json(
        params: &[Param],
        known: bool,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        for p in params
            .iter()
            .filter(|p| p.known == known && !p.key.is_empty())
        {
            map.entry(p.key.clone())
                .or_insert(serde_json::Value::String(p.value.clone()));
        }
        map
    }

    /// Stable deduplication fingerprint; see [`crate::fingerprint`].
    pub fn fingerprint(&self) -> String {
        crate::fingerprint::fingerprint(self)
    }
}

/// Normalise a protocol allowlist: an empty list means "accept every
/// scheme", the same as `None`.
///
/// The two spellings used to mean different things — `None` accepts every
/// scheme, an empty list accepts none — but nothing checked the difference:
/// a source with an empty allowlist dropped every entry at ingest and
/// then failed every fetch with "no proxies left after the protocol
/// allowlist", looking configured while loading nothing.
pub fn normalize_protocols(protocols: Option<Vec<Scheme>>) -> Option<Vec<Scheme>> {
    protocols.filter(|list| !list.is_empty())
}

/// Subscription source (`sources` table).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    /// `nanoid(12)`; doubles as the `/src/{id}` token when `slug` is unset.
    pub id: String,
    /// Optional human-readable identifier for `/sub/{slug}`-style references.
    pub slug: Option<String>,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    /// Payload encoding expectation; `auto` detects from content.
    pub encoding: Encoding,
    /// Explicitly pinned input format; `None` means auto-detect
    /// (URI list / Clash YAML / sing-box JSON).
    pub input_format: Option<InputFormat>,
    /// Protocol allowlist; `None` means accept every supported scheme.
    pub protocols: Option<Vec<Scheme>>,
    pub cache_ttl_seconds: i64,
    pub tags: Option<Vec<String>>,
    /// Processing rules, pipeline JSON v1. Validated by the
    /// pipeline module before storage.
    pub pipeline: Option<serde_json::Value>,
    /// Extra HTTP headers sent with the fetch request. They usually carry
    /// an `Authorization`, so the map is a secret and never leaves the
    /// server in a serialised form.
    #[serde(default, skip_serializing)]
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    /// Preferred IP protocol family for fetching the URL.
    /// `None` inherits the deployment default (`[fetch] ip_family`); a set
    /// family is strict, without an address of that family the fetch fails.
    pub ip_family: Option<IpFamily>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_fetched_at: Option<i64>,
    pub last_error: Option<String>,
    /// Class of the last fetch error; `None` means the last fetch succeeded.
    pub error_class: Option<ErrorClass>,
}

/// IP protocol family used to reach a source URL (`sources.ip_family`,
/// `[fetch] ip_family`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    /// Dual-stack: pick the first IPv4 address, fall back to IPv6 (the
    /// historical behavior).
    #[default]
    Any,
    /// Connect via IPv4 addresses only.
    Ipv4,
    /// Connect via IPv6 addresses only.
    Ipv6,
}

impl IpFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            IpFamily::Any => "any",
            IpFamily::Ipv4 => "ipv4",
            IpFamily::Ipv6 => "ipv6",
        }
    }
}

impl FromStr for IpFamily {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let family = match s {
            "any" => IpFamily::Any,
            "ipv4" => IpFamily::Ipv4,
            "ipv6" => IpFamily::Ipv6,
            other => {
                return Err(crate::Error::Parse(format!("unknown IP family: {other:?}")));
            }
        };
        Ok(family)
    }
}

/// Profile, a named combination of sources plus output rules (`profiles`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// `nanoid(12)`; doubles as the `/sub/{id}` token when `slug` is unset.
    pub id: String,
    pub slug: Option<String>,
    /// Optional access token for `/sub`; `None` = public. The token is a
    /// secret (the database keeps its hash), so it never leaves the server
    /// in a serialised form.
    #[serde(default, skip_serializing)]
    pub access_token: Option<String>,
    pub name: String,
    pub output_format: OutputFormat,
    /// Pipeline overrides applied on top of the source pipelines.
    pub pipeline: Option<serde_json::Value>,
    /// Country allowlist for `/sub`: ISO 3166-1 alpha-2 codes, uppercase.
    /// Empty = every country; while set, proxies with no determined country
    /// stay out, the filter passes confirmed geo facts only.
    pub countries: Vec<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Expected payload encoding of a source (`sources.encoding`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Plain,
    Base64,
    #[default]
    Auto,
}

impl Encoding {
    pub const fn as_str(self) -> &'static str {
        match self {
            Encoding::Plain => "plain",
            Encoding::Base64 => "base64",
            Encoding::Auto => "auto",
        }
    }
}

impl FromStr for Encoding {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let enc = match s {
            "plain" => Encoding::Plain,
            "base64" => Encoding::Base64,
            "auto" => Encoding::Auto,
            other => {
                return Err(crate::Error::Parse(format!("unknown encoding: {other:?}")));
            }
        };
        Ok(enc)
    }
}

/// Explicitly pinned input format (`sources.input_format`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputFormat {
    #[default]
    UriList,
    ClashYaml,
    SingBoxJson,
}

impl InputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            InputFormat::UriList => "uri_list",
            InputFormat::ClashYaml => "clash_yaml",
            InputFormat::SingBoxJson => "sing_box_json",
        }
    }
}

impl FromStr for InputFormat {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fmt = match s {
            "uri_list" => InputFormat::UriList,
            "clash_yaml" => InputFormat::ClashYaml,
            "sing_box_json" => InputFormat::SingBoxJson,
            other => {
                return Err(crate::Error::Parse(format!(
                    "unknown input format: {other:?}"
                )));
            }
        };
        Ok(fmt)
    }
}

/// Subscription output format (`profiles.output_format`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    #[default]
    UriList,
    Base64,
    Clash,
    SingBox,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            OutputFormat::UriList => "uri_list",
            OutputFormat::Base64 => "base64",
            OutputFormat::Clash => "clash",
            OutputFormat::SingBox => "sing_box",
        }
    }
}

impl FromStr for OutputFormat {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fmt = match s {
            "uri_list" => OutputFormat::UriList,
            "base64" => OutputFormat::Base64,
            "clash" => OutputFormat::Clash,
            "sing_box" => OutputFormat::SingBox,
            other => {
                return Err(crate::Error::Parse(format!(
                    "unknown output format: {other:?}"
                )));
            }
        };
        Ok(fmt)
    }
}

/// Identifier alphabet for `nanoid(12)`.
pub const ID_ALPHABET: &[char; 64] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '_', '-',
];

/// Generate a new identifier: `nanoid(12)` over `A-Za-z0-9_-`.
pub fn new_id() -> String {
    nanoid::nanoid!(12, ID_ALPHABET)
}

/// Current Unix timestamp in seconds (UTC), the timestamp convention used
/// across the schema. Panicking on a pre-epoch clock is deliberate: a clock
/// error that far off would poison every stored timestamp, and failing the
/// first write is easier to diagnose than silently negative ages.
pub fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthy_toggle_vocabulary_is_1_true_yes_on() {
        for truthy in ["1", "true", "yes", "on", " TRUE ", "Yes"] {
            assert!(is_truthy_toggle(truthy), "{truthy:?} must be truthy");
        }
        for falsy in ["0", "false", "no", "off", "", " enabled"] {
            assert!(!is_truthy_toggle(falsy), "{falsy:?} must be falsy");
        }
    }

    #[test]
    fn scheme_wire_names_round_trip() {
        for scheme in Scheme::all() {
            let parsed: Scheme = scheme.as_str().parse().unwrap();
            assert_eq!(parsed, *scheme);
            assert_eq!(
                serde_json::to_string(scheme).unwrap(),
                format!("\"{}\"", scheme.as_str())
            );
            let from_json: Scheme = serde_json::from_str(&format!("\"{}\"", scheme.as_str()))
                .expect("the canonical wire name must parse");
            assert_eq!(from_json, *scheme);
        }
    }

    /// One alias table, two entry points: every spelling a scheme accepts
    /// is accepted by `FromStr` *and* by the serde deserializer, so a
    /// config or an import file that spells a scheme `hy2` is not rejected
    /// while the same word parses as a string.
    #[test]
    fn every_scheme_alias_parses_on_both_paths() {
        for scheme in Scheme::all() {
            for alias in scheme.aliases() {
                assert_eq!(
                    alias.parse::<Scheme>().unwrap(),
                    *scheme,
                    "FromStr must accept {alias}"
                );
                let from_json: Scheme = serde_json::from_str(&format!("\"{alias}\""))
                    .unwrap_or_else(|err| {
                        panic!("serde must accept {alias}: {err}");
                    });
                assert_eq!(from_json, *scheme, "serde must accept {alias}");
            }
        }
    }

    /// The alias table is the single source of truth: the canonical wire
    /// name is the first alias of its scheme.
    #[test]
    fn the_canonical_wire_name_is_the_first_alias() {
        for scheme in Scheme::all() {
            assert_eq!(scheme.aliases().first(), Some(&scheme.as_str()));
        }
    }

    #[test]
    fn scheme_hy2_alias_parses() {
        assert_eq!("hy2".parse::<Scheme>().unwrap(), Scheme::Hysteria2);
    }

    /// A serialised model carries no secret: the proxy credential, the
    /// source headers and the profile access token never reach a JSON dump.
    #[test]
    fn serialised_models_carry_no_secret() {
        let entry = ProxyEntry {
            scheme: Scheme::Vless,
            name: "n".into(),
            host: "h".into(),
            port: 443,
            credential: "super-secret-uuid".into(),
            params: Vec::new(),
            raw_path: "/ws".into(),
            raw_line: "vless://super-secret-uuid@h:443".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("super-secret-uuid"), "{json}");

        let source = Source {
            id: "s".into(),
            slug: None,
            name: "n".into(),
            url: "https://example.com".into(),
            enabled: true,
            encoding: Encoding::Auto,
            input_format: None,
            protocols: None,
            cache_ttl_seconds: 60,
            tags: None,
            pipeline: None,
            headers: Some(std::collections::BTreeMap::from([(
                "Authorization".into(),
                "Bearer super-secret-header".into(),
            )])),
            ip_family: None,
            created_at: 0,
            updated_at: 0,
            last_fetched_at: None,
            last_error: None,
            error_class: None,
        };
        let json = serde_json::to_string(&source).unwrap();
        assert!(!json.contains("super-secret-header"), "{json}");
        // The field is gone entirely, not emptied: there is no key to fill
        // with a secret later.
        assert!(!json.contains("headers"), "{json}");

        let profile = Profile {
            id: "p".into(),
            slug: None,
            access_token: Some("super-secret-token".into()),
            name: "n".into(),
            output_format: OutputFormat::UriList,
            pipeline: None,
            countries: Vec::new(),
            enabled: true,
            created_at: 0,
            updated_at: 0,
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(!json.contains("super-secret-token"), "{json}");
        assert!(!json.contains("access_token"), "{json}");
    }

    #[test]
    fn unprobeable_schemes() {
        assert!(!Scheme::Tuic.is_probeable());
        assert!(!Scheme::Mieru.is_probeable());
        assert!(Scheme::Vless.is_probeable());
        assert!(Scheme::Hysteria2.is_probeable());
    }

    #[test]
    fn status_wire_names_round_trip() {
        for (status, name) in [
            (ProxyStatus::Unknown, "unknown"),
            (ProxyStatus::Alive, "alive"),
            (ProxyStatus::Ready, "ready"),
            (ProxyStatus::Quarantine, "quarantine"),
            (ProxyStatus::Removed, "removed"),
        ] {
            assert_eq!(status.as_str(), name);
            assert_eq!(name.parse::<ProxyStatus>().unwrap(), status);
        }
        // ALL carries every wire name exactly once (admin option lists
        // derive from it).
        let names: Vec<&str> = ProxyStatus::all().iter().map(|s| s.as_str()).collect();
        for (_, name) in [
            (ProxyStatus::Unknown, "unknown"),
            (ProxyStatus::Alive, "alive"),
            (ProxyStatus::Ready, "ready"),
            (ProxyStatus::Quarantine, "quarantine"),
            (ProxyStatus::Removed, "removed"),
        ] {
            assert!(names.contains(&name), "ALL must contain {name}");
        }
    }

    #[test]
    fn error_class_wire_names_round_trip() {
        for (class, name) in [
            (ErrorClass::Network, "network"),
            (ErrorClass::HttpServer, "http_server"),
            (ErrorClass::HttpClient, "http_client"),
            (ErrorClass::ParseError, "parse_error"),
        ] {
            assert_eq!(class.as_str(), name);
            assert_eq!(name.parse::<ErrorClass>().unwrap(), class);
            assert_eq!(
                serde_json::to_string(&class).unwrap(),
                format!("\"{name}\"")
            );
        }
    }

    #[test]
    fn new_id_shape() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let id = new_id();
            assert_eq!(id.len(), 12);
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            );
            assert!(seen.insert(id));
        }
    }

    fn entry_with_params(params: Vec<Param>) -> ProxyEntry {
        ProxyEntry {
            scheme: Scheme::Vless,
            name: "n".into(),
            host: "h".into(),
            port: 443,
            credential: "c".into(),
            params,
            raw_path: String::new(),
            raw_line: String::new(),
        }
    }

    #[test]
    fn param_lookup_exact_and_case_insensitive() {
        let entry = entry_with_params(vec![
            Param {
                key: "headerType".into(),
                value: "none".into(),
                known: true,
            },
            Param {
                key: "sni".into(),
                value: "example.com".into(),
                known: true,
            },
        ]);
        assert_eq!(entry.param("headerType"), Some("none"));
        assert_eq!(entry.param("headertype"), None);
        assert_eq!(entry.param_ignore_case("headertype"), Some("none"));
        assert_eq!(entry.param_ignore_case("SNI"), Some("example.com"));
        assert_eq!(entry.param("missing"), None);
    }

    #[test]
    fn params_split_into_known_and_unknown_json() {
        let entry = entry_with_params(vec![
            Param {
                key: "security".into(),
                value: "reality".into(),
                known: true,
            },
            Param {
                key: "telegram".into(),
                value: "@spam".into(),
                known: false,
            },
            // Duplicate known key: first occurrence wins in the JSON view.
            Param {
                key: "security".into(),
                value: "tls".into(),
                known: true,
            },
        ]);
        let known = entry.known_params_json();
        let unknown = entry.unknown_params_json();
        assert_eq!(known.get("security").unwrap(), "reality");
        assert_eq!(known.len(), 1);
        assert_eq!(unknown.get("telegram").unwrap(), "@spam");
        assert_eq!(unknown.len(), 1);
    }

    #[test]
    fn encoding_and_format_wire_names() {
        assert_eq!(Encoding::default(), Encoding::Auto);
        assert_eq!("base64".parse::<Encoding>().unwrap(), Encoding::Base64);
        assert_eq!(
            "clash_yaml".parse::<InputFormat>().unwrap(),
            InputFormat::ClashYaml
        );
        assert_eq!(
            "sing_box".parse::<OutputFormat>().unwrap(),
            OutputFormat::SingBox
        );
        assert_eq!(OutputFormat::default(), OutputFormat::UriList);
    }

    #[test]
    fn now_ts_is_reasonable() {
        // Somewhere after 2286-11-20 is impossible for the next centuries;
        // before 2020 means the clock helper is broken.
        let ts = now_ts();
        assert!(ts > 1_577_836_800 && ts < 10_000_000_000);
    }
}
