//! Domain models shared by `fumox-server` and `fumox-probe`.
//!
//! The types mirror the SQLite schema (`docs/DATABASE.md` v0.4). The
//! persistence mapping itself lives in the repository layer; these structs
//! stay database-agnostic so parsers and the pipeline can work with them
//! without a database handle.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Proxy protocol scheme (`proxies.scheme` in DATABASE.md).
///
/// Serialized as the lower-case wire name used in subscription URIs and in
/// the database. `naive` covers both `naive+https` and `naive+quic` origins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
        ]
    }

    /// Whether the probe daemon can actively health-check this scheme.
    ///
    /// tuic and mieru are UDP-only with no T2 support, so they stay
    /// permanently `unknown` and pass health filters (SPEC §8.5).
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
        let scheme = match s {
            "vless" => Scheme::Vless,
            "vmess" => Scheme::Vmess,
            "trojan" => Scheme::Trojan,
            "ss" => Scheme::Ss,
            "hysteria2" | "hy2" => Scheme::Hysteria2,
            "tuic" => Scheme::Tuic,
            "mieru" => Scheme::Mieru,
            "socks5" => Scheme::Socks5,
            "naive" => Scheme::Naive,
            other => {
                return Err(crate::Error::Parse(format!("unknown scheme: {other:?}")));
            }
        };
        Ok(scheme)
    }
}

/// Proxy lifecycle status (`proxies.status`, SPEC §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyStatus {
    Unknown,
    Alive,
    Quarantine,
    Removed,
}

impl ProxyStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProxyStatus::Unknown => "unknown",
            ProxyStatus::Alive => "alive",
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

/// Fetch error classification (`sources.error_class`, `fetch_log.error_class`;
/// SPEC §10.2). This is the only permitted vocabulary — the legacy
/// `stale|unreachable|…` set is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    Network,
    HttpServer,
    HttpClient,
    ParseError,
}

impl ErrorClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorClass::Network => "network",
            ErrorClass::HttpServer => "http_server",
            ErrorClass::HttpClient => "http_client",
            ErrorClass::ParseError => "parse_error",
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

/// A parsed, normalized proxy record — the unit of deduplication and of the
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
    pub credential: String,
    /// All parameters in original order (query pairs for URI schemes, JSON
    /// fields for vmess).
    pub params: Vec<Param>,
    /// Raw path segment between the authority and the query ("" or "/"),
    /// preserved verbatim for round-trip fidelity.
    pub raw_path: String,
    /// The exact source line this entry was parsed from (debugging and
    /// recovery; `proxies.raw_line`).
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
    /// Processing rules, pipeline JSON v1 (SPEC §5.1). Validated by the
    /// pipeline module before storage.
    pub pipeline: Option<serde_json::Value>,
    /// Extra HTTP headers sent with the fetch request.
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_fetched_at: Option<i64>,
    pub last_error: Option<String>,
    /// Class of the last fetch error; `None` means the last fetch succeeded.
    pub error_class: Option<ErrorClass>,
}

/// Profile — a named combination of sources plus output rules (`profiles`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// `nanoid(12)`; doubles as the `/sub/{id}` token when `slug` is unset.
    pub id: String,
    pub slug: Option<String>,
    /// Optional access token for `/sub` (SPEC §10.1); `None` = public.
    pub access_token: Option<String>,
    pub name: String,
    pub output_format: OutputFormat,
    /// Pipeline overrides applied on top of the source pipelines.
    pub pipeline: Option<serde_json::Value>,
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

/// Identifier alphabet for `nanoid(12)` (PLAN invariant).
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

/// Current Unix timestamp in seconds (UTC) — the timestamp convention used
/// across the schema.
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
    fn scheme_wire_names_round_trip() {
        for scheme in Scheme::all() {
            let parsed: Scheme = scheme.as_str().parse().unwrap();
            assert_eq!(parsed, *scheme);
            assert_eq!(
                serde_json::to_string(scheme).unwrap(),
                format!("\"{}\"", scheme.as_str())
            );
        }
    }

    #[test]
    fn scheme_hy2_alias_parses() {
        assert_eq!("hy2".parse::<Scheme>().unwrap(), Scheme::Hysteria2);
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
            (ProxyStatus::Quarantine, "quarantine"),
            (ProxyStatus::Removed, "removed"),
        ] {
            assert_eq!(status.as_str(), name);
            assert_eq!(name.parse::<ProxyStatus>().unwrap(), status);
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
