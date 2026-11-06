//! vmess parser/serializer.
//!
//! Line format: `vmess://base64(JSON)[#fragment]`. The JSON object carries
//! the whole proxy definition; the optional fragment is redundant advertising
//! (it never matches `ps` in practice) and is ignored, the display name
//! comes from `ps` per SPEC.
//!
//! Real feeds are inconsistent: `port`/`aid` appear as JSON numbers or
//! strings, `skip-cert-verify` as a boolean, base64 with or without padding,
//! both alphabets. Parsing is lenient on all of it; serialization emits the
//! dominant style (string values, unpadded standard base64, no fragment), so
//! vmess round-trip is **semantic**: `parse(serialize(parse(x))) == parse(x)`,
//! with field order and value types normalized.
//!
//! Field mapping: `add`→host, `port`→port, `id`→credential, `ps`→name; every
//! other field (including non-standard ones like `serverPort`) is preserved
//! verbatim as a parameter.

use crate::models::{Param, ProxyEntry, Scheme};
use serde_json::Value;

use super::uri::{decode_b64_lenient, split_fragment};
use super::{ParseError, ParseErrorKind};

/// Lower-cased JSON fields defined by the vmess URI convention. Anything
/// else is preserved as an unknown pass-through parameter.
const KNOWN_FIELDS: &[&str] = &[
    "v",
    "ps",
    "add",
    "port",
    "id",
    "aid",
    "scy",
    "net",
    "type",
    "host",
    "path",
    "tls",
    "sni",
    "alpn",
    "fp",
    "allowinsecure",
    "insecure",
    "skip-cert-verify",
];

/// Fields consumed into the structured ProxyEntry fields (not kept as params).
const CONSUMED_FIELDS: &[&str] = &["ps", "add", "port", "id"];

/// Parse the part of a vmess line that follows `vmess://`. The error carries
/// a machine-readable [`ParseErrorKind`] next to its message (see
/// [`super::ParseError`]).
pub fn parse(rest: &str, raw_line: &str) -> Result<ProxyEntry, ParseError> {
    let (b64, _fragment) = split_fragment(rest);
    if b64.is_empty() {
        return Err(ParseError::new(
            ParseErrorKind::MalformedPayload,
            "vmess: empty base64 payload",
        ));
    }
    let bytes = decode_b64_lenient(b64).ok_or_else(|| {
        ParseError::new(ParseErrorKind::MalformedPayload, "vmess: invalid base64")
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        ParseError::new(
            ParseErrorKind::MalformedPayload,
            format!("vmess: invalid JSON: {e}"),
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        ParseError::new(
            ParseErrorKind::MalformedPayload,
            "vmess: payload is not a JSON object",
        )
    })?;

    let host = string_field(object, "add")?;
    let port = numeric_field(object, "port")?;
    let credential = string_field(object, "id")?;
    // A number/bool `ps` becomes its literal text, like every parameter
    // value: the name is display data, never worth failing the line.
    let name = object
        .get("ps")
        .map(json_to_param_value)
        .unwrap_or_default();

    let mut params: Vec<Param> = object
        .iter()
        .filter(|(key, _)| !CONSUMED_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            Param {
                key: key.clone(),
                value: json_to_param_value(value),
                known: KNOWN_FIELDS.contains(&lower.as_str()),
                bare: false,
            }
        })
        .collect();
    // The serializer emits `v` first (see `serialize`); sorting it to the
    // front here keeps the stored parameter order the one a re-parse reads
    // back, which is what the semantic round-trip contract compares.
    params.sort_by_key(|p| p.key != "v");

    if host.is_empty() {
        return Err(invalid("vmess: empty add"));
    }
    // Field-size cap: vmess
    // params bypass `parse_query`, so the caps are enforced here.
    super::validate_params("vmess", &params).map_err(over_cap)?;
    // JSON strings may contain `\n`, and the URI serializers emit these
    // fields verbatim (see `parsers::reject_line_breaks`).
    super::reject_line_breaks("vmess: add", &host).map_err(invalid)?;
    super::reject_line_breaks("vmess: id", &credential).map_err(invalid)?;
    for param in &params {
        super::reject_line_breaks(&format!("vmess: field {:?}", param.key), &param.value)
            .map_err(invalid)?;
    }
    // The host, the credential and the name are persisted verbatim, so they
    // are capped like the parameters.
    super::check_field_size("vmess: add", &host).map_err(over_cap)?;
    super::check_field_size("vmess: id", &credential).map_err(over_cap)?;
    super::check_field_size("vmess: ps", &name).map_err(over_cap)?;

    Ok(ProxyEntry {
        scheme: Scheme::Vmess,
        name,
        host,
        port,
        credential,
        params,
        raw_path: String::new(),
        raw_line: raw_line.to_string(),
        canonical: None,
    })
}

/// A present field with an unusable value.
fn invalid(message: impl Into<String>) -> ParseError {
    ParseError::new(ParseErrorKind::InvalidField, message)
}

/// A size cap (parameter count, byte size) is exceeded.
fn over_cap(message: impl Into<String>) -> ParseError {
    ParseError::new(ParseErrorKind::OverCap, message)
}

/// Serialize to `vmess://base64(JSON)` in the dominant producer style:
/// `v` (when present), `ps`, `add`, `port`, `id` first, then the remaining
/// fields in stored order, all values as JSON strings, unpadded standard
/// base64, no fragment. Fields absent from the entry are never fabricated,
/// keeping `parse ∘ serialize` idempotent.
pub fn serialize(entry: &ProxyEntry) -> String {
    let mut object = serde_json::Map::new();
    let param = |key: &str| {
        entry
            .params
            .iter()
            .find(|p| p.key.eq_ignore_ascii_case(key))
            .map(|p| p.value.clone())
    };
    // The order is fixed here and only here: `v` first (when present), then
    // the fixed fields, then the remaining parameters in stored order. The
    // parser sorts `v` to the front of the stored list for the same reason,
    // so a re-parse reads back the same parameter order.
    if let Some(v) = param("v") {
        object.insert("v".into(), Value::String(v));
    }
    object.insert("ps".into(), Value::String(entry.name.clone()));
    object.insert("add".into(), Value::String(entry.host.clone()));
    object.insert("port".into(), Value::String(entry.port.to_string()));
    object.insert("id".into(), Value::String(entry.credential.clone()));
    for p in &entry.params {
        // The structured fields are the single source of truth: a stray
        // parameter spelled `add`/`port`/`ps`/`id` (Clash passes unknown
        // fields through, a vmess JSON can carry `PS` next to `ps`) must
        // not overwrite the host, port, name or credential on output.
        if p.key.eq_ignore_ascii_case("v")
            || CONSUMED_FIELDS
                .iter()
                .any(|field| p.key.eq_ignore_ascii_case(field))
        {
            continue;
        }
        object.insert(p.key.clone(), Value::String(p.value.clone()));
    }
    let json = serde_json::to_string(&Value::Object(object))
        .expect("vmess JSON object serialization cannot fail");
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        json.as_bytes(),
    );
    format!("vmess://{b64}")
}

fn string_field(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, ParseError> {
    match object.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(_) => Err(invalid(format!("vmess: field {key} is not a string"))),
        None => Err(ParseError::new(
            ParseErrorKind::MissingField,
            format!("vmess: missing field {key}"),
        )),
    }
}

fn numeric_field(object: &serde_json::Map<String, Value>, key: &str) -> Result<u16, ParseError> {
    match object.get(key) {
        Some(Value::Number(n)) => {
            let port = match n.as_u64() {
                Some(v) => u16::try_from(v).ok(),
                // A producer may spell the port as a float (`443.0`): it is
                // accepted when the fraction is zero and it fits u16.
                None => n
                    .as_f64()
                    .filter(|v| v.fract() == 0.0 && *v >= 0.0 && *v <= f64::from(u16::MAX))
                    .map(|v| v as u16),
            };
            // Port 0 is not a dialable endpoint (the schema CHECK, migration
            // 0018, refuses it too), so the line is as invalid as an
            // out-of-range one.
            port.filter(|&p| p != 0)
                .ok_or_else(|| invalid(format!("vmess: port out of range: {n}")))
        }
        Some(Value::String(s)) => match s.trim().parse::<u16>() {
            // The same zero rejection on the string spelling.
            Ok(0) | Err(_) => Err(invalid(format!("vmess: invalid port string: {s:?}"))),
            Ok(port) => Ok(port),
        },
        Some(_) => Err(invalid(format!("vmess: field {key} is not numeric"))),
        None => Err(ParseError::new(
            ParseErrorKind::MissingField,
            format!("vmess: missing field {key}"),
        )),
    }
}

/// Flatten an arbitrary JSON value into the string carried by [`Param`].
/// Booleans and numbers use their JSON literal form; nested structures are
/// rare in the wild and fall back to compact JSON.
fn json_to_param_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn b64(json: &str) -> String {
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(json.as_bytes())
    }

    #[test]
    fn parses_string_typed_fields() {
        let json = r#"{"v":"2","ps":"🇭🇰 HK-1","add":"hk.example.com","port":"443","id":"f23bb427","aid":"0","net":"ws","path":"/ws-vmess","tls":"tls","scy":"auto","type":"none"}"#;
        let line = format!("vmess://{}", b64(json));
        let entry = parse(&line[8..], &line).unwrap();
        assert_eq!(entry.name, "🇭🇰 HK-1");
        assert_eq!(entry.host, "hk.example.com");
        assert_eq!(entry.port, 443);
        assert_eq!(entry.credential, "f23bb427");
        assert_eq!(entry.param("net"), Some("ws"));
        assert_eq!(entry.param("aid"), Some("0"));
    }

    #[test]
    fn parses_numeric_and_bool_fields() {
        let json = r#"{"v":"2","ps":"x","add":"1.2.3.4","port":22324,"id":"u","aid":0,"skip-cert-verify":true,"tls":"tls"}"#;
        let line = format!("vmess://{}", b64(json));
        let entry = parse(&line[8..], &line).unwrap();
        assert_eq!(entry.port, 22324);
        assert_eq!(entry.param("aid"), Some("0"));
        assert_eq!(entry.param("skip-cert-verify"), Some("true"));
        // Bool field is recognized and lands in known params.
        assert!(
            entry
                .params
                .iter()
                .find(|p| p.key == "skip-cert-verify")
                .unwrap()
                .known
        );
    }

    /// Port 0 is not a dialable endpoint: the line is a parse error in
    /// either spelling, so no record with it reaches the database.
    #[test]
    fn a_zero_vmess_port_is_a_parse_error() {
        for json in [
            r#"{"v":"2","ps":"x","add":"h","port":0,"id":"u"}"#,
            r#"{"v":"2","ps":"x","add":"h","port":"0","id":"u"}"#,
        ] {
            assert!(parse(&b64(json), "").is_err(), "{json}");
        }
    }

    #[test]
    fn unknown_fields_pass_through() {
        let json =
            r#"{"v":"2","ps":"x","add":"h","port":"80","id":"u","serverPort":0,"weird":"q"}"#;
        let entry = parse(&b64(json), "").unwrap();
        let unknown = entry.unknown_params_json();
        assert_eq!(unknown.get("serverPort").unwrap(), "0");
        assert_eq!(unknown.get("weird").unwrap(), "q");
    }

    #[test]
    fn padded_and_urlsafe_base64_are_accepted() {
        let json = r#"{"v":"2","ps":"p","add":"h","port":"80","id":"u"}"#;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        assert!(b64.ends_with('='));
        let entry = parse(&b64, "").unwrap();
        assert_eq!(entry.name, "p");

        let urlsafe = b64.replace('+', "-").replace('/', "_");
        assert!(parse(&urlsafe, "").is_ok());
    }

    #[test]
    fn semantic_round_trip() {
        let json = r#"{"add":"h.example.com","aid":0,"id":"uuid-1","net":"ws","path":"/vmess/","port":"80","ps":"🇵🇭 PH | [BL]","scy":"auto","skip-cert-verify":true,"tls":"","type":"none","v":"2"}"#;
        let line = format!("vmess://{}", b64(json));
        let first = parse(&line[8..], &line).unwrap();
        let serialized = serialize(&first);
        let second = parse(serialized.strip_prefix("vmess://").unwrap(), &serialized).unwrap();

        assert_eq!(first.scheme, second.scheme);
        assert_eq!(first.name, second.name);
        assert_eq!(first.host, second.host);
        assert_eq!(first.port, second.port);
        assert_eq!(first.credential, second.credential);
        // Field order is normalized by the serializer, so compare as a set.
        let mut a = first.params.clone();
        let mut b = second.params.clone();
        a.sort_by(|x, y| x.key.cmp(&y.key));
        b.sort_by(|x, y| x.key.cmp(&y.key));
        assert_eq!(a, b);
    }

    /// A stray parameter whose name collides with a consumed field
    /// (case-insensitively) must not overwrite the structured one: a
    /// Clash item passing `add` through used to serialize a line whose
    /// host, port, name or credential differed from the stored entry.
    #[test]
    fn consumed_fields_win_over_colliding_params() {
        let entry = ProxyEntry {
            scheme: Scheme::Vmess,
            name: "real-name".into(),
            host: "real.example.com".into(),
            port: 443,
            credential: "uuid-1".into(),
            params: vec![
                Param {
                    key: "v".into(),
                    value: "2".into(),
                    known: true,
                    bare: false,
                },
                Param {
                    key: "add".into(),
                    value: "evil.example.com".into(),
                    known: false,
                    bare: false,
                },
                Param {
                    key: "PS".into(),
                    value: "evil-name".into(),
                    known: false,
                    bare: false,
                },
                Param {
                    key: "PORT".into(),
                    value: "1".into(),
                    known: false,
                    bare: false,
                },
                Param {
                    key: "id".into(),
                    value: "evil-id".into(),
                    known: false,
                    bare: false,
                },
                Param {
                    key: "net".into(),
                    value: "ws".into(),
                    known: true,
                    bare: false,
                },
            ],
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        };
        let line = serialize(&entry);
        let back = parse(line.strip_prefix("vmess://").unwrap(), &line).unwrap();
        assert_eq!(back.name, "real-name");
        assert_eq!(back.host, "real.example.com");
        assert_eq!(back.port, 443);
        assert_eq!(back.credential, "uuid-1");
        assert_eq!(back.param("net"), Some("ws"));
        for gone in ["add", "ps", "port", "id"] {
            assert!(
                back.param_ignore_case(gone).is_none(),
                "{gone} leaked through"
            );
        }
    }

    /// The emitted JSON keeps the documented key order (`v` when present,
    /// then `ps`, `add`, `port`, `id`, then the stored parameters): it rides
    /// on serde_json's `preserve_order` feature (workspace Cargo.toml), so a
    /// regression to a hash-ordered map would scramble every vmess line.
    #[test]
    fn serialize_emits_the_documented_key_order() {
        let entry = ProxyEntry {
            scheme: Scheme::Vmess,
            name: "n".into(),
            host: "h.example.com".into(),
            port: 443,
            credential: "uuid-1".into(),
            params: vec![
                Param {
                    key: "v".into(),
                    value: "2".into(),
                    known: true,
                    bare: false,
                },
                Param {
                    key: "net".into(),
                    value: "ws".into(),
                    known: true,
                    bare: false,
                },
                Param {
                    key: "path".into(),
                    value: "/ws".into(),
                    known: true,
                    bare: false,
                },
            ],
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        };
        let line = serialize(&entry);
        let bytes = decode_b64_lenient(line.strip_prefix("vmess://").unwrap()).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["v", "ps", "add", "port", "id", "net", "path"]);
    }

    #[test]
    fn rejects_invalid_payloads() {
        assert!(parse("", "").is_err());
        assert!(parse("!!!", "").is_err());
        let not_json = b64("not json");
        assert!(parse(&not_json, "").is_err());
        let missing_add = b64(r#"{"ps":"x","port":"80","id":"u"}"#);
        assert!(parse(&missing_add, "").is_err());
        let port_over_range = b64(r#"{"ps":"x","add":"h","port":65536,"id":"u"}"#);
        assert!(parse(&port_over_range, "").is_err());
        let port_not_numeric = b64(r#"{"ps":"x","add":"h","port":"abc","id":"u"}"#);
        assert!(parse(&port_not_numeric, "").is_err());
        let missing_id = b64(r#"{"ps":"x","add":"h","port":"80"}"#);
        assert!(parse(&missing_id, "").is_err());
    }

    /// The parameter caps apply to vmess JSON fields too: they bypass
    /// `parse_query`, so a payload over the parameter count cap or carrying
    /// an oversized field is rejected.
    #[test]
    fn oversized_or_too_many_fields_are_rejected() {
        let fields: String = (0..crate::parsers::uri::MAX_QUERY_PARAMS + 1)
            .map(|i| format!(r#""f{i}":"v{i}","#))
            .collect();
        let json = format!(r#"{{"ps":"x","add":"h","port":"80","id":"u",{fields}}}"#);
        assert!(parse(&b64(&json), "").is_err());

        let long = "v".repeat(crate::parsers::uri::MAX_PARAM_BYTES + 1);
        let json = format!(r#"{{"ps":"x","add":"h","port":"80","id":"u","note":"{long}"}}"#);
        assert!(parse(&b64(&json), "").is_err());
    }
}
