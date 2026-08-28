//! vmess parser/serializer.
//!
//! Line format: `vmess://base64(JSON)[#fragment]`. The JSON object carries
//! the whole proxy definition; the optional fragment is redundant advertising
//! (it never matches `ps` in practice) and is ignored — the display name
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

use super::ss::decode_b64_lenient;
use super::uri::{encode_fragment, split_fragment};

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

pub fn parse(rest: &str, raw_line: &str) -> Result<ProxyEntry, String> {
    let (b64, _fragment) = split_fragment(rest);
    if b64.is_empty() {
        return Err("vmess: empty base64 payload".to_string());
    }
    let bytes = decode_b64_lenient(b64).ok_or("vmess: invalid base64")?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("vmess: invalid JSON: {e}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "vmess: payload is not a JSON object".to_string())?;

    let host = string_field(object, "add")?;
    let port = numeric_field(object, "port")?;
    let credential = string_field(object, "id")?;
    let name = object
        .get("ps")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let mut params: Vec<Param> = object
        .iter()
        .filter(|(key, _)| !CONSUMED_FIELDS.contains(&key.as_str()))
        .map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            Param {
                key: key.clone(),
                value: json_to_param_value(value),
                known: KNOWN_FIELDS.contains(&lower.as_str()),
            }
        })
        .collect();
    // Keep a stable, documented order: `v` first if present (already true
    // for most producers), the rest in original JSON order.
    params.sort_by_key(|p| p.key != "v");

    if host.is_empty() {
        return Err("vmess: empty add".to_string());
    }

    Ok(ProxyEntry {
        scheme: Scheme::Vmess,
        name,
        host,
        port,
        credential,
        params,
        raw_path: String::new(),
        raw_line: raw_line.to_string(),
    })
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
    if let Some(v) = param("v") {
        object.insert("v".into(), Value::String(v));
    }
    object.insert("ps".into(), Value::String(entry.name.clone()));
    object.insert("add".into(), Value::String(entry.host.clone()));
    object.insert("port".into(), Value::String(entry.port.to_string()));
    object.insert("id".into(), Value::String(entry.credential.clone()));
    for p in &entry.params {
        if p.key.eq_ignore_ascii_case("v") {
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

/// Re-encode the display name as a fragment; used only by tools that want
/// the redundant `#name` form. The canonical serializer drops it.
#[allow(dead_code)]
pub fn serialize_with_fragment(entry: &ProxyEntry) -> String {
    if entry.name.is_empty() {
        serialize(entry)
    } else {
        format!("{}#{}", serialize(entry), encode_fragment(&entry.name))
    }
}

fn string_field(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, String> {
    match object.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(_) => Err(format!("vmess: field {key} is not a string")),
        None => Err(format!("vmess: missing field {key}")),
    }
}

fn numeric_field(object: &serde_json::Map<String, Value>, key: &str) -> Result<u16, String> {
    match object.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| format!("vmess: port out of range: {n}")),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u16>()
            .map_err(|_| format!("vmess: invalid port string: {s:?}")),
        Some(_) => Err(format!("vmess: field {key} is not numeric")),
        None => Err(format!("vmess: missing field {key}")),
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

    #[test]
    fn rejects_invalid_payloads() {
        assert!(parse("", "").is_err());
        assert!(parse("!!!", "").is_err());
        let not_json = b64("not json");
        assert!(parse(&not_json, "").is_err());
        let missing_add = b64(r#"{"ps":"x","port":"80","id":"u"}"#);
        assert!(parse(&missing_add, "").is_err());
    }
}
