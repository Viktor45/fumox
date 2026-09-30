//! Clash (mihomo) YAML generation for T2 batches.
//!
//! The probe writes this config to `meow.config_path` and asks meow-rs to
//! reload it via `PUT /configs`; every proxy is then delay-tested through a
//! real tunnel. Proxy names are `fumox-{id}` so results map back to DB rows
//! unambiguously.

use fumox_core::formats::clash::entry_to_clash_named;
use fumox_core::models::{Param, ProxyEntry, Scheme};
use fumox_core::repo::proxies::ProxyRow;
use serde_norway::Value;

/// Schemes meow-rs can actually tunnel. naive has no mihomo counterpart and
/// tuic/mieru are unsupported, so they never enter a T2 batch.
pub fn is_supported(scheme: Scheme) -> bool {
    matches!(
        scheme,
        Scheme::Vless
            | Scheme::Vmess
            | Scheme::Trojan
            | Scheme::Ss
            | Scheme::Hysteria2
            | Scheme::Socks5
    )
}

/// Deterministic name of a proxy inside the generated config.
pub fn proxy_name(proxy_id: i64) -> String {
    format!("fumox-{proxy_id}")
}

/// Shorthand for integer YAML scalars.
fn num(value: i64) -> Value {
    Value::Number(value.into())
}

/// Generate the full Clash config for one T2 batch, returning the YAML plus
/// the ids of the rows actually included in it.
///
/// Rows whose entry cannot be serialized are skipped (`None` from
/// [`proxy_to_value`]) and their ids stay out of the returned list, the
/// caller must journal them explicitly, otherwise the engine later answers
/// "proxy not found" for them and the journal shows a misleading reason.
///
/// Listener ports are disabled (`0`): meow-rs only needs the proxy
/// definitions to run delay tests. Proxy definitions come from the shared
/// core mapping (the same one serving Clash subscriptions); the T2 policy
/// on top is deterministic `fumox-{id}` names.
///
/// Certificate verification is **not** forced off here. Unlike T1, which
/// only times a handshake, T2 builds a real authenticated tunnel and the
/// generated YAML carries the proxy's own credential (uuid / password /
/// `method:password`), so an unverified connection lets an on-path attacker
/// impersonate the server and harvest it. `skip-cert-verify` is therefore
/// emitted by the core mapping only for entries whose own parameters ask for
/// it.
pub fn generate(
    rows: &[ProxyRow],
    pins: &std::collections::HashMap<String, std::net::IpAddr>,
) -> serde_norway::Result<(String, Vec<i64>)> {
    let mut included = Vec::new();
    let mut proxies = Vec::new();
    for row in rows {
        if let Some(value) = proxy_to_value(row, pins) {
            included.push(row.id);
            proxies.push(value);
        }
    }

    let mut root = serde_norway::Mapping::new();
    root.insert(Value::String("port".into()), num(0));
    root.insert(Value::String("socks-port".into()), num(0));
    root.insert(Value::String("allow-lan".into()), Value::Bool(false));
    root.insert(Value::String("mode".into()), Value::String("rule".into()));
    root.insert(
        Value::String("log-level".into()),
        Value::String("silent".into()),
    );
    root.insert(Value::String("proxies".into()), Value::Sequence(proxies));
    Ok((serde_norway::to_string(&Value::Mapping(root))?, included))
}

/// Map one DB row onto a Clash proxy definition; returns `None` for
/// unsupported schemes (they are skipped, never fatal, log+skip policy).
///
/// When `pins` contains an entry for the row's host, the entry is cloned with
/// `host` replaced by the pinned IP literal before being serialized. This
/// closes the vet/dial TOCTOU the same way T1 closes it: the proxy dials the
/// vetted address, not whatever the OS resolver returns next. mihomo accepts
/// an IP literal in `server`, and an IP is no certificate server name, so
/// pinning also carries the proxy's own hostname into the scheme's
/// server-name param (see [`carry_server_name`]): the entry's `sni` /
/// `servername` when it has one, its pre-pin host when it does not, which is
/// what keeps certificate verification — never forced off here, see
/// [`generate`] — pointed at the right name while the hostname itself never
/// enters the dial.
fn proxy_to_value(
    row: &ProxyRow,
    pins: &std::collections::HashMap<String, std::net::IpAddr>,
) -> Option<Value> {
    let entry = row.to_entry().ok()?;
    if !is_supported(entry.scheme) {
        return None;
    }
    let mut entry = entry;
    if let Some(ip) = pins.get(&row.host) {
        carry_server_name(&mut entry, &row.host);
        entry.host = ip.to_string();
    }
    entry_to_clash_named(&entry, &proxy_name(row.id))
}

/// The parameter the shared mapping reads the TLS server name from, as
/// (destination key, source keys in the order they must be consulted), per
/// scheme (`formats::clash`). `None` for the schemes the mapping never
/// negotiates TLS with: ss has no TLS there, and mihomo reads no server name
/// for a socks5 proxy.
///
/// For vless/vmess both spellings are copied into the same destination key
/// and the later insert is the one that survives, so the mapping renders
/// `servername` over `sni`; that is the order listed here, which keeps a
/// pinned row on the name the unpinned row of the same entry renders.
///
/// For trojan/hysteria2 the mapping reads `sni` alone. `servername` is
/// listed second as a fallback the mapping itself would drop, since it
/// emits no name at all for such a row — reading it is deliberate, see
/// [`carry_server_name`].
fn server_name_sources(scheme: Scheme) -> Option<(&'static str, &'static [&'static str])> {
    match scheme {
        Scheme::Vless | Scheme::Vmess => Some(("servername", &["servername", "sni"])),
        Scheme::Trojan | Scheme::Hysteria2 => Some(("sni", &["sni", "servername"])),
        Scheme::Ss | Scheme::Socks5 | Scheme::Naive | Scheme::Tuic | Scheme::Mieru => None,
    }
}

/// Leave the entry with exactly one server-name param, under the key
/// `formats::clash` renders it, so a pinned row carries the same name the
/// unpinned render of that row carries: the entry's own spelling,
/// consulted in the mapping's own order and skipping values it would not
/// copy (empty ones). When the entry names no server at all, the pre-pin
/// host stands in — the case the pin exists for.
///
/// One case deliberately goes past that parity: a trojan or hysteria2 row
/// spelling `servername` and no `sni` renders no name unpinned (the mapping
/// reads `sni` alone there), and pinning turns that spelling into the `sni`
/// mihomo reads rather than letting an IP literal stand in for the
/// certificate name. See
/// `pinning_supplies_a_sni_the_mapping_would_drop`.
///
/// A host that already is an IP literal is left alone: pinning it changes
/// nothing and an IP is not a name any server certificate can be verified
/// against.
fn carry_server_name(entry: &mut ProxyEntry, pre_pin_host: &str) {
    let Some((key, sources)) = server_name_sources(entry.scheme) else {
        return;
    };
    if pre_pin_host.parse::<std::net::IpAddr>().is_ok() {
        return;
    }
    let name = sources
        .iter()
        .filter_map(|param| entry.param_ignore_case(param))
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or(pre_pin_host)
        .to_string();
    entry.params.retain(|p| {
        !p.key.eq_ignore_ascii_case("sni") && !p.key.eq_ignore_ascii_case("servername")
    });
    entry.params.push(Param {
        key: key.to_string(),
        value: name,
        known: true,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::models::{Param, ProxyEntry};

    fn row_from_entry(id: i64, entry: ProxyEntry) -> ProxyRow {
        let known = serde_json::to_string(&entry.known_params_json()).unwrap();
        ProxyRow {
            id,
            fingerprint: format!("fp{id}"),
            scheme: entry.scheme.as_str().to_string(),
            name: entry.name.clone(),
            host: entry.host.clone(),
            port: i64::from(entry.port),
            credential: entry.credential.clone(),
            params: Some(known),
            unknown_params: None,
            raw_line: None,
            last_t2_failed_at: None,
            geo_country: None,
            geo_city: None,
            geo_asn: None,
            resolved_ip: None,
            status: "alive".into(),
            fail_count: 0,
            last_checked_at: None,
            last_alive_at: None,
            quarantined_at: None,
            ladder_at: None,
            ladder_step: 0,
            removed_at: None,
            latency_ms: None,
            speed_mbps: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    /// (scheme, params, the key `formats::clash` renders the server name
    /// under for that scheme)
    type ServerNameCase = (Scheme, Vec<(&'static str, &'static str)>, &'static str);

    fn entry(scheme: Scheme, credential: &str, params: &[(&str, &str)]) -> ProxyEntry {
        ProxyEntry {
            scheme,
            name: "n".into(),
            host: "h.example.com".into(),
            port: 443,
            credential: credential.into(),
            params: params
                .iter()
                .map(|(k, v)| Param {
                    key: (*k).into(),
                    value: (*v).into(),
                    known: true,
                })
                .collect(),
            raw_path: String::new(),
            raw_line: String::new(),
        }
    }

    #[test]
    fn generates_valid_yaml_with_expected_keys() {
        let rows = vec![
            row_from_entry(
                1,
                entry(
                    Scheme::Vless,
                    "uuid-1",
                    &[
                        ("security", "reality"),
                        ("sni", "s.example.com"),
                        ("pbk", "key"),
                    ],
                ),
            ),
            row_from_entry(2, entry(Scheme::Ss, "aes-256-gcm:secret", &[])),
            row_from_entry(
                3,
                entry(
                    Scheme::Trojan,
                    "pass",
                    &[("sni", "t.example.com"), ("type", "ws"), ("path", "/ws")],
                ),
            ),
            row_from_entry(4, entry(Scheme::Hysteria2, "hy-pass", &[])),
            row_from_entry(5, entry(Scheme::Socks5, "user:pw", &[])),
            row_from_entry(
                6,
                entry(
                    Scheme::Vmess,
                    "uuid-2",
                    &[("security", "tls"), ("scy", "aes-128-gcm"), ("aid", "4")],
                ),
            ),
        ];

        let (yaml, _) = generate(&rows, &std::collections::HashMap::new()).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();
        assert_eq!(proxies.len(), 6);

        let vless = &proxies[0];
        assert_eq!(vless["name"].as_str(), Some("fumox-1"));
        assert_eq!(vless["type"].as_str(), Some("vless"));
        assert_eq!(vless["uuid"].as_str(), Some("uuid-1"));
        assert_eq!(vless["servername"].as_str(), Some("s.example.com"));
        assert_eq!(vless["reality-opts"]["public-key"].as_str(), Some("key"));
        // No `insecure` parameter on the entry: verification stays on, since
        // T2 sends the credential through the tunnel.
        assert!(vless.get("skip-cert-verify").is_none());

        let ss = &proxies[1];
        assert_eq!(ss["type"].as_str(), Some("ss"));
        assert_eq!(ss["cipher"].as_str(), Some("aes-256-gcm"));
        assert_eq!(ss["password"].as_str(), Some("secret"));

        let trojan = &proxies[2];
        assert_eq!(trojan["type"].as_str(), Some("trojan"));
        assert_eq!(trojan["password"].as_str(), Some("pass"));
        assert_eq!(trojan["network"].as_str(), Some("ws"));
        assert_eq!(trojan["ws-opts"]["path"].as_str(), Some("/ws"));

        let hy2 = &proxies[3];
        assert_eq!(hy2["type"].as_str(), Some("hysteria2"));
        assert_eq!(hy2["password"].as_str(), Some("hy-pass"));

        let socks = &proxies[4];
        assert_eq!(socks["type"].as_str(), Some("socks5"));
        assert_eq!(socks["username"].as_str(), Some("user"));
        assert_eq!(socks["password"].as_str(), Some("pw"));

        let vmess = &proxies[5];
        assert_eq!(vmess["type"].as_str(), Some("vmess"));
        assert_eq!(vmess["uuid"].as_str(), Some("uuid-2"));
        assert_eq!(vmess["alterId"].as_u64(), Some(4));
        assert_eq!(vmess["cipher"].as_str(), Some("aes-128-gcm"));
        assert_eq!(vmess["tls"].as_bool(), Some(true));

        // Listener ports are disabled in the generated config.
        assert_eq!(parsed["port"].as_u64(), Some(0));
        assert_eq!(parsed["socks-port"].as_u64(), Some(0));
    }

    #[test]
    fn unsupported_schemes_are_skipped() {
        assert!(is_supported(Scheme::Vless));
        assert!(is_supported(Scheme::Hysteria2));
        assert!(!is_supported(Scheme::Tuic));
        assert!(!is_supported(Scheme::Mieru));
        assert!(!is_supported(Scheme::Naive));

        let rows = vec![row_from_entry(9, entry(Scheme::Tuic, "c", &[]))];
        let (yaml, _) = generate(&rows, &std::collections::HashMap::new()).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        assert!(parsed["proxies"].as_sequence().unwrap().is_empty());
    }

    /// T2 tunnels carry the proxy credential, so certificate verification
    /// follows the entry's own setting instead of being forced off.
    #[test]
    fn skip_cert_verify_follows_the_entry_and_is_never_forced() {
        let rows = vec![
            row_from_entry(
                1,
                entry(Scheme::Trojan, "pass", &[("sni", "t.example.com")]),
            ),
            row_from_entry(2, entry(Scheme::Trojan, "pass", &[("insecure", "1")])),
            row_from_entry(
                3,
                entry(Scheme::Trojan, "pass", &[("skip-cert-verify", "true")]),
            ),
        ];
        let (yaml, _) = generate(&rows, &std::collections::HashMap::new()).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();

        assert!(
            proxies[0].get("skip-cert-verify").is_none(),
            "verification must stay on for an entry that did not ask to skip it"
        );
        assert_eq!(proxies[1]["skip-cert-verify"].as_bool(), Some(true));
        assert_eq!(proxies[2]["skip-cert-verify"].as_bool(), Some(true));
    }

    /// Single-row batch + pin map mapping the row's host to a vetted IP:
    /// the emitted `server` must be the pinned IP literal, and any
    /// `sni`/`servername` on the entry must remain the original hostname
    /// (mihomo's TLS handshake reads SNI from those params, not from
    /// `server`).
    #[test]
    fn generates_yaml_with_pinned_ip_overrides_server() {
        let rows = vec![row_from_entry(
            1,
            entry(
                Scheme::Vless,
                "uuid",
                &[("security", "tls"), ("sni", "real.example.com")],
            ),
        )];
        let mut pins = std::collections::HashMap::new();
        pins.insert(
            "h.example.com".to_string(),
            "203.0.113.10".parse::<std::net::IpAddr>().unwrap(),
        );

        let (yaml, included) = generate(&rows, &pins).unwrap();
        assert_eq!(included, vec![1]);
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxy = &parsed["proxies"].as_sequence().unwrap()[0];
        assert_eq!(proxy["server"].as_str(), Some("203.0.113.10"));
        assert_eq!(proxy["servername"].as_str(), Some("real.example.com"));
    }

    /// Empty pin map → `server` keeps the original hostname verbatim,
    /// matching today's behavior for any operator who hasn't enabled T2
    /// IP pinning via the vetted-address path.
    #[test]
    fn generates_yaml_with_empty_pin_keeps_original_host() {
        let rows = vec![row_from_entry(
            1,
            entry(Scheme::Trojan, "pass", &[("sni", "t.example.com")]),
        )];
        let (yaml, _) = generate(&rows, &std::collections::HashMap::new()).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxy = &parsed["proxies"].as_sequence().unwrap()[0];
        assert_eq!(proxy["server"].as_str(), Some("h.example.com"));
    }

    /// Two rows sharing a hostname with one pin map entry → both YAML
    /// entries use the pinned IP. This is the documented overwrite
    /// semantic: the probe batch is already id-deduplicated upstream, so
    /// two rows sharing a hostname is by definition the same operator
    /// intent for the same vetted IP.
    #[test]
    fn two_rows_same_host_use_the_same_pin() {
        let rows = vec![
            row_from_entry(1, entry(Scheme::Vless, "uuid-1", &[])),
            row_from_entry(2, entry(Scheme::Trojan, "pw", &[])),
        ];
        let mut pins = std::collections::HashMap::new();
        pins.insert(
            "h.example.com".to_string(),
            "203.0.113.10".parse::<std::net::IpAddr>().unwrap(),
        );

        let (yaml, _) = generate(&rows, &pins).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();
        assert_eq!(proxies[0]["server"].as_str(), Some("203.0.113.10"));
        assert_eq!(proxies[1]["server"].as_str(), Some("203.0.113.10"));
    }

    /// A pinned TLS entry with no `sni`/`servername` of its own — the shape
    /// of a plain `trojan://pass@real.example.com:443` feed line — used to
    /// be emitted as `server: <vetted ip>` and nothing else, so mihomo had
    /// no name to verify the certificate against while verification itself
    /// stayed on (T2 never forces `skip-cert-verify`). The pre-pin hostname
    /// has to travel along as the server name, per scheme key.
    #[test]
    fn pinning_keeps_a_tls_server_name_for_a_bare_entry() {
        let rows = vec![
            row_from_entry(1, entry(Scheme::Trojan, "pass", &[])),
            row_from_entry(2, entry(Scheme::Vless, "uuid", &[("security", "tls")])),
            row_from_entry(3, entry(Scheme::Vmess, "uuid", &[("security", "tls")])),
            row_from_entry(4, entry(Scheme::Hysteria2, "pw", &[])),
        ];
        let mut pins = std::collections::HashMap::new();
        pins.insert(
            "h.example.com".to_string(),
            "203.0.113.10".parse::<std::net::IpAddr>().unwrap(),
        );

        let (yaml, included) = generate(&rows, &pins).unwrap();
        assert_eq!(included, vec![1, 2, 3, 4]);
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();
        for (proxy, name) in proxies
            .iter()
            .zip(["sni", "servername", "servername", "sni"])
        {
            assert_eq!(proxy["server"].as_str(), Some("203.0.113.10"));
            assert_eq!(
                proxy[name].as_str(),
                Some("h.example.com"),
                "the pre-pin hostname must survive as the TLS server name: {yaml}"
            );
            assert!(
                proxy.get("skip-cert-verify").is_none(),
                "the server name is what makes verification work, not turning it off"
            );
        }
    }

    /// Pinning supplies a server name the entry is missing; it must never
    /// re-rank or shadow the one the entry already renders. The unpinned
    /// render is the reference: the shared mapping copies `sni` and then
    /// `servername` into the same `servername` key, the later insert wins,
    /// and an empty value is not copied at all. Both renderings of the same
    /// row have to agree on the name, or the pin silently changes which
    /// certificate gets verified.
    #[test]
    fn pinning_never_re_ranks_the_entry_server_name() {
        // (scheme, params, the key `formats::clash` renders the name under)
        let cases: Vec<ServerNameCase> = vec![
            // Both spellings: `servername` is the one the mapping keeps.
            (
                Scheme::Vless,
                vec![
                    ("security", "tls"),
                    ("sni", "sni.example.com"),
                    ("servername", "cdn.example.com"),
                ],
                "servername",
            ),
            // An empty `sni` is not copied by the mapping, so `servername`
            // is the rendered name.
            (
                Scheme::Vless,
                vec![
                    ("security", "tls"),
                    ("sni", ""),
                    ("servername", "cdn.example.com"),
                ],
                "servername",
            ),
            // Only one spelling: it is the rendered name, whatever its key.
            (
                Scheme::Vless,
                vec![("security", "tls"), ("sni", "sni.example.com")],
                "servername",
            ),
            (
                Scheme::Vmess,
                vec![("security", "tls"), ("servername", "cdn.example.com")],
                "servername",
            ),
            (Scheme::Trojan, vec![("sni", "sni.example.com")], "sni"),
        ];

        let rows: Vec<ProxyRow> = cases
            .iter()
            .enumerate()
            .map(|(i, (scheme, params, _))| {
                row_from_entry(i as i64 + 1, entry(*scheme, "c", params))
            })
            .collect();
        let mut pins = std::collections::HashMap::new();
        pins.insert(
            "h.example.com".to_string(),
            "203.0.113.10".parse::<std::net::IpAddr>().unwrap(),
        );

        let (plain, _) = generate(&rows, &std::collections::HashMap::new()).unwrap();
        let (pinned, _) = generate(&rows, &pins).unwrap();
        let plain: serde_norway::Value = serde_norway::from_str(&plain).unwrap();
        let pinned: serde_norway::Value = serde_norway::from_str(&pinned).unwrap();
        let plain = plain["proxies"].as_sequence().unwrap();
        let pinned = pinned["proxies"].as_sequence().unwrap();

        let mut mismatches = Vec::new();
        for (index, (_, _, key)) in cases.iter().enumerate() {
            let before = plain[index][key].as_str();
            assert!(before.is_some(), "row {index} must render a name unpinned");
            if pinned[index][key].as_str() != before {
                mismatches.push(format!(
                    "row {index} ({key}): unpinned {before:?}, pinned {:?}",
                    pinned[index][key].as_str()
                ));
            }
            assert_eq!(pinned[index]["server"].as_str(), Some("203.0.113.10"));
        }
        assert!(
            mismatches.is_empty(),
            "pinning must not change the server name the mapping renders:\n{}",
            mismatches.join("\n")
        );
    }

    /// The one place pinning does more than supply a missing name: a
    /// trojan or hysteria2 that spells `servername` alone renders no name
    /// at all (the mapping reads `sni` for those two schemes and nothing
    /// else), and the pin turns that spelling into the `sni` mihomo reads,
    /// so the certificate is verified against a name instead of the IP.
    /// This is the exception [`carry_server_name`] documents.
    #[test]
    fn pinning_supplies_a_sni_the_mapping_would_drop() {
        let rows = vec![
            row_from_entry(
                1,
                entry(Scheme::Trojan, "pass", &[("servername", "cdn.example.com")]),
            ),
            row_from_entry(
                2,
                entry(
                    Scheme::Hysteria2,
                    "pw",
                    &[("servername", "cdn.example.com")],
                ),
            ),
        ];
        let mut pins = std::collections::HashMap::new();
        pins.insert(
            "h.example.com".to_string(),
            "203.0.113.10".parse::<std::net::IpAddr>().unwrap(),
        );

        let (plain, _) = generate(&rows, &std::collections::HashMap::new()).unwrap();
        let (pinned, _) = generate(&rows, &pins).unwrap();
        let plain: serde_norway::Value = serde_norway::from_str(&plain).unwrap();
        let pinned: serde_norway::Value = serde_norway::from_str(&pinned).unwrap();
        let plain = plain["proxies"].as_sequence().unwrap();
        let pinned = pinned["proxies"].as_sequence().unwrap();
        for (index, proxy) in plain.iter().enumerate() {
            assert!(proxy.get("sni").is_none(), "row {index} renders no sni");
        }
        for (index, proxy) in pinned.iter().enumerate() {
            assert_eq!(
                proxy["sni"].as_str(),
                Some("cdn.example.com"),
                "row {index}"
            );
        }
    }

    /// A row whose host already is an IP literal loses nothing when
    /// pinned, and an IP is not a valid TLS server name: such an entry is
    /// serialized exactly as it was.
    #[test]
    fn pinning_an_ip_literal_host_does_not_invent_a_server_name() {
        let mut row = row_from_entry(1, entry(Scheme::Trojan, "pass", &[]));
        row.host = "203.0.113.10".into();
        let mut pins = std::collections::HashMap::new();
        pins.insert("203.0.113.10".to_string(), "203.0.113.10".parse().unwrap());

        let (yaml, _) = generate(&[row], &pins).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxy = &parsed["proxies"].as_sequence().unwrap()[0];
        assert_eq!(proxy["server"].as_str(), Some("203.0.113.10"));
        assert!(proxy.get("sni").is_none(), "{yaml}");
    }
}
