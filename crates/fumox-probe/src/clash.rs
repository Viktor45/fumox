//! Clash (mihomo) YAML generation for T2 batches.
//!
//! The probe writes this config to `meow.config_path` and asks meow-rs to
//! reload it via `PUT /configs`; every proxy is then delay-tested through a
//! real tunnel. Proxy names are `fumox-{id}` so results map back to DB rows
//! unambiguously.

use fumox_core::formats::clash::entry_to_clash_named;
use fumox_core::models::{Param, ProxyEntry, Scheme, is_insecure_param};
use serde_norway::Value;

/// Deterministic name of a proxy inside the generated config.
pub fn proxy_name(proxy_id: i64) -> String {
    format!("fumox-{proxy_id}")
}

/// One record of a T2 batch, the input of [`generate`]: the entry as the
/// calling layer already parsed it from storage, the id the results map
/// back to, and the vetted address the proxy dials when IP pinning is on
/// (`None` keeps the entry's own host). The storage-row → entry conversion
/// belongs to the calling layer, so this module only formats.
pub struct BatchRow {
    pub id: i64,
    pub entry: ProxyEntry,
    pub vetted: Option<std::net::IpAddr>,
}

/// Shorthand for integer YAML scalars.
fn num(value: i64) -> Value {
    Value::Number(value.into())
}

/// The required credential field a scheme's entry must carry for the
/// engine config, as a short problem description; `None` when the entry is
/// complete. meow-rs (mihomo) refuses a config whose proxy carries no
/// credential, and one such record used to void the whole batch at
/// `PUT /configs`, so the caller rejects the record itself before the
/// config is generated. `socks5` may run without a credential (an
/// anonymous proxy is valid); only a one-sided `user:pass` is malformed.
pub fn required_field_problem(entry: &ProxyEntry) -> Option<&'static str> {
    let credential = entry.credential.trim();
    match entry.scheme {
        Scheme::Vless | Scheme::Vmess if credential.is_empty() => Some("missing uuid"),
        Scheme::Trojan | Scheme::Hysteria2 | Scheme::Snell | Scheme::AnyTls
            if credential.is_empty() =>
        {
            Some("missing password")
        }
        Scheme::Ss => match credential.split_once(':') {
            Some((cipher, password)) if !cipher.is_empty() && !password.is_empty() => None,
            _ => Some("missing cipher or password"),
        },
        Scheme::Socks5 => match credential.split_once(':') {
            Some(("", _)) | Some((_, "")) => Some("missing username or password"),
            _ => None,
        },
        _ => None,
    }
}

/// Generate the full Clash config for one T2 batch, returning the YAML plus
/// the ids of the records actually included in it.
///
/// The insecure parameters travel in from an untrusted feed and are not
/// carried into the T2 config: T2 carries the proxy's own credential
/// through the tunnel, so the generator drops them before the mapping runs
/// (see [`proxy_to_value`]) instead of tunnel-testing with verification
/// off behind the operator's back.
pub fn generate(rows: &[BatchRow], ipv6: bool) -> serde_norway::Result<(String, Vec<i64>)> {
    let mut included = Vec::new();
    let mut proxies = Vec::new();
    for row in rows {
        if let Some(value) = proxy_to_value(row) {
            included.push(row.id);
            proxies.push(value);
        }
    }

    let mut root = serde_norway::Mapping::new();
    root.insert(Value::String("port".into()), num(0));
    root.insert(Value::String("socks-port".into()), num(0));
    root.insert(Value::String("allow-lan".into()), Value::Bool(false));
    root.insert(Value::String("mode".into()), Value::String("rule".into()));
    // warning, not silent: a fully quiet kernel hides what a T2 batch died
    // of (config rejects, listen failures) in the container log; the
    // per-request chatter below warning stays off.
    root.insert(
        Value::String("log-level".into()),
        Value::String("warning".into()),
    );
    // Emitted explicitly, never left to the engine default: meow-rs 0.22.0
    // made `ipv6` effective end-to-end, so an omitted key is a real
    // behavioural choice (IPv4-only) that `[meow].ipv6` should own.
    root.insert(Value::String("ipv6".into()), Value::Bool(ipv6));
    root.insert(Value::String("proxies".into()), Value::Sequence(proxies));
    Ok((serde_norway::to_string(&Value::Mapping(root))?, included))
}

/// Map one batch record onto a Clash proxy definition; returns `None` for
/// entries the core mapping cannot express (they are skipped, never
/// fatal, log+skip policy).
///
/// The core mapping is the single source of truth for what meow-rs can
/// tunnel: a scheme it does not know has no mihomo counterpart, and the
/// mapping says so by returning `None`. The probe keeps no second list.
///
/// When the record carries a vetted address, the entry is cloned with
/// `host` replaced by that address before being serialized. This closes
/// the vet/dial TOCTOU the same way T1 closes it: the proxy dials the
/// vetted address, not whatever the OS resolver returns next. mihomo accepts
/// an IP literal in `server`, and an IP is no certificate server name, so
/// pinning also carries the proxy's own hostname into the scheme's
/// server-name param (see [`carry_server_name`]): the entry's `sni` /
/// `servername` when it has one, its pre-pin host when it does not, which is
/// what keeps certificate verification (its insecure toggle is dropped
/// here, see [`generate`]) pointed at the right name while the hostname
/// itself never enters the dial.
fn proxy_to_value(row: &BatchRow) -> Option<Value> {
    let mut entry = row.entry.clone();
    if let Some(ip) = row.vetted {
        let pre_pin_host = entry.host.clone();
        carry_server_name(&mut entry, &pre_pin_host);
        entry.host = ip.to_string();
    }
    // The insecure parameters (`is_insecure`'s aliases) come from the feed,
    // not from the operator: dropping them keeps the shared mapping from
    // rendering `skip-cert-verify` into the T2 config, so the tunnel check
    // never verifies nothing just because the entry asked to.
    entry.params.retain(|p| !is_insecure_param(p));
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
/// emits no name at all for such a row, reading it is deliberate, see
/// [`carry_server_name`].
fn server_name_sources(scheme: Scheme) -> Option<(&'static str, &'static [&'static str])> {
    match scheme {
        Scheme::Vless | Scheme::Vmess => Some(("servername", &["servername", "sni"])),
        // AnyTLS is TLS to its server and meow reads `sni` alone, so it
        // pins exactly like trojan.
        Scheme::Trojan | Scheme::Hysteria2 | Scheme::AnyTls => {
            Some(("sni", &["sni", "servername"]))
        }
        // Snell carries no top-level server name: its obfs name lives in
        // `obfs-opts.host`, which the Clash mapping emits untouched, and
        // with no obfs there is nothing to pin at all.
        Scheme::Ss
        | Scheme::Socks5
        | Scheme::Naive
        | Scheme::Tuic
        | Scheme::Mieru
        | Scheme::Snell => None,
    }
}

/// The entry keeps exactly one server-name param, under the key
/// `formats::clash` renders it: its own spelling, else the pre-pin host.
/// A trojan/hysteria2 spelling only `servername` becomes `sni`, which the
/// mapping would drop.
///
/// The name is only carried for entries that actually negotiate TLS: a
/// carried `servername` is an SNI to the shared predicate, so pinning a
/// plain-TCP vless/vmess would flip it to a TLS node (`tls: true`) and
/// the T2 check would tunnel-test a plaintext proxy as TLS. The decision
/// is [`fumox_core::params::wants_tls`], the same one `t1::check_kind`
/// consults; trojan/hysteria2/anytls negotiate TLS unconditionally, and
/// the schemes [`server_name_sources`] maps to `None` get no param.
fn carry_server_name(entry: &mut ProxyEntry, pre_pin_host: &str) {
    let Some((key, sources)) = server_name_sources(entry.scheme) else {
        return;
    };
    if pre_pin_host.parse::<std::net::IpAddr>().is_ok() {
        return;
    }
    if matches!(entry.scheme, Scheme::Vless | Scheme::Vmess)
        && !fumox_core::params::wants_tls(entry, &fumox_core::params::Blocks::of(entry))
    {
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
        bare: false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use fumox_core::models::{Param, ProxyEntry, Scheme};

    /// An unpinned batch record: the entry dials its own host.
    fn record(id: i64, entry: ProxyEntry) -> BatchRow {
        BatchRow {
            id,
            entry,
            vetted: None,
        }
    }

    /// A pinned batch record: the entry dials the vetted address instead of
    /// its host, the way the calling layer pins a row whose host it has
    /// resolved once per cycle.
    fn pinned(id: i64, entry: ProxyEntry) -> BatchRow {
        BatchRow {
            id,
            entry,
            vetted: Some("203.0.113.10".parse().unwrap()),
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
                    bare: false,
                })
                .collect(),
            raw_path: String::new(),
            raw_line: String::new(),
            canonical: None,
        }
    }

    #[test]
    fn generates_valid_yaml_with_expected_keys() {
        let rows = vec![
            record(
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
            record(2, entry(Scheme::Ss, "aes-256-gcm:secret", &[])),
            record(
                3,
                entry(
                    Scheme::Trojan,
                    "pass",
                    &[("sni", "t.example.com"), ("type", "ws"), ("path", "/ws")],
                ),
            ),
            record(4, entry(Scheme::Hysteria2, "hy-pass", &[])),
            record(5, entry(Scheme::Socks5, "user:pw", &[])),
            record(
                6,
                entry(
                    Scheme::Vmess,
                    "uuid-2",
                    &[("security", "tls"), ("scy", "aes-128-gcm"), ("aid", "4")],
                ),
            ),
        ];

        let (yaml, _) = generate(&rows, false).unwrap();
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
        // The probe keeps no list of its own: the core mapping decides,
        // and a scheme it cannot express yields no proxy definition.
        assert!(fumox_core::formats::clash::is_supported(Scheme::Vless));
        assert!(fumox_core::formats::clash::is_supported(Scheme::Hysteria2));
        assert!(!fumox_core::formats::clash::is_supported(Scheme::Tuic));
        assert!(!fumox_core::formats::clash::is_supported(Scheme::Mieru));
        assert!(!fumox_core::formats::clash::is_supported(Scheme::Naive));

        let rows = vec![record(9, entry(Scheme::Tuic, "c", &[]))];
        let (yaml, included) = generate(&rows, false).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        assert!(parsed["proxies"].as_sequence().unwrap().is_empty());
        assert!(
            included.is_empty(),
            "a skipped row must not be reported as included"
        );
    }

    /// The engine refuses a config whose proxy carries no credential, so
    /// the validator must name the missing field per scheme — and let an
    /// anonymous socks5 (a valid spelling) and a complete ss entry pass.
    #[test]
    fn required_field_problem_names_the_missing_credential() {
        assert_eq!(
            required_field_problem(&entry(Scheme::Vless, "", &[])),
            Some("missing uuid")
        );
        assert_eq!(
            required_field_problem(&entry(Scheme::Vmess, "  ", &[])),
            Some("missing uuid")
        );
        assert_eq!(
            required_field_problem(&entry(Scheme::Trojan, "", &[])),
            Some("missing password")
        );
        assert_eq!(
            required_field_problem(&entry(Scheme::Hysteria2, "", &[])),
            Some("missing password")
        );
        // ss carries `cipher:password`; either half missing is malformed.
        assert_eq!(
            required_field_problem(&entry(Scheme::Ss, "aes-256-gcm:pw", &[])),
            None
        );
        assert_eq!(
            required_field_problem(&entry(Scheme::Ss, ":pw", &[])),
            Some("missing cipher or password")
        );
        assert_eq!(
            required_field_problem(&entry(Scheme::Ss, "noseparator", &[])),
            Some("missing cipher or password")
        );
        // An anonymous socks5 is a valid node; a one-sided pair is not.
        assert_eq!(
            required_field_problem(&entry(Scheme::Socks5, "", &[])),
            None
        );
        assert_eq!(
            required_field_problem(&entry(Scheme::Socks5, "user:", &[])),
            Some("missing username or password")
        );
    }

    /// AnyTLS and Snell have mapping arms, so both reach the engine config
    /// and `included`; a pinned AnyTLS entry renders the `sni` meow's
    /// anytls parser reads beside the pinned IP: the name the certificate
    /// is verified against travels along while the dial goes to the
    /// vetted address.
    #[test]
    fn anytls_and_snell_are_included_and_a_pinned_anytls_keeps_its_server_name() {
        assert!(fumox_core::formats::clash::is_supported(Scheme::AnyTls));
        assert!(fumox_core::formats::clash::is_supported(Scheme::Snell));

        let rows = vec![
            pinned(1, entry(Scheme::AnyTls, "pw", &[])),
            record(2, entry(Scheme::Snell, "psk", &[])),
        ];
        let (yaml, included) = generate(&rows, false).unwrap();
        assert_eq!(included, vec![1, 2]);
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();
        assert_eq!(proxies.len(), 2);

        let anytls = &proxies[0];
        assert_eq!(anytls["type"].as_str(), Some("anytls"));
        assert_eq!(
            anytls["server"].as_str(),
            Some("203.0.113.10"),
            "the record dials the vetted address"
        );
        assert_eq!(
            anytls["sni"].as_str(),
            Some("h.example.com"),
            "the pre-pin host must survive as the server name: {yaml}"
        );

        assert_eq!(proxies[1]["type"].as_str(), Some("snell"));
        assert_eq!(proxies[1]["psk"].as_str(), Some("psk"));
    }

    /// The insecure parameters (`insecure`, `allowInsecure`,
    /// `allow_insecure`, `skip-cert-verify`) ride in from an untrusted
    /// feed: T2 must not tunnel-test with verification off just because
    /// the entry asked to, so the generator drops them and the config
    /// carries no `skip-cert-verify` key at all.
    #[test]
    fn skip_cert_verify_is_not_carried_from_the_entry_params() {
        let rows = vec![
            record(
                1,
                entry(Scheme::Trojan, "pass", &[("sni", "t.example.com")]),
            ),
            record(2, entry(Scheme::Trojan, "pass", &[("insecure", "1")])),
            record(
                3,
                entry(Scheme::Trojan, "pass", &[("skip-cert-verify", "true")]),
            ),
            record(
                4,
                entry(Scheme::Trojan, "pass", &[("allowInsecure", "true")]),
            ),
            record(5, entry(Scheme::Trojan, "pass", &[("allow_insecure", "1")])),
        ];
        let (yaml, _) = generate(&rows, false).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();

        assert!(
            proxies[0].get("skip-cert-verify").is_none(),
            "verification must stay on for an entry that did not ask to skip it"
        );
        for (index, proxy) in proxies.iter().enumerate() {
            assert!(
                proxy.get("skip-cert-verify").is_none(),
                "row {index} must not carry the feed's insecure toggle: {yaml}"
            );
        }
    }

    /// Single-row batch + pin map mapping the row's host to a vetted IP:
    /// the emitted `server` must be the pinned IP literal, and any
    /// `sni`/`servername` on the entry must remain the original hostname
    /// (mihomo's TLS handshake reads SNI from those params, not from
    /// `server`).
    #[test]
    fn generates_yaml_with_pinned_ip_overrides_server() {
        let rows = vec![pinned(
            1,
            entry(
                Scheme::Vless,
                "uuid",
                &[("security", "tls"), ("sni", "real.example.com")],
            ),
        )];

        let (yaml, included) = generate(&rows, false).unwrap();
        assert_eq!(included, vec![1]);
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxy = &parsed["proxies"].as_sequence().unwrap()[0];
        assert_eq!(proxy["server"].as_str(), Some("203.0.113.10"));
        assert_eq!(proxy["servername"].as_str(), Some("real.example.com"));
    }

    /// No vetted address → `server` keeps the original hostname verbatim,
    /// matching today's behavior for any operator who hasn't enabled T2
    /// IP pinning via the vetted-address path.
    #[test]
    fn generates_yaml_with_empty_pin_keeps_original_host() {
        let rows = vec![record(
            1,
            entry(Scheme::Trojan, "pass", &[("sni", "t.example.com")]),
        )];
        let (yaml, _) = generate(&rows, false).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxy = &parsed["proxies"].as_sequence().unwrap()[0];
        assert_eq!(proxy["server"].as_str(), Some("h.example.com"));
    }

    /// Two rows sharing a hostname → both YAML entries use the same vetted
    /// address: the calling layer resolves one address per host per cycle,
    /// and the probe batch is already id-deduplicated upstream, so two
    /// rows sharing a hostname is by definition the same operator intent
    /// for the same vetted IP.
    #[test]
    fn two_rows_same_host_use_the_same_pin() {
        let rows = vec![
            pinned(1, entry(Scheme::Vless, "uuid-1", &[])),
            pinned(2, entry(Scheme::Trojan, "pw", &[])),
        ];

        let (yaml, _) = generate(&rows, false).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();
        assert_eq!(proxies[0]["server"].as_str(), Some("203.0.113.10"));
        assert_eq!(proxies[1]["server"].as_str(), Some("203.0.113.10"));
    }

    /// A pinned TLS entry with no `sni`/`servername` of its own, the shape
    /// of a plain `trojan://pass@real.example.com:443` feed line, used to
    /// be emitted as `server: <vetted ip>` and nothing else, so mihomo had
    /// no name to verify the certificate against while verification itself
    /// stayed on (T2 never forces `skip-cert-verify`). The pre-pin hostname
    /// has to travel along as the server name, per scheme key.
    #[test]
    fn pinning_keeps_a_tls_server_name_for_a_bare_entry() {
        let rows = vec![
            pinned(1, entry(Scheme::Trojan, "pass", &[])),
            pinned(2, entry(Scheme::Vless, "uuid", &[("security", "tls")])),
            pinned(3, entry(Scheme::Vmess, "uuid", &[("security", "tls")])),
            pinned(4, entry(Scheme::Hysteria2, "pw", &[])),
        ];

        let (yaml, included) = generate(&rows, false).unwrap();
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

        let plain: Vec<BatchRow> = cases
            .iter()
            .enumerate()
            .map(|(i, (scheme, params, _))| record(i as i64 + 1, entry(*scheme, "c", params)))
            .collect();
        let pinned_rows: Vec<BatchRow> = cases
            .iter()
            .enumerate()
            .map(|(i, (scheme, params, _))| pinned(i as i64 + 1, entry(*scheme, "c", params)))
            .collect();

        let (plain, _) = generate(&plain, false).unwrap();
        let (pinned, _) = generate(&pinned_rows, false).unwrap();
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
        let plain = vec![
            record(
                1,
                entry(Scheme::Trojan, "pass", &[("servername", "cdn.example.com")]),
            ),
            record(
                2,
                entry(
                    Scheme::Hysteria2,
                    "pw",
                    &[("servername", "cdn.example.com")],
                ),
            ),
        ];
        let pinned_rows = vec![
            pinned(
                1,
                entry(Scheme::Trojan, "pass", &[("servername", "cdn.example.com")]),
            ),
            pinned(
                2,
                entry(
                    Scheme::Hysteria2,
                    "pw",
                    &[("servername", "cdn.example.com")],
                ),
            ),
        ];

        let (plain, _) = generate(&plain, false).unwrap();
        let (pinned, _) = generate(&pinned_rows, false).unwrap();
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
        let mut ip_entry = entry(Scheme::Trojan, "pass", &[]);
        ip_entry.host = "203.0.113.10".into();
        let rows = vec![pinned(1, ip_entry)];

        let (yaml, _) = generate(&rows, false).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxy = &parsed["proxies"].as_sequence().unwrap()[0];
        assert_eq!(proxy["server"].as_str(), Some("203.0.113.10"));
        assert!(proxy.get("sni").is_none(), "{yaml}");
    }

    /// A pinned entry that does not negotiate TLS must not grow a server
    /// name: a carried `servername` is an SNI to the shared predicate, so
    /// the pin would flip a plain-TCP vless/vmess to a TLS node and the
    /// T2 check would tunnel-test a plaintext proxy as TLS. The decision
    /// is `params::wants_tls`, the same one `t1::check_kind` asks; an
    /// entry that really negotiates TLS keeps its `servername`.
    #[test]
    fn pinning_a_plain_tcp_entry_does_not_invent_a_server_name() {
        let rows = vec![
            pinned(1, entry(Scheme::Vless, "uuid", &[("security", "none")])),
            pinned(2, entry(Scheme::Vless, "uuid", &[])),
            pinned(3, entry(Scheme::Vmess, "uuid", &[("tls", "false")])),
            pinned(
                4,
                entry(
                    Scheme::Vless,
                    "uuid",
                    &[("security", "tls"), ("sni", "s.example.com")],
                ),
            ),
        ];

        let (yaml, _) = generate(&rows, false).unwrap();
        let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();
        for (index, proxy) in proxies.iter().enumerate().take(3) {
            assert_eq!(
                proxy["server"].as_str(),
                Some("203.0.113.10"),
                "row {index} is pinned"
            );
            assert_eq!(
                proxy.get("tls"),
                None,
                "row {index} must stay plain TCP: {yaml}"
            );
            assert!(
                proxy.get("servername").is_none() && proxy.get("sni").is_none(),
                "row {index} must not grow a server name: {yaml}"
            );
        }
        assert_eq!(proxies[3]["tls"].as_bool(), Some(true));
        assert_eq!(
            proxies[3]["servername"].as_str(),
            Some("s.example.com"),
            "a TLS entry keeps its server name: {yaml}"
        );
    }

    /// `ipv6` rides into the rendered config: meow-rs 0.22.0 made the key
    /// effective end-to-end, so an omitted one would silently mean
    /// "IPv4 only" no matter what `[meow].ipv6` says.
    #[test]
    fn ipv6_flag_is_rendered_explicitly() {
        let rows = vec![record(7, entry(Scheme::Vless, "uuid-7", &[]))];

        let (off, _) = generate(&rows, false).unwrap();
        let (on, _) = generate(&rows, true).unwrap();
        let off: serde_norway::Value = serde_norway::from_str(&off).unwrap();
        let on: serde_norway::Value = serde_norway::from_str(&on).unwrap();

        assert_eq!(off["ipv6"].as_bool(), Some(false));
        assert_eq!(on["ipv6"].as_bool(), Some(true));
    }
}
