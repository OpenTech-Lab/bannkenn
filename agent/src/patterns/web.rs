use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// Web server authentication brute-force detection patterns.
/// Covers Apache httpd (mod_auth_basic, mod_auth_digest) and nginx (ngx_http_auth_basic).
/// MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1110.001 (Brute Force),
///               T1595.002 (Active Scanning: Vulnerability Scanning)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // Apache: AH01617 — user not found in HTTP Basic auth
        // Apache logs client as [client IP:port], so port suffix is optional
        DetectionPattern {
            regex: Regex::new(
                r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01617:.*user .* not found",
            )?,
            reason: "Web Apache Basic auth user not found (AH01617)",
        },
        // Apache: AH01618 — password mismatch in HTTP Basic auth
        DetectionPattern {
            regex: Regex::new(
                r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01618:.*password mismatch",
            )?,
            reason: "Web Apache Basic auth password mismatch (AH01618)",
        },
        // Apache: AH01776 — user denied by require directives
        DetectionPattern {
            regex: Regex::new(
                r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01776:.*user .* not authorized",
            )?,
            reason: "Web Apache user not authorized (AH01776)",
        },
        // Apache: AH01627 — digest auth: nonce mismatch / stale
        DetectionPattern {
            regex: Regex::new(r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01627:")?,
            reason: "Web Apache Digest auth failure (AH01627)",
        },
        // Apache generic: user not found / user denied (older log format without AH codes)
        DetectionPattern {
            regex: Regex::new(
                r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*user .* (?:not found|denied)",
            )?,
            reason: "Web Apache HTTP auth denied",
        },
        // nginx: no user/password provided (basic auth probe)
        DetectionPattern {
            regex: Regex::new(
                r"no user/pass was provided for basic authentication.*client: (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "Web nginx Basic auth: no credentials",
        },
        // nginx: user was not found in basic auth
        DetectionPattern {
            regex: Regex::new(r#"user ".*" was not found.*client: (\d+\.\d+\.\d+\.\d+)"#)?,
            reason: "Web nginx Basic auth user not found",
        },
        // nginx: password mismatch
        DetectionPattern {
            regex: Regex::new(r#"user ".*" password mismatch.*client: (\d+\.\d+\.\d+\.\d+)"#)?,
            reason: "Web nginx Basic auth password mismatch",
        },
        // mod_security / WAF: blocked request with client IP
        DetectionPattern {
            regex: Regex::new(
                r#"ModSecurity.*\[client (\d+\.\d+\.\d+\.\d+)\].*\[severity "CRITICAL"\]"#,
            )?,
            reason: "Web ModSecurity critical rule match",
        },
    ])
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    #[test]
    fn test_apache_ah01617_user_not_found() {
        let re =
            Regex::new(r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01617:.*user .* not found")
                .unwrap();

        let line = "[Wed Jan 15 14:00:01.123456 2025] [auth_basic:error] [pid 1234] [client 198.51.100.5:43210] AH01617: user admin not found: /secret/";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "198.51.100.5"
        );
    }

    #[test]
    fn test_apache_ah01618_password_mismatch() {
        let re =
            Regex::new(r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01618:.*password mismatch")
                .unwrap();

        let line = "[Wed Jan 15 14:01:10.000000 2025] [auth_basic:error] [pid 5678] [client 203.0.113.99:55001] AH01618: user admin: password mismatch: /admin/";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "203.0.113.99"
        );
    }

    #[test]
    fn test_apache_ah01776_not_authorized() {
        let re = Regex::new(
            r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01776:.*user .* not authorized",
        )
        .unwrap();

        let line = "[Wed Jan 15 14:02:00.000000 2025] [authz_core:error] [pid 9999] [client 10.0.0.200:12345] AH01776: user bob: not authorized to access /private/";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "10.0.0.200"
        );
    }

    #[test]
    fn test_nginx_user_not_found() {
        let re = Regex::new(r#"user ".*" was not found.*client: (\d+\.\d+\.\d+\.\d+)"#).unwrap();

        let line = "2025/01/15 14:03:12 [error] 1234#0: *1 user \"admin\" was not found in \"/etc/nginx/.htpasswd\", client: 172.16.0.77, server: example.com, request: \"GET /admin/ HTTP/1.1\"";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "172.16.0.77"
        );
    }

    #[test]
    fn test_nginx_password_mismatch() {
        let re =
            Regex::new(r#"user ".*" password mismatch.*client: (\d+\.\d+\.\d+\.\d+)"#).unwrap();

        let line = "2025/01/15 14:04:00 [error] 1234#0: *2 user \"root\" password mismatch, client: 192.0.2.111, server: example.com, request: \"GET /private/ HTTP/1.1\"";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "192.0.2.111"
        );
    }
}
