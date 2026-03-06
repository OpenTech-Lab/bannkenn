use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// A pattern that matches a successful SSH login.
/// capture group 1 = username, capture group 2 = attacker/source IP.
pub struct SshLoginPattern {
    pub regex: Regex,
}

/// Return all patterns that detect a *successful* SSH authentication.
/// These events are informational (not blocks) and carry the authenticated
/// username so the dashboard can display who logged in and from where.
pub fn login_patterns() -> Result<Vec<SshLoginPattern>> {
    Ok(vec![
        // password auth: "Accepted password for root from 1.2.3.4 port 22 ssh2"
        SshLoginPattern {
            regex: Regex::new(
                r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            )?,
        },
        // pubkey auth: "Accepted publickey for ubuntu from 1.2.3.4 port 22 ssh2: ..."
        SshLoginPattern {
            regex: Regex::new(
                r"Accepted publickey for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            )?,
        },
        // keyboard-interactive / PAM auth
        SshLoginPattern {
            regex: Regex::new(
                r"Accepted keyboard-interactive(?:/pam)? for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            )?,
        },
        // GSSAPI auth (Kerberos)
        SshLoginPattern {
            regex: Regex::new(
                r"Accepted gssapi(?:-with-mic|-keyex)? for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            )?,
        },
    ])
}

pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // Classic SSH brute-force
        DetectionPattern {
            regex: Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")?,
            reason: "Failed SSH password",
        },
        // Unknown username probes
        DetectionPattern {
            regex: Regex::new(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)")?,
            reason: "Invalid SSH user",
        },
        // Connection dropped after too many failures (sshd preauth)
        DetectionPattern {
            regex: Regex::new(
                r"Connection closed by (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "SSH repeated connection close",
        },
        // Explicit disconnect due to too many auth failures
        DetectionPattern {
            regex: Regex::new(
                r"Disconnecting (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "SSH disconnected: too many auth failures",
        },
        // sshd hard limit on authentication rounds
        DetectionPattern {
            regex: Regex::new(
                r"maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "SSH max auth attempts exceeded",
        },
        // Port scanners that never send an SSH banner
        DetectionPattern {
            regex: Regex::new(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)")?,
            reason: "SSH port scan (no identification string)",
        },
        // Clients with incompatible algorithms — common in automated scans
        DetectionPattern {
            regex: Regex::new(r"Unable to negotiate with (\d+\.\d+\.\d+\.\d+)")?,
            reason: "SSH port scan (unable to negotiate)",
        },
    ])
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    #[test]
    fn test_failed_password_regex() {
        let re = Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Jan 15 10:23:45 server sshd[1234]: Failed password for user from 192.168.1.100 port 22 ssh2";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "192.168.1.100"
        );

        // Also matches "Failed password for invalid user"
        let line2 = "Failed password for invalid user admin from 10.0.0.1 port 22 ssh2";
        assert_eq!(
            re.captures(line2).unwrap().get(1).unwrap().as_str(),
            "10.0.0.1"
        );
    }

    #[test]
    fn test_invalid_user_regex() {
        let re = Regex::new(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Jan 15 10:25:12 server sshd[5678]: Invalid user admin from 10.0.0.50 port 22";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "10.0.0.50"
        );
    }

    #[test]
    fn test_connection_closed_regex() {
        let re = Regex::new(
            r"Connection closed by (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();

        let line1 = "Connection closed by invalid user root 203.0.113.5 port 41022 [preauth]";
        assert_eq!(
            re.captures(line1).unwrap().get(1).unwrap().as_str(),
            "203.0.113.5"
        );

        let line2 =
            "Connection closed by authenticating user admin 198.51.100.9 port 59900 [preauth]";
        assert_eq!(
            re.captures(line2).unwrap().get(1).unwrap().as_str(),
            "198.51.100.9"
        );
    }

    #[test]
    fn test_disconnecting_regex() {
        let re = Regex::new(
            r"Disconnecting (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();
        let line = "Disconnecting invalid user postgres 172.16.0.7 port 55000: Too many authentication failures [preauth]";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "172.16.0.7"
        );
    }

    #[test]
    fn test_max_auth_attempts_regex() {
        let re = Regex::new(
            r"maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();
        let line = "error: maximum authentication attempts exceeded for invalid user git from 192.0.2.1 port 12345 ssh2";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "192.0.2.1"
        );
    }

    #[test]
    fn test_no_identification_regex() {
        let re =
            Regex::new(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Did not receive identification string from 198.51.100.42 port 4444";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "198.51.100.42"
        );
    }

    #[test]
    fn test_unable_to_negotiate_regex() {
        let re = Regex::new(r"Unable to negotiate with (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Unable to negotiate with 203.0.113.77 port 60000: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "203.0.113.77"
        );
    }

    #[test]
    fn test_ssh_login_password() {
        let patterns = super::login_patterns().unwrap();
        let line = "Accepted password for root from 203.0.113.5 port 41022 ssh2";
        let matched = patterns.iter().find_map(|p| p.regex.captures(line));
        let caps = matched.expect("should match password accepted");
        assert_eq!(caps.get(1).unwrap().as_str(), "root");
        assert_eq!(caps.get(2).unwrap().as_str(), "203.0.113.5");
    }

    #[test]
    fn test_ssh_login_pubkey() {
        let patterns = super::login_patterns().unwrap();
        let line = "Accepted publickey for deploy from 10.0.0.99 port 55000 ssh2: RSA SHA256:abc";
        let matched = patterns.iter().find_map(|p| p.regex.captures(line));
        let caps = matched.expect("should match pubkey accepted");
        assert_eq!(caps.get(1).unwrap().as_str(), "deploy");
        assert_eq!(caps.get(2).unwrap().as_str(), "10.0.0.99");
    }

    #[test]
    fn test_ssh_login_keyboard_interactive() {
        let patterns = super::login_patterns().unwrap();
        let line = "Accepted keyboard-interactive/pam for ubuntu from 192.168.1.50 port 22 ssh2";
        let matched = patterns.iter().find_map(|p| p.regex.captures(line));
        let caps = matched.expect("should match keyboard-interactive accepted");
        assert_eq!(caps.get(1).unwrap().as_str(), "ubuntu");
        assert_eq!(caps.get(2).unwrap().as_str(), "192.168.1.50");
    }

    #[test]
    fn test_ssh_login_does_not_match_failed() {
        let patterns = super::login_patterns().unwrap();
        let line = "Failed password for root from 203.0.113.5 port 41022 ssh2";
        let matched = patterns.iter().any(|p| p.regex.is_match(line));
        assert!(!matched, "login patterns must NOT match failed attempts");
    }
}
