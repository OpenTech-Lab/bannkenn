use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

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
}
