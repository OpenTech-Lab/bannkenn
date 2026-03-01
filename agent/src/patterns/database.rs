use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// Database authentication brute-force detection patterns.
/// Covers MySQL/MariaDB and PostgreSQL.
/// MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing), T1078 (Valid Accounts)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // MySQL/MariaDB: access denied for user from host
        // Log format: Access denied for user 'user'@'1.2.3.4' (using password: YES)
        DetectionPattern {
            regex: Regex::new(r"Access denied for user '.*'@'(\d+\.\d+\.\d+\.\d+)'")?,
            reason: "Database MySQL access denied",
        },
        // MySQL/MariaDB: host blocked due to too many connection errors
        DetectionPattern {
            regex: Regex::new(
                r"Host '(\d+\.\d+\.\d+\.\d+)' is blocked because of many connection errors",
            )?,
            reason: "Database MySQL host blocked (too many errors)",
        },
        // MySQL/MariaDB: host not allowed to connect
        DetectionPattern {
            regex: Regex::new(r"Host '(\d+\.\d+\.\d+\.\d+)' is not allowed to connect")?,
            reason: "Database MySQL host not allowed",
        },
        // PostgreSQL: no pg_hba.conf entry for host (connection rejected at auth layer)
        DetectionPattern {
            regex: Regex::new(r#"no pg_hba\.conf entry for host "(\d+\.\d+\.\d+\.\d+)""#)?,
            reason: "Database PostgreSQL no pg_hba entry for host",
        },
        // PostgreSQL: pg_hba rejects the connection (host= in log prefix)
        DetectionPattern {
            regex: Regex::new(
                r"FATAL:.*pg_hba\.conf rejects connection.*host=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "Database PostgreSQL pg_hba connection rejected",
        },
        // PostgreSQL: password authentication failed (with host in log_line_prefix)
        // Standard postgresql.conf log_line_prefix includes %h for remote host
        DetectionPattern {
            regex: Regex::new(
                r"FATAL:.*password authentication failed for user.*host=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "Database PostgreSQL password authentication failed",
        },
        // MongoDB: authentication failed with remote IP in message
        DetectionPattern {
            regex: Regex::new(
                r"SASL SCRAM.*authentication failed.*client:.*\b(\d+\.\d+\.\d+\.\d+)\b",
            )?,
            reason: "Database MongoDB SCRAM authentication failed",
        },
        // Redis: protected by requirepass — wrong password from remote IP
        DetectionPattern {
            regex: Regex::new(r"NOAUTH.*from (\d+\.\d+\.\d+\.\d+)")?,
            reason: "Database Redis NOAUTH error",
        },
    ])
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    #[test]
    fn test_mysql_access_denied() {
        let re = Regex::new(r"Access denied for user '.*'@'(\d+\.\d+\.\d+\.\d+)'").unwrap();

        let line = "2025-01-15T16:00:01.000000Z 10 [Note] Access denied for user 'root'@'203.0.113.11' (using password: YES)";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "203.0.113.11"
        );
    }

    #[test]
    fn test_mysql_host_blocked() {
        let re =
            Regex::new(r"Host '(\d+\.\d+\.\d+\.\d+)' is blocked because of many connection errors")
                .unwrap();

        let line = "2025-01-15T16:01:22.000000Z 0 [Warning] Host '198.51.100.77' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "198.51.100.77"
        );
    }

    #[test]
    fn test_mysql_host_not_allowed() {
        let re = Regex::new(r"Host '(\d+\.\d+\.\d+\.\d+)' is not allowed to connect").unwrap();

        let line = "Host '10.99.0.5' is not allowed to connect to this MySQL server";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "10.99.0.5"
        );
    }

    #[test]
    fn test_postgres_no_pghba() {
        let re = Regex::new(r#"no pg_hba\.conf entry for host "(\d+\.\d+\.\d+\.\d+)""#).unwrap();

        let line = "2025-01-15 16:02:00 UTC [5678] FATAL:  no pg_hba.conf entry for host \"192.0.2.200\", user \"postgres\", database \"prod\", SSL off";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "192.0.2.200"
        );
    }

    #[test]
    fn test_postgres_password_failed_with_host() {
        let re = Regex::new(
            r"FATAL:.*password authentication failed for user.*host=(\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();

        let line = "2025-01-15 16:03:11 UTC [9999] FATAL:  password authentication failed for user \"admin\" host=172.31.0.50";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "172.31.0.50"
        );
    }
}
