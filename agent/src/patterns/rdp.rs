use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// RDP (Remote Desktop Protocol) brute-force detection patterns.
/// Covers xrdp on Linux.
/// MITRE ATT&CK: T1021.001 (Remote Services: Remote Desktop Protocol), T1110.001 (Brute Force)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // xrdp-sesman: PAM authentication failed — includes source IP
        DetectionPattern {
            regex: Regex::new(
                r"xrdp-sesman\[\d+\]:.*(?:[Aa]uth(?:entication)? failed|[Ll]ogin [Ff]ailed).*\b(\d+\.\d+\.\d+\.\d+)\b",
            )?,
            reason: "RDP xrdp authentication failed",
        },
        // xrdp-sesman: PAM error line with IP
        DetectionPattern {
            regex: Regex::new(r"xrdp-sesman\[\d+\]:.*pam_\w+.*fail.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "RDP xrdp PAM failure",
        },
        // xrdp: connection established then closed — logs client IP in "ip" field
        DetectionPattern {
            regex: Regex::new(
                r"xrdp\[\d+\]:.*connection (?:error|lost|closed|dropped).*ip (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "RDP xrdp connection dropped",
        },
        // xrdp: incoming connection log — useful for rate-limiting aggressive scanners
        DetectionPattern {
            regex: Regex::new(r"xrdp\[\d+\]:.*\[(?:WARN|ERROR)\].*from ip (\d+\.\d+\.\d+\.\d+)")?,
            reason: "RDP xrdp warning from IP",
        },
        // FreeRDP / xrdp NLA: NTLM logon failure
        DetectionPattern {
            regex: Regex::new(r"xrdp(?:-sesman)?\[\d+\]:.*ntlm.*fail.*(\d+\.\d+\.\d+\.\d+)")?,
            reason: "RDP xrdp NTLM authentication failed",
        },
    ])
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    #[test]
    fn test_xrdp_sesman_auth_failed() {
        let re = Regex::new(
            r"xrdp-sesman\[\d+\]:.*(?:[Aa]uth(?:entication)? failed|[Ll]ogin [Ff]ailed).*\b(\d+\.\d+\.\d+\.\d+)\b",
        )
        .unwrap();

        let line = "Jan 15 13:00:01 server xrdp-sesman[3456]: authentication failed for user 'admin' from 203.0.113.7";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "203.0.113.7"
        );
    }

    #[test]
    fn test_xrdp_connection_lost() {
        let re = Regex::new(
            r"xrdp\[\d+\]:.*connection (?:error|lost|closed|dropped).*ip (\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();

        let line = "Jan 15 13:01:14 server xrdp[7890]: connection lost from ip 198.51.100.33";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "198.51.100.33"
        );
    }

    #[test]
    fn test_xrdp_login_failed() {
        let re = Regex::new(
            r"xrdp-sesman\[\d+\]:.*(?:[Aa]uth(?:entication)? failed|[Ll]ogin [Ff]ailed).*\b(\d+\.\d+\.\d+\.\d+)\b",
        )
        .unwrap();

        let line = "Jan 15 13:02:59 server xrdp-sesman[3457]: Login Failed from 10.1.2.3 for user administrator";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "10.1.2.3"
        );
    }
}
