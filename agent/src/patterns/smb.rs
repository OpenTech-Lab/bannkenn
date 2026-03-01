use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// SMB / Samba brute-force and lateral movement detection patterns.
/// MITRE ATT&CK: T1021.002 (Remote Services: SMB/Windows Admin Shares),
///               T1110.001 (Brute Force: Password Guessing)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // Samba smbd: authentication failure for IP address (smb_audit or verbose logging)
        DetectionPattern {
            regex: Regex::new(r"smbd.*[Aa]uth(?:entication)? failed.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB Samba authentication failed",
        },
        // Samba: NT_STATUS_LOGON_FAILURE with remote IP
        DetectionPattern {
            regex: Regex::new(r"smbd.*NT_STATUS_LOGON_FAILURE.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB NT_STATUS_LOGON_FAILURE",
        },
        // Samba: NT_STATUS_WRONG_PASSWORD with remote IP
        DetectionPattern {
            regex: Regex::new(r"smbd.*NT_STATUS_WRONG_PASSWORD.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB NT_STATUS_WRONG_PASSWORD",
        },
        // Samba: NT_STATUS_ACCOUNT_LOCKED_OUT — lockout policy triggered
        DetectionPattern {
            regex: Regex::new(r"smbd.*NT_STATUS_ACCOUNT_LOCKED_OUT.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB account locked out",
        },
        // Samba PAM authentication failure via pam_unix with rhost
        DetectionPattern {
            regex: Regex::new(
                r"pam_unix\(samba:auth\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "SMB Samba PAM authentication failure",
        },
        // Winbind: check_password failed with remote IP
        DetectionPattern {
            regex: Regex::new(r"winbindd.*check_password.*failed.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB Winbind password check failed",
        },
    ])
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    #[test]
    fn test_smbd_auth_failed() {
        let re =
            Regex::new(r"smbd.*[Aa]uth(?:entication)? failed.*\b(\d+\.\d+\.\d+\.\d+)\b").unwrap();

        let line = "Jan 15 15:00:01 server smbd[2222]: Authentication failed for user 'administrator' from 203.0.113.10";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "203.0.113.10"
        );
    }

    #[test]
    fn test_smbd_nt_status_logon_failure() {
        let re = Regex::new(r"smbd.*NT_STATUS_LOGON_FAILURE.*\b(\d+\.\d+\.\d+\.\d+)\b").unwrap();

        let line = "Jan 15 15:01:12 server smbd[2223]: check_ntlm_password: Authentication for user [guest] -> [guest] FAILED with error NT_STATUS_LOGON_FAILURE from 198.51.100.6";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "198.51.100.6"
        );
    }

    #[test]
    fn test_smbd_nt_status_wrong_password() {
        let re = Regex::new(r"smbd.*NT_STATUS_WRONG_PASSWORD.*\b(\d+\.\d+\.\d+\.\d+)\b").unwrap();

        let line = "Jan 15 15:02:33 server smbd[2224]: NT_STATUS_WRONG_PASSWORD from 10.1.2.3";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "10.1.2.3"
        );
    }

    #[test]
    fn test_samba_pam_failure() {
        let re = Regex::new(
            r"pam_unix\(samba:auth\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();

        let line = "samba[3000]: pam_unix(samba:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=192.168.5.50 user=root";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "192.168.5.50"
        );
    }
}
