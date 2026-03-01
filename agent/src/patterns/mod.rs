use anyhow::Result;
use regex::Regex;

pub mod database;
pub mod ftp;
pub mod mail;
pub mod pam;
pub mod rdp;
pub mod smb;
pub mod ssh;
pub mod web;

/// A single detection rule. The regex MUST capture the attacker's IPv4
/// address in capture group 1.
pub struct DetectionPattern {
    pub regex: Regex,
    pub reason: &'static str,
}

/// Return all active detection patterns from every protocol module.
/// To add a new protocol: create `agent/src/patterns/<proto>.rs`,
/// implement a `patterns() -> Result<Vec<DetectionPattern>>` function,
/// declare it here with `pub mod <proto>;`, and add an `extend` call.
pub fn all_patterns() -> Result<Vec<DetectionPattern>> {
    let mut patterns = Vec::new();
    patterns.extend(ssh::patterns()?);
    patterns.extend(pam::patterns()?);
    patterns.extend(ftp::patterns()?);
    patterns.extend(mail::patterns()?);
    patterns.extend(rdp::patterns()?);
    patterns.extend(web::patterns()?);
    patterns.extend(smb::patterns()?);
    patterns.extend(database::patterns()?);
    Ok(patterns)
}
