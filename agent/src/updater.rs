use crate::service::{install_systemd_unit, resolve_service_binary_path, SERVICE_UNIT_PATH};
use anyhow::{anyhow, Context, Result};
use reqwest::{header::LOCATION, redirect::Policy, Client};
use std::env;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::time::{sleep, Duration};

const GITHUB_RELEASES_BASE: &str = "https://github.com/OpenTech-Lab/bannkenn/releases";
const SERVICE_NAME: &str = "bannkenn-agent";
const SERVICE_RESTART_SETTLE_ATTEMPTS: usize = 10;
const SERVICE_RESTART_SETTLE_DELAY_MS: u64 = 500;
const SERVICE_RESTART_REQUIRED_ACTIVE_SAMPLES: usize = 3;
const LINUX_EBPF_OBJECT_NAME: &str = "bannkenn-containment.bpf.o";
const LINUX_EBPF_INSTALL_DIR_ENV: &str = "BANNKENN_EBPF_INSTALL_DIR";
const DEFAULT_LINUX_EBPF_OBJECT_PATH: &str = "/usr/lib/bannkenn/ebpf/bannkenn-containment.bpf.o";
const FALLBACK_LINUX_EBPF_OBJECT_PATH: &str =
    "/usr/local/lib/bannkenn/ebpf/bannkenn-containment.bpf.o";
const LINUX_EBPF_OBJECT_CANDIDATES: &[&str] = &[
    DEFAULT_LINUX_EBPF_OBJECT_PATH,
    FALLBACK_LINUX_EBPF_OBJECT_PATH,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReleaseAssets {
    binary: &'static str,
    bpf: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinuxEbpfAssetStatus {
    NotSupported,
    AlreadyPresent(PathBuf),
    Installed(PathBuf),
}

pub async fn update(version: Option<&str>) -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    let assets = release_asset_names()?;
    let target_version = resolve_target_version(version, assets.binary).await?;
    let client = Client::new();
    if same_release_version(current_version, &target_version) {
        let bpf_status =
            ensure_linux_ebpf_asset_for_version_with_client(&client, &target_version, false)
                .await?;
        let restarted = if should_restart_service_after_ebpf_repair(&bpf_status) {
            restart_service_if_active().await?
        } else {
            false
        };
        println!("bannkenn-agent is already up to date ({})", current_version);
        if let LinuxEbpfAssetStatus::Installed(path) = &bpf_status {
            println!("Installed containment BPF object: {}", path.display());
        }
        if restarted {
            println!("Restarted systemd service: bannkenn-agent");
        } else if should_restart_service_after_ebpf_repair(&bpf_status) {
            println!("Systemd service not active; skipped restart");
        }
        return Ok(());
    }

    let download_url = release_download_url(Some(&target_version), assets.binary)?;
    let current_exe = env::current_exe().context("Could not determine current executable path")?;
    let target_path = resolve_service_binary_path(&current_exe).to_path_buf();
    tracing::info!(
        "Updating bannkenn-agent {} using {}",
        current_version,
        download_url
    );

    let bytes = download_release_asset(&client, &download_url).await?;

    install_binary(&target_path, &bytes).await?;
    let bpf_status =
        ensure_linux_ebpf_asset_for_version_with_client(&client, &target_version, true).await?;
    let refreshed_service_unit = refresh_service_unit_after_update(&target_path)?;
    let restarted = restart_service_if_active().await?;

    println!(
        "Updated bannkenn-agent {} -> {} at {}",
        current_version,
        target_version,
        target_path.display()
    );
    if let LinuxEbpfAssetStatus::Installed(path) = &bpf_status {
        println!("Installed containment BPF object: {}", path.display());
    }
    if refreshed_service_unit {
        println!("Refreshed systemd unit: {}", SERVICE_UNIT_PATH);
    }
    if restarted {
        println!("Restarted systemd service: bannkenn-agent");
    } else {
        println!("Systemd service not active; skipped restart");
    }

    Ok(())
}

async fn resolve_target_version(version: Option<&str>, asset_name: &str) -> Result<String> {
    if let Some(version) = version {
        return Ok(strip_version_prefix(&normalize_version(version)?).to_string());
    }

    probe_latest_release_version(asset_name)
        .await?
        .ok_or_else(|| anyhow!("Failed to determine the latest release version"))
}

fn release_asset_names() -> Result<ReleaseAssets> {
    release_asset_names_for(env::consts::OS, env::consts::ARCH)
}

pub(crate) async fn ensure_linux_ebpf_asset_for_current_release() -> Result<LinuxEbpfAssetStatus> {
    if env::consts::OS != "linux" {
        return Ok(LinuxEbpfAssetStatus::NotSupported);
    }

    let version = strip_version_prefix(env!("CARGO_PKG_VERSION")).to_string();
    let client = Client::new();
    ensure_linux_ebpf_asset_for_version_with_client(&client, &version, false).await
}

fn release_asset_names_for(os: &str, arch: &str) -> Result<ReleaseAssets> {
    match (os, arch) {
        ("linux", "x86_64") => Ok(ReleaseAssets {
            binary: "bannkenn-agent-linux-x64",
            bpf: Some("bannkenn-containment-linux-x64.bpf.o"),
        }),
        ("linux", "aarch64") => Ok(ReleaseAssets {
            binary: "bannkenn-agent-linux-arm64",
            bpf: Some("bannkenn-containment-linux-arm64.bpf.o"),
        }),
        ("windows", "x86_64") => Ok(ReleaseAssets {
            binary: "bannkenn-agent-windows-x64.exe",
            bpf: None,
        }),
        (os, arch) => Err(anyhow!("Unsupported platform for self-update: {os}/{arch}")),
    }
}

fn release_download_url(version: Option<&str>, asset_name: &str) -> Result<String> {
    if let Some(version) = version {
        let version = normalize_version(version)?;
        Ok(format!(
            "{}/download/{}/{}",
            GITHUB_RELEASES_BASE, version, asset_name
        ))
    } else {
        Ok(format!(
            "{}/latest/download/{}",
            GITHUB_RELEASES_BASE, asset_name
        ))
    }
}

fn normalize_version(version: &str) -> Result<String> {
    let version = version.trim();
    let version = version.strip_prefix('v').unwrap_or(version);
    if version.is_empty() {
        return Err(anyhow!("Version cannot be empty"));
    }

    let is_valid = regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?$")
        .expect("version regex should compile")
        .is_match(version);
    if !is_valid {
        return Err(anyhow!("Version must look like 1.3.18 or 1.3.18-beta.1"));
    }

    Ok(format!("v{}", version))
}

fn release_version_from_url(url: &str) -> Option<String> {
    url.split("/download/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .map(|version| strip_version_prefix(version).to_string())
}

async fn install_binary(target_path: &Path, bytes: &[u8]) -> Result<()> {
    install_file(target_path, bytes, Some(0o755)).await
}

async fn install_linux_ebpf_object(target_path: &Path, bytes: &[u8]) -> Result<()> {
    install_file(target_path, bytes, Some(0o644)).await
}

async fn install_file(target_path: &Path, bytes: &[u8], mode: Option<u32>) -> Result<()> {
    if let Some(parent) = target_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    let temp_path = temp_install_path(target_path);
    tokio::fs::write(&temp_path, bytes)
        .await
        .with_context(|| format!("Failed to write {}", temp_path.display()))?;

    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("Failed to chmod {}", temp_path.display()))?;
    }

    tokio::fs::rename(&temp_path, target_path)
        .await
        .with_context(|| format!("Failed to replace {}", target_path.display()))?;

    Ok(())
}

async fn probe_latest_release_version(asset_name: &str) -> Result<Option<String>> {
    let url = release_download_url(None, asset_name)?;
    let client = Client::builder()
        .redirect(Policy::none())
        .build()
        .context("Failed to build HTTP client for release probe")?;
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("Failed to probe {}", url))?;

    if response.status().is_redirection() {
        return Ok(response
            .headers()
            .get(LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(release_version_from_url));
    }

    Ok(release_version_from_url(response.url().as_str()))
}

fn temp_install_path(target_path: &Path) -> PathBuf {
    let name = target_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bannkenn-agent");
    target_path.with_file_name(format!(".{}.update-{}", name, std::process::id()))
}

async fn download_release_asset(client: &Client, download_url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(download_url)
        .send()
        .await
        .with_context(|| format!("Failed to download {}", download_url))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "Release download failed with status {}: {}",
            status,
            body
        ));
    }

    Ok(response.bytes().await?.to_vec())
}

async fn ensure_linux_ebpf_asset_for_version_with_client(
    client: &Client,
    version: &str,
    force_install: bool,
) -> Result<LinuxEbpfAssetStatus> {
    let assets = release_asset_names()?;
    let Some(asset_name) = assets.bpf else {
        return Ok(LinuxEbpfAssetStatus::NotSupported);
    };

    let target_path = resolve_linux_ebpf_object_install_path();
    if !force_install && target_path.exists() {
        return Ok(LinuxEbpfAssetStatus::AlreadyPresent(target_path));
    }

    let download_url = release_download_url(Some(version), asset_name)?;
    let bytes = download_release_asset(client, &download_url).await?;
    install_linux_ebpf_object(&target_path, &bytes).await?;
    Ok(LinuxEbpfAssetStatus::Installed(target_path))
}

fn should_restart_service_after_ebpf_repair(status: &LinuxEbpfAssetStatus) -> bool {
    matches!(status, LinuxEbpfAssetStatus::Installed(_))
}

fn resolve_linux_ebpf_object_install_path() -> PathBuf {
    let env_override = env::var_os(LINUX_EBPF_INSTALL_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let existing_candidates = LINUX_EBPF_OBJECT_CANDIDATES
        .iter()
        .map(Path::new)
        .filter(|path| path.exists())
        .collect::<Vec<_>>();
    resolve_linux_ebpf_object_install_path_for(env_override.as_deref(), &existing_candidates)
}

fn resolve_linux_ebpf_object_install_path_for(
    env_override: Option<&Path>,
    existing_candidates: &[&Path],
) -> PathBuf {
    if let Some(dir) = env_override {
        return dir.join(LINUX_EBPF_OBJECT_NAME);
    }

    existing_candidates
        .first()
        .map(|path| (*path).to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LINUX_EBPF_OBJECT_PATH))
}

fn refresh_service_unit_after_update(target_path: &Path) -> Result<bool> {
    install_systemd_unit(target_path)
        .with_context(|| format!("Failed to refresh {}", SERVICE_UNIT_PATH))
}

async fn restart_service_if_active() -> Result<bool> {
    let active = match service_is_active().await {
        Ok(active) => active,
        Err(_) => return Ok(false),
    };

    if !active {
        return Ok(false);
    }

    let status = Command::new("systemctl")
        .args(["restart", SERVICE_NAME])
        .status()
        .await
        .with_context(|| format!("Failed to restart systemd service {}", SERVICE_NAME))?;
    if !status.success() {
        return Err(anyhow!("systemctl restart {} failed", SERVICE_NAME));
    }

    verify_service_stayed_active_after_restart().await?;
    Ok(true)
}

async fn verify_service_stayed_active_after_restart() -> Result<()> {
    let mut consecutive_active = 0usize;

    for _ in 0..SERVICE_RESTART_SETTLE_ATTEMPTS {
        if service_is_active().await.unwrap_or(false) {
            consecutive_active += 1;
            if consecutive_active >= SERVICE_RESTART_REQUIRED_ACTIVE_SAMPLES {
                return Ok(());
            }
        } else {
            consecutive_active = 0;
        }
        sleep(Duration::from_millis(SERVICE_RESTART_SETTLE_DELAY_MS)).await;
    }

    let status = service_status_snapshot().await.unwrap_or_else(|err| {
        format!(
            "unable to collect `systemctl status {}`: {}",
            SERVICE_NAME, err
        )
    });

    Err(anyhow!(
        "{} restarted but did not stay active.\n{}",
        SERVICE_NAME,
        status.trim()
    ))
}

async fn service_is_active() -> Result<bool> {
    let status = Command::new("systemctl")
        .args(["is-active", "--quiet", SERVICE_NAME])
        .status()
        .await
        .with_context(|| format!("Failed to run systemctl is-active {}", SERVICE_NAME))?;
    Ok(status.success())
}

async fn service_status_snapshot() -> Result<String> {
    let output = Command::new("systemctl")
        .args(["status", "--no-pager", "--full", SERVICE_NAME])
        .output()
        .await
        .with_context(|| format!("Failed to run systemctl status {}", SERVICE_NAME))?;

    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if text.is_empty() {
        text = stderr;
    } else if !stderr.is_empty() {
        text.push('\n');
        text.push_str(&stderr);
    }
    Ok(text)
}

fn same_release_version(current: &str, release: &str) -> bool {
    strip_version_prefix(current) == strip_version_prefix(release)
}

fn strip_version_prefix(version: &str) -> &str {
    version.trim().strip_prefix('v').unwrap_or(version.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_version_is_normalized() {
        assert_eq!(
            release_download_url(Some("1.3.18"), "bannkenn-agent-linux-x64").unwrap(),
            "https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.3.18/bannkenn-agent-linux-x64"
        );
        assert_eq!(
            release_download_url(Some("v1.3.18"), "bannkenn-agent-linux-x64").unwrap(),
            "https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.3.18/bannkenn-agent-linux-x64"
        );
    }

    #[test]
    fn no_version_uses_latest_release_redirect() {
        assert_eq!(
            release_download_url(None, "bannkenn-agent-linux-x64").unwrap(),
            "https://github.com/OpenTech-Lab/bannkenn/releases/latest/download/bannkenn-agent-linux-x64"
        );
    }

    #[test]
    fn invalid_version_is_rejected() {
        assert!(normalize_version("latest").is_err());
        assert!(normalize_version("1.3").is_err());
    }

    #[test]
    fn resolved_release_is_parsed_from_redirect_url() {
        assert_eq!(
            release_version_from_url(
                "https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.3.18/bannkenn-agent-linux-x64"
            ),
            Some("1.3.18".to_string())
        );
    }

    #[test]
    fn same_release_version_ignores_v_prefix() {
        assert!(same_release_version("1.3.23", "v1.3.23"));
        assert!(same_release_version("v1.3.23", "1.3.23"));
        assert!(!same_release_version("1.3.23", "1.3.24"));
    }

    #[test]
    fn linux_release_assets_include_matching_bpf_object() {
        let assets = release_asset_names_for("linux", "x86_64").unwrap();
        assert_eq!(assets.binary, "bannkenn-agent-linux-x64");
        assert_eq!(assets.bpf, Some("bannkenn-containment-linux-x64.bpf.o"));
    }

    #[test]
    fn windows_release_assets_skip_bpf_object() {
        let assets = release_asset_names_for("windows", "x86_64").unwrap();
        assert_eq!(assets.binary, "bannkenn-agent-windows-x64.exe");
        assert_eq!(assets.bpf, None);
    }

    #[test]
    fn ebpf_install_path_prefers_env_override() {
        let path =
            resolve_linux_ebpf_object_install_path_for(Some(Path::new("/opt/bannkenn/ebpf")), &[]);
        assert_eq!(
            path,
            PathBuf::from("/opt/bannkenn/ebpf").join(LINUX_EBPF_OBJECT_NAME)
        );
    }

    #[test]
    fn ebpf_install_path_prefers_existing_candidate() {
        let path = resolve_linux_ebpf_object_install_path_for(
            None,
            &[Path::new(FALLBACK_LINUX_EBPF_OBJECT_PATH)],
        );
        assert_eq!(path, PathBuf::from(FALLBACK_LINUX_EBPF_OBJECT_PATH));
    }

    #[test]
    fn ebpf_install_path_defaults_to_usr_lib() {
        let path = resolve_linux_ebpf_object_install_path_for(None, &[]);
        assert_eq!(path, PathBuf::from(DEFAULT_LINUX_EBPF_OBJECT_PATH));
    }

    #[test]
    fn repaired_ebpf_asset_requires_service_restart() {
        assert!(should_restart_service_after_ebpf_repair(
            &LinuxEbpfAssetStatus::Installed(PathBuf::from(DEFAULT_LINUX_EBPF_OBJECT_PATH))
        ));
        assert!(!should_restart_service_after_ebpf_repair(
            &LinuxEbpfAssetStatus::AlreadyPresent(PathBuf::from(DEFAULT_LINUX_EBPF_OBJECT_PATH))
        ));
        assert!(!should_restart_service_after_ebpf_repair(
            &LinuxEbpfAssetStatus::NotSupported
        ));
    }
}
