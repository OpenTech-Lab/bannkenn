use anyhow::{Context, Result};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;

pub const SERVICE_NAME: &str = "bannkenn-agent";
pub const SERVICE_UNIT_PATH: &str = "/etc/systemd/system/bannkenn-agent.service";
pub const DEFAULT_SYSTEM_BINARY_PATH: &str = "/usr/local/bin/bannkenn-agent";
pub const SERVICE_HOME: &str = "/root";

pub fn install_systemd_unit(binary_path: &Path) -> Result<bool> {
    if !supports_systemd() {
        return Ok(false);
    }

    let unit_path = Path::new(SERVICE_UNIT_PATH);
    let contents = render_systemd_unit(binary_path);

    if fs::read_to_string(unit_path).ok().as_deref() != Some(contents.as_str()) {
        fs::write(unit_path, contents)
            .with_context(|| format!("Failed to write {}", SERVICE_UNIT_PATH))?;
    }

    run_systemctl(&["daemon-reload"])?;
    Ok(true)
}

pub fn uninstall_systemd_unit() -> Result<bool> {
    if !supports_systemd() {
        return Ok(false);
    }

    run_systemctl_allow_failure(&["stop", SERVICE_NAME])?;
    run_systemctl_allow_failure(&["disable", SERVICE_NAME])?;

    let removed = match fs::remove_file(SERVICE_UNIT_PATH) {
        Ok(_) => true,
        Err(err) if err.kind() == ErrorKind::NotFound => false,
        Err(err) => {
            return Err(err).with_context(|| format!("Failed to remove {}", SERVICE_UNIT_PATH))
        }
    };

    run_systemctl(&["daemon-reload"])?;
    run_systemctl_allow_failure(&["reset-failed", SERVICE_NAME])?;

    Ok(removed)
}

pub fn render_systemd_unit(binary_path: &Path) -> String {
    let exec_start = resolve_service_binary_path(binary_path)
        .display()
        .to_string();
    format!(
        "[Unit]\nDescription=BannKenn IPS Agent\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nWorkingDirectory={service_home}\nEnvironment=HOME={service_home}\nEnvironment=XDG_CONFIG_HOME={service_home}/.config\nExecStart={exec_start} run\nExecStopPost=-{exec_start} cleanup-firewall\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n",
        service_home = SERVICE_HOME
    )
}

fn resolve_service_binary_path(binary_path: &Path) -> &Path {
    let installed_path = Path::new(DEFAULT_SYSTEM_BINARY_PATH);
    if installed_path.exists() {
        installed_path
    } else {
        binary_path
    }
}

fn supports_systemd() -> bool {
    cfg!(target_os = "linux")
        && Path::new("/run/systemd/system").exists()
        && command_exists("systemctl")
}

fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_systemctl(args: &[&str]) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run systemctl {}", args.join(" ")))?;

    if output.status.success() {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "systemctl {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn run_systemctl_allow_failure(args: &[&str]) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run systemctl {}", args.join(" ")))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("not loaded")
        || lower.contains("not-found")
        || lower.contains("not found")
        || lower.contains("no such file")
    {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "systemctl {} failed: {}",
        args.join(" "),
        stderr.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_systemd_unit_uses_binary_path_for_start_and_stop() {
        let unit = render_systemd_unit(Path::new(DEFAULT_SYSTEM_BINARY_PATH));

        assert!(unit.contains("After=network-online.target"));
        assert!(unit.contains("Environment=HOME=/root"));
        assert!(unit.contains("Environment=XDG_CONFIG_HOME=/root/.config"));
        assert!(unit.contains("ExecStart=/usr/local/bin/bannkenn-agent run"));
        assert!(unit.contains("ExecStopPost=-/usr/local/bin/bannkenn-agent cleanup-firewall"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn render_systemd_unit_falls_back_to_supplied_binary_when_default_is_missing() {
        let non_installed = Path::new("/tmp/bannkenn-agent");
        let unit = render_systemd_unit(non_installed);

        if Path::new(DEFAULT_SYSTEM_BINARY_PATH).exists() {
            assert!(unit.contains("ExecStart=/usr/local/bin/bannkenn-agent run"));
        } else {
            assert!(unit.contains("ExecStart=/tmp/bannkenn-agent run"));
        }
    }
}
