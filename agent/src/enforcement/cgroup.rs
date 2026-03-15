use crate::config::ContainmentConfig;
use crate::enforcement::{EnforcementAction, EnforcementFuture, EnforcementOutcome, Enforcer};
use anyhow::{anyhow, Context, Result};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tokio::fs;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const BANNKENN_CGROUP_NAMESPACE: &str = "bannkenn";

#[derive(Debug, Clone)]
pub struct CgroupEnforcer {
    root: PathBuf,
    read_bps: u64,
    write_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IoThrottlePlan {
    cgroup_dir: PathBuf,
    device_key: String,
    io_limit_entry: String,
    pid: u32,
}

impl CgroupEnforcer {
    pub fn new(config: &ContainmentConfig) -> Self {
        Self {
            root: PathBuf::from(CGROUP_ROOT),
            read_bps: config.throttle_io_read_bps,
            write_bps: config.throttle_io_write_bps,
        }
    }

    fn build_plan(&self, pid: u32, watched_root: &str) -> Result<IoThrottlePlan> {
        if self.read_bps == 0 || self.write_bps == 0 {
            return Err(anyhow!(
                "throttle_io_read_bps and throttle_io_write_bps must both be > 0"
            ));
        }

        let watched_root = Path::new(watched_root);
        let (major, minor) = device_major_minor(watched_root)?;
        let device_key = format!("{}:{}", major, minor);

        Ok(IoThrottlePlan {
            cgroup_dir: self
                .root
                .join(BANNKENN_CGROUP_NAMESPACE)
                .join(format!("pid-{}", pid)),
            io_limit_entry: format!(
                "{} rbps={} wbps={}",
                device_key, self.read_bps, self.write_bps
            ),
            device_key,
            pid,
        })
    }

    async fn apply_plan(&self, plan: &IoThrottlePlan) -> Result<()> {
        ensure_controller_available(&self.root, "io").await?;
        ensure_controller_enabled(&self.root, "io").await?;

        let namespace_dir = self.root.join(BANNKENN_CGROUP_NAMESPACE);
        fs::create_dir_all(&namespace_dir)
            .await
            .with_context(|| format!("failed to create {}", namespace_dir.display()))?;
        ensure_controller_enabled(&namespace_dir, "io").await?;

        fs::create_dir_all(&plan.cgroup_dir)
            .await
            .with_context(|| format!("failed to create {}", plan.cgroup_dir.display()))?;

        let io_max_path = plan.cgroup_dir.join("io.max");
        let existing = read_to_string_if_exists(&io_max_path).await?;
        let merged = upsert_io_limit(&existing, &plan.device_key, &plan.io_limit_entry);

        fs::write(&io_max_path, format!("{}\n", merged))
            .await
            .with_context(|| format!("failed to write {}", io_max_path.display()))?;

        let cgroup_procs_path = plan.cgroup_dir.join("cgroup.procs");
        fs::write(&cgroup_procs_path, format!("{}\n", plan.pid))
            .await
            .with_context(|| format!("failed to write {}", cgroup_procs_path.display()))?;

        Ok(())
    }
}

impl Default for CgroupEnforcer {
    fn default() -> Self {
        Self::new(&ContainmentConfig::default())
    }
}

impl Enforcer for CgroupEnforcer {
    fn name(&self) -> &'static str {
        "cgroup"
    }

    fn supports(&self, action: &EnforcementAction) -> bool {
        matches!(action, EnforcementAction::ApplyIoThrottle { .. })
    }

    fn execute<'a>(
        &'a self,
        action: &'a EnforcementAction,
        dry_run: bool,
    ) -> EnforcementFuture<'a> {
        Box::pin(async move {
            let (pid, watched_root) = match action {
                EnforcementAction::ApplyIoThrottle {
                    pid: Some(pid),
                    watched_root,
                } => (*pid, watched_root.as_str()),
                EnforcementAction::ApplyIoThrottle { pid: None, .. } => {
                    return Ok(EnforcementOutcome {
                        action: action.clone(),
                        enforcer: self.name().to_string(),
                        applied: false,
                        dry_run,
                        detail: "I/O throttle requires a process PID".to_string(),
                    });
                }
                _ => {
                    return Ok(EnforcementOutcome {
                        action: action.clone(),
                        enforcer: self.name().to_string(),
                        applied: false,
                        dry_run,
                        detail: "unsupported cgroup action".to_string(),
                    });
                }
            };

            let plan = match self.build_plan(pid, watched_root) {
                Ok(plan) => plan,
                Err(error) => {
                    return Ok(EnforcementOutcome {
                        action: action.clone(),
                        enforcer: self.name().to_string(),
                        applied: false,
                        dry_run,
                        detail: format!("failed to build cgroup I/O throttle plan: {}", error),
                    });
                }
            };

            if dry_run {
                return Ok(EnforcementOutcome {
                    action: action.clone(),
                    enforcer: self.name().to_string(),
                    applied: false,
                    dry_run: true,
                    detail: format!(
                        "dry-run I/O throttle via cgroups v2 in {} with {}",
                        plan.cgroup_dir.display(),
                        plan.io_limit_entry
                    ),
                });
            }

            match self.apply_plan(&plan).await {
                Ok(()) => Ok(EnforcementOutcome {
                    action: action.clone(),
                    enforcer: self.name().to_string(),
                    applied: true,
                    dry_run: false,
                    detail: format!(
                        "applied cgroup I/O throttle in {} with {}",
                        plan.cgroup_dir.display(),
                        plan.io_limit_entry
                    ),
                }),
                Err(error) => Ok(EnforcementOutcome {
                    action: action.clone(),
                    enforcer: self.name().to_string(),
                    applied: false,
                    dry_run: false,
                    detail: format!("cgroup I/O throttle failed: {}", error),
                }),
            }
        })
    }
}

async fn ensure_controller_available(root: &Path, controller: &str) -> Result<()> {
    let controllers_path = root.join("cgroup.controllers");
    let controllers = fs::read_to_string(&controllers_path)
        .await
        .with_context(|| format!("failed to read {}", controllers_path.display()))?;
    if controllers
        .split_whitespace()
        .any(|value| value == controller)
    {
        Ok(())
    } else {
        Err(anyhow!(
            "cgroup controller '{}' not available in {}",
            controller,
            controllers_path.display()
        ))
    }
}

async fn ensure_controller_enabled(root: &Path, controller: &str) -> Result<()> {
    let subtree_control_path = root.join("cgroup.subtree_control");
    let subtree_control = read_to_string_if_exists(&subtree_control_path).await?;
    if subtree_control
        .split_whitespace()
        .any(|value| value == controller)
    {
        return Ok(());
    }

    fs::write(&subtree_control_path, format!("+{}\n", controller))
        .await
        .with_context(|| {
            format!(
                "failed to enable {} in {}",
                controller,
                subtree_control_path.display()
            )
        })
}

async fn read_to_string_if_exists(path: &Path) -> Result<String> {
    match fs::read_to_string(path).await {
        Ok(content) => Ok(content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn upsert_io_limit(existing: &str, device_key: &str, io_limit_entry: &str) -> String {
    let mut lines: Vec<String> = existing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();

    if let Some(index) = lines
        .iter()
        .position(|line| line == device_key || line.starts_with(&format!("{} ", device_key)))
    {
        lines[index] = io_limit_entry.to_string();
    } else {
        lines.push(io_limit_entry.to_string());
    }

    lines.join("\n")
}

#[cfg(unix)]
fn device_major_minor(path: &Path) -> Result<(u32, u32)> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat watched_root {}", path.display()))?;
    let dev = metadata.dev();
    Ok((linux_major(dev), linux_minor(dev)))
}

#[cfg(not(unix))]
fn device_major_minor(path: &Path) -> Result<(u32, u32)> {
    Err(anyhow!(
        "cgroup I/O throttle is not supported on this platform ({})",
        path.display()
    ))
}

fn linux_major(dev: u64) -> u32 {
    (((dev >> 8) & 0x0fff) | ((dev >> 32) & 0xffff_f000)) as u32
}

fn linux_minor(dev: u64) -> u32 {
    ((dev & 0x00ff) | ((dev >> 12) & 0xffff_ff00)) as u32
}

#[cfg(test)]
fn linux_makedev(major: u32, minor: u32) -> u64 {
    ((minor as u64) & 0x00ff)
        | (((major as u64) & 0x0fff) << 8)
        | (((minor as u64) & !0x00ff) << 12)
        | (((major as u64) & !0x0fff) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;

    #[test]
    fn upsert_io_limit_replaces_matching_device_and_preserves_others() {
        let existing = "8:0 rbps=2097152 wbps=1048576\n9:0 rbps=max wbps=max";
        let merged = upsert_io_limit(existing, "8:0", "8:0 rbps=1024 wbps=2048");

        assert_eq!(merged, "8:0 rbps=1024 wbps=2048\n9:0 rbps=max wbps=max");
    }

    #[test]
    fn linux_major_minor_round_trip() {
        let dev = linux_makedev(259, 7);
        assert_eq!(linux_major(dev), 259);
        assert_eq!(linux_minor(dev), 7);
    }

    #[test]
    fn build_plan_uses_pid_namespace_and_device_limits() {
        let mut config = ContainmentConfig::default();
        config.throttle_io_read_bps = 2048;
        config.throttle_io_write_bps = 1024;

        let test_root =
            std::env::temp_dir().join(format!("bannkenn-cgroup-plan-{}", uuid::Uuid::new_v4()));
        let watched_root = test_root.join("watched");
        stdfs::create_dir_all(&watched_root).unwrap();

        let enforcer = CgroupEnforcer {
            root: test_root.clone(),
            read_bps: config.throttle_io_read_bps,
            write_bps: config.throttle_io_write_bps,
        };

        let plan = enforcer
            .build_plan(42, watched_root.to_str().unwrap())
            .unwrap();

        assert_eq!(
            plan.cgroup_dir,
            test_root.join(BANNKENN_CGROUP_NAMESPACE).join("pid-42")
        );
        assert!(plan.io_limit_entry.ends_with("rbps=2048 wbps=1024"));
        assert!(plan.device_key.contains(':'));

        let _ = stdfs::remove_dir_all(test_root);
    }
}
