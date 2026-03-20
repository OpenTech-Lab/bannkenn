use super::*;
use std::fs as stdfs;

fn linux_makedev(major: u32, minor: u32) -> u64 {
    ((minor as u64) & 0x00ff)
        | (((major as u64) & 0x0fff) << 8)
        | (((minor as u64) & !0x00ff) << 12)
        | (((major as u64) & !0x0fff) << 32)
}

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
    let config = ContainmentConfig {
        throttle_io_read_bps: 2048,
        throttle_io_write_bps: 1024,
        ..ContainmentConfig::default()
    };

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
