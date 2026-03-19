use super::*;
use crate::config::{MaintenanceWindow, TrustPolicyRule, TrustPolicyVisibility};
use crate::ebpf::events::{MaintenanceActivity, ProcessAncestor, ProcessTrustClass};
use std::os::unix::fs::symlink;

fn tracked_process(pid: u32, process_name: &str, exe_path: &str) -> TrackedProcess {
    TrackedProcess {
        pid,
        parent_pid: None,
        uid: None,
        gid: None,
        service_unit: None,
        first_seen_at: chrono::Utc::now(),
        trust_class: ProcessTrustClass::Unknown,
        trust_policy_name: None,
        maintenance_activity: None,
        trust_policy_visibility: TrustPolicyVisibility::Visible,
        package_name: None,
        package_manager: None,
        process_name: process_name.to_string(),
        exe_path: exe_path.to_string(),
        command_line: exe_path.to_string(),
        parent_process_name: None,
        parent_command_line: None,
        parent_chain: Vec::new(),
        container_runtime: None,
        container_id: None,
        open_paths: HashSet::from(["/srv/data/file.txt".to_string()]),
        protected: false,
    }
}

#[test]
fn lifecycle_diff_detects_exec_exit_and_reexec() {
    let previous = HashMap::from([
        (
            10,
            ProcessIdentity {
                process_name: "bash".to_string(),
                exe_path: "/usr/bin/bash".to_string(),
            },
        ),
        (
            20,
            ProcessIdentity {
                process_name: "python3".to_string(),
                exe_path: "/usr/bin/python3".to_string(),
            },
        ),
    ]);
    let current = HashMap::from([
        (20, tracked_process(20, "python3", "/usr/bin/python3.12")),
        (30, tracked_process(30, "ransom", "/tmp/ransom")),
    ]);

    let events = diff_lifecycle_events(&previous, &current);
    assert!(events.contains(&LifecycleEvent::Exec {
        pid: 20,
        process_name: "python3".to_string(),
        exe_path: "/usr/bin/python3.12".to_string(),
    }));
    assert!(events.contains(&LifecycleEvent::Exec {
        pid: 30,
        process_name: "ransom".to_string(),
        exe_path: "/tmp/ransom".to_string(),
    }));
    assert!(events.contains(&LifecycleEvent::Exit {
        pid: 10,
        process_name: "bash".to_string(),
    }));
}

#[test]
fn allowlist_matching_is_case_insensitive() {
    assert!(matches_allowlist(
        "/usr/local/bin/BannKenn-Agent",
        &["bannkenn-agent".to_string()]
    ));
    assert!(!matches_allowlist(
        "/usr/bin/python3",
        &["systemd".to_string()]
    ));
}

#[test]
fn container_context_detects_runtime_and_id_from_cgroup_lines() {
    let metadata = read_cgroup_metadata_from_str(
        "0::/system.slice/docker-0123456789abcdef0123456789abcdef.scope\n",
    );
    assert_eq!(metadata.container_runtime.as_deref(), Some("docker"));
    assert_eq!(
        metadata.container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn container_context_detects_kubernetes_containerd_paths() {
    let metadata = read_cgroup_metadata_from_str(
        "0::/kubepods/besteffort/pod1234/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    );
    assert_eq!(metadata.container_runtime.as_deref(), Some("kubernetes"));
    assert_eq!(
        metadata.container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn container_context_detects_crio_runtime_from_scope_prefix() {
    let metadata = read_cgroup_metadata_from_str(
        "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/crio-0123456789abcdef0123456789abcdef.scope\n",
    );
    assert_eq!(metadata.container_runtime.as_deref(), Some("crio"));
    assert_eq!(
        metadata.container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn cgroup_metadata_extracts_service_unit() {
    let metadata = read_cgroup_metadata_from_str("0::/system.slice/fwupd.service\n");
    assert_eq!(metadata.service_unit.as_deref(), Some("fwupd.service"));
}

#[test]
fn process_profiles_keep_first_seen_across_refreshes() {
    let config = ContainmentConfig {
        watch_paths: vec!["/srv/data".to_string()],
        ..ContainmentConfig::default()
    };
    let mut tracker = ProcessLifecycleTracker::new(&config);
    let mut first = tracked_process(10, "fwupd", "/usr/libexec/fwupd/fwupd");
    first.service_unit = Some("fwupd.service".to_string());
    let first_seen = chrono::Utc::now();

    let mut initial = HashMap::from([(10, first)]);
    tracker.apply_profile_metadata(&mut initial, first_seen);

    let initial_seen_at = initial.get(&10).expect("tracked process").first_seen_at;

    let mut second = tracked_process(11, "fwupd", "/usr/libexec/fwupd/fwupd");
    second.service_unit = Some("fwupd.service".to_string());
    let mut next = HashMap::from([(11, second)]);
    tracker.apply_profile_metadata(&mut next, first_seen + chrono::Duration::minutes(5));

    assert_eq!(
        next.get(&11).expect("tracked process").first_seen_at,
        initial_seen_at
    );
}

#[test]
fn trust_policy_override_applies_matching_rule() {
    let config = ContainmentConfig {
        watch_paths: vec!["/srv/data".to_string()],
        trust_policies: vec![TrustPolicyRule {
            name: "backup-window".to_string(),
            exe_paths: vec!["/usr/bin/python3".to_string()],
            package_names: vec!["python3-minimal".to_string()],
            service_units: vec!["backup.service".to_string()],
            trust_class: ProcessTrustClass::TrustedPackageManaged,
            visibility: TrustPolicyVisibility::Hidden,
            maintenance_windows: vec![MaintenanceWindow {
                weekdays: Vec::new(),
                start: "00:00".to_string(),
                end: "00:00".to_string(),
            }],
        }],
        ..ContainmentConfig::default()
    };
    let mut tracker = ProcessLifecycleTracker::new(&config);
    let now = chrono::Utc::now();
    let mut process = tracked_process(42, "python3", "/usr/bin/python3");
    process.service_unit = Some("backup.service".to_string());

    let mut processes = HashMap::from([(42, process)]);
    tracker.apply_profile_metadata(&mut processes, now);

    let process = processes.get(&42).expect("tracked process");
    assert_eq!(
        process.trust_class,
        ProcessTrustClass::TrustedPackageManaged
    );
    assert_eq!(process.trust_policy_name.as_deref(), Some("backup-window"));
    assert_eq!(
        process.trust_policy_visibility,
        TrustPolicyVisibility::Hidden
    );
}

#[test]
fn maintenance_activity_is_classified_for_trusted_service_work() {
    let config = ContainmentConfig {
        watch_paths: vec!["/srv/data".to_string()],
        ..ContainmentConfig::default()
    };
    let mut tracker = ProcessLifecycleTracker::new(&config);
    let now = chrono::Utc::now();
    let mut process = tracked_process(55, "fwupd", "/usr/libexec/fwupd/fwupd");
    process.parent_process_name = Some("systemd".to_string());
    process.parent_command_line = Some("systemd".to_string());
    process.service_unit = Some("fwupd.service".to_string());

    let mut processes = HashMap::from([(55, process)]);
    tracker.apply_profile_metadata(&mut processes, now);

    assert_eq!(
        processes
            .get(&55)
            .and_then(|process| process.maintenance_activity),
        Some(MaintenanceActivity::TrustedMaintenance)
    );
}

#[test]
fn classify_process_trust_marks_temp_exec_as_suspicious() {
    let process = tracked_process(44, "payload", "/tmp/payload");
    assert_eq!(
        classify_process_trust(&process),
        ProcessTrustClass::Suspicious
    );
}

#[test]
fn classify_process_trust_marks_package_managed_service_as_trusted() {
    let mut process = tracked_process(55, "fwupd", "/usr/libexec/fwupd/fwupd");
    process.uid = Some(0);
    process.parent_process_name = Some("systemd".to_string());
    process.service_unit = Some("fwupd.service".to_string());

    assert_eq!(
        classify_process_trust(&process),
        ProcessTrustClass::TrustedPackageManaged
    );
}

#[test]
fn classify_process_trust_uses_package_ownership_evidence() {
    let mut process = tracked_process(55, "python3", "/usr/bin/python3");
    process.package_name = Some("python3-minimal".to_string());

    assert_eq!(
        classify_process_trust(&process),
        ProcessTrustClass::TrustedPackageManaged
    );
}

#[test]
fn trust_policy_override_matches_package_name() {
    let config = ContainmentConfig {
        watch_paths: vec!["/srv/data".to_string()],
        trust_policies: vec![TrustPolicyRule {
            name: "python-backup".to_string(),
            exe_paths: Vec::new(),
            package_names: vec!["python3-minimal".to_string()],
            service_units: Vec::new(),
            trust_class: ProcessTrustClass::AllowedLocal,
            visibility: TrustPolicyVisibility::Visible,
            maintenance_windows: Vec::new(),
        }],
        ..ContainmentConfig::default()
    };
    let mut tracker = ProcessLifecycleTracker::new(&config);
    let now = chrono::Utc::now();
    let mut process = tracked_process(42, "python3", "/usr/bin/python3");
    process.package_name = Some("python3-minimal".to_string());
    process.package_manager = Some("dpkg".to_string());

    let mut processes = HashMap::from([(42, process)]);
    tracker.apply_profile_metadata(&mut processes, now);

    let process = processes.get(&42).expect("tracked process");
    assert_eq!(process.trust_class, ProcessTrustClass::AllowedLocal);
    assert_eq!(process.trust_policy_name.as_deref(), Some("python-backup"));
}

#[test]
fn package_owner_parsers_extract_expected_names() {
    assert_eq!(
        parse_dpkg_owner_output("python3-minimal: /usr/bin/python3\n").as_deref(),
        Some("python3-minimal")
    );
    assert_eq!(
        parse_rpm_owner_output("bash-5.2.26-4.fc39.x86_64\n").as_deref(),
        Some("bash-5.2.26-4.fc39.x86_64")
    );
    assert_eq!(
        parse_pacman_owner_output("/usr/bin/bash is owned by bash 5.2.015-1\n").as_deref(),
        Some("bash")
    );
    assert_eq!(
        parse_apk_owner_output("/bin/busybox is owned by busybox-1.36.1-r20\n").as_deref(),
        Some("busybox-1.36.1-r20")
    );
}

#[test]
fn inspect_parent_chain_reads_multiple_ancestors() {
    let root = std::env::temp_dir().join(format!("bannkenn-parent-chain-{}", uuid::Uuid::new_v4()));
    write_proc_entry(
        &root,
        20,
        10,
        "bash",
        "/usr/bin/bash",
        "/usr/bin/bash /tmp/run.sh",
    );
    write_proc_entry(&root, 10, 1, "sshd", "/usr/sbin/sshd", "sshd: root@pts/0");
    write_proc_entry(
        &root,
        1,
        0,
        "systemd",
        "/usr/lib/systemd/systemd",
        "systemd",
    );

    let chain = inspect_parent_chain(&root, 20, 6);

    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].pid, 20);
    assert_eq!(chain[0].process_name.as_deref(), Some("bash"));
    assert_eq!(chain[1].process_name.as_deref(), Some("sshd"));
    assert_eq!(chain[2].process_name.as_deref(), Some("systemd"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn maintenance_activity_skips_shell_ancestor_anywhere_in_chain() {
    let config = ContainmentConfig {
        watch_paths: vec!["/srv/data".to_string()],
        ..ContainmentConfig::default()
    };
    let mut tracker = ProcessLifecycleTracker::new(&config);
    let now = chrono::Utc::now();
    let mut process = tracked_process(55, "fwupd", "/usr/libexec/fwupd/fwupd");
    process.service_unit = Some("fwupd.service".to_string());
    process.parent_process_name = Some("systemd".to_string());
    process.parent_command_line = Some("systemd".to_string());
    process.parent_chain = vec![
        ProcessAncestor {
            pid: 1,
            process_name: Some("systemd".to_string()),
            exe_path: Some("/usr/lib/systemd/systemd".to_string()),
            command_line: Some("systemd".to_string()),
        },
        ProcessAncestor {
            pid: 999,
            process_name: Some("bash".to_string()),
            exe_path: Some("/usr/bin/bash".to_string()),
            command_line: Some("/usr/bin/bash /tmp/fwupd-wrapper.sh".to_string()),
        },
    ];

    let mut processes = HashMap::from([(55, process)]);
    tracker.apply_profile_metadata(&mut processes, now);

    assert_eq!(
        processes
            .get(&55)
            .and_then(|process| process.maintenance_activity),
        None
    );
}

#[test]
fn status_metadata_reads_parent_uid_and_gid() {
    let path = std::env::temp_dir().join(format!("bannkenn-status-{}", uuid::Uuid::new_v4()));
    fs::write(
        &path,
        "Name:\tpython3\nPPid:\t77\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n",
    )
    .unwrap();

    let metadata = read_status_metadata(path.clone());

    assert_eq!(metadata.parent_pid, Some(77));
    assert_eq!(metadata.uid, Some(1000));
    assert_eq!(metadata.gid, Some(1001));

    let _ = fs::remove_file(path);
}

fn read_cgroup_metadata_from_str(content: &str) -> CgroupMetadata {
    let path = std::env::temp_dir().join(format!("bannkenn-cgroup-{}", uuid::Uuid::new_v4()));
    fs::write(&path, content).unwrap();
    let result = read_cgroup_metadata(path.clone());
    let _ = fs::remove_file(path);
    result
}

fn write_proc_entry(
    proc_root: &Path,
    pid: u32,
    ppid: u32,
    name: &str,
    exe_path: &str,
    command_line: &str,
) {
    let dir = proc_root.join(pid.to_string());
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("comm"), format!("{name}\n")).unwrap();
    fs::write(
        dir.join("cmdline"),
        command_line
            .split_whitespace()
            .flat_map(|part| part.as_bytes().iter().copied().chain(std::iter::once(0)))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    fs::write(
        dir.join("status"),
        format!("Name:\t{name}\nPPid:\t{ppid}\n"),
    )
    .unwrap();
    symlink(exe_path, dir.join("exe")).unwrap();
}
