use super::*;

fn tracked_process(pid: u32, process_name: &str, exe_path: &str) -> TrackedProcess {
    TrackedProcess {
        pid,
        process_name: process_name.to_string(),
        exe_path: exe_path.to_string(),
        command_line: exe_path.to_string(),
        parent_process_name: None,
        parent_command_line: None,
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
    let (runtime, id) = read_container_context_from_str(
        "0::/system.slice/docker-0123456789abcdef0123456789abcdef.scope\n",
    );
    assert_eq!(runtime.as_deref(), Some("docker"));
    assert_eq!(id.as_deref(), Some("0123456789abcdef0123456789abcdef"));
}

#[test]
fn container_context_detects_kubernetes_containerd_paths() {
    let (runtime, id) = read_container_context_from_str(
        "0::/kubepods/besteffort/pod1234/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    );
    assert_eq!(runtime.as_deref(), Some("kubernetes"));
    assert_eq!(
        id.as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn container_context_detects_crio_runtime_from_scope_prefix() {
    let (runtime, id) = read_container_context_from_str(
        "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/crio-0123456789abcdef0123456789abcdef.scope\n",
    );
    assert_eq!(runtime.as_deref(), Some("crio"));
    assert_eq!(id.as_deref(), Some("0123456789abcdef0123456789abcdef"));
}

fn read_container_context_from_str(content: &str) -> (Option<String>, Option<String>) {
    let path = std::env::temp_dir().join(format!("bannkenn-cgroup-{}", uuid::Uuid::new_v4()));
    fs::write(&path, content).unwrap();
    let result = read_container_context(path.clone());
    let _ = fs::remove_file(path);
    result
}
