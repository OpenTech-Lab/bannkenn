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
            "https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.3.18/bannkenn-agent-linux-x64",
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
