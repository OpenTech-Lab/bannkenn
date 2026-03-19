use super::{
    apply_containment_setup, invalid_containment_paths, is_cloudflare_response,
    is_https_plain_http_mismatch_error, parse_containment_path_list, Cli, Commands,
    ContainmentConfig, HttpProbeResult,
};
use clap::Parser;
use reqwest::StatusCode;

#[test]
fn plain_http_on_https_error_is_detected() {
    let err = anyhow::anyhow!(
        "error trying to connect: received corrupt message of type InvalidContentType"
    );
    assert!(is_https_plain_http_mismatch_error(&err));
}

#[test]
fn unrelated_tls_error_is_not_classified_as_plain_http_mismatch() {
    let err = anyhow::anyhow!("certificate verify failed: UnknownIssuer");
    assert!(!is_https_plain_http_mismatch_error(&err));
}

#[test]
fn connecttest_command_parses() {
    let cli = Cli::parse_from(["bannkenn-agent", "connecttest"]);
    assert!(matches!(cli.command, Some(Commands::ConnectTest)));
}

#[test]
fn update_command_parses_configure_containment_flag() {
    let cli = Cli::parse_from(["bannkenn-agent", "update", "--configure-containment"]);
    assert!(matches!(
        cli.command,
        Some(Commands::Update {
            configure_containment: true,
            ..
        })
    ));
}

#[test]
fn cloudflare_probe_is_detected() {
    let probe = HttpProbeResult {
        status: StatusCode::FORBIDDEN,
        server_header: Some("cloudflare".to_string()),
        cf_ray: Some("88e4ec9ec8c8e123-NRT".to_string()),
        content_type: Some("text/html".to_string()),
        body_preview: Some("Access denied".to_string()),
    };

    assert!(is_cloudflare_response(&probe));
}

#[test]
fn containment_path_parser_trims_and_deduplicates() {
    assert_eq!(
        parse_containment_path_list(" /srv/data , /var/www , /srv/data "),
        vec!["/srv/data".to_string(), "/var/www".to_string()]
    );
}

#[test]
fn relative_containment_paths_are_rejected() {
    assert_eq!(
        invalid_containment_paths(&[
            "/srv/data".to_string(),
            "relative/path".to_string(),
            "../tmp".to_string()
        ]),
        vec!["relative/path".to_string(), "../tmp".to_string()]
    );
}

#[test]
fn containment_setup_enables_dry_run_with_prompted_paths() {
    let mut containment = ContainmentConfig::default();
    apply_containment_setup(
        &mut containment,
        vec!["/srv/data".to_string()],
        vec!["/srv/data".to_string(), "/srv/backups".to_string()],
    );

    assert!(containment.enabled);
    assert!(containment.dry_run);
    assert_eq!(containment.watch_paths, vec!["/srv/data".to_string()]);
    assert_eq!(
        containment.protected_paths,
        vec!["/srv/data".to_string(), "/srv/backups".to_string()]
    );
}
