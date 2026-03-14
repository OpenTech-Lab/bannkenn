use bannkenn_server::ip_pattern::{canonicalize_ip_pattern, pattern_covers_pattern};

#[test]
fn canonicalize_ip_pattern_rewrites_cidr_to_network_boundary() {
    assert_eq!(
        canonicalize_ip_pattern("123.123.123.123/24"),
        Some("123.123.123.0/24".to_string())
    );
}

#[test]
fn pattern_covers_pattern_matches_ips_and_subnets() {
    assert!(pattern_covers_pattern("203.0.113.0/24", "203.0.113.0/25"));
    assert!(pattern_covers_pattern("203.0.113.0/24", "203.0.113.44"));
    assert!(!pattern_covers_pattern("203.0.113.44", "203.0.113.0/24"));
}
