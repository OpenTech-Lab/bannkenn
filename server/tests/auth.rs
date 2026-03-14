use bannkenn_server::auth::{create_token, verify_token};

#[test]
fn create_and_verify_token_round_trips_agent_name() {
    let token = create_token("test-agent", "test-secret").expect("Failed to create token");
    let claims = verify_token(&token, "test-secret").expect("Failed to verify token");

    assert_eq!(claims.sub, "test-agent");
    assert!(claims.exp > claims.iat);
}

#[test]
fn verify_token_rejects_invalid_input() {
    let result = verify_token("invalid.token.here", "test-secret");
    assert!(result.is_err());
}
