use std::sync::Arc;

use super::*;
use crate::domain::metrics::test_harness::MetricsHarness;
use crate::test_support::test_fixtures::claims;

/// Create a test `AuthNMetrics` instance for claim mapper tests.
fn create_test_metrics() -> Arc<AuthNMetrics> {
    MetricsHarness::new().metrics()
}

#[test]
fn extract_subject_id_returns_uuid_for_valid_sub()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let claims = claims(&[(
        "sub",
        serde_json::Value::String("550e8400-e29b-41d4-a716-446655440000".to_owned()),
    )]);

    let subject_id = extract_subject_id(&claims)?;
    assert_eq!(
        subject_id,
        Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_0000_u128)
    );
    Ok(())
}

#[test]
fn extract_subject_id_rejects_non_uuid_sub() {
    let claims = claims(&[("sub", serde_json::Value::String("not-a-uuid".to_owned()))]);

    let err = extract_subject_id(&claims);
    assert!(matches!(
        err,
        Err(AuthNResolverError::Unauthorized(msg)) if msg == "invalid subject id"
    ));
}

#[test]
fn extract_subject_id_rejects_missing_sub() {
    let claims = claims(&[(
        "tenant_id",
        serde_json::Value::String("550e8400-e29b-41d4-a716-446655440001".to_owned()),
    )]);

    let err = extract_subject_id(&claims);
    assert!(matches!(
        err,
        Err(AuthNResolverError::Unauthorized(msg)) if msg == "invalid subject id"
    ));
}

#[test]
fn extract_tenant_id_returns_uuid_when_claim_is_present()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let claims = claims(&[(
        "tenant_id",
        serde_json::Value::String("550e8400-e29b-41d4-a716-446655440010".to_owned()),
    )]);

    let tenant_id = extract_tenant_id(&claims, "tenant_id", &create_test_metrics())?;
    assert_eq!(
        tenant_id,
        Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_0010_u128)
    );
    Ok(())
}

#[test]
fn extract_tenant_id_rejects_missing_claim() {
    let claims = claims(&[(
        "sub",
        serde_json::Value::String("550e8400-e29b-41d4-a716-446655440000".to_owned()),
    )]);

    let err = extract_tenant_id(&claims, "tenant_id", &create_test_metrics());
    assert!(matches!(
        err,
        Err(AuthNResolverError::Unauthorized(msg)) if msg == "missing tenant_id"
    ));
}

#[test]
fn extract_tenant_id_records_invalid_tenant_rejection_metric() {
    let harness = MetricsHarness::new();
    let metrics = harness.metrics();
    let claims = claims(&[(
        "tenant_id",
        serde_json::Value::String("not-a-uuid".to_owned()),
    )]);

    let err = extract_tenant_id(&claims, "tenant_id", &metrics);

    assert!(matches!(
        err,
        Err(AuthNResolverError::Unauthorized(msg)) if msg == "invalid tenant_id"
    ));
    harness.force_flush();
    assert_eq!(
        harness.counter_value(
            crate::domain::metrics::AUTHN_TOKEN_REJECTED_TOTAL,
            &[("reason", "invalid_tenant")]
        ),
        1
    );
}

#[test]
fn extract_tenant_id_supports_custom_claim_name()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let claims = claims(&[(
        "tenant",
        serde_json::Value::String("550e8400-e29b-41d4-a716-446655440020".to_owned()),
    )]);

    let tenant_id = extract_tenant_id(&claims, "tenant", &create_test_metrics())?;
    assert_eq!(
        tenant_id,
        Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_0020_u128)
    );
    Ok(())
}

#[test]
fn extract_user_type_returns_value_when_present() {
    let claims = claims(&[("user_type", serde_json::Value::String("human".to_owned()))]);
    assert_eq!(extract_user_type(&claims), Some("human".to_owned()));
}

#[test]
fn extract_user_type_returns_none_when_absent() {
    let claims = claims(&[(
        "sub",
        serde_json::Value::String("550e8400-e29b-41d4-a716-446655440000".to_owned()),
    )]);
    assert_eq!(extract_user_type(&claims), None);
}

#[test]
fn detect_app_type_prefers_azp_for_first_party_match() {
    let claims = claims(&[(
        "azp",
        serde_json::Value::String("cyber-fabric-portal".to_owned()),
    )]);
    let first_party_clients = vec![
        "cyber-fabric-portal".to_owned(),
        "cyber-fabric-cli".to_owned(),
    ];

    let app_type = detect_app_type(&claims, &first_party_clients);
    assert_eq!(app_type, AppType::FirstParty);
}

#[test]
fn detect_app_type_falls_back_to_client_id_when_azp_absent() {
    let claims = claims(&[(
        "client_id",
        serde_json::Value::String("cyber-fabric-cli".to_owned()),
    )]);
    let first_party_clients = vec![
        "cyber-fabric-portal".to_owned(),
        "cyber-fabric-cli".to_owned(),
    ];

    let app_type = detect_app_type(&claims, &first_party_clients);
    assert_eq!(app_type, AppType::FirstParty);
}

#[test]
fn detect_app_type_returns_third_party_when_client_is_unknown() {
    let claims = claims(&[("azp", serde_json::Value::String("partner-app".to_owned()))]);
    let first_party_clients = vec![
        "cyber-fabric-portal".to_owned(),
        "cyber-fabric-cli".to_owned(),
    ];

    let app_type = detect_app_type(&claims, &first_party_clients);
    assert_eq!(app_type, AppType::ThirdParty);
}

#[test]
fn extract_scopes_returns_wildcard_for_first_party() {
    let claims = claims(&[(
        "scope",
        serde_json::Value::String("read:resource write:resource".to_owned()),
    )]);

    let scopes = extract_scopes(&claims, AppType::FirstParty);
    assert_eq!(scopes, vec!["*".to_owned()]);
}

#[test]
fn extract_scopes_splits_scope_claim_for_third_party() {
    let claims = claims(&[(
        "scope",
        serde_json::Value::String("read:resource write:resource".to_owned()),
    )]);

    let scopes = extract_scopes(&claims, AppType::ThirdParty);
    assert_eq!(
        scopes,
        vec!["read:resource".to_owned(), "write:resource".to_owned()]
    );
}

#[test]
fn extract_scopes_returns_empty_when_scope_claim_is_missing_for_third_party() {
    let claims = claims(&[("azp", serde_json::Value::String("partner-app".to_owned()))]);

    let scopes = extract_scopes(&claims, AppType::ThirdParty);
    assert!(scopes.is_empty());
}

#[test]
fn map_builds_security_context_for_first_party_claims() {
    let claims = claims(&[
        (
            "sub",
            serde_json::Value::String("550e8400-e29b-41d4-a716-446655440000".to_owned()),
        ),
        (
            "tenant_id",
            serde_json::Value::String("550e8400-e29b-41d4-a716-446655440001".to_owned()),
        ),
        ("user_type", serde_json::Value::String("user".to_owned())),
        (
            "azp",
            serde_json::Value::String("cyber-fabric-portal".to_owned()),
        ),
        (
            "scope",
            serde_json::Value::String("read:resource write:resource".to_owned()),
        ),
    ]);

    let config = default_config();
    let options = ClaimMapperOptions {
        first_party_clients: vec![
            "cyber-fabric-portal".to_owned(),
            "cyber-fabric-cli".to_owned(),
        ],
        ..ClaimMapperOptions::default()
    };

    let mapped = map_with_options(&claims, &config, &options, &create_test_metrics());
    assert!(mapped.is_ok());

    let context = mapped.expect("first-party claims should map to security context");
    assert_eq!(
        context.subject_id(),
        Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_0000_u128)
    );
    assert_eq!(
        context.subject_tenant_id(),
        Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_0001_u128)
    );
    assert_eq!(context.subject_type(), Some("user"));
    assert_eq!(context.token_scopes(), &["*"]); // first-party wildcard
}

#[test]
fn map_builds_security_context_for_third_party_claims() {
    let claims = claims(&[
        (
            "sub",
            serde_json::Value::String("550e8400-e29b-41d4-a716-446655440100".to_owned()),
        ),
        (
            "tenant_id",
            serde_json::Value::String("550e8400-e29b-41d4-a716-446655440101".to_owned()),
        ),
        (
            "azp",
            serde_json::Value::String("partner-integration".to_owned()),
        ),
        (
            "scope",
            serde_json::Value::String("read:orders write:orders".to_owned()),
        ),
    ]);

    let config = default_config();
    let options = ClaimMapperOptions {
        first_party_clients: vec![
            "cyber-fabric-portal".to_owned(),
            "cyber-fabric-cli".to_owned(),
        ],
        ..ClaimMapperOptions::default()
    };

    let mapped = map_with_options(&claims, &config, &options, &create_test_metrics());
    assert!(mapped.is_ok());

    let context = mapped.expect("third-party claims should map to security context");
    assert_eq!(context.subject_type(), None);
    assert_eq!(
        context.token_scopes(),
        &["read:orders".to_owned(), "write:orders".to_owned()]
    );
}

#[test]
fn map_rejects_invalid_subject_claim() {
    let claims = claims(&[
        ("sub", serde_json::Value::String("not-a-uuid".to_owned())),
        (
            "tenant_id",
            serde_json::Value::String("550e8400-e29b-41d4-a716-446655440001".to_owned()),
        ),
    ]);

    let err = map(&claims, &default_config(), &create_test_metrics());
    assert!(matches!(
        err,
        Err(AuthNResolverError::Unauthorized(msg)) if msg == "invalid subject id"
    ));
}

#[test]
fn map_rejects_missing_tenant_claim() {
    let claims = claims(&[(
        "sub",
        serde_json::Value::String("550e8400-e29b-41d4-a716-446655440000".to_owned()),
    )]);

    let err = map(&claims, &default_config(), &create_test_metrics());
    assert!(matches!(
        err,
        Err(AuthNResolverError::Unauthorized(msg)) if msg == "missing tenant_id"
    ));
}

#[test]
fn map_supports_custom_tenant_claim_name() {
    let claims = claims(&[
        (
            "sub",
            serde_json::Value::String("550e8400-e29b-41d4-a716-446655441000".to_owned()),
        ),
        (
            "tenant",
            serde_json::Value::String("550e8400-e29b-41d4-a716-446655441001".to_owned()),
        ),
        (
            "client_id",
            serde_json::Value::String("cyber-fabric-cli".to_owned()),
        ),
    ]);

    let config = ClaimMapperConfig {
        subject_tenant_id: "tenant".to_owned(),
        ..default_config()
    };
    let options = ClaimMapperOptions {
        first_party_clients: vec!["cyber-fabric-cli".to_owned()],
        ..ClaimMapperOptions::default()
    };

    let mapped = map_with_options(&claims, &config, &options, &create_test_metrics());
    assert!(mapped.is_ok());

    let context = mapped.expect("custom tenant claim should be honored");
    assert_eq!(
        context.subject_tenant_id(),
        Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_1001_u128)
    );
    assert_eq!(context.token_scopes(), &["*"]);
}
