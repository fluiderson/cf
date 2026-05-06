use super::*;
use uuid::Uuid;

/// Stable test tenant id used by every conversion test below. Its
/// concrete value is irrelevant to the redaction / variant-mapping
/// invariants under test — only the `tenant_id` field on the
/// emitted `am.idp` log is shaped by it, and these tests don't
/// assert log payload, just the resulting `DomainError` shape.
fn fixture_tenant_id() -> Uuid {
    Uuid::from_u128(0xA11CE)
}

#[test]
fn clean_failure_maps_to_service_unavailable() {
    let err = ProvisionFailure::CleanFailure {
        detail: "conn refused".into(),
    }
    .into_domain_error(fixture_tenant_id());
    assert!(matches!(err, DomainError::ServiceUnavailable { .. }));
}

#[test]
fn provision_unsupported_operation_maps_to_unsupported_operation() {
    let err = ProvisionFailure::UnsupportedOperation {
        detail: "not supported by provider".into(),
    }
    .into_domain_error(fixture_tenant_id());
    let DomainError::UnsupportedOperation { detail } = err else {
        panic!("expected UnsupportedOperation");
    };
    // Public detail MUST carry the redaction marker and MUST NOT
    // leak the raw provider string.
    assert!(
        detail.contains("detail redacted"),
        "missing redaction marker in public detail: {detail}"
    );
    assert!(
        !detail.contains("not supported by provider"),
        "raw provider string leaked into public detail: {detail}"
    );
}

#[test]
fn provision_ambiguous_maps_to_internal_with_redacted_diagnostic() {
    let err = ProvisionFailure::Ambiguous {
        detail: "vendor stack trace with token=secret-LEAK-9f3a7c2e".into(),
    }
    .into_domain_error(fixture_tenant_id());
    let DomainError::Internal { diagnostic, .. } = err else {
        panic!("expected Internal");
    };
    assert!(diagnostic.contains("provider detail redacted"));
    // Pin the redaction contract for vendor-text leaks: even a
    // sentinel-shaped token in `detail` MUST NOT reach the public
    // `Internal::diagnostic` field (which is forwarded verbatim into
    // `Problem.detail` by the canonical-mapping boundary). The
    // symmetric Deprovision-side coverage previously lived in this
    // file too; with `DeprovisionFailureExt` removed (no production
    // callers — see `domain::idp::mod`), the redaction-helper itself
    // is exercised by the Provision tests since both Provision and
    // Deprovision conversions share `redact_provider_detail`.
    assert!(
        !diagnostic.contains("token="),
        "raw vendor token leaked into Internal diagnostic: {diagnostic}"
    );
    assert!(
        !diagnostic.contains("secret-LEAK-9f3a7c2e"),
        "raw vendor sentinel leaked into Internal diagnostic: {diagnostic}"
    );
}
