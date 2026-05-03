use super::*;

#[test]
fn clean_failure_maps_to_service_unavailable() {
    let err: DomainError = ProvisionFailure::CleanFailure {
        detail: "conn refused".into(),
    }
    .into();
    assert!(matches!(err, DomainError::ServiceUnavailable { .. }));
}

#[test]
fn provision_unsupported_operation_maps_to_unsupported_operation() {
    let err: DomainError = ProvisionFailure::UnsupportedOperation {
        detail: "not supported by provider".into(),
    }
    .into();
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
    let err: DomainError = ProvisionFailure::Ambiguous {
        detail: "vendor stack trace with token=...".into(),
    }
    .into();
    let DomainError::Internal { diagnostic, .. } = err else {
        panic!("expected Internal");
    };
    assert!(diagnostic.contains("provider detail redacted"));
    assert!(!diagnostic.contains("token="));
}

#[test]
fn deprovision_terminal_maps_to_internal() {
    let err: DomainError = DeprovisionFailure::Terminal {
        detail: "torched".into(),
    }
    .into();
    assert!(matches!(err, DomainError::Internal { .. }));
}

#[test]
fn deprovision_retryable_maps_to_service_unavailable() {
    let err: DomainError = DeprovisionFailure::Retryable {
        detail: "try later".into(),
    }
    .into();
    assert!(matches!(err, DomainError::ServiceUnavailable { .. }));
}

#[test]
fn deprovision_unsupported_maps_to_unsupported_operation() {
    let err: DomainError = DeprovisionFailure::UnsupportedOperation {
        detail: "nope please dont".into(),
    }
    .into();
    let DomainError::UnsupportedOperation { detail } = err else {
        panic!("expected UnsupportedOperation");
    };
    assert!(
        detail.contains("detail redacted"),
        "missing redaction marker in public detail: {detail}"
    );
    assert!(
        !detail.contains("nope please dont"),
        "raw provider string leaked into public detail: {detail}"
    );
}

#[test]
fn deprovision_not_found_maps_to_internal_loudly() {
    // NotFound should be intercepted by the pipelines before reaching
    // the DomainError boundary; if it ever propagates, surface as
    // Internal with a redacted diagnostic so the propagation is
    // loud rather than silent. The detail carries a sentinel
    // secret-shape so the test also pins the redaction contract:
    // even on this rare loud-Internal path, raw vendor text must not
    // reach the public diagnostic field.
    let err: DomainError = DeprovisionFailure::NotFound {
        detail: "absent token=secret-LEAK-9f3a7c2e".into(),
    }
    .into();
    let DomainError::Internal { diagnostic, .. } = err else {
        panic!("expected Internal");
    };
    assert!(diagnostic.contains("NotFound reached"));
    assert!(
        !diagnostic.contains("token="),
        "raw vendor token leaked into Internal diagnostic: {diagnostic}"
    );
    assert!(
        !diagnostic.contains("secret-LEAK-9f3a7c2e"),
        "raw vendor sentinel leaked into Internal diagnostic: {diagnostic}"
    );
}
