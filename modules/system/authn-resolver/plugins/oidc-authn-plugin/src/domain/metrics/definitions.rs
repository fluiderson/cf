//! Metric name constants.

// ─── Efficiency ──────────────────────────────────────────────────────

/// Gauge: JWKS cache hit ratio in `[0.0, 1.0]`.
pub const AUTHN_JWKS_CACHE_HIT_RATIO: &str = "authn_jwks_cache_hit_ratio";
/// Gauge: current JWKS cache entry count.
pub const AUTHN_JWKS_CACHE_ENTRIES: &str = "authn_jwks_cache_entries";

// ─── Performance ─────────────────────────────────────────────────────

/// Histogram: total JWT local validation duration in seconds.
pub const AUTHN_JWT_VALIDATION_DURATION_SECONDS: &str = "authn_jwt_validation_duration_seconds";
/// Histogram: JWKS remote fetch duration in seconds.
pub const AUTHN_JWKS_FETCH_DURATION_SECONDS: &str = "authn_jwks_fetch_duration_seconds";
/// Counter family: successful requests by validation method (`method` label).
pub const AUTHN_REQUESTS_TOTAL: &str = "authn_requests_total";
/// Counter: total authentication attempts (regardless of outcome).
pub const AUTHN_ATTEMPTS_TOTAL: &str = "authn_attempts_total";

// ─── Reliability ─────────────────────────────────────────────────────

/// Counter family: resolver errors by variant (`type` label).
pub const AUTHN_ERRORS_TOTAL: &str = "authn_errors_total";
/// Gauge family: circuit-breaker state by host (`0=closed,1=half-open,2=open`).
pub const AUTHN_CIRCUIT_BREAKER_STATE: &str = "authn_circuit_breaker_state";
/// Gauge family: Oidc availability probe by host (`0` down, `1` up).
pub const AUTHN_OIDC_UP: &str = "authn_oidc_up";
/// Counter: failed forced JWKS refresh attempts.
pub const AUTHN_JWKS_REFRESH_FAILURES_TOTAL: &str = "authn_jwks_refresh_failures_total";

// ─── Security ────────────────────────────────────────────────────────

/// Counter family: token rejections by reason (`reason` label).
pub const AUTHN_TOKEN_REJECTED_TOTAL: &str = "authn_token_rejected_total";
/// Counter: untrusted issuer rejections.
pub const AUTHN_UNTRUSTED_ISSUER_TOTAL: &str = "authn_untrusted_issuer_total";
/// Counter: missing tenant id rejections.
pub const AUTHN_MISSING_TENANT_ID_TOTAL: &str = "authn_missing_tenant_id_total";

// ─── S2S Exchange ───────────────────────────────────────────────────

/// Counter: total S2S client credentials exchange attempts.
pub const AUTHN_S2S_EXCHANGE_TOTAL: &str = "authn_s2s_exchange_total";
/// Counter family: S2S exchange errors by error type (`type` label).
pub const AUTHN_S2S_EXCHANGE_ERRORS_TOTAL: &str = "authn_s2s_exchange_errors_total";
/// Histogram: S2S client credentials exchange duration in seconds.
pub const AUTHN_S2S_EXCHANGE_DURATION_SECONDS: &str = "authn_s2s_exchange_duration_seconds";

// ─── Versatility ─────────────────────────────────────────────────────

/// Gauge: ratio of first-party auth outcomes (`0.0..=1.0`).
pub const AUTHN_FIRST_PARTY_RATIO: &str = "authn_first_party_ratio";
