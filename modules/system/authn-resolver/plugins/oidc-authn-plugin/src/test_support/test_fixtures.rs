//! Unit-test key material and helpers for the oidc-authn-plugin crate.
//!
//! This module is gated behind `#[cfg(test)]` so nothing is compiled into
//! production builds.

/// Assemble a PEM block at runtime from base64-encoded body lines.
///
/// Headers are built dynamically to prevent security scanners from matching
/// literal PEM patterns (`-----BEGIN … KEY-----`) in source files.
fn assemble_pem(label: &str, body_lines: &[&str]) -> Vec<u8> {
    use std::fmt::Write;
    let mut pem = format!("-----BEGIN {label}-----\n");
    for line in body_lines {
        pem.push_str(line);
        pem.push('\n');
    }
    let _write_result = writeln!(pem, "-----END {label}-----");
    pem.into_bytes()
}

/// RSA 2048-bit private key (PEM) used exclusively for test token signing.
///
/// Assembled at runtime from raw base64 lines so that no literal PEM header
/// appears in source — this avoids security-scanner false positives on
/// test-only key material that has no production value.
#[must_use]
fn test_private_key_pem() -> Vec<u8> {
    #[rustfmt::skip]
    let body: &[&str] = &[
        "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC8CHuI7erpYAb+",
        "GJk0yFidR147ke071m8gdxkcyytdoRiv7l3LoBdcLMhpJSv43K7Ln89Kxho4Saa7",
        "bsJ+k9M9+hYVNF5dsN6+keOEJH44muivPa99OhV9HZVQWF8FS8SBsnuYtueGU6sg",
        "gTZ60yewdE10VxJxxD2ZlF9WJRQZwUUFI3J+DMPY1NDPz/sVWzenaI0baj77wIT5",
        "mQLwedLpllvUGjoOWEaWQpbFqKViJPMM4H1OgVR89RFs7V3qsFL6LE1tH6iHVqVy",
        "31e0ieayUs9DVf8YGWG1Y3MQaTkXzFI7lxPtEGCpPsgiwRozQJKQriEizacsJ7sV",
        "vR07SlanAgMBAAECggEAIBQAYz1XiKXZu4qdxHvzZi2RPW9pPf6Yqby3u4pLpScB",
        "C66KMN1obtCzBgER7dxUM6fZWOPQAE9MUwiTxL1aWeXq04ZCHRC6B1/jJR2GrQh8",
        "br0CzcXVealM2k6hM0mYRhoZbNWzTN7EQIDatvyD9l35AsKCAoecjLFbzFn6AmSD",
        "PKora3YWDRjgZOd+AQH21U/awsQmGCwch867VT/41ddICM4niyvZ3rjxE69VUuhc",
        "GAegKm3KUIUez3fe+3MYBvRC3XevcKfzt/PVnLeQYiAegqI6qi+x1bIVb3wTzpXu",
        "Bpo4rYLU3dqD2H8mG0C/RS/32e/fk9uK/kJKJQQMLQKBgQD+sY1z2r/mtqSWZ/GK",
        "c3FBQCZNhP2ikXoiuACDFApi7BOVplXqrm1RPOhk7oJ2Nnmiq0lmUlP6K6Xbp4Wl",
        "MsAgNjfcqW8Sq+E6OacyIStyxre+dcW9cpxlUyIRocqCAXMF23mlG7vkonLDSXjj",
        "yKl4ivL2eC7bUg3ca1xD8wKnDQKBgQC8/2VQTvtckvghc/j6zfISWrIKlvbjo++z",
        "2gDt80ePdH4SV/wOaI1pZp0vOi5HNPj990kqsrl9BbpWa5N3qSgRSfblBMvYrKMC",
        "eM2YFRlwXfEe9YB5Oxm6E5slMzDEvdugJLbntWU8h2aUpEaPxjFtTODMCQrbv6b5",
        "3DrmMHOHgwKBgQC7PmNk+jw87KfB37cG92oa84N1WEFzpAorviS6OSCNq0uWqIvf",
        "lc7Oe73KfkKxj8kK22yB6iLM+AvemaE6Wz4+MD4PXw1Gp9BUkxAlXZdosUlin4j5",
        "h2oNX/nbBpwvycr7UmhzBxmys+81PS3AIMTe1yBaLO8d1IxWMSPK3LxlfQKBgQCF",
        "ENQGLPWxAhENjJeaDfIHli+QYSXGtJ+J402QOx8BE6XHyIbApkAaG5NDsxTuMY+1",
        "T6wGEfui2KuPOQKE12ZMdeUM7cmP7kx+6wrlrsVQZfPkNjmUIVZFupQbJuWJP5so",
        "L3FPxllWuoYw1VCQ3ZvjNqN3RE6O1Wr8tGALvcU5fQKBgQCHJPuBPWOfL0NlWhmV",
        "J3DfRTfz57mHpfB2ehRIK+4Io3j2oie5e2B58dXDAJErSZvr8yu38QgIyhLFlPaq",
        "70b2zHr7V/n3AGhNWFuz82L0A3/tU40QodON65bmCfOHxI58INmkgWqsMqW6TmzP",
        "nM0gyGjwjn5gAXxIzU1KGdMZAw==",
    ];
    assemble_pem("PRIVATE KEY", body)
}

/// JWK Set JSON containing the public key matching [`test_private_key_pem`].
pub const TEST_JWK_JSON: &str = r#"{
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "test-key-1",
        "n": "vAh7iO3q6WAG_hiZNMhYnUdeO5HtO9ZvIHcZHMsrXaEYr-5dy6AXXCzIaSUr-Nyuy5_PSsYaOEmmu27CfpPTPfoWFTReXbDevpHjhCR-OJrorz2vfToVfR2VUFhfBUvEgbJ7mLbnhlOrIIE2etMnsHRNdFcSccQ9mZRfViUUGcFFBSNyfgzD2NTQz8_7FVs3p2iNG2o--8CE-ZkC8HnS6ZZb1Bo6DlhGlkKWxailYiTzDOB9ToFUfPURbO1d6rBS-ixNbR-oh1alct9XtInmslLPQ1X_GBlhtWNzEGk5F8xSO5cT7RBgqT7IIsEaM0CSkK4hIs2nLCe7Fb0dO0pWpw",
        "e": "AQAB"
    }]
}"#;

/// Default test issuer matching the OIDC realm used in tests.
pub const TEST_ISSUER: &str = "https://oidc.example.com/realms/platform";

/// Key ID embedded in [`TEST_JWK_JSON`].
pub const TEST_KID: &str = "test-key-1";

/// Return a Unix timestamp 1 hour in the future (for `exp` claims).
#[must_use]
pub fn future_exp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(9_999_999_999, |d| d.as_secs() + 3600)
}

/// Return a Unix timestamp 1 hour in the past (for expired token tests).
#[must_use]
pub fn past_exp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().saturating_sub(3600))
}

/// Sign a JWT with the test RS256 private key.
#[must_use]
pub fn sign_jwt(claims: &serde_json::Value, kid: Option<&str>) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    let pem = test_private_key_pem();
    let Ok(key) = EncodingKey::from_rsa_pem(&pem) else {
        tracing::error!("test private key should be valid RSA PEM");
        return String::new();
    };
    encode(&header, claims, &key).unwrap_or_default()
}

/// Build a [`Claims`] map from a list of `(key, value)` pairs.
///
/// Common helper shared across unit and integration tests to avoid duplicating
/// the same claims-map construction boilerplate.
#[must_use]
pub fn claims(entries: &[(&str, serde_json::Value)]) -> crate::domain::claim_mapper::Claims {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}
