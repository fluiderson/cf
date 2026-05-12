#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

/// JWK set JSON containing the public key matching `test_private_key_pem`.
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

/// Key ID embedded in `TEST_JWK_JSON`.
pub const TEST_KID: &str = "test-key-1";

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

#[must_use]
pub fn future_exp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(9_999_999_999, |d| d.as_secs() + 3600)
}

#[must_use]
pub fn sign_jwt(claims: &serde_json::Value, kid: Option<&str>) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    let pem = test_private_key_pem();
    let key = EncodingKey::from_rsa_pem(&pem).expect("test private key should be valid RSA PEM");
    encode(&header, claims, &key).expect("benchmark JWT should sign")
}
