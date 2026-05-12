#![allow(clippy::expect_used)]

//! Criterion benchmark for JWT local validation with warm JWKS cache.
//!
//! Target: p95 ≤5ms for `validate()` with a pre-cached JWKS entry.
//! Run with: `cargo bench -p oidc-authn-plugin`

use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use jsonwebtoken::Algorithm;
use oidc_authn_plugin::config::{
    IssuerTrustConfig, JwtValidationConfig, RetryPolicyConfig, TrustedIssuerEntry,
    TrustedIssuerInput,
};
use oidc_authn_plugin::domain::metrics::AuthNMetrics;
use oidc_authn_plugin::domain::validator::JwtValidator;
use oidc_authn_plugin::infra::jwks::{JwksFetcher, JwksFetcherConfig, JwksFetcherDeps};
use oidc_authn_plugin::infra::oidc::OidcDiscovery;

const TEST_KID: &str = "test-key-1";

const TEST_JWK_JSON: &str = r#"{
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "test-key-1",
        "n": "vAh7iO3q6WAG_hiZNMhYnUdeO5HtO9ZvIHcZHMsrXaEYr-5dy6AXXCzIaSUr-Nyuy5_PSsYaOEmmu27CfpPTPfoWFTReXbDevpHjhCR-OJrorz2vfToVfR2VUFhfBUvEgbJ7mLbnhlOrIIE2etMnsHRNdFcSccQ9mZRfViUUGcFFBSNyfgzD2NTQz8_7FVs3p2iNG2o--8CE-ZkC8HnS6ZZb1Bo6DlhGlkKWxailYiTzDOB9ToFUfPURbO1d6rBS-ixNbR-oh1alct9XtInmslLPQ1X_GBlhtWNzEGk5F8xSO5cT7RBgqT7IIsEaM0CSkK4hIs2nLCe7Fb0dO0pWpw",
        "e": "AQAB"
    }]
}"#;

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

fn future_exp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(9_999_999_999, |d| d.as_secs() + 3600)
}

fn sign_jwt(claims: &serde_json::Value, kid: Option<&str>) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_owned);
    let pem = test_private_key_pem();
    let key = EncodingKey::from_rsa_pem(&pem).expect("test private key should be valid RSA PEM");
    encode(&header, claims, &key).expect("benchmark JWT should sign")
}

fn base_jwt_validation_config() -> JwtValidationConfig {
    JwtValidationConfig {
        supported_algorithms: vec![Algorithm::RS256, Algorithm::ES256],
        clock_skew_leeway_secs: 60,
        require_audience: false,
        expected_audience: Vec::new(),
        jwks_cache_ttl_secs: 3600,
        jwks_stale_ttl_secs: 86_400,
        jwks_max_entries: 64,
        jwks_refresh_on_unknown_kid: true,
        jwks_refresh_min_interval_secs: 30,
        discovery_cache_ttl_secs: 3600,
        discovery_max_entries: 64,
    }
}

fn exact_issuer_trust(issuer: String) -> anyhow::Result<IssuerTrustConfig> {
    IssuerTrustConfig::from_inputs([TrustedIssuerInput {
        entry: TrustedIssuerEntry::Issuer(issuer),
        discovery_url: None,
    }])
    .map_err(anyhow::Error::msg)
}

struct MockOidcServer {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl MockOidcServer {
    async fn spawn() -> anyhow::Result<Self> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let base_url = format!("http://{addr}");

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    continue;
                };
                let mut buffer = vec![0_u8; 8192];
                let Ok(bytes) = socket.read(&mut buffer).await else {
                    continue;
                };
                if bytes == 0 {
                    continue;
                }

                let request = String::from_utf8_lossy(&buffer[..bytes]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let (status, body) = if let Some(issuer_path) =
                    path.strip_suffix("/.well-known/openid-configuration")
                {
                    let issuer = format!("http://{addr}{issuer_path}");
                    let jwks_uri = format!("{issuer}/protocol/openid-connect/certs");
                    (
                        "200 OK",
                        format!(r#"{{"issuer":"{issuer}","jwks_uri":"{jwks_uri}"}}"#),
                    )
                } else if path.ends_with("/protocol/openid-connect/certs") {
                    ("200 OK", TEST_JWK_JSON.to_owned())
                } else {
                    ("404 Not Found", r#"{"error":"not-found"}"#.to_owned())
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n\
                     {body}",
                    body.len()
                );
                drop(socket.write_all(response.as_bytes()).await);
            }
        });

        Ok(Self { base_url, handle })
    }

    fn issuer(&self, realm: &str) -> String {
        let realm = realm.trim_start_matches('/');
        format!("{}/{realm}", self.base_url)
    }
}

impl Drop for MockOidcServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn make_validator() -> JwtValidator {
    let retry_policy = RetryPolicyConfig {
        max_attempts: 3,
        initial_backoff_ms: 100,
        max_backoff_ms: 2_000,
        jitter: true,
    };
    let discovery = Arc::new(OidcDiscovery::new(
        3600,
        10,
        reqwest::Client::new(),
        retry_policy.clone(),
    ));
    let metrics = Arc::new(AuthNMetrics::new(&opentelemetry::global::meter(
        "oidc-authn-plugin.bench",
    )));
    let fetcher = Arc::new(JwksFetcher::new(
        JwksFetcherConfig {
            ttl: Duration::from_hours(1),
            stale_ttl: Duration::from_hours(24),
            max_entries: 10,
            refresh_on_unknown_kid: true,
            refresh_min_interval: Duration::from_secs(30),
        },
        JwksFetcherDeps {
            discovery,
            client: reqwest::Client::new(),
            metrics: Arc::clone(&metrics),
            retry_policy,
        },
    ));
    JwtValidator::new(fetcher, metrics)
}

fn sign_test_jwt(issuer: &str) -> String {
    let claims = serde_json::json!({
        "sub": "550e8400-e29b-41d4-a716-446655440000",
        "iss": issuer,
        "exp": future_exp(),
        "tenant_id": "tenant-benchmark",
    });
    sign_jwt(&claims, Some(TEST_KID))
}

fn benchmark_jwt_validation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let server = rt
        .block_on(MockOidcServer::spawn())
        .expect("mock oidc server");
    let issuer = server.issuer("realms/platform");
    let validator = make_validator();
    let config = base_jwt_validation_config();
    let trust = exact_issuer_trust(issuer.clone()).expect("trust config should build");
    let token = sign_test_jwt(&issuer);

    rt.block_on(async {
        validator
            .validate(&token, &config, &trust)
            .await
            .expect("warm-up validation should populate JWKS cache");
    });

    c.bench_function("jwt_validate_warm_cache", |b| {
        b.iter(|| {
            rt.block_on(async {
                validator
                    .validate(&token, &config, &trust)
                    .await
                    .expect("should validate")
            })
        });
    });
}

criterion_group!(benches, benchmark_jwt_validation);
criterion_main!(benches);
