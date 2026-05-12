//! OIDC Discovery component.
//!
//! Fetches and caches the `OpenID` Connect discovery document from
//! `{issuer}/.well-known/openid-configuration` to resolve the `jwks_uri`.
//!
//! The discovery document is cached in memory with a configurable TTL
//! (default 1 hour) for up to a configurable number of issuers (default 10).

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::config::RetryPolicyConfig;
use crate::domain::error::AuthNError;
use crate::infra::circuit_breaker::{HostCircuitBreakers, host_key};
use crate::infra::retry::{RetriedRequestError, send_with_retry};
use crate::infra::ttl_cache::{Timestamped, TtlCache};

/// The subset of the OIDC Discovery document we care about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// The issuer identifier from the discovery document.
    pub issuer: String,
    /// URI pointing to the JWKS (JSON Web Key Set) endpoint.
    pub jwks_uri: String,
    /// URI of the `OAuth2` token endpoint (used for S2S client credentials exchange).
    pub token_endpoint: Option<String>,
}

/// A cached OIDC Discovery entry.
#[derive(Debug, Clone)]
pub(crate) struct CachedDiscovery {
    pub config: OidcConfig,
    pub fetched_at: Instant,
}

impl Timestamped for CachedDiscovery {
    fn fetched_at(&self) -> Instant {
        self.fetched_at
    }
}

/// In-memory OIDC Discovery cache with TTL and max-entry eviction.
///
/// Thread-safe via [`TtlCache`]. Fetches are performed lazily on cache miss.
pub struct OidcDiscovery {
    // Debug is implemented manually below to show cache size without contents.
    cache: TtlCache<CachedDiscovery>,
    client: reqwest::Client,
    retry_policy: RetryPolicyConfig,
    circuit_breakers: Option<Arc<HostCircuitBreakers>>,
}

impl std::fmt::Debug for OidcDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcDiscovery")
            .field("cached_issuers", &self.cache.len())
            .finish_non_exhaustive()
    }
}

impl OidcDiscovery {
    /// Create a new `OidcDiscovery` with the given TTL and max entry count.
    #[must_use]
    pub fn new(
        ttl_secs: u64,
        max_entries: usize,
        client: reqwest::Client,
        retry_policy: RetryPolicyConfig,
    ) -> Self {
        Self {
            cache: TtlCache::new(Duration::from_secs(ttl_secs), max_entries),
            client,
            retry_policy,
            circuit_breakers: None,
        }
    }

    /// Attach host-scoped circuit breakers for discovery network calls.
    #[must_use]
    pub fn with_circuit_breakers(mut self, circuit_breakers: Arc<HostCircuitBreakers>) -> Self {
        self.circuit_breakers = Some(circuit_breakers);
        self
    }

    /// Fetch the OIDC configuration for the given issuer.
    ///
    /// Returns the cached config if available and not expired. Otherwise
    /// fetches from `{issuer}/.well-known/openid-configuration`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthNError::IdpUnreachable`] if the HTTP request fails.
    #[instrument(skip(self))]
    pub async fn get_config(&self, issuer: &str) -> Result<OidcConfig, AuthNError> {
        if let Some(entry) = self.cache.get_fresh(issuer) {
            debug!(issuer, "OIDC discovery cache hit");
            return Ok(entry.config);
        }

        info!(issuer, "OIDC discovery cache miss or stale, fetching");

        if let Some(circuit_breakers) = &self.circuit_breakers {
            let host = host_key(issuer);
            circuit_breakers
                .call(&host, || async { self.fetch_and_cache(issuer).await })
                .await
        } else {
            self.fetch_and_cache(issuer).await
        }
    }

    /// Unconditionally fetch and cache the OIDC config for the given issuer.
    async fn fetch_and_cache(&self, issuer: &str) -> Result<OidcConfig, AuthNError> {
        let discovery_url = format!("{issuer}/.well-known/openid-configuration");
        let response = send_with_retry(&self.retry_policy, || {
            self.client.get(&discovery_url).send()
        })
        .await
        .map_err(|error| {
            match error {
                RetriedRequestError::Transport(e) => {
                    warn!(url = %discovery_url, error = %e, "OIDC discovery fetch failed");
                }
                RetriedRequestError::Status(status) => {
                    warn!(
                        url = %discovery_url,
                        status = %status,
                        "OIDC discovery returned non-success status"
                    );
                }
            }
            AuthNError::IdpUnreachable
        })?;

        let config: OidcConfig = response.json().await.map_err(|e| {
            warn!(url = %discovery_url, error = %e, "OIDC discovery response parse failed");
            AuthNError::IdpUnreachable
        })?;

        self.cache.insert_with_eviction(
            issuer,
            CachedDiscovery {
                config: config.clone(),
                fetched_at: Instant::now(),
            },
            "OIDC discovery",
        );

        Ok(config)
    }

    /// Inject a discovery entry directly into the cache (for testing).
    #[cfg(test)]
    fn inject_cached_config(&self, issuer: &str, config: OidcConfig) {
        self.cache.insert(
            issuer,
            CachedDiscovery {
                config,
                fetched_at: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::metrics::test_harness::MetricsHarness;
    use crate::infra::circuit_breaker::{HostCircuitBreakers, STATE_OPEN, host_key};

    const TEST_ISSUER: &str = "http://127.0.0.1:19090/realms/platform";

    fn make_discovery(max_entries: usize, ttl_secs: u64) -> OidcDiscovery {
        OidcDiscovery::new(
            ttl_secs,
            max_entries,
            reqwest::Client::new(),
            crate::config::default_retry_policy_config(),
        )
    }

    fn create_test_metrics() -> Arc<crate::domain::metrics::AuthNMetrics> {
        MetricsHarness::new().metrics()
    }

    fn fake_config(issuer: &str) -> OidcConfig {
        OidcConfig {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{issuer}/protocol/openid-connect/certs"),
            token_endpoint: None,
        }
    }

    #[tokio::test]
    async fn cache_hit_returns_without_network() {
        let discovery = make_discovery(10, 3600);
        discovery.inject_cached_config(TEST_ISSUER, fake_config(TEST_ISSUER));

        let result = discovery.get_config(TEST_ISSUER).await;
        assert!(result.is_ok(), "cache hit should succeed");
        assert_eq!(result.unwrap().issuer, TEST_ISSUER);
    }

    #[tokio::test]
    async fn cold_cache_miss_returns_idp_unreachable() {
        let discovery = make_discovery(10, 3600);

        let result = discovery.get_config(TEST_ISSUER).await;
        assert!(
            matches!(result, Err(AuthNError::IdpUnreachable)),
            "cold cache miss with unreachable IdP should return IdpUnreachable: {result:?}"
        );
    }

    #[tokio::test]
    async fn discovery_failure_opens_only_that_host_breaker() {
        let breakers = Arc::new(HostCircuitBreakers::new(1, 30, create_test_metrics()));
        let discovery = OidcDiscovery::new(
            3600,
            10,
            reqwest::Client::new(),
            crate::config::default_retry_policy_config(),
        )
        .with_circuit_breakers(Arc::clone(&breakers));

        let result = discovery.get_config(TEST_ISSUER).await;

        assert!(matches!(result, Err(AuthNError::IdpUnreachable)));
        assert_eq!(
            breakers.state_for_host(&host_key(TEST_ISSUER)),
            Some(STATE_OPEN)
        );
        assert_eq!(
            breakers.state_for_host("unrelated.example.com"),
            None,
            "failing one discovery host must not create or open unrelated host breakers"
        );
    }

    #[tokio::test]
    async fn expired_entry_fails_closed_when_idp_unreachable() {
        let discovery = OidcDiscovery::new(
            0,
            10,
            reqwest::Client::new(),
            crate::config::default_retry_policy_config(),
        );
        discovery.inject_cached_config(TEST_ISSUER, fake_config(TEST_ISSUER));

        let result = discovery.get_config(TEST_ISSUER).await;
        assert!(
            matches!(result, Err(AuthNError::IdpUnreachable)),
            "expired entry with unreachable IdP should fail closed: {result:?}"
        );
    }

    #[tokio::test]
    async fn cold_cache_miss_with_no_stale_entry_returns_idp_unreachable() {
        let discovery = OidcDiscovery::new(
            0,
            10,
            reqwest::Client::new(),
            crate::config::default_retry_policy_config(),
        );

        let result = discovery.get_config(TEST_ISSUER).await;
        assert!(
            matches!(result, Err(AuthNError::IdpUnreachable)),
            "cold cache with unreachable IdP and no stale entry should return IdpUnreachable: {result:?}"
        );
    }
}
