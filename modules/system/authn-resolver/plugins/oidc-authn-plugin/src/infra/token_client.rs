//! `OAuth2` client credentials token exchange client with caching.
//!
//! Implements the `client_credentials` grant (RFC 6749 section 4.4) against an
//! `IdP` token endpoint. Obtained access tokens are cached per normalized
//! client/scope/credential identity with bounded TTL.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use authn_resolver_sdk::ClientCredentialsRequest;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use secrecy::ExposeSecret;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::{RetryPolicyConfig, S2sConfig};
use crate::domain::error::AuthNError;
use crate::domain::ports::ClientCredentialsExchanger;
use crate::infra::circuit_breaker::{HostCircuitBreakers, host_key};
use crate::infra::oidc::OidcDiscovery;
use crate::infra::retry::{RetriedRequestError, is_retryable_status, send_with_retry};
use crate::infra::ttl_cache::{Timestamped, TtlCache};

/// Cached S2S access token entry.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    fetched_at: Instant,
    /// Per-token TTL derived from `min(expires_in, config.token_cache_ttl_secs)`.
    effective_ttl: Duration,
}

impl Timestamped for CachedToken {
    fn fetched_at(&self) -> Instant {
        self.fetched_at
    }

    fn effective_ttl(&self) -> Option<Duration> {
        Some(self.effective_ttl)
    }
}

struct SingleFlightGate {
    mutex: Mutex<()>,
    leases: AtomicUsize,
}

impl SingleFlightGate {
    fn new() -> Self {
        Self {
            mutex: Mutex::new(()),
            leases: AtomicUsize::new(1),
        }
    }

    fn retain(&self) {
        self.leases.fetch_add(1, Ordering::AcqRel);
    }

    fn release(&self) -> bool {
        self.leases.fetch_sub(1, Ordering::AcqRel) == 1
    }

    fn is_idle(&self) -> bool {
        self.leases.load(Ordering::Acquire) == 0
    }
}

/// `OAuth2` token endpoint response (subset we use).
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheIdentity {
    key: String,
    normalized_scopes: String,
}

/// HTTP client for `OAuth2` `client_credentials` token exchange with caching.
///
/// Created once during module init and shared via `Arc`. Uses the same
/// `reqwest::Client` and `OidcDiscovery` as the JWT validation path.
pub struct TokenClient {
    http_client: reqwest::Client,
    discovery: Arc<OidcDiscovery>,
    cache: TtlCache<CachedToken>,
    in_flight: DashMap<String, Arc<SingleFlightGate>>,
    s2s_config: S2sConfig,
    retry_policy: RetryPolicyConfig,
    circuit_breakers: Option<Arc<HostCircuitBreakers>>,
}

impl std::fmt::Debug for TokenClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenClient")
            .field("cache_entries", &self.cache.len())
            .finish_non_exhaustive()
    }
}

impl TokenClient {
    /// Create a new `TokenClient`.
    ///
    /// `discovery` is shared with the JWT validation path so that OIDC
    /// discovery results (including `token_endpoint`) are fetched at most once.
    pub(crate) fn new(
        http_client: reqwest::Client,
        discovery: Arc<OidcDiscovery>,
        s2s_config: S2sConfig,
        retry_policy: RetryPolicyConfig,
    ) -> Self {
        let cache = TtlCache::new(
            Duration::from_secs(s2s_config.token_cache_ttl_secs),
            s2s_config.token_cache_max_entries,
        );
        Self {
            http_client,
            discovery,
            cache,
            in_flight: DashMap::new(),
            s2s_config,
            retry_policy,
            circuit_breakers: None,
        }
    }

    /// Attach host-scoped circuit breakers for token endpoint calls.
    #[must_use]
    pub(crate) fn with_circuit_breakers(
        mut self,
        circuit_breakers: Arc<HostCircuitBreakers>,
    ) -> Self {
        self.circuit_breakers = Some(circuit_breakers);
        self
    }

    /// Exchange client credentials for an access token (JWT string).
    ///
    /// Returns a cached token on cache hit. On cache miss, performs the full
    /// `OAuth2` `client_credentials` grant against the `IdP` token endpoint.
    #[allow(clippy::cognitive_complexity)]
    pub(crate) async fn exchange(
        &self,
        request: &ClientCredentialsRequest,
    ) -> Result<String, AuthNError> {
        let identity = Self::cache_identity(request);

        if let Some(cached) = self.cache.get_fresh(&identity.key) {
            debug!(client_id = %request.client_id, "S2S token cache hit");
            return Ok(cached.access_token);
        }

        let gate = self.single_flight_gate(&identity.key);
        let result = {
            let _single_flight_guard = gate.mutex.lock().await;

            if let Some(cached) = self.cache.get_fresh(&identity.key) {
                debug!(client_id = %request.client_id, "S2S token cache hit after wait");
                Ok(cached.access_token)
            } else {
                self.exchange_uncached(request, &identity).await
            }
        };
        self.release_single_flight_gate(&identity.key, &gate);
        result
    }

    async fn exchange_uncached(
        &self,
        request: &ClientCredentialsRequest,
        identity: &CacheIdentity,
    ) -> Result<String, AuthNError> {
        info!(client_id = %request.client_id, "S2S token cache miss, fetching from IdP");
        let endpoint = self.resolve_token_endpoint().await?;
        let token_response = self
            .post_client_credentials(&endpoint, request, &identity.normalized_scopes)
            .await?;

        let ttl_secs = token_response
            .expires_in
            .map_or(self.s2s_config.token_cache_ttl_secs, |expires_in| {
                expires_in.min(self.s2s_config.token_cache_ttl_secs)
            });
        debug!(
            client_id = %request.client_id,
            ttl_secs,
            "Caching S2S access token"
        );

        let cached = CachedToken {
            access_token: token_response.access_token.clone(),
            fetched_at: Instant::now(),
            effective_ttl: Duration::from_secs(ttl_secs),
        };
        self.cache
            .insert_with_eviction(&identity.key, cached, "S2S token");

        Ok(token_response.access_token)
    }

    fn cache_identity(request: &ClientCredentialsRequest) -> CacheIdentity {
        let normalized_scopes = Self::normalize_scopes(&request.scopes);
        let credential_fingerprint =
            Self::credential_fingerprint(request.client_secret.expose_secret());
        let key = Self::build_cache_key(
            &request.client_id,
            &normalized_scopes,
            &credential_fingerprint,
        );
        CacheIdentity {
            key,
            normalized_scopes,
        }
    }

    fn normalize_scopes(scopes: &[String]) -> String {
        let mut scope_parts = scopes
            .iter()
            .map(|scope| scope.trim())
            .filter(|scope| !scope.is_empty())
            .collect::<Vec<_>>();
        scope_parts.sort_unstable();
        scope_parts.dedup();
        scope_parts.join(" ")
    }

    fn credential_fingerprint(secret: &str) -> String {
        let digest = Sha256::digest(secret.as_bytes());
        hex::encode(digest)
    }

    fn build_cache_key(client_id: &str, normalized_scopes: &str, fingerprint: &str) -> String {
        format!(
            "client_id:{}:{client_id}|scopes:{}:{normalized_scopes}|secret_sha256:{fingerprint}",
            client_id.len(),
            normalized_scopes.len()
        )
    }

    fn single_flight_gate(&self, key: &str) -> Arc<SingleFlightGate> {
        match self.in_flight.entry(key.to_owned()) {
            Entry::Occupied(entry) => {
                let gate = Arc::clone(entry.get());
                gate.retain();
                gate
            }
            Entry::Vacant(entry) => {
                let gate = Arc::new(SingleFlightGate::new());
                entry.insert(Arc::clone(&gate));
                gate
            }
        }
    }

    fn release_single_flight_gate(&self, key: &str, gate: &Arc<SingleFlightGate>) {
        if gate.release() {
            self.in_flight.remove_if(key, |_, current| {
                Arc::ptr_eq(current, gate) && gate.is_idle()
            });
        }
    }

    /// Resolve the token endpoint URL from OIDC discovery metadata.
    async fn resolve_token_endpoint(&self) -> Result<String, AuthNError> {
        if self.s2s_config.discovery_url.trim().is_empty() {
            return Err(AuthNError::TokenEndpointNotConfigured);
        }

        let oidc_config = self
            .discovery
            .get_config(&self.s2s_config.discovery_url)
            .await?;
        if let Some(endpoint) = oidc_config.token_endpoint {
            debug!(
                endpoint,
                discovery_url = &self.s2s_config.discovery_url,
                "Discovered S2S token endpoint via OIDC"
            );
            return Ok(endpoint);
        }
        warn!(
            discovery_url = &self.s2s_config.discovery_url,
            "OIDC discovery document missing token_endpoint"
        );
        Err(AuthNError::TokenEndpointNotConfigured)
    }

    /// POST `grant_type=client_credentials` to the token endpoint.
    #[allow(clippy::cognitive_complexity)]
    async fn post_client_credentials(
        &self,
        endpoint: &str,
        request: &ClientCredentialsRequest,
        normalized_scopes: &str,
    ) -> Result<TokenResponse, AuthNError> {
        if let Some(circuit_breakers) = &self.circuit_breakers {
            let host = host_key(endpoint);
            return circuit_breakers
                .call(&host, || async {
                    self.post_client_credentials_unchecked(endpoint, request, normalized_scopes)
                        .await
                })
                .await;
        }

        self.post_client_credentials_unchecked(endpoint, request, normalized_scopes)
            .await
    }

    #[allow(clippy::cognitive_complexity)]
    async fn post_client_credentials_unchecked(
        &self,
        endpoint: &str,
        request: &ClientCredentialsRequest,
        normalized_scopes: &str,
    ) -> Result<TokenResponse, AuthNError> {
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", &request.client_id),
            ("client_secret", request.client_secret.expose_secret()),
        ];

        if !normalized_scopes.is_empty() {
            form.push(("scope", normalized_scopes));
        }

        let response = send_with_retry(&self.retry_policy, || {
            self.http_client.post(endpoint).form(&form).send()
        })
        .await
        .map_err(|error| match error {
            RetriedRequestError::Transport(e) => {
                warn!(endpoint, error = %e, "S2S token endpoint unreachable");
                AuthNError::IdpUnreachable
            }
            RetriedRequestError::Status(status) if is_retryable_status(status) => {
                warn!(
                    endpoint,
                    %status,
                    "S2S token endpoint exhausted retryable failures"
                );
                AuthNError::IdpUnreachable
            }
            RetriedRequestError::Status(status) => {
                let msg = format!("token endpoint returned {status}");
                warn!(endpoint, %status, "S2S token acquisition failed");
                AuthNError::TokenAcquisitionFailed(msg)
            }
        })?;

        response.json().await.map_err(|e| {
            warn!(endpoint, error = %e, "Failed to parse token endpoint response");
            AuthNError::TokenAcquisitionFailed(format!("response parse failed: {e}"))
        })
    }
}

#[async_trait::async_trait]
impl ClientCredentialsExchanger for TokenClient {
    async fn exchange(&self, request: &ClientCredentialsRequest) -> Result<String, AuthNError> {
        TokenClient::exchange(self, request).await
    }
}

#[cfg(test)]
#[path = "token_client_tests.rs"]
mod token_client_tests;
