use modkit_macros::domain_model;
use oagw_sdk::error::ServiceGatewayError;
use uuid::Uuid;

use super::repo::RepositoryError;

/// Domain-layer errors for OAGW control-plane and data-plane operations.
#[domain_model]
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("{entity} not found: {id}")]
    NotFound { entity: &'static str, id: Uuid },

    #[error("conflict: {detail}")]
    Conflict { detail: String },

    #[error("validation: {detail}")]
    Validation { detail: String },

    #[error("upstream '{alias}' is disabled")]
    UpstreamDisabled { alias: String },

    #[error("internal: {message}")]
    Internal { message: String },

    #[error("target host header required for multi-endpoint upstream")]
    MissingTargetHost,

    #[error("invalid target host header format")]
    InvalidTargetHost,

    #[error("{detail}")]
    UnknownTargetHost { detail: String },

    #[error("{detail}")]
    AuthenticationFailed { detail: String },

    #[error("{detail}")]
    PayloadTooLarge { detail: String },

    #[error("{detail}")]
    RateLimitExceeded {
        detail: String,
        retry_after_secs: Option<u64>,
    },

    #[error("{detail}")]
    SecretNotFound { detail: String },

    #[error("{detail}")]
    DownstreamError { detail: String },

    #[error("{detail}")]
    ProtocolError { detail: String },

    #[error("{detail}")]
    ConnectionTimeout { detail: String },

    #[error("{detail}")]
    RequestTimeout { detail: String },

    /// A guard plugin rejected the request with a specific status and error code.
    #[error("guard rejected: {detail}")]
    GuardRejected {
        status: u16,
        error_code: String,
        detail: String,
    },

    /// CORS: the request origin is not in the allowed origins list.
    #[error("CORS origin not allowed: {origin}")]
    CorsOriginNotAllowed { origin: String },

    /// CORS: the request method is not in the allowed methods list.
    #[error("CORS method not allowed: {method}")]
    CorsMethodNotAllowed { method: String },

    #[error("{detail}")]
    StreamAborted { detail: String },

    #[error("{detail}")]
    LinkUnavailable { detail: String },

    #[error("{detail}")]
    CircuitBreakerOpen { detail: String },

    #[error("{detail}")]
    IdleTimeout { detail: String },

    #[error("plugin not found: {detail}")]
    PluginNotFound { detail: String },

    #[error("plugin in use: {detail}")]
    PluginInUse { detail: String },

    /// The request was denied by the authorization policy.
    #[error("access forbidden: {detail}")]
    Forbidden { detail: String },
}

impl DomainError {
    #[must_use]
    pub fn not_found(entity: &'static str, id: Uuid) -> Self {
        Self::NotFound { entity, id }
    }

    #[must_use]
    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::Conflict {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn validation(detail: impl Into<String>) -> Self {
        Self::Validation {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn upstream_disabled(alias: impl Into<String>) -> Self {
        Self::UpstreamDisabled {
            alias: alias.into(),
        }
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Construct a [`DomainError::Forbidden`] with the given detail message.
    #[must_use]
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::Forbidden {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn protocol(detail: impl Into<String>) -> Self {
        Self::ProtocolError {
            detail: detail.into(),
        }
    }
}

impl From<DomainError> for ServiceGatewayError {
    fn from(e: DomainError) -> Self {
        match e {
            DomainError::NotFound { entity, id } => ServiceGatewayError::NotFound {
                entity: entity.to_string(),
                id: id.to_string(),
            },
            DomainError::Conflict { detail } => ServiceGatewayError::ValidationError { detail },
            DomainError::Validation { detail } => ServiceGatewayError::ValidationError { detail },
            DomainError::UpstreamDisabled { alias } => ServiceGatewayError::UpstreamDisabled {
                detail: format!("upstream '{alias}' is disabled"),
            },
            DomainError::Internal { message } => {
                ServiceGatewayError::DownstreamError { detail: message }
            }
            DomainError::MissingTargetHost => ServiceGatewayError::MissingTargetHost,
            DomainError::InvalidTargetHost => ServiceGatewayError::InvalidTargetHost,
            DomainError::UnknownTargetHost { detail } => {
                ServiceGatewayError::UnknownTargetHost { detail }
            }
            DomainError::AuthenticationFailed { detail } => {
                ServiceGatewayError::AuthenticationFailed { detail }
            }
            DomainError::PayloadTooLarge { detail } => {
                ServiceGatewayError::PayloadTooLarge { detail }
            }
            DomainError::RateLimitExceeded {
                detail,
                retry_after_secs,
            } => ServiceGatewayError::RateLimitExceeded {
                detail,
                retry_after_secs,
            },
            DomainError::SecretNotFound { detail } => {
                ServiceGatewayError::SecretNotFound { detail }
            }
            DomainError::DownstreamError { detail } => {
                ServiceGatewayError::DownstreamError { detail }
            }
            DomainError::ProtocolError { detail } => ServiceGatewayError::ProtocolError { detail },
            DomainError::ConnectionTimeout { detail } => {
                ServiceGatewayError::ConnectionTimeout { detail }
            }
            DomainError::RequestTimeout { detail } => {
                ServiceGatewayError::RequestTimeout { detail }
            }
            DomainError::GuardRejected {
                status,
                error_code,
                detail,
            } => ServiceGatewayError::GuardRejected {
                status,
                error_code,
                detail,
            },
            DomainError::CorsOriginNotAllowed { origin, .. } => ServiceGatewayError::Forbidden {
                detail: format!("CORS origin not allowed: {origin}"),
            },
            DomainError::CorsMethodNotAllowed { method, .. } => ServiceGatewayError::Forbidden {
                detail: format!("CORS method not allowed: {method}"),
            },
            DomainError::StreamAborted { detail } => ServiceGatewayError::StreamAborted { detail },
            DomainError::LinkUnavailable { detail } => {
                ServiceGatewayError::LinkUnavailable { detail }
            }
            DomainError::CircuitBreakerOpen { detail } => {
                ServiceGatewayError::CircuitBreakerOpen { detail }
            }
            DomainError::IdleTimeout { detail } => ServiceGatewayError::IdleTimeout { detail },
            DomainError::PluginNotFound { detail } => {
                ServiceGatewayError::PluginNotFound { detail }
            }
            DomainError::PluginInUse { detail } => ServiceGatewayError::PluginInUse { detail },
            DomainError::Forbidden { detail } => ServiceGatewayError::Forbidden { detail },
        }
    }
}

// ---------------------------------------------------------------------------
// From<RepositoryError>
// ---------------------------------------------------------------------------

impl From<RepositoryError> for DomainError {
    fn from(e: RepositoryError) -> Self {
        match e {
            RepositoryError::NotFound { entity, id } => Self::NotFound { entity, id },
            RepositoryError::Conflict(detail) => Self::Conflict { detail },
            RepositoryError::Internal(message) => Self::Internal { message },
        }
    }
}

// ---------------------------------------------------------------------------
// From<TenantResolverError>
// ---------------------------------------------------------------------------

impl From<tenant_resolver_sdk::TenantResolverError> for DomainError {
    fn from(e: tenant_resolver_sdk::TenantResolverError) -> Self {
        use tenant_resolver_sdk::TenantResolverError;

        match e {
            TenantResolverError::TenantNotFound { tenant_id } => {
                tracing::warn!(tenant_id = %tenant_id, "tenant not found during hierarchy resolution");
                Self::NotFound {
                    entity: "tenant",
                    id: tenant_id.0,
                }
            }
            TenantResolverError::Unauthorized => Self::Forbidden {
                detail: "tenant resolver: unauthorized".to_string(),
            },
            TenantResolverError::NoPluginAvailable => Self::Internal {
                message: "tenant resolver: no plugin available".to_string(),
            },
            TenantResolverError::ServiceUnavailable(msg) => Self::Internal {
                message: format!("tenant resolver unavailable: {msg}"),
            },
            TenantResolverError::Internal(msg) => Self::Internal {
                message: format!("tenant resolver internal error: {msg}"),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// From<EnforcerError>
// ---------------------------------------------------------------------------

/// Convert an authorization enforcer error into a domain error.
impl From<authz_resolver_sdk::EnforcerError> for DomainError {
    fn from(e: authz_resolver_sdk::EnforcerError) -> Self {
        use authz_resolver_sdk::EnforcerError;

        tracing::error!(error = %e, "OAGW authorization check failed");
        match e {
            EnforcerError::Denied { deny_reason } => {
                let detail = deny_reason
                    .map(|r| format!("{}: {}", r.error_code, r.details.unwrap_or_default()))
                    .unwrap_or_else(|| "access denied by policy".to_string());
                Self::Forbidden { detail }
            }
            EnforcerError::CompileFailed(_) => Self::Internal {
                message: "authorization constraint compilation failed".to_string(),
            },
            EnforcerError::EvaluationFailed(_) => Self::Internal {
                message: "authorization evaluation failed".to_string(),
            },
        }
    }
}
