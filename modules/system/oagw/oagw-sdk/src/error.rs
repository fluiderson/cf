/// Gateway-originated error with all information needed to produce a Problem Details response.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ServiceGatewayError {
    #[error("{detail}")]
    ValidationError { detail: String },

    #[error("target host header required for multi-endpoint upstream")]
    MissingTargetHost,

    #[error("invalid target host header format")]
    InvalidTargetHost,

    #[error("{detail}")]
    UnknownTargetHost { detail: String },

    #[error("{detail}")]
    AuthenticationFailed { detail: String },

    #[error("{entity}/{id} not found")]
    NotFound { entity: String, id: String },

    #[error("no matching route found")]
    RouteNotFound,

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
    UpstreamDisabled { detail: String },

    #[error("{detail}")]
    ConnectionTimeout { detail: String },

    #[error("{detail}")]
    RequestTimeout { detail: String },

    /// A guard plugin rejected the request.
    #[error("guard rejected: {detail}")]
    GuardRejected {
        status: u16,
        error_code: String,
        detail: String,
    },

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

    /// The caller is authenticated but not authorized to perform the requested action.
    #[error("access forbidden: {detail}")]
    Forbidden { detail: String },
}

/// Errors produced by the streaming helpers.
#[derive(Debug, thiserror::Error)]
pub enum StreamingError {
    /// SSE parse error — a chunk could not be decoded as UTF-8.
    #[error("SSE parse error: {detail}")]
    ServerEventsParse { detail: String },

    /// Underlying byte stream produced an error.
    #[error("stream error: {0}")]
    Stream(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// WebSocket connection to upstream failed.
    #[error("WebSocket connect error: {detail}")]
    WebSocketConnect { detail: String },

    /// WebSocket bridge error during forwarding.
    #[error("WebSocket bridge error: {detail}")]
    WebSocketBridge { detail: String },
}
