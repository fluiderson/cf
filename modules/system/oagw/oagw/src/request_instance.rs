use std::convert::Infallible;

use axum::extract::FromRequestParts;
use http::{Uri, request::Parts};

/// RFC 9457 `instance` value derived from an HTTP request target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestInstance(String);

impl RequestInstance {
    #[must_use]
    pub(crate) fn from_uri(uri: &Uri) -> Self {
        Self(
            uri.path_and_query()
                .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string()),
        )
    }

    /// Trusted constructor for values already derived from an inbound request URI.
    #[must_use]
    pub(crate) fn from_trusted(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<RequestInstance> for String {
    fn from(instance: RequestInstance) -> Self {
        instance.0
    }
}

impl AsRef<str> for RequestInstance {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<S: Sync> FromRequestParts<S> for RequestInstance {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(RequestInstance::from_uri(&parts.uri))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_uses_path_when_query_absent() {
        let uri: Uri = "/oagw/v1/upstreams".parse().unwrap();
        let instance = RequestInstance::from_uri(&uri);
        assert_eq!(instance.as_str(), "/oagw/v1/upstreams");
    }

    #[test]
    fn from_uri_preserves_query_string() {
        let uri: Uri = "/oagw/v1/routes?limit=10&offset=20".parse().unwrap();
        let instance = RequestInstance::from_uri(&uri);
        assert_eq!(instance.as_str(), "/oagw/v1/routes?limit=10&offset=20");
    }

    #[test]
    fn from_uri_preserves_proxy_wildcard_query() {
        let uri: Uri = "/oagw/v1/proxy/api.openai.com/v1/chat/completions?model=gpt-4"
            .parse()
            .unwrap();
        let instance = RequestInstance::from_uri(&uri);
        assert_eq!(
            instance.as_str(),
            "/oagw/v1/proxy/api.openai.com/v1/chat/completions?model=gpt-4"
        );
    }
}
