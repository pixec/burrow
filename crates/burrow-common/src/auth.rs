//! Bearer-token authentication for the gRPC APIs.
//!
//! One shared secret guards both surfaces: clients present it to the
//! orchestrator, and the orchestrator presents it to nodes. Per-tenant
//! credentials would need a real identity model, which this deliberately is
//! not.
//!
//! Authentication is *off* when no token is configured, so the stack runs out
//! of the box. Callers are expected to warn about that at startup; see
//! [`TokenAuth::is_enabled`].

// tonic's `Status` is large by design; boxing it would only obscure the
// signatures of functions that exist to return one.
#![allow(clippy::result_large_err)]

use tonic::metadata::MetadataMap;
use tonic::{Request, Status};

#[derive(Clone, Default)]
pub struct TokenAuth {
    tokens: Vec<String>,
}

impl TokenAuth {
    /// Accepts any of `tokens`. Empty input disables authentication.
    pub fn new(tokens: impl IntoIterator<Item = String>) -> Self {
        Self {
            tokens: tokens
                .into_iter()
                .filter(|t| !t.trim().is_empty())
                .collect(),
        }
    }

    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn is_enabled(&self) -> bool {
        !self.tokens.is_empty()
    }

    /// Rejects a request whose `authorization` header does not carry a
    /// recognised bearer token.
    pub fn check(&self, metadata: &MetadataMap) -> Result<(), Status> {
        if !self.is_enabled() {
            return Ok(());
        }
        let header = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| Status::unauthenticated("missing authorization header"))?;

        let presented = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or_else(|| Status::unauthenticated("expected a Bearer token"))?
            .trim();

        if self
            .tokens
            .iter()
            .any(|token| constant_time_eq(token.as_bytes(), presented.as_bytes()))
        {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid token"))
        }
    }
}

/// Lets a `TokenAuth` be handed straight to `with_interceptor`.
impl tonic::service::Interceptor for TokenAuth {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        self.check(req.metadata())?;
        Ok(req)
    }
}

/// Compares two secrets without an early exit, so a caller cannot recover a
/// token byte by byte from response timing. Length is not hidden.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    difference == 0
}

/// Loads tokens from a value or a file.
///
/// A path is preferred in production: a token on a command line is visible in
/// `ps` output to every user on the host.
pub fn load_tokens(inline: Option<&str>, path: Option<&std::path::Path>) -> Vec<String> {
    let mut tokens = Vec::new();
    if let Some(value) = inline {
        tokens.push(value.to_string());
    }
    if let Some(path) = path {
        match std::fs::read_to_string(path) {
            Ok(contents) => tokens.extend(
                contents
                    .lines()
                    .map(str::trim)
                    // `#` comments so a token file can be annotated.
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(str::to_string),
            ),
            Err(err) => {
                tracing::error!(path = %path.display(), %err, "cannot read token file");
            }
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(value: &str) -> MetadataMap {
        let mut md = MetadataMap::new();
        md.insert("authorization", value.parse().unwrap());
        md
    }

    #[test]
    fn disabled_auth_accepts_anything() {
        let auth = TokenAuth::disabled();
        assert!(!auth.is_enabled());
        assert!(auth.check(&MetadataMap::new()).is_ok());
    }

    #[test]
    fn a_configured_token_is_required() {
        let auth = TokenAuth::new(["secret".to_string()]);
        assert!(auth.check(&MetadataMap::new()).is_err());
        assert!(auth.check(&metadata("Bearer secret")).is_ok());
        assert!(auth.check(&metadata("bearer secret")).is_ok());
    }

    #[test]
    fn wrong_or_malformed_tokens_are_rejected() {
        let auth = TokenAuth::new(["secret".to_string()]);
        assert!(auth.check(&metadata("Bearer wrong")).is_err());
        assert!(auth.check(&metadata("secret")).is_err());
        assert!(auth.check(&metadata("Basic secret")).is_err());
        // A prefix of the real token must not pass.
        assert!(auth.check(&metadata("Bearer sec")).is_err());
    }

    #[test]
    fn any_configured_token_is_accepted_so_keys_can_be_rotated() {
        let auth = TokenAuth::new(["old".to_string(), "new".to_string()]);
        assert!(auth.check(&metadata("Bearer old")).is_ok());
        assert!(auth.check(&metadata("Bearer new")).is_ok());
    }

    #[test]
    fn blank_tokens_do_not_silently_enable_auth() {
        // A misconfigured empty value must not become a token everyone knows.
        let auth = TokenAuth::new(["".to_string(), "   ".to_string()]);
        assert!(!auth.is_enabled());
    }

    #[test]
    fn comparison_rejects_different_lengths() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"abc", b"abc"));
    }
}
