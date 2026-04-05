//! HTTP forward proxy implementation

use super::{
    config::ProxyConfig,
    error::{ProxyError, ProxyResult},
    scrubber::{ResponseScrubber, ScrubContext},
    signing::AwsSigV4Signer,
};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming},
    Method, Request, Response, StatusCode, Uri, Version,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

/// HTTP forward proxy server
#[derive(Clone)]
pub struct ProxyServer {
    config: Arc<ProxyConfig>,
    client: Client<HttpConnector, Full<Bytes>>,
}

impl ProxyServer {
    /// Create a new proxy server
    pub fn new(config: ProxyConfig) -> ProxyResult<Self> {
        let config = Arc::new(config);
        let client = Client::builder(TokioExecutor::new()).build_http();

        Ok(Self { config, client })
    }

    /// Get the actual listen address after binding
    pub async fn bind(&self) -> ProxyResult<TcpListener> {
        let addr = self.config.listen_addr()?;
        let listener = TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;
        info!("Proxy listening on {}", actual_addr);
        Ok(listener)
    }

    /// Start serving requests
    pub async fn serve(self) -> ProxyResult<()> {
        let listener = self.bind().await?;
        info!("Proxy server started on {}", listener.local_addr()?);

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            debug!("Connection from {}", remote_addr);

            let server = self.clone();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream).await {
                    error!("Connection error: {}", e);
                }
            });
        }
    }

    /// Handle a single connection
    async fn handle_connection(&self, stream: tokio::net::TcpStream) -> ProxyResult<()> {
        use hyper::server::conn::http1;
        use hyper_util::rt::TokioIo;

        let io = TokioIo::new(stream);
        let conn = http1::Builder::new().serve_connection(io, self.clone());

        conn.await?;
        Ok(())
    }

    /// Handle a single request
    async fn handle_request(
        &self,
        mut req: Request<hyper::body::Incoming>,
    ) -> ProxyResult<Response<Full<Bytes>>> {
        // Extract the target URI from the request
        let uri = req.uri().clone();
        let host = uri
            .host()
            .ok_or_else(|| ProxyError::InvalidUri("missing host".to_string()))?;

        debug!("Proxy request to {} {}", req.method(), uri);

        // Check domain allowlist
        if !self.config.is_domain_allowed(host) {
            warn!("Domain not in allowlist: {}", host);
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Domain not in allowlist")))
                .unwrap());
        }

        // Find matching rule
        let rule = self.config.find_rule_for_domain(host);
        if rule.is_none() && self.config.allowlist_only {
            warn!("No rule configured for domain: {}", host);
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("No rule configured for this domain")))
                .unwrap());
        }

        // Read request body
        let body_bytes = if req.body().size_hint().upper() > Some(0) {
            let mut body_bytes = Vec::new();
            while let Some(frame) = req.frame().await {
                let frame = frame?;
                if let Ok(chunk) = frame.into_data() {
                    body_bytes.extend_from_slice(&chunk);
                }
            }
            body_bytes
        } else {
            Vec::new()
        };

        // Apply rule (inject headers, sign request, etc.)
        if let Some(rule) = rule {
            let mut headers: HashMap<String, String> = req
                .headers()
                .iter()
                .filter_map(|(k, v)| {
                    v.to_str()
                        .ok()
                        .map(|s| (k.as_str().to_string(), s.to_string()))
                })
                .collect();

            self.apply_rule(&mut headers, &mut req, rule, host, &uri, &body_bytes)
                .await?;

            // Rebuild request with modified headers
            for (k, v) in headers {
                if let Ok(name) = hyper::header::HeaderName::from_bytes(k.as_bytes()) {
                    if let Ok(value) = hyper::header::HeaderValue::from_str(&v) {
                        req.headers_mut().insert(name, value);
                    }
                }
            }
        }

        // Forward the request
        let forwarded_req = Request::builder()
            .method(req.method().clone())
            .uri(uri.clone())
            .version(Version::HTTP_11)
            .body(Full::new(Bytes::from(body_bytes)))?;

        let response = self.client.request(forwarded_req).await?;

        // Read response body
        let (parts, body) = response.into_parts();
        let mut body_bytes = Vec::new();
        let mut body = body;
        while let Some(frame) = frame_body(&mut body).await {
            match frame {
                Ok(frame) => {
                    if let Ok(chunk) = frame.into_data() {
                        body_bytes.extend_from_slice(&chunk);
                    }
                }
                Err(_) => break,
            }
        }

        // Scrub response body if needed
        let scrubbed_body = if let Some(rule) = rule {
            self.scrub_response(&body_bytes, rule)?
        } else {
            body_bytes
        };

        // Build response
        let scrubbed_response = Response::from_parts(parts, Full::new(Bytes::from(scrubbed_body)));

        // Log audit event
        if self.config.audit_logging {
            self.log_audit(req.method(), &uri, scrubbed_response.status(), rule);
        }

        Ok(scrubbed_response)
    }

    /// Apply a proxy rule to a request
    async fn apply_rule(
        &self,
        headers: &mut HashMap<String, String>,
        req: &mut Request<Incoming>,
        rule: &super::config::ProxyRule,
        host: &str,
        uri: &Uri,
        body: &[u8],
    ) -> ProxyResult<()> {
        match &rule.rule_type {
            super::config::ProxyRuleType::Header { header, value } => {
                headers.insert(header.clone(), value.clone());
            }
            super::config::ProxyRuleType::Bearer { secret } => {
                // In a real implementation, this would resolve the secret from the vault
                // For now, we use a placeholder
                headers.insert("Authorization".to_string(), format!("Bearer {}", secret));
            }
            super::config::ProxyRuleType::AwsSigV4 {
                access_key,
                secret_key,
                region,
                service,
            } => {
                let signer = AwsSigV4Signer::new(
                    access_key.clone(),
                    secret_key.clone(),
                    region.clone(),
                    service.clone(),
                );

                let auth_header = signer.sign_request(
                    req.method().as_str(),
                    host,
                    uri.path(),
                    uri.query().unwrap_or(""),
                    &headers
                        .iter()
                        .filter(|(k, _)| *k != "host" && *k != "authorization")
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<Vec<_>>(),
                    body,
                )?;

                headers.insert("Authorization".to_string(), auth_header);
            }
            super::config::ProxyRuleType::Basic { username, password } => {
                // In a real implementation, this would resolve secrets from the vault
                let creds = format!("{}:{}", username, password);
                use base64::prelude::BASE64_STANDARD;
                let encoded = BASE64_STANDARD.encode(creds);
                headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
            }
            super::config::ProxyRuleType::Custom { headers: custom } => {
                for (k, v) in custom {
                    headers.insert(k.clone(), v.clone());
                }
            }
        }

        Ok(())
    }

    /// Scrub response body for leaked credentials
    fn scrub_response(
        &self,
        body: &[u8],
        _rule: &super::config::ProxyRule,
    ) -> ProxyResult<Vec<u8>> {
        let body_str = String::from_utf8_lossy(body);
        let ctx = ScrubContext {
            secrets: vec![], // Would be populated from the rule
            patterns: super::scrubber::default_credential_patterns(),
        };

        let scrubber = ResponseScrubber::new(&ctx)?;
        let scrubbed = scrubber.scrub(&body_str);
        Ok(scrubbed.into_bytes())
    }

    /// Log an audit event
    fn log_audit(
        &self,
        method: &Method,
        uri: &Uri,
        status: StatusCode,
        rule: Option<&super::config::ProxyRule>,
    ) {
        info!(
            "Proxy: {} {} -> {} (rule: {})",
            method,
            uri,
            status.as_u16(),
            rule.map(|r| r.domain.as_str()).unwrap_or("none")
        );
    }
}

/// Helper to get the next frame from a body
async fn frame_body(body: &mut Incoming) -> Option<Result<Frame<Bytes>, hyper::Error>> {
    body.frame().await
}

impl hyper::service::Service<Request<Incoming>> for ProxyServer {
    type Response = Response<Full<Bytes>>;
    type Error = ProxyError;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let server = self.clone();
        Box::pin(async move { server.handle_request(req).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_server_creation() {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config);
        assert!(server.is_ok());
    }

    #[test]
    fn test_domain_allowlist() {
        let mut config = ProxyConfig {
            allowlist_only: true,
            ..Default::default()
        };

        let rule = super::super::config::ProxyRule {
            domain: "example.com".to_string(),
            rule_type: super::super::config::ProxyRuleType::Header {
                header: "Authorization".to_string(),
                value: "Bearer test".to_string(),
            },
        };

        config.rules.push(rule);

        assert!(config.is_domain_allowed("example.com"));
        assert!(!config.is_domain_allowed("other.com"));
    }
}
