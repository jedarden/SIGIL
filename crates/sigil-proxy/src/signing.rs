//! AWS SigV4 request signing

use crate::ProxyError;
use chrono::Utc;
use hex::encode;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Result of signing operation
pub type SignResult<T> = Result<T, ProxyError>;

/// AWS SigV4 signer
pub struct AwsSigV4Signer {
    access_key: String,
    secret_key: String,
    region: String,
    service: String,
}

impl AwsSigV4Signer {
    /// Create a new AWS SigV4 signer
    pub fn new(access_key: String, secret_key: String, region: String, service: String) -> Self {
        Self {
            access_key,
            secret_key,
            region,
            service,
        }
    }

    /// Sign an HTTP request
    ///
    /// Returns the Authorization header value
    pub fn sign_request(
        &self,
        method: &str,
        host: &str,
        path: &str,
        query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> SignResult<String> {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        // Build canonical request
        let canonical_headers = self.build_canonical_headers(host, headers, &amz_date);
        let signed_headers = self.get_signed_headers(headers);
        let payload_hash = hex_digest(body);

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            self.canonical_path(path),
            self.canonical_query(query),
            canonical_headers,
            signed_headers,
            payload_hash
        );

        // Create string to sign
        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            date_stamp, self.region, self.service
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            hex_digest(canonical_request.as_bytes())
        );

        // Calculate signature
        let signing_key = self.get_signing_key(&date_stamp)?;
        let signature = self.calculate_signature(&signing_key, &string_to_sign)?;

        // Build authorization header
        let authorization_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, credential_scope, signed_headers, signature
        );

        Ok(authorization_header)
    }

    fn build_canonical_headers(
        &self,
        host: &str,
        headers: &[(String, String)],
        amz_date: &str,
    ) -> String {
        let mut canonical_headers = String::new();
        let mut header_map: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();

        // Add host header
        header_map.insert("host".to_string(), host.to_lowercase());

        // Add x-amz-date header
        header_map.insert("x-amz-date".to_string(), amz_date.to_string());

        // Add other headers
        for (k, v) in headers {
            header_map.insert(k.to_lowercase(), v.trim().to_string());
        }

        // Build canonical headers string
        for (k, v) in &header_map {
            canonical_headers.push_str(&format!("{}:{}\n", k.to_lowercase(), v));
        }

        canonical_headers
    }

    fn get_signed_headers(&self, headers: &[(String, String)]) -> String {
        let mut signed_headers = vec!["host".to_string(), "x-amz-date".to_string()];

        for (k, _) in headers {
            let lower = k.to_lowercase();
            if !signed_headers.contains(&lower) && lower != "authorization" {
                signed_headers.push(lower);
            }
        }

        signed_headers.sort();
        signed_headers.join(";")
    }

    fn canonical_path(&self, path: &str) -> String {
        // URI-encode the path except for slashes
        path.chars()
            .map(|c| match c {
                '/' => "/".to_string(),
                _ => urlencoding::encode(&c.to_string()).to_string(),
            })
            .collect()
    }

    fn canonical_query(&self, query: &str) -> String {
        if query.is_empty() {
            return String::new();
        }

        // Sort and encode query parameters
        let params: Vec<&str> = query.split('&').collect();
        let mut sorted_params = params.to_vec();
        sorted_params.sort();

        sorted_params
            .iter()
            .map(|p| {
                if let Some((k, v)) = p.split_once('=') {
                    format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))
                } else {
                    urlencoding::encode(p).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    fn get_signing_key(&self, date_stamp: &str) -> SignResult<Vec<u8>> {
        let k_date = Self::hmac_sha256(
            format!("AWS4{}", self.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        )?;

        let k_region = Self::hmac_sha256(&k_date, self.region.as_bytes())?;
        let k_service = Self::hmac_sha256(&k_region, self.service.as_bytes())?;
        let k_signing = Self::hmac_sha256(&k_service, b"aws4_request")?;

        Ok(k_signing)
    }

    fn calculate_signature(&self, key: &[u8], data: &str) -> SignResult<String> {
        Ok(encode(Self::hmac_sha256(key, data.as_bytes())?))
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> SignResult<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| ProxyError::SigningError(format!("HMAC error: {}", e)))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

fn hex_digest(data: &[u8]) -> String {
    encode(sha2::Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_get_request() {
        let signer = AwsSigV4Signer::new(
            "AKIDEXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            "us-east-1".to_string(),
            "iam".to_string(),
        );

        let auth = signer
            .sign_request("GET", "example.amazonaws.com", "/", "", &[], b"")
            .unwrap();

        assert!(auth.contains("AWS4-HMAC-SHA256"));
        assert!(auth.contains("Credential=AKIDEXAMPLE"));
        assert!(auth.contains("SignedHeaders="));
        assert!(auth.contains("Signature="));
    }

    #[test]
    fn test_sign_post_request() {
        let signer = AwsSigV4Signer::new(
            "AKIDEXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            "us-east-1".to_string(),
            "s3".to_string(),
        );

        let body = r#"{"test": "data"}"#;
        let auth = signer
            .sign_request(
                "POST",
                "example.s3.amazonaws.com",
                "/test",
                "",
                &[("content-type".to_string(), "application/json".to_string())],
                body.as_bytes(),
            )
            .unwrap();

        assert!(auth.contains("AWS4-HMAC-SHA256"));
        assert!(auth.contains("content-type"));
    }
}
