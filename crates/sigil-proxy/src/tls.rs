//! MITM TLS certificate generation and interception
//!
//! This module provides functionality for generating per-session CA certificates
//! and intercepting TLS connections for HTTPS traffic inspection and modification.

use crate::ProxyError;
// Import rcgen types with explicit paths to avoid conflicts
use rcgen::{
    BasicConstraints as RcgenBasicConstraints, Certificate, CertificateParams, DnType,
    ExtendedKeyUsagePurpose, Ia5String, KeyPair, SanType,
};
use std::sync::Arc;
// Use explicit path to avoid conflict with x509_parser's time module
use ::time::OffsetDateTime;
use x509_parser::prelude::*;

#[cfg(test)]
use base64::Engine;

/// Result type for TLS operations
pub type TlsResult<T> = Result<T, ProxyError>;

/// Per-session CA certificate for MITM TLS
#[derive(Clone)]
pub struct MitmCa {
    /// The CA certificate (wrapped in Arc for thread-safe sharing)
    cert: Arc<Certificate>,
    /// The CA key pair (wrapped in Arc for thread-safe sharing)
    key_pair: Arc<KeyPair>,
    /// The PEM-encoded certificate
    cert_pem: String,
    /// The PEM-encoded private key
    key_pem: String,
}

impl MitmCa {
    /// Generate a new per-session CA certificate
    ///
    /// The CA certificate is valid for 24 hours and is generated
    /// specifically for this session to prevent certificate accumulation.
    pub fn generate() -> TlsResult<Self> {
        let now = OffsetDateTime::now_utc();

        // Create CA certificate parameters
        let mut params = CertificateParams::default();
        params.not_before = now;
        params.not_after = now + ::time::Duration::hours(24);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "SIGIL MITM CA");
        params
            .distinguished_name
            .push(DnType::CommonName, "SIGIL Session CA");

        // Mark as CA certificate
        params.is_ca = rcgen::IsCa::Ca(RcgenBasicConstraints::Unconstrained);

        // Add key usage extensions for CA
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        // Add extended key usage for server and client auth
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        // Generate the certificate
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        // Serialize to PEM
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        Ok(Self {
            cert: Arc::new(cert),
            key_pair: Arc::new(key_pair),
            cert_pem,
            key_pem,
        })
    }

    /// Get the CA certificate in PEM format
    ///
    /// This should be added to the sandbox's trust store.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Get the CA private key in PEM format
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Generate a certificate for a specific domain
    ///
    /// This creates a certificate signed by the CA for the target domain,
    /// allowing the proxy to intercept TLS connections.
    pub fn generate_cert_for_domain(&self, domain: &str) -> TlsResult<String> {
        let now = OffsetDateTime::now_utc();

        // Create certificate parameters for the target domain
        let mut params = CertificateParams::default();
        params.not_before = now;
        params.not_after = now + ::time::Duration::hours(24);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "SIGIL MITM");
        params.distinguished_name.push(DnType::CommonName, domain);

        // Add Subject Alternative Name for the domain
        params
            .subject_alt_names
            .push(SanType::DnsName(Ia5String::try_from(domain.to_string())?));

        // Mark as end-entity certificate (not CA)
        params.is_ca = rcgen::IsCa::NoCa;

        // Add key usage for server auth
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);

        // Generate the certificate signed by our CA
        let key_pair = KeyPair::generate()?;
        let cert = params.signed_by(&key_pair, &self.cert, &self.key_pair)?;

        Ok(cert.pem())
    }

    /// Parse a DER-encoded certificate to extract the domain
    pub fn extract_domain_from_cert(der: &[u8]) -> TlsResult<String> {
        let (_, parsed) = X509Certificate::from_der(der)
            .map_err(|e| ProxyError::TlsError(format!("Failed to parse certificate: {:?}", e)))?;

        // Extract CN from subject
        if let Some(cn) = parsed.subject().iter_common_name().next() {
            if let Ok(s) = cn.as_str() {
                return Ok(s.to_string());
            }
        }

        // Try SAN (Subject Alternative Name) if CN fails
        if let Ok(Some(san)) = parsed.subject_alternative_name() {
            let general_names = &san.value.general_names;
            for name in general_names {
                // Handle the SAN from x509-parser, not rcgen's SanType
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    return Ok(dns.to_string());
                }
            }
        }

        Err(ProxyError::TlsError(
            "Could not extract domain from certificate".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mitm_ca() {
        let ca = MitmCa::generate().unwrap();

        // Check that the CA certificate is valid
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.cert_pem().contains("END CERTIFICATE"));
        assert!(ca.key_pem().contains("BEGIN PRIVATE KEY"));
        assert!(ca.key_pem().contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_generate_cert_for_domain() {
        let ca = MitmCa::generate().unwrap();
        let cert = ca.generate_cert_for_domain("example.com").unwrap();

        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(cert.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_extract_domain_from_cert() {
        let ca = MitmCa::generate().unwrap();
        let cert_pem = ca.generate_cert_for_domain("test.example.com").unwrap();

        // Extract the DER-encoded bytes from the PEM string
        // PEM format is: -----BEGIN CERTIFICATE----- <base64> -----END CERTIFICATE-----
        let der_bytes = cert_pem
            .lines()
            .skip_while(|line| !line.starts_with("-----BEGIN"))
            .skip(1)
            .take_while(|line| !line.starts_with("-----END"))
            .fold(String::new(), |mut acc, line| {
                acc.push_str(line.trim());
                acc
            });

        let der = base64::engine::general_purpose::STANDARD
            .decode(der_bytes)
            .unwrap();
        let domain = MitmCa::extract_domain_from_cert(&der).unwrap();

        assert_eq!(domain, "test.example.com");
    }
}
