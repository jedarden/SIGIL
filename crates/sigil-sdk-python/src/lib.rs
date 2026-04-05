//! SIGIL SDK Python Bindings
//!
//! This module provides Python bindings for the SIGIL SDK using PyO3.
//! Python users can install via `pip install sigil-sdk` and use the client
//! to interact with the SIGIL daemon.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3_asyncio::tokio::future_into_py;
use sigil_core::SigilError;
use sigil_sdk::{
    client::{AccessGrant, DaemonStatusInfo, SecretMetadata},
    SigilClient,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// SIGIL SDK Client for Python
///
/// This client communicates with the sigild daemon via IPC to:
/// - Get, list, and check for secrets
/// - Resolve placeholders in strings
/// - Request access to secrets
/// - Scrub secrets from output
///
/// # Example
///
/// ```python
/// import asyncio
/// from sigil_sdk import SigilClient
///
/// async def main():
///     client = await SigilClient.connect_default()
///     api_key = await client.get("kalshi/api_key")
///     print(f"Got API key: {api_key}")
///
/// asyncio.run(main())
/// ```
#[pyclass]
pub struct PySigilClient {
    client: Arc<Mutex<SigilClient>>,
}

#[pymethods]
impl PySigilClient {
    /// Create a new client with the default socket path
    ///
    /// # Returns
    ///
    /// A new `PySigilClient` instance
    ///
    /// # Example
    ///
    /// ```python
    /// client = await PySigilClient.connect_default()
    /// ```
    #[staticmethod]
    fn connect_default(py: Python<'_>) -> PyResult<&PyAny> {
        future_into_py(py, async move {
            let client = SigilClient::connect_default()
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            client
                .connect()
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            Ok(PySigilClient {
                client: Arc::new(Mutex::new(client)),
            })
        })
    }

    /// Create a new client with a custom socket path
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the SIGIL daemon Unix socket
    ///
    /// # Returns
    ///
    /// A new `PySigilClient` instance
    ///
    /// # Example
    ///
    /// ```python
    /// client = await PySigilClient.connect("/tmp/sigil.sock")
    /// ```
    #[staticmethod]
    fn connect<'a>(socket_path: &str, py: Python<'a>) -> PyResult<&'a PyAny> {
        let path = socket_path.to_string();
        future_into_py(py, async move {
            let client = SigilClient::new(PathBuf::from(path))
                .map_err(|e: sigil_core::SigilError| PyRuntimeError::new_err(e.to_string()))?;
            client
                .connect()
                .await
                .map_err(|e: sigil_core::SigilError| PyRuntimeError::new_err(e.to_string()))?;

            Ok(PySigilClient {
                client: Arc::new(Mutex::new(client)),
            })
        })
    }

    /// Resolve a single secret by path
    ///
    /// # Arguments
    ///
    /// * `path` - Secret path (e.g., "kalshi/api_key")
    ///
    /// # Returns
    ///
    /// The secret value as a string
    ///
    /// # Example
    ///
    /// ```python
    /// api_key = await client.get("kalshi/api_key")
    /// ```
    fn get<'a>(&self, path: &str, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.client.clone();
        let path = path.to_string();
        future_into_py(py, async move {
            let client = client.lock().await;
            let value = client
                .get(&path)
                .await
                .map_err(|e: SigilError| PyRuntimeError::new_err(e.to_string()))?;

            // Expose the secret value
            value
                .expose(|bytes| Ok(String::from_utf8_lossy(bytes).to_string()))
                .map_err(|e: SigilError| PyRuntimeError::new_err(e.to_string()))
        })
    }

    /// Check if a secret exists
    ///
    /// # Arguments
    ///
    /// * `path` - Secret path to check
    ///
    /// # Returns
    ///
    /// `True` if the secret exists, `False` otherwise
    ///
    /// # Example
    ///
    /// ```python
    /// exists = await client.exists("kalshi/api_key")
    /// if exists:
    ///     print("Secret exists!")
    /// ```
    fn exists<'a>(&self, path: &str, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.client.clone();
        let path = path.to_string();
        future_into_py(py, async move {
            let client = client.lock().await;
            let exists = client
                .exists(&path)
                .await
                .map_err(|e: SigilError| PyRuntimeError::new_err(e.to_string()))?;
            Ok(exists)
        })
    }

    /// List secrets with optional prefix filter
    ///
    /// # Arguments
    ///
    /// * `prefix` - Optional prefix to filter secrets (e.g., "aws/")
    ///
    /// # Returns
    ///
    /// A list of dictionaries containing secret metadata
    ///
    /// # Example
    ///
    /// ```python
    /// secrets = await client.list("aws/")
    /// for secret in secrets:
    ///     print(f"{secret['path']}: {secret['type']}")
    /// ```
    fn list<'a>(&self, prefix: &str, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.client.clone();
        let prefix = prefix.to_string();
        future_into_py(py, async move {
            let client = client.lock().await;
            let secrets = client
                .list(&prefix)
                .await
                .map_err(|e: SigilError| PyRuntimeError::new_err(e.to_string()))?;

            // Convert to Python-friendly format
            let py_secrets: Vec<PySecretMetadata> = secrets
                .into_iter()
                .map(|s| PySecretMetadata {
                    path: s.path,
                    secret_type: s.secret_type,
                    created_at: s.created_at,
                    updated_at: s.updated_at,
                    tags: s.tags,
                    notes: s.notes,
                })
                .collect();

            Ok(py_secrets)
        })
    }

    /// Resolve a string containing secret placeholders
    ///
    /// # Arguments
    ///
    /// * `input` - String containing placeholders like `{{secret:path}}`
    ///
    /// # Returns
    ///
    /// The resolved string with placeholders replaced by actual values
    ///
    /// # Example
    ///
    /// ```python
    /// resolved = await client.resolve("Bearer {{secret:kalshi/api_key}}")
    /// ```
    fn resolve<'a>(&self, input: &str, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.client.clone();
        let input = input.to_string();
        future_into_py(py, async move {
            let client = client.lock().await;
            let resolved = client
                .resolve(&input)
                .await
                .map_err(|e: SigilError| PyRuntimeError::new_err(e.to_string()))?;
            Ok(resolved)
        })
    }

    /// Request access to a secret (triggers TUI approval workflow)
    ///
    /// # Arguments
    ///
    /// * `path` - Secret path to request access for
    /// * `reason` - Reason for the access request
    /// * `duration_secs` - Optional duration in seconds for time-bounded access
    ///
    /// # Returns
    ///
    /// A dictionary with `granted` (bool) and `expires_at` (optional string)
    ///
    /// # Example
    ///
    /// ```python
    /// grant = await client.request_access("prod/db_password", "Running migrations", 300)
    /// if grant["granted"]:
    ///     print("Access granted!")
    /// ```
    #[pyo3(signature = (path, reason, duration_secs = None))]
    fn request_access<'a>(
        &self,
        path: &str,
        reason: &str,
        duration_secs: Option<u32>,
        py: Python<'a>,
    ) -> PyResult<&'a PyAny> {
        let client = self.client.clone();
        let path = path.to_string();
        let reason = reason.to_string();
        future_into_py(py, async move {
            let client = client.lock().await;
            let grant = client
                .request_access(&path, &reason, duration_secs)
                .await
                .map_err(|e: SigilError| PyRuntimeError::new_err(e.to_string()))?;

            Ok(PyAccessGrant {
                granted: grant.granted,
                expires_at: grant.expires_at,
            })
        })
    }

    /// Scrub secrets from output
    ///
    /// # Arguments
    ///
    /// * `output` - Output string that may contain secrets
    ///
    /// # Returns
    ///
    /// The scrubbed output with secrets removed
    ///
    /// # Example
    ///
    /// ```python
    /// scrubbed = await client.scrub("API key: sk_live_abc123")
    /// ```
    fn scrub<'a>(&self, output: &str, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.client.clone();
        let output = output.to_string();
        future_into_py(py, async move {
            let client = client.lock().await;
            let scrubbed = client
                .scrub(&output)
                .await
                .map_err(|e: SigilError| PyRuntimeError::new_err(e.to_string()))?;
            Ok(scrubbed)
        })
    }

    /// Get daemon status information
    ///
    /// # Returns
    ///
    /// A dictionary containing daemon status
    ///
    /// # Example
    ///
    /// ```python
    /// status = await client.status()
    /// print(f"Daemon running: {status['running']}")
    /// print(f"Uptime: {status['uptime_secs']} seconds")
    /// ```
    fn status<'a>(&self, py: Python<'a>) -> PyResult<&'a PyAny> {
        let client = self.client.clone();
        future_into_py(py, async move {
            let client = client.lock().await;
            let status = client
                .status()
                .await
                .map_err(|e: SigilError| PyRuntimeError::new_err(e.to_string()))?;

            Ok(PyDaemonStatusInfo {
                running: status.running,
                uptime_secs: status.uptime_secs,
                active_sessions: status.active_sessions,
                secrets_loaded: status.secrets_loaded,
            })
        })
    }
}

/// Python-friendly wrapper for secret metadata
#[pyclass]
#[derive(Clone)]
pub struct PySecretMetadata {
    /// Secret path
    #[pyo3(get, set)]
    pub path: String,
    /// Secret type
    #[pyo3(get, set)]
    pub secret_type: String,
    /// When the secret was created
    #[pyo3(get, set)]
    pub created_at: String,
    /// When the secret was last updated
    #[pyo3(get, set)]
    pub updated_at: String,
    /// Tags
    #[pyo3(get, set)]
    pub tags: Vec<String>,
    /// Notes
    #[pyo3(get, set)]
    pub notes: Option<String>,
}

impl From<SecretMetadata> for PySecretMetadata {
    fn from(meta: SecretMetadata) -> Self {
        Self {
            path: meta.path,
            secret_type: meta.secret_type,
            created_at: meta.created_at,
            updated_at: meta.updated_at,
            tags: meta.tags,
            notes: meta.notes,
        }
    }
}

/// Python-friendly wrapper for access grant result
#[pyclass]
#[derive(Clone)]
pub struct PyAccessGrant {
    /// Whether access was granted
    #[pyo3(get, set)]
    pub granted: bool,
    /// When the grant expires (if applicable)
    #[pyo3(get, set)]
    pub expires_at: Option<String>,
}

impl From<AccessGrant> for PyAccessGrant {
    fn from(grant: AccessGrant) -> Self {
        Self {
            granted: grant.granted,
            expires_at: grant.expires_at,
        }
    }
}

/// Python-friendly wrapper for daemon status
#[pyclass]
#[derive(Clone)]
pub struct PyDaemonStatusInfo {
    /// Whether the daemon is running
    #[pyo3(get, set)]
    pub running: bool,
    /// Daemon uptime in seconds
    #[pyo3(get, set)]
    pub uptime_secs: u64,
    /// Number of active sessions
    #[pyo3(get, set)]
    pub active_sessions: u32,
    /// Number of secrets loaded
    #[pyo3(get, set)]
    pub secrets_loaded: u32,
}

impl From<DaemonStatusInfo> for PyDaemonStatusInfo {
    fn from(info: DaemonStatusInfo) -> Self {
        Self {
            running: info.running,
            uptime_secs: info.uptime_secs,
            active_sessions: info.active_sessions,
            secrets_loaded: info.secrets_loaded,
        }
    }
}

/// SIGIL SDK Python module
#[pymodule]
fn sigil_sdk_python(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PySigilClient>()?;
    m.add_class::<PySecretMetadata>()?;
    m.add_class::<PyAccessGrant>()?;
    m.add_class::<PyDaemonStatusInfo>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_py_secret_metadata_conversion() {
        let meta = SecretMetadata {
            path: "test/path".to_string(),
            secret_type: "string".to_string(),
            created_at: "2024-01-01".to_string(),
            updated_at: "2024-01-02".to_string(),
            tags: vec!["tag1".to_string()],
            notes: Some("test".to_string()),
        };

        let py_meta = PySecretMetadata::from(meta);
        assert_eq!(py_meta.path, "test/path");
        assert_eq!(py_meta.secret_type, "string");
    }
}
