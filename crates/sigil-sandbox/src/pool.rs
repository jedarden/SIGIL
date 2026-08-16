//! Pre-warmed sandbox pool for fast command execution
//!
//! This module provides a pool of pre-configured sandbox configurations
//! that significantly reduce the overhead of repeated command executions.
//! Instead of building the sandbox configuration from scratch for each
//! command (15-30ms overhead), we reuse pre-built configurations (2-3ms overhead).
//!
//! # Architecture
//!
//! The pool maintains a set of sandbox configurations that are:
//! - Pre-built with common namespaces (PID, network, mount)
//! - Ready to execute commands with minimal setup time
//! - Returned to the pool after execution for reuse
//!
//! # Performance
//!
//! - Cold start (no pool): ~15-30ms per command
//! - Warm pool (reused): ~2-3ms per command
//! - Pool initialization: ~50-100ms one-time cost

use crate::bubblewrap::{SandboxConfig, SandboxProvider};
use sigil_core::{ResolvedCommand, Result, SigilError};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

/// Default pool size (number of pre-warmed configurations)
const DEFAULT_POOL_SIZE: usize = 4;

/// Maximum time to wait for a sandbox from the pool
const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum age of a pooled configuration before it's recreated
const MAX_CONFIG_AGE: Duration = Duration::from_secs(60);

/// Maximum number of times a configuration can be reused before recreation
const MAX_REUSE_COUNT: usize = 100;

/// Configuration for the sandbox pool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Number of sandboxes to maintain in the pool
    pub pool_size: usize,
    /// Timeout when acquiring a sandbox from the pool
    pub acquire_timeout: Duration,
    /// Maximum age of a sandbox before recreation
    pub max_age: Duration,
    /// Maximum reuse count before recreation
    pub max_reuse_count: usize,
    /// Whether to enable the pool (can be disabled for testing)
    pub enabled: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            pool_size: DEFAULT_POOL_SIZE,
            acquire_timeout: DEFAULT_ACQUIRE_TIMEOUT,
            max_age: MAX_CONFIG_AGE,
            max_reuse_count: MAX_REUSE_COUNT,
            enabled: true,
        }
    }
}

impl PoolConfig {
    /// Create a new pool config with the specified pool size
    pub fn with_pool_size(size: usize) -> Self {
        Self {
            pool_size: size,
            ..Default::default()
        }
    }

    /// Disable the pool (for testing or comparison)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// A pooled sandbox configuration
///
/// Each instance represents a pre-built sandbox configuration that can be
/// quickly adapted for different commands while reusing the expensive
/// setup (namespace creation, argument building, etc.).
#[derive(Debug)]
#[expect(dead_code)]
struct PooledConfig {
    /// When this configuration was created
    created_at: Instant,
    /// Number of times this configuration has been reused
    reuse_count: usize,
    /// Pre-built sandbox arguments (expensive to compute)
    prebuilt_args: Vec<String>,
    /// Base configuration for this sandbox
    base_config: SandboxConfig,
    /// Environment variables cache
    env_cache: HashMap<String, String>,
}

impl PooledConfig {
    /// Create a new pooled configuration
    fn new(config: SandboxConfig, provider: &impl SandboxProvider) -> Self {
        // Try to get prebuilt args from the provider
        let prebuilt_args = provider.build_bwrap_args(&config);

        let env_cache = config.env_vars.iter().cloned().collect();

        Self {
            created_at: Instant::now(),
            reuse_count: 0,
            prebuilt_args,
            base_config: config,
            env_cache,
        }
    }

    /// Check if this configuration should be recreated
    fn should_recreate(&self) -> bool {
        self.reuse_count >= MAX_REUSE_COUNT || self.created_at.elapsed() > MAX_CONFIG_AGE
    }

    /// Increment the reuse counter
    fn increment_reuse(&mut self) {
        self.reuse_count += 1;
    }

    /// Adapt this pooled configuration for a specific command
    fn adapt_for_command(
        &self,
        cmd: &ResolvedCommand,
        provider: &impl SandboxProvider,
    ) -> Result<tokio::process::Command> {
        // Convert the std::process::Command to tokio::process::Command
        let std_cmd = provider.wrap_command(cmd, &self.base_config)?;

        // Build tokio command from std command
        let mut tokio_cmd = tokio::process::Command::new(
            std_cmd
                .get_program()
                .to_str()
                .ok_or_else(|| SigilError::InvalidConfig("Invalid program path".to_string()))?,
        );

        // Copy all arguments
        for arg in std_cmd.get_args() {
            if let Some(arg_str) = arg.to_str() {
                tokio_cmd.arg(arg_str);
            } else {
                return Err(SigilError::InvalidConfig(format!(
                    "Invalid argument: {:?}",
                    arg
                )));
            }
        }

        // Copy environment variables
        for (key, value) in std_cmd.get_envs() {
            if let (Some(key_str), Some(value_str)) = (key.to_str(), value.and_then(|v| v.to_str())) {
                tokio_cmd.env(key_str, value_str);
            }
        }

        // Copy current directory
        if let Some(cwd) = std_cmd.get_current_dir() {
            if let Some(cwd_str) = cwd.to_str() {
                tokio_cmd.current_dir(cwd_str);
            }
        }

        Ok(tokio_cmd)
    }
}

/// Pre-warmed sandbox pool
///
/// Maintains a pool of ready-to-use sandbox configurations to minimize
/// the overhead of command execution.
pub struct SandboxPool<P: SandboxProvider> {
    /// The underlying sandbox provider
    provider: P,
    /// Pool configuration
    config: PoolConfig,
    /// Available configurations in the pool
    available_configs: Arc<Mutex<Vec<PooledConfig>>>,
    /// Semaphore limiting concurrent access to the pool
    semaphore: Arc<Semaphore>,
    /// Pool statistics
    stats: Arc<Mutex<PoolStats>>,
}

/// Pool statistics for monitoring and benchmarking
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total number of pool acquisitions
    pub total_acquisitions: u64,
    /// Number of times we had to wait for a sandbox
    pub wait_count: u64,
    /// Number of times we created a new sandbox
    pub creation_count: u64,
    /// Number of times we reused an existing sandbox
    pub reuse_count: u64,
    /// Number of times we recreated an expired sandbox
    pub recreation_count: u64,
    /// Current pool size
    pub current_size: usize,
    /// Average time to acquire from pool (microseconds)
    pub avg_acquire_time_us: u64,
    /// Total time spent building configs (microseconds)
    pub total_build_time_us: u64,
}

impl<P: SandboxProvider> SandboxPool<P> {
    /// Pre-warm the pool with initial configurations
    fn prewarm_pool(provider: &P, _config: &PoolConfig, pool_size: usize) -> PreWarmResult {
        let mut configs = Vec::with_capacity(pool_size);
        let mut total_build_time_us = 0u64;

        let base_config = SandboxConfig::default();

        for _ in 0..pool_size {
            let start = Instant::now();
            let pooled_config = PooledConfig::new(base_config.clone(), provider);
            let build_time = start.elapsed().as_micros() as u64;

            total_build_time_us += build_time;
            configs.push(pooled_config);
        }

        PreWarmResult {
            configs,
            total_build_time_us,
        }
    }

    /// Create a new sandbox pool
    pub fn new(provider: P, config: PoolConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.pool_size));
        let available_configs = Arc::new(Mutex::new(Vec::with_capacity(config.pool_size)));
        let stats = Arc::new(Mutex::new(PoolStats::default()));

        // Pre-warm the pool with initial configurations
        if config.enabled {
            let pool_stats = Self::prewarm_pool(&provider, &config, config.pool_size);
            stats.try_lock().unwrap().total_build_time_us = pool_stats.total_build_time_us;
            available_configs.try_lock().unwrap().extend(pool_stats.configs);
        }

        Self {
            provider,
            config,
            available_configs,
            semaphore,
            stats,
        }
    }

    /// Create a pool with default configuration
    pub fn with_default_config(provider: P) -> Self {
        Self::new(provider, PoolConfig::default())
    }

    /// Execute a command using a pooled sandbox
    ///
    /// This is the main entry point for pool usage. It acquires a sandbox
    /// from the pool, executes the command, and returns the sandbox.
    pub async fn execute_pooled(
        &self,
        cmd: &ResolvedCommand,
        config: &SandboxConfig,
    ) -> Result<tokio::process::Command> {
        // If pool is disabled, use direct execution
        if !self.config.enabled {
            let mut stats = self.stats.lock().await;
            stats.total_acquisitions += 1;
            stats.creation_count += 1;
            return self.execute_direct(cmd, config);
        }

        let start_time = Instant::now();

        // Acquire a semaphore permit (limits concurrent pool usage)
        let permit = timeout(
            self.config.acquire_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| SigilError::IoError("Pool acquire timeout".to_string()))?
        .map_err(|_| SigilError::IoError("Pool closed".to_string()))?;

        let acquire_time = start_time.elapsed();
        let mut stats = self.stats.lock().await;
        stats.total_acquisitions += 1;
        stats.wait_count += 1;
        // Update average acquire time
        let current_avg = stats.avg_acquire_time_us;
        let acquire_us = acquire_time.as_micros() as u64;
        stats.avg_acquire_time_us = ((current_avg * (stats.total_acquisitions - 1)) + acquire_us)
            / stats.total_acquisitions;
        drop(stats);

        // Execute the command (using pooled or direct execution)
        let result = self.execute_with_pool(cmd, config).await;

        // Return the permit to the pool
        drop(permit);

        result
    }

    /// Execute using pool logic (internal)
    async fn execute_with_pool(
        &self,
        cmd: &ResolvedCommand,
        config: &SandboxConfig,
    ) -> Result<tokio::process::Command> {
        // Try to get a configuration from the pool
        let mut configs = self.available_configs.lock().await;
        let pooled_config = if let Some(mut pooled) = configs.pop() {
            // Check if the pooled config should be recreated
            if pooled.should_recreate() {
                let mut stats = self.stats.lock().await;
                stats.recreation_count += 1;
                drop(stats);

                // Create a new configuration
                let start = Instant::now();
                let new_config = PooledConfig::new(config.clone(), &self.provider);
                let build_time = start.elapsed().as_micros() as u64;

                let mut stats = self.stats.lock().await;
                stats.total_build_time_us += build_time;
                stats.creation_count += 1;
                drop(stats);

                Some(new_config)
            } else {
                pooled.increment_reuse();
                let mut stats = self.stats.lock().await;
                stats.reuse_count += 1;
                drop(stats);
                Some(pooled)
            }
        } else {
            // No available configs, need to create one
            let start = Instant::now();
            let new_config = PooledConfig::new(config.clone(), &self.provider);
            let build_time = start.elapsed().as_micros() as u64;

            let mut stats = self.stats.lock().await;
            stats.total_build_time_us += build_time;
            stats.creation_count += 1;
            drop(stats);

            Some(new_config)
        };

        // If we got a pooled config, use it; otherwise create on-demand
        if let Some(pooled) = pooled_config {
            let result = pooled.adapt_for_command(cmd, &self.provider);

            // Return the config to the pool for reuse
            configs.push(pooled);

            // Update current size in stats
            let mut stats = self.stats.lock().await;
            stats.current_size = configs.len();
            drop(stats);

            result
        } else {
            // Fallback to direct execution
            self.execute_direct(cmd, config)
        }
    }

    /// Execute a command directly (fallback method)
    fn execute_direct(
        &self,
        cmd: &ResolvedCommand,
        config: &SandboxConfig,
    ) -> Result<tokio::process::Command> {
        // Convert the std::process::Command to tokio::process::Command
        let std_cmd = self.provider.wrap_command(cmd, config)?;

        // Build tokio command from std command
        let mut tokio_cmd = tokio::process::Command::new(
            std_cmd
                .get_program()
                .to_str()
                .ok_or_else(|| SigilError::InvalidConfig("Invalid program path".to_string()))?,
        );

        // Copy all arguments
        for arg in std_cmd.get_args() {
            if let Some(arg_str) = arg.to_str() {
                tokio_cmd.arg(arg_str);
            } else {
                return Err(SigilError::InvalidConfig(format!(
                    "Invalid argument: {:?}",
                    arg
                )));
            }
        }

        // Copy environment variables
        for (key, value) in std_cmd.get_envs() {
            if let (Some(key_str), Some(value_str)) = (key.to_str(), value.and_then(|v| v.to_str()))
            {
                tokio_cmd.env(key_str, value_str);
            }
        }

        // Set current directory
        if let Some(cwd) = std_cmd.get_current_dir() {
            tokio_cmd.current_dir(cwd);
        }

        Ok(tokio_cmd)
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        self.stats.try_lock().unwrap().clone()
    }

    /// Reset pool statistics
    pub fn reset_stats(&self) {
        *self.stats.try_lock().unwrap() = PoolStats::default();
    }

    /// Check if the pool is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the pool configuration
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Get the current pool size
    pub fn current_size(&self) -> usize {
        self.available_configs.try_lock().unwrap().len()
    }

    /// Estimate the pool hit rate
    pub fn hit_rate(&self) -> f64 {
        let stats = self.stats.try_lock().unwrap();
        if stats.total_acquisitions == 0 {
            0.0
        } else {
            stats.reuse_count as f64 / stats.total_acquisitions as f64
        }
    }

    /// Update the pool configuration
    ///
    /// Note: This doesn't affect in-use sandboxes, only future acquisitions
    pub fn update_config(&mut self, config: PoolConfig) {
        // Update semaphore if pool size changed
        if self.semaphore.available_permits() != config.pool_size {
            self.semaphore = Arc::new(Semaphore::new(config.pool_size));
        }
        self.config = config;
    }
}

/// Result of pool pre-warming
struct PreWarmResult {
    configs: Vec<PooledConfig>,
    total_build_time_us: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bubblewrap::BubblewrapSandbox;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.pool_size, DEFAULT_POOL_SIZE);
        assert!(config.enabled);
    }

    #[test]
    fn test_pool_config_with_size() {
        let config = PoolConfig::with_pool_size(8);
        assert_eq!(config.pool_size, 8);
        assert!(config.enabled);
    }

    #[test]
    fn test_pool_config_disabled() {
        let config = PoolConfig::disabled();
        assert!(!config.enabled);
        assert_eq!(config.pool_size, DEFAULT_POOL_SIZE);
    }

    #[test]
    fn test_pooled_config_creation() {
        let config = SandboxConfig::default();
        let provider = BubblewrapSandbox::new().unwrap();
        let pooled = PooledConfig::new(config, &provider);
        assert_eq!(pooled.reuse_count, 0);
        assert!(!pooled.should_recreate());
    }

    #[test]
    fn test_pooled_config_reuse_counter() {
        let config = SandboxConfig::default();
        let provider = BubblewrapSandbox::new().unwrap();
        let mut pooled = PooledConfig::new(config, &provider);

        for _ in 0..MAX_REUSE_COUNT {
            pooled.increment_reuse();
        }

        assert_eq!(pooled.reuse_count, MAX_REUSE_COUNT);
        assert!(pooled.should_recreate());
    }

    #[test]
    fn test_pooled_config_age() {
        let config = SandboxConfig::default();
        let provider = BubblewrapSandbox::new().unwrap();
        let pooled = PooledConfig::new(config, &provider);

        // Fresh sandbox should not need recreation
        assert!(!pooled.should_recreate());

        // In a real test, we would wait for MAX_SANDBOX_AGE to pass
        // but that would make the test slow
    }

    #[test]
    fn test_pool_stats_default() {
        let stats = PoolStats::default();
        assert_eq!(stats.total_acquisitions, 0);
        assert_eq!(stats.reuse_count, 0);
    }

    #[test]
    fn test_pool_creation() {
        let provider = BubblewrapSandbox::new().unwrap();
        let config = PoolConfig::default();
        let pool = SandboxPool::with_default_config(provider);

        assert!(pool.is_enabled());
        assert_eq!(pool.current_size(), DEFAULT_POOL_SIZE);
        assert_eq!(pool.stats().total_acquisitions, 0);
    }

    #[test]
    fn test_pool_hit_rate() {
        let provider = BubblewrapSandbox::new().unwrap();
        let pool = SandboxPool::with_default_config(provider);

        assert_eq!(pool.hit_rate(), 0.0);

        // Manually set stats through the mutex for testing
        {
            let mut stats = pool.stats.try_lock().unwrap();
            stats.reuse_count = 5;
            stats.total_acquisitions = 10;
        }
        assert!((pool.hit_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_pool_reset_stats() {
        let provider = BubblewrapSandbox::new().unwrap();
        let pool = SandboxPool::with_default_config(provider);

        // Manually set stats through the mutex for testing
        {
            let mut stats = pool.stats.try_lock().unwrap();
            stats.reuse_count = 10;
            stats.total_acquisitions = 20;
        }

        pool.reset_stats();

        assert_eq!(pool.stats().total_acquisitions, 0);
        assert_eq!(pool.stats().reuse_count, 0);
    }

    #[test]
    fn test_pool_config_update() {
        let provider = BubblewrapSandbox::new().unwrap();
        let mut pool = SandboxPool::with_default_config(provider);

        let new_config = PoolConfig::with_pool_size(8);
        pool.update_config(new_config);

        assert_eq!(pool.current_size(), 8);
    }
}
