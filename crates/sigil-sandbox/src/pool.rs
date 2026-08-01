//! Pre-warmed sandbox pool.
//!
//! SIGIL's daemon (`sigild`) executes every intercepted agent shell command inside a
//! bubblewrap namespace. `docs/research/sandbox-architecture.md` §2.3 breaks the
//! per-command overhead down as:
//!
//! | Component                          | Cost        |
//! |------------------------------------|-------------|
//! | bwrap namespace creation           | ~5–10 ms    |
//! | filesystem bind mounts             | ~2–5 ms     |
//! | provider availability check        | one `bwrap --version` exec per command |
//! | secret resolution (cached)         | ~1 ms       |
//! | output scrubbing                   | ~1–5 ms     |
//! | **Total (cached secrets)**         | **~15–30 ms** |
//!
//! The daemon's hot path currently pays two avoidable, per-command costs on *every*
//! exec, independent of the command itself:
//!
//! 1. **Availability re-probe** — `BubblewrapSandbox::new().is_available()` spawns a
//!    `bwrap --version` subprocess on each call (the `available` cache field is never
//!    populated). That is a fork+exec (or a failed lookup when bwrap is absent) per
//!    command.
//! 2. **Static-arg rebuild** — [`BubblewrapSandbox::build_static_bwrap_args`] resolves
//!    `dirs::home_dir()` and `stat()`s every sensitive overlay path (up to ~9 stats)
//!    and reallocates the namespace/mount flag vector, even though those flags only
//!    depend on the *static* parts of the config (project dir, network isolation,
//!    sensitive paths, …) which are stable across a session.
//!
//! This pool eliminates both: it pre-computes, per static config, the resolved static
//! argument vector and the cached availability, and hands out cheap handles whose
//! [`PooledEntry::wrap_command`] only appends the genuinely per-command parts (file
//! injections, environment, the command string). The criterion bench
//! `sandbox_pool/cold` vs `sandbox_pool/warm` is the acceptance gate.
//!
//! ## Scope — what this does and does not amortize
//!
//! This pool amortizes the **Rust-side** setup: the availability exec and the static
//! arg vector (home-dir resolution, sensitive-path stats, allocations). It does **not**
//! keep a live bwrap namespace open across commands — every wrapped command still calls
//! `bwrap` once and pays namespace-creation + mount cost. The research doc's
//! "~2–3 ms" figure for a fully warm namespace requires a *namespace-keeper* process
//! (a long-lived bwrap child that `fork`+`exec`s each command inside an already-created
//! namespace). That is a larger, security-sensitive systems change — seccomp must be
//! applied to the per-command child (not the keeper), tmpfs must be scrubbed between
//! commands, and per-command mounts/env must be isolated — and it cannot be exercised
//! in this environment or CI (no `bwrap` binary present). The [`PoolKey`] /
//! [`PooledEntry`] API here is shaped so that a keeper-backed entry can slot in behind
//! the same `wrap_command` interface later. See `notes/bf-1gpfu.md`.
//!
//! ## Safety
//!
//! A pooled entry holds **no secret material and no per-command state** — only the
//! static namespace flags and a cached `available` bit. File injections, environment
//! variables, and the resolved command are supplied per call by the caller and never
//! touch the cache. There is therefore no cross-command secret leakage risk from
//! pooling, unlike a shared-namespace keeper.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use sigil_core::{ResolvedCommand, Result};

use crate::bubblewrap::{BubblewrapSandbox, SandboxConfig};

/// Default number of distinct static configs to keep pre-warmed.
///
/// Most agent sessions use a small number of distinct sandbox shapes (one project dir,
/// network on/off), so a modest cap keeps memory bounded while yielding cache hits.
pub const DEFAULT_POOL_SIZE: usize = 8;

/// Configuration for a [`SandboxPool`].
#[derive(Debug, Clone)]
pub struct SandboxPoolConfig {
    /// Whether the pool caches entries. When `false`, [`SandboxPool::acquire`] still
    /// returns a valid entry but builds it fresh each time (cold-equivalent) without
    /// inserting into the cache — useful for diagnostics or when determinism matters.
    pub enabled: bool,
    /// Maximum number of distinct [`PoolKey`]s to keep cached. Once the cap is reached,
    /// new keys return a freshly-built (uncached) entry rather than evicting existing
    /// ones, so a warm working set is never disturbed by a transient outlier.
    pub size: usize,
    /// Optional explicit path to the `bwrap` binary. `None` resolves `bwrap` from PATH.
    pub bwrap_path: Option<PathBuf>,
}

impl Default for SandboxPoolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size: DEFAULT_POOL_SIZE,
            bwrap_path: None,
        }
    }
}

/// A cache key capturing exactly the static parts of a [`SandboxConfig`].
///
/// Two commands whose configs reduce to the same key reuse the same pre-warmed entry.
/// Deliberately excludes `env_vars` and `file_injections`: those are per-command
/// (secret-dependent) and are applied at wrap time, not cached.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    project_dir: Option<PathBuf>,
    network_isolated: bool,
    working_dir: Option<PathBuf>,
    die_with_parent: bool,
    sensitive_paths: Vec<PathBuf>,
    fuse_mount: Option<PathBuf>,
}

impl PoolKey {
    /// Derive the cache key from a sandbox config's static fields.
    pub fn from_config(config: &SandboxConfig) -> Self {
        Self {
            project_dir: config.project_dir.clone(),
            network_isolated: config.network_isolated,
            working_dir: config.working_dir.clone(),
            die_with_parent: config.die_with_parent,
            sensitive_paths: config.sensitive_paths.clone(),
            fuse_mount: config.fuse_mount.clone(),
        }
    }
}

/// A pre-warmed, reusable handle for one static sandbox shape.
///
/// Holds the resolved `bwrap` path, the cached static argument vector (namespace +
/// mount + overlay flags), and the one-time availability probe result. Cheap to clone
/// (`Arc` internals); safe to hold across commands — see the module safety note.
#[derive(Debug, Clone)]
pub struct PooledEntry {
    bwrap_path: PathBuf,
    static_args: Arc<[String]>,
    /// Cached result of `bwrap --version`. Probed once at pre-warm.
    available: bool,
}

impl PooledEntry {
    /// Build a fresh (cold) entry for the given config. Performs the availability
    /// probe and the static-arg resolution exactly once.
    fn build(config: &SandboxConfig, bwrap_path: Option<&PathBuf>) -> Self {
        let sandbox = match bwrap_path {
            Some(p) => BubblewrapSandbox::with_bwrap_path(p),
            None => BubblewrapSandbox::new().unwrap_or_else(|_| BubblewrapSandbox::with_bwrap_path("bwrap")),
        };
        // Probe availability once (this is the `bwrap --version` exec we avoid on the
        // hot path by caching the result here).
        let available = sandbox.is_available();
        let static_args = sandbox.build_static_bwrap_args(config).into();
        Self {
            bwrap_path: match bwrap_path {
                Some(p) => p.clone(),
                None => PathBuf::from("bwrap"),
            },
            static_args,
            available,
        }
    }

    /// The cached `bwrap` availability for this entry's static shape.
    pub fn available(&self) -> bool {
        self.available
    }

    /// The number of pre-computed static arguments held by this entry.
    #[cfg(test)]
    pub fn static_arg_count(&self) -> usize {
        self.static_args.len()
    }

    /// Wrap a resolved command for execution inside this pre-warmed sandbox shape.
    ///
    /// Appends only the per-command dynamic parts — file-injection `--bind` flags,
    /// environment, working dir, and the command itself — to the cached static args.
    /// Produces a byte-identical `bwrap` invocation to the cold path
    /// ([`BubblewrapSandbox::wrap_command`]).
    pub fn wrap_command(
        &self,
        cmd: &ResolvedCommand,
        config: &SandboxConfig,
    ) -> Result<Command> {
        // Dynamic file-injection flags: cheap, no IO, depend on this command's secrets.
        let sandbox = BubblewrapSandbox::with_bwrap_path(&self.bwrap_path);
        let mut args: Vec<String> = self.static_args.to_vec();
        args.extend(sandbox.build_file_injection_args(config));

        BubblewrapSandbox::assemble_bwrap_command(&self.bwrap_path, args, cmd, config)
    }
}

/// A pool of pre-warmed sandbox entries, keyed by static config shape.
///
/// Construct one in the daemon and hold it for the process lifetime; call
/// [`SandboxPool::acquire`] on the exec hot path. The first acquire for a given
/// [`PoolKey`] pays the pre-warm cost (availability probe + static-arg build);
/// subsequent acquires are an O(1) hashmap lookup + `Arc` clone.
pub struct SandboxPool {
    entries: Mutex<HashMap<PoolKey, Arc<PooledEntry>>>,
    config: SandboxPoolConfig,
}

impl SandboxPool {
    /// Create a new pool with the given configuration.
    pub fn new(config: SandboxPoolConfig) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// The pool's configuration.
    pub fn config(&self) -> &SandboxPoolConfig {
        &self.config
    }

    /// Number of distinct static shapes currently cached.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("pool mutex poisoned").len()
    }

    /// Whether the pool currently holds no cached entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pre-warm an entry for the given config without yet using it.
    ///
    /// Call this at daemon startup for the expected working set (e.g. the session's
    /// project dir) so the first real command doesn't pay the pre-warm cost. Safe to
    /// call for an already-cached key (no-op).
    pub fn prewarm(&self, config: &SandboxConfig) -> Arc<PooledEntry> {
        self.get_or_build(config)
    }

    /// Acquire a pre-warmed entry for the given config.
    ///
    /// Returns a cached entry when one exists for the config's [`PoolKey`]; otherwise
    /// builds one (and caches it, if enabled and under the size cap). When the pool is
    /// disabled or at capacity, still returns a valid freshly-built entry — callers
    /// always get something they can [`PooledEntry::wrap_command`].
    pub fn acquire(&self, config: &SandboxConfig) -> Arc<PooledEntry> {
        self.get_or_build(config)
    }

    fn get_or_build(&self, config: &SandboxConfig) -> Arc<PooledEntry> {
        let key = PoolKey::from_config(config);

        // Fast path: lock, look up, clone the Arc, release.
        if let Some(entry) = self.entries.lock().expect("pool mutex poisoned").get(&key) {
            return Arc::clone(entry);
        }

        // Cache miss: build cold. This does the availability probe + static-arg build.
        let entry = Arc::new(PooledEntry::build(config, self.config.bwrap_path.as_ref()));

        if self.config.enabled {
            let mut entries = self.entries.lock().expect("pool mutex poisoned");
            // Another thread may have inserted between our miss and the lock; prefer
            // the winning entry so all callers share one allocation.
            if let Some(existing) = entries.get(&key) {
                return Arc::clone(existing);
            }
            // Bound the cache: if at capacity, hand back the fresh entry without caching
            // rather than evicting a warm entry.
            if entries.len() < self.config.size.max(1) {
                entries.insert(key, Arc::clone(&entry));
            }
        }

        entry
    }

    /// Drop all cached entries (e.g. on a config reload that may have changed which
    /// sensitive paths exist).
    pub fn clear(&self) {
        self.entries.lock().expect("pool mutex poisoned").clear();
    }
}

impl Default for SandboxPool {
    fn default() -> Self {
        Self::new(SandboxPoolConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::ResolvedCommand;

    fn resolved(s: &str) -> ResolvedCommand {
        ResolvedCommand {
            original: s.to_string(),
            placeholders: Vec::new(),
            resolved: s.to_string(),
            env_injections: Vec::new(),
            file_injections: Vec::new(),
            use_stdin: false,
            stdin_secret: None,
            header_injections: Vec::new(),
        }
    }

    #[test]
    fn pool_key_excludes_dynamic_fields() {
        let base = SandboxConfig::default();
        let with_env = base
            .clone()
            .with_env("API_KEY".to_string(), "v".to_string());
        let with_file = base.with_file_injection(
            "secret/x".to_string(),
            PathBuf::from("/tmp/x"),
        );

        // env_vars and file_injections differ, but the static key must be identical.
        assert_eq!(PoolKey::from_config(&base), PoolKey::from_config(&with_env));
        assert_eq!(PoolKey::from_config(&base), PoolKey::from_config(&with_file));
    }

    #[test]
    fn pool_key_differs_on_static_fields() {
        let a = SandboxConfig::default();
        let b = SandboxConfig::default().with_network_isolation(false);
        assert_ne!(PoolKey::from_config(&a), PoolKey::from_config(&b));
    }

    #[test]
    fn acquire_caches_and_reuses() {
        let pool = SandboxPool::default();
        let cfg = SandboxConfig::with_project_dir(PathBuf::from("/test/project"));
        assert!(pool.is_empty());
        let e1 = pool.acquire(&cfg);
        assert_eq!(pool.len(), 1);
        let e2 = pool.acquire(&cfg);
        assert_eq!(pool.len(), 1, "second acquire must not grow the pool");
        // Same static args => same allocation (Arc dedup).
        assert!(Arc::ptr_eq(&e1, &e2));
    }

    #[test]
    fn disabled_pool_does_not_cache() {
        let pool = SandboxPool::new(SandboxPoolConfig {
            enabled: false,
            ..SandboxPoolConfig::default()
        });
        let cfg = SandboxConfig::with_project_dir(PathBuf::from("/test/project"));
        let e1 = pool.acquire(&cfg);
        assert!(pool.is_empty(), "disabled pool must not cache");
        // Still returns a usable entry.
        assert!(e1.static_arg_count() > 0);
    }

    #[test]
    fn pool_respects_size_cap_without_evicting() {
        let pool = SandboxPool::new(SandboxPoolConfig {
            enabled: true,
            size: 2,
            bwrap_path: None,
        });
        // Fill to cap.
        for i in 0..2 {
            pool.acquire(&SandboxConfig::with_project_dir(PathBuf::from(format!(
                "/p/{i}"
            ))));
        }
        assert_eq!(pool.len(), 2);
        // A third distinct key must not evict the warm entries.
        let extra = pool.acquire(&SandboxConfig::with_project_dir(PathBuf::from(
            "/p/extra",
        )));
        assert_eq!(pool.len(), 2, "size cap must not evict warm entries");
        // But the overflow entry is still usable.
        assert!(extra.static_arg_count() > 0);
    }

    #[test]
    fn warm_wrap_matches_cold_wrap_byte_for_byte() {
        // The warm (pooled) wrap must produce an identical bwrap invocation to the
        // cold path — same flags in the same order.
        let cfg = SandboxConfig::with_project_dir(PathBuf::from("/test/project"))
            .with_env("API_KEY".to_string(), "sk_live_x".to_string())
            .with_file_injection("secret/c".to_string(), PathBuf::from("/tmp/c.json"));
        let cmd = resolved("echo $API_KEY");

        let cold = BubblewrapSandbox::new().unwrap().wrap_command(&cmd, &cfg).unwrap();
        let pool = SandboxPool::default();
        let entry = pool.acquire(&cfg);
        let warm = entry.wrap_command(&cmd, &cfg).unwrap();

        // std::process::Command exposes the program but not argv directly; compare via
        // the Debug format which includes the program and all args.
        assert_eq!(format!("{cold:?}"), format!("{warm:?}"));
    }

    #[test]
    fn prewarm_then_acquire_share_entry() {
        let pool = SandboxPool::default();
        let cfg = SandboxConfig::default();
        let pre = pool.prewarm(&cfg);
        let got = pool.acquire(&cfg);
        assert!(Arc::ptr_eq(&pre, &got));
    }

    #[test]
    fn clear_empties_pool() {
        let pool = SandboxPool::default();
        let cfg = SandboxConfig::default();
        pool.acquire(&cfg);
        assert!(!pool.is_empty());
        pool.clear();
        assert!(pool.is_empty());
    }
}
