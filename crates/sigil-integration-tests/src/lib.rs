//! SIGIL Integration Tests
//!
//! This crate contains integration tests for verifying the security properties
//! of SIGIL as specified in the Phase 9 Red Team Checkpoint.
//!
//! These tests verify:
//! - FUSE filesystem security (PID/UID verification)
//! - HTTP proxy auth hiding and scrubbing
//! - Decoy response format correctness
//! - Lockdown functionality and timing
//! - SDK authentication requirements
//! - Doctor health check coverage
//! - Sealed operations isolation
//! - Credential helper protocol compliance
