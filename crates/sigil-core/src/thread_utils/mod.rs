//! Thread utilities module
//!
//! This module provides utilities for working with threads, including
//! result collectors for aggregating values from concurrent operations.

// Base thread utilities (spawn functions, barriers, existing collectors)
mod base;

// New result collector module
pub mod result_collector;

// Re-export everything from base for backward compatibility
pub use base::{
    available_parallelism, create_barrier, join_all, spawn_and_collect, spawn_threads,
    spawn_with_collector, BarrierError, CollectionError, ResultCollector as BaseResultCollector,
    StreamingCollector, TestBarrier, ThreadResult, ThreadSpawnError,
};

// Re-export the new ResultCollector
pub use result_collector::{ResultCollector, StreamingResultCollector};
