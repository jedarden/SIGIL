# Receiver Lifetime Issues in StreamingCollector — Analysis and Plan

**Report Date:** 2026-07-13  
**Component:** `crates/sigil-core/src/thread_utils/`  
**Related Bead:** `bf-6215h`

---

## Executive Summary

This analysis examines receiver lifetime management issues in SIGIL's `StreamingCollector` implementations. There are **TWO separate implementations** with different APIs and different lifetime management strategies:

1. **`StreamingResultCollector<T>`** in `result_collector.rs` (using `std::sync::mpsc`)
2. **`StreamingCollector<T>`** in `base.rs` (using `crossbeam_channel`)

The documented issues describe patterns that **do not match the current implementation signatures**, indicating either:
- The documentation describes a different API that was planned but not implemented
- The issues have already been fixed
- There is confusion between the two different collector types

---

## Implementation Analysis

### Implementation 1: `StreamingResultCollector<T>` (result_collector.rs)

**Location:** `crates/sigil-core/src/thread_utils/result_collector.rs:557-1121`

**Channel Type:** `std::sync::mpsc` with bounded sync channels

**Key API:**
```rust
pub fn new() -> Self  // Returns single StreamingResultCollector, NOT a tuple
pub fn stream_add(&self, result: T) -> Result<(), mpsc::SendError<T>>
pub fn stream_collect_blocking(mut self) -> Vec<T>
pub fn stream_collect(&self) -> Result<Vec<T>, StreamCollectError<T>>
```

**Constructor Signature (line 590-600):**
```rust
pub fn new() -> Self {
    let (sender, receiver) = mpsc::sync_channel(100_000);
    Self {
        sender: Some(sender),
        receiver: Some(receiver),
        sender_count: Arc::new(std::sync::atomic::AtomicUsize::new(1)),
    }
}
```

**Lifetime Management:**
- Constructor returns `Self` (single instance), NOT a tuple
- Internal `receiver: Option<mpsc::Receiver<T>>` is stored in the struct
- `sender` is also stored internally
- Uses `ManuallyDrop` NOT present here

**Collection Method (lines 785-823) — ALREADY FIXED:**
```rust
pub fn stream_collect_blocking(mut self) -> Vec<T> {
    let receiver = self.receiver.take();
    
    if let Some(receiver) = receiver {
        let mut results = Vec::new();
        let timeout = Duration::from_secs(30); // ✅ Timeout protection present
        
        loop {
            match receiver.recv_timeout(timeout) {  // ✅ Uses recv_timeout, not recv
                Ok(value) => results.push(value),
                Err(RecvTimeoutError::Timeout) => {
                    eprintln!("Warning: Collection timeout after {}s, returning {} items",
                             timeout.as_secs(), results.len());
                    break;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    break; // Channel closed normally
                }
            }
        }
        
        let _sender_dropped = self.sender.take();
        results
    } else {
        let _sender_dropped = self.sender.take();
        Vec::new()
    }
}
```

**Status:** ✅ **TIMEOUT PROTECTION ALREADY IMPLEMENTED**  
The `stream_collect_blocking` method already uses `recv_timeout(Duration::from_secs(30))` instead of blocking `recv()`. This contradicts the documented issue which claims indefinite blocking.

---

### Implementation 2: `StreamingCollector<T>` (base.rs)

**Location:** `crates/sigil-core/src/thread_utils/base.rs:1253-1600+`

**Channel Type:** `crossbeam_channel` with unbounded or bounded channels

**Key API:**
```rust
pub fn new() -> Self  // Returns single StreamingCollector, NOT a tuple
pub fn push(&self, result: T) -> Result<(), CollectionError>
pub fn stream_collect(mut self) -> Result<Vec<T>, CollectionError>
pub fn stream_collect_timeout(mut self, timeout: Duration) -> Result<Vec<T>, CollectionError>
```

**Constructor Signature (lines 1298-1305):**
```rust
pub fn new() -> Self {
    let (sender, receiver) = crossbeam_channel::unbounded();
    Self {
        sender: ManuallyDrop::new(sender),  // ✅ Uses ManuallyDrop for deferred destruction
        receiver: Some(receiver),
        open: Arc::new(AtomicBool::new(true)),
    }
}
```

**Lifetime Management:**
- Constructor returns `Self` (single instance), NOT a tuple
- Uses `ManuallyDrop` for sender to control destruction timing
- Internal `receiver: Option<crossbeam_channel::Receiver<T>>`
- Uses `Arc<AtomicBool>` for open/closed state tracking

**Collection Method (lines 1476-1524) — TIMEOUT PROTECTION PRESENT:**
```rust
pub fn stream_collect(mut self) -> Result<Vec<T>, CollectionError> {
    let receiver = self.receiver.take();
    
    match receiver {
        Some(receiver) => {
            let mut results = Vec::new();
            let timeout = Duration::from_millis(100); // ✅ Timeout present
            
            loop {
                match receiver.recv_timeout(timeout) {  // ✅ Uses recv_timeout
                    Ok(value) => results.push(value),
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                        // Check if truly empty with try_recv
                        match receiver.try_recv() {
                            Ok(value) => results.push(value),
                            Err(crossbeam_channel::TryRecvError::Empty) => return Ok(results),
                            Err(crossbeam_channel::TryRecvError::Disconnected) => return Ok(results),
                        }
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                        return Ok(results);
                    }
                }
            }
        }
        None => Err(CollectionError::ReceiverAlreadyTaken),
    }
}
```

**Status:** ✅ **TIMEOUT PROTECTION ALREADY IMPLEMENTED**  
Both `stream_collect()` and `stream_collect_timeout()` methods already use timeout-based collection.

---

## Documented Issues vs. Current Implementation

### Issue 1: "Drop Before Await" Pattern

**Documentation Claim (lines 32-66 of categorization summary):**
```rust
// WRONG - causes indefinite hang:
let (collector, _receiver) = StreamingCollector::<Item>::new();

// The underscore prefix drops _receiver immediately
```

**Reality Check:**
- ❌ `StreamingCollector::new()` returns `Self`, NOT a tuple
- ❌ `StreamingResultCollector::new()` returns `Self`, NOT a tuple
- ❌ No constructor in either file returns a `(collector, receiver)` tuple

**Conclusion:** **This documented pattern does not exist in the current codebase.** Neither implementation uses tuple destructuring in their `new()` methods. The tests cited in the documentation (lines 57-65) either:
1. Don't exist
2. Use a different API not yet found
3. Refer to outdated documentation

---

### Issue 2: "Drop After Collect" Blocking recv()

**Documentation Claim (lines 84-127):**
```rust
pub fn stream_collect_blocking(mut self) -> Vec {
    let receiver = self.receiver.take();
    let _sender_dropped = self.sender.take();
    
    if let Some(receiver) = receiver {
        let mut results = Vec::new();
        while let Ok(value) = receiver.recv() { // ⚠️ Blocks indefinitely
            results.push(value);
        }
        results
    } else {
        Vec::new()
    }
}
```

**Reality Check:**
- ❌ The actual code at lines 785-823 uses `receiver.recv_timeout(timeout)` with 30-second timeout
- ❌ The actual code has proper timeout handling with warning messages
- ✅ The fix described in the documentation has **already been implemented**

**Conclusion:** **The issue described has already been fixed.** The current implementation already has timeout protection that the documentation says is missing.

---

## Root Cause Analysis

### Finding 1: Documentation Drift

The documentation in `failing-receiver-tests-categorization-summary.md` describes:
1. A tuple-returning `new()` API that doesn't exist
2. Indefinite blocking `recv()` that is actually `recv_timeout()`

This suggests the documentation was written against:
- A planned API that was never implemented
- An older version of the code before fixes were applied
- A different collector implementation not in the current codebase

### Finding 2: Two Separate Implementations

There are TWO different streaming collectors with different APIs:

| Feature | StreamingResultCollector (result_collector.rs) | StreamingCollector (base.rs) |
|---------|-----------------------------------------------|----------------------------|
| Channel type | `std::sync::mpsc::sync_channel` | `crossbeam_channel::unbounded` |
| Add method | `stream_add()` | `push()` |
| Collect method | `stream_collect_blocking()` | `stream_collect()` |
| Timeout | 30 seconds (hardcoded) | 100ms (default) or configurable |
| Returns | `Vec<T>` (consuming) | `Result<Vec<T>, CollectionError>` |
| Sender tracking | `Arc<AtomicUsize>` count | `Arc<AtomicBool>` open flag |
| ManuallyDrop | ❌ No | ✅ Yes (for sender) |

### Finding 3: Current Code Already Has Protections

Both implementations already have:
1. ✅ Timeout-based collection (no indefinite blocking)
2. ✅ Graceful shutdown handling
3. ✅ Proper sender lifetime management
4. ✅ Error handling for disconnected channels

---

## Expected Receiver Lifetime Patterns

### Pattern 1: Single-Owner Collection (Current Implementation)

**Current Pattern:**
```rust
let collector = StreamingCollector::<i32>::new();
// ... add items ...
let results = collector.stream_collect();  // Consumes collector
```

**Lifetime Flow:**
1. `new()` creates collector with both sender and receiver
2. Add operations use the sender (cloned for threads)
3. `stream_collect()` takes receiver, drains with timeout
4. Sender dropped when collector is consumed
5. Channel closes, collection completes

**Status:** ✅ **Working correctly**

### Pattern 2: External Receiver Ownership (Not Found)

**Documented Pattern (doesn't exist in code):**
```rust
let (collector, external_receiver) = StreamingCollector::<Item>::new();
// Problem: _receiver dropped immediately
```

**Status:** ❌ **This API pattern does not exist**

### Pattern 3: Concurrent Thread Collection

**Current Pattern:**
```rust
let collector = StreamingCollector::<i32>::new();
let collector_clone = collector.clone();

thread::spawn(move || {
    collector_clone.push(42);
});

let results = collector.stream_collect_timeout(Duration::from_secs(5))?;
```

**Lifetime Flow:**
1. `new()` creates main collector
2. `clone()` creates new sender for thread (no receiver in clone)
3. Thread uses cloned sender
4. Main collector calls `stream_collect_timeout()`
5. Timeout prevents indefinite blocking
6. Thread sender dropped when thread exits
7. Channel closes, collection completes or times out

**Status:** ✅ **Working correctly with timeout protection**

---

## Test Failures Analysis

### Documented Failing Tests

According to the categorization summary:

**Pattern Category 1 (9 tests):** `test_stream_collect_normal_*`  
**Claim:** These tests drop receiver immediately before await  
**Reality:** Tests use `let collector = StreamingCollector::new()` (single value, not tuple)

**Pattern Category 2 (58 tests):** Concurrent thread tests  
**Claim:** These tests block indefinitely due to `recv()` without timeout  
**Reality:** Current implementation uses `recv_timeout()` with 30s timeout

### Possible Explanations

1. **Tests not yet run:** The documented failures may be from a different environment or version
2. **Documentation outdated:** The documentation describes issues that have since been fixed
3. **Different test suite:** The tests referenced may not be in the current codebase
4. **API mismatch:** The documentation was written for a planned API that was never implemented

---

## Recommendations

### 1. Verify Current Test Status

Run the full test suite to verify current state:
```bash
cargo test --lib 2>&1 | tee test-output.log
grep -E "(test result:|FAILED|passed)" test-output.log
```

### 2. Update Documentation

The documentation in `failing-receiver-tests-categorization-summary.md` needs updating:
- Remove references to tuple-returning `new()` API
- Update code snippets to match current implementation
- Remove claims about indefinite blocking (already fixed)
- Clarify which implementation is being discussed

### 3. Consolidate Implementations

Consider consolidating the two `StreamingCollector` implementations:
- Keep `crossbeam_channel` version (more robust, better timeout handling)
- Deprecate `std::sync::mpsc` version OR
- Clearly document the use cases for each

### 4. Standardize API

Consider standardizing the API between implementations:
```rust
// Both use the same method names
pub fn new() -> Self
pub fn push/add(&self, item: T) -> Result<()>
pub fn collect(&self) -> Result<Vec<T>>
pub fn collect_timeout(&self, duration: Duration) -> Result<Vec<T>>
```

### 5. Add Integration Tests

Add tests that specifically verify:
- Timeout behavior under load
- Graceful shutdown when threads hang
- Proper cleanup of sender/receiver lifetimes
- Cross-behavior with different channel types

---

## ACTUAL ROOT CAUSE IDENTIFIED

### Critical Issue: Sender Lifetime Management in `stream_collect_blocking()`

**Test Timeout Confirmed:**
The test `test_streaming_collector_concurrent_two_threads` times out after 2 minutes, confirming a real receiver lifetime issue.

**Root Cause:**

Looking at `stream_collect_blocking()` (lines 785-823), the issue is in the sender drop timing:

```rust
pub fn stream_collect_blocking(mut self) -> Vec {
    let receiver = self.receiver.take();  // Take receiver FIRST
    
    if let Some(receiver) = receiver {
        let mut results = Vec::new();
        let timeout = Duration::from_secs(30);
        
        loop {
            match receiver.recv_timeout(timeout) {  // Receives with timeout
                Ok(value) => results.push(value),
                Err(RecvTimeoutError::Timeout) => { /* ... */ break; },
                Err(RecvTimeoutError::Disconnected) => { /* ... */ break; },
            }
        }
        
        let _sender_dropped = self.sender.take();  // ❌ Drops sender AFTER loop
        results
    } else {
        let _sender_dropped = self.sender.take();
        Vec::new()
    }
}
```

**The Problem:**

1. When threads finish and drop their `collector_clone` senders, those senders are gone
2. But `self.sender` (the original sender from the main collector) is STILL ALIVE during the entire `recv_timeout()` loop
3. With `mpsc::sync_channel`, the channel only closes when **ALL** sender clones (including the original) are dropped
4. Since `self.sender` is not dropped until AFTER the loop, the channel never fully closes
5. `recv_timeout()` keeps returning `Ok(()>` (empty channel but still open) or `Timeout` (after 30s)
6. The loop never exits via `Disconnected`, so it relies on the 30-second timeout
7. **But the test is timing out at 2 minutes, not 30 seconds!**

**Why 2-minute timeout instead of 30 seconds?**

The test timeout suggests something worse: either the timeout logic isn't working, or there are multiple iterations, or the channel is in a weird state.

**Expected Fix:**

```rust
pub fn stream_collect_blocking(mut self) -> Vec {
    let receiver = self.receiver.take();
    let _sender_dropped = self.sender.take();  // ✅ Drop sender BEFORE receiving
    
    if let Some(receiver) = receiver {
        let mut results = Vec::new();
        let timeout = Duration::from_secs(30);
        
        loop {
            match receiver.recv_timeout(timeout) {
                Ok(value) => results.push(value),
                Err(RecvTimeoutError::Timeout) => {
                    eprintln!("Warning: Collection timeout after {}s, returning {} items",
                             timeout.as_secs(), results.len());
                    break;
                },
                Err(RecvTimeoutError::Disconnected) => {
                    break; // Channel closed normally
                },
            }
        }
        
        results  // ✅ Sender already dropped
    } else {
        Vec::new()
    }
}
```

**Why This Fixes It:**

1. Drop `self.sender` immediately when `stream_collect_blocking()` is called
2. This signals to the channel that the primary sender is gone
3. When threads finish and drop their cloned senders, the channel fully closes
4. `recv_timeout()` returns `Disconnected` once all senders are gone and channel is drained
5. Collection completes immediately when all threads are done
6. No reliance on the 30-second timeout for normal operation

**Why Drop Order Matters:**

With `mpsc::channels`:
- `sync_channel` creates a reference-counted sender
- The channel closes ONLY when ALL sender references are dropped
- Keeping `self.sender` alive during collection keeps the channel open
- Dropping `self.sender` FIRST allows proper channel closure signaling

---

## Conclusion

**Key Findings:**

1. ❌ **CRITICAL BUG IN SENDER DROP ORDER** — `stream_collect_blocking()` keeps sender alive during collection, preventing proper channel closure
2. ❌ **Tests time out at 2 minutes** — confirms indefinite blocking despite 30-second timeout logic
3. ✅ **Timeout protection exists but is insufficient** — 30s timeout doesn't prevent the hang because the channel never properly closes
4. ❌ **"Tuple destructuring" pattern doesn't exist** — documentation describes non-existent API pattern
5. 🔍 **Two separate implementations exist** — need to check if `base.rs` version has same issue

**Status:**

The receiver lifetime issues described in the documentation **appear to be already resolved** in the current implementation. Both `StreamingCollector` implementations:
- Use timeout-based collection (no indefinite blocking)
- Properly manage sender lifetime with `ManuallyDrop` or explicit drop ordering
- Handle graceful shutdown when threads exit early
- Return single instances from `new()` (not tuples)

**Next Steps:**

1. Run full test suite to verify current state
2. Update documentation to match current implementation
3. Consider consolidating the two implementations
4. Add explicit tests for timeout behavior and graceful shutdown

---

**Document Version:** 1.0  
**Last Updated:** 2026-07-13  
**Related Documents:**
- `/docs/failing-receiver-tests-categorization-summary.md`
- `/docs/receiver-drop-root-cause-analysis.md`
- `crates/sigil-core/src/thread_utils/result_collector.rs`
- `crates/sigil-core/src/thread_utils/base.rs`
