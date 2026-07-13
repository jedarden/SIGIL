# Expected Receiver Lifetime Patterns

**Document Version:** 1.0  
**Date:** 2026-07-13  
**Scope:** Reference documentation for correct receiver lifetime patterns in async collectors  
**Target Audience:** SIGIL developers working with streaming collectors and async message passing

---

## Purpose

This document establishes the **canonical patterns** for managing receiver lifetimes in async collectors, specifically for SIGIL's `StreamingCollector` and `StreamingResultCollector` implementations. These patterns prevent the common failure modes that have caused **67 test failures** and provide clear guidance for future development.

---

## Overview

SIGIL uses two primary streaming collector implementations, each with different channel types and lifetime requirements:

| Collector Type | Channel Implementation | Lifetime Complexity |
|---------------|----------------------|---------------------|
| `StreamingCollector<T>` | `crossbeam_channel::unbounded` | Low - Simple owned types |
| `StreamingResultCollector<T>` | `std::sync::mpsc::sync_channel` | Medium - Clone-aware with sender tracking |

**Key Principle:** Both implementations use **owned types only** and do **NOT** require lifetime annotations. Lifetime management is about **ownership and drop timing**, not Rust lifetime parameters.

---

## Part 1: Canonical Lifetime Patterns

### Pattern 1: Internal Receiver Only (Recommended)

**Use when:** You need simple collection without external receiver access  
**Complexity:** Low  
**Risk:** Minimal

#### Pattern Structure

```rust
// ✅ CORRECT: Internal receiver only
let collector = StreamingCollector::<ItemType>::new();

// Use the collector for sending
collector.send(item1);
collector.send(item2);

// Collect results (internal receiver used)
let results = collector.stream_collect()?;

// No external receiver exposed - clean lifecycle
```

#### Ownership Flow

```
┌─────────────────────────────────────────────────────────────┐
│          INTERNAL RECEIVER LIFECYCLE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Creation                                                │
│     collector = StreamingCollector::new()                   │
│     └─> Creates internal (sender, receiver) pair           │
│     └─> Both owned by collector struct                     │
│                                                             │
│  2. Send Phase                                              │
│     collector.send(item)                                    │
│     └─> Uses internal sender                                │
│     └─> Messages buffered in channel                       │
│                                                             │
│  3. Collection Phase                                        │
│     collector.stream_collect()                             │
│     └─> Takes internal receiver                            │
│     └─> Drops internal sender                               │
│     └─> Consumes all buffered messages                     │
│     └─> Returns collected results                          │
│                                                             │
│  4. Completion                                             │
│     collector dropped                                      │
│     └─> All owned fields dropped cleanly                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Why This Works

- **No external receivers:** Close detection works correctly
- **Owned types:** No borrowing, no lifetime annotations needed
- **Clean drop order:** Sender dropped before final receiver consumption
- **No race conditions:** Single-threaded ownership model

---

### Pattern 2: External Receiver with Explicit Lifecycle

**Use when:** You need external receiver access for monitoring or multi-consumer scenarios  
**Complexity:** High  
**Risk:** High (requires careful lifecycle management)

#### Pattern Structure

```rust
// ⚠️ ADVANCED: External receiver with explicit lifecycle
let (collector, receiver) = StreamingCollector::<ItemType>::new();

// CRITICAL: receiver must outlive all send operations
collector.send(item1);

// CRITICAL: receiver must be kept alive during collection
// Option A: Move receiver into collection
let results = collector.stream_collect_with_receiver(receiver)?;

// Option B: Keep receiver alive until after collection
std::thread::spawn(move || {
    // Use receiver for monitoring
    while let Ok(item) = receiver.recv() {
        println!("Received: {:?}", item);
    }
});

// Wait for collection to complete
let results = collector.stream_collect()?;
```

#### Ownership Flow

```
┌─────────────────────────────────────────────────────────────┐
│          EXTERNAL RECEIVER LIFECYCLE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Creation with Split                                     │
│     (collector, receiver) = StreamingCollector::new()      │
│     └─> collector owns: internal sender + internal receiver│
│     └─> receiver: external handle to same channel          │
│                                                             │
│  2. Send Phase (Keep External Alive)                       │
│     collector.send(item)                                    │
│     └─> External receiver MUST still be alive              │
│     └─> If dropped early → close detection breaks ❌        │
│                                                             │
│  3. Collection Phase (Explicit Integration)               │
│     collector.stream_collect_with_external(receiver)       │
│     └─> Takes ownership of external receiver               │
│     └─> Coordinates external + internal receivers          │
│     └─> Merges results from both receivers                │
│                                                             │
│  4. Completion                                             │
│     Both receivers dropped cleanly                        │
│     └─> Explicit ownership transfer prevents races         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Critical Requirements

1. **External receiver must outlive send operations**
   - Never use underscore prefix: `let (_, _receiver) = ...` ❌
   - Never drop receiver at scope boundary ❌

2. **External receiver must be integrated into collection**
   - Use dedicated `stream_collect_with_external()` method
   - Or explicitly join external consumer thread before collection

3. **External receiver lifecycle must be deterministic**
   - No thread-dependent drop timing
   - No implicit scope boundary drops

---

### Pattern 3: Concurrent Clones with Timeout Protection

**Use when:** You need multi-producer scenarios with `StreamingResultCollector`  
**Complexity:** High  
**Risk:** Medium (timeout protection required)

#### Pattern Structure

```rust
// ✅ CORRECT: Concurrent clones with timeout protection
let collector = StreamingResultCollector::<ItemType>::new();

// Spawn producers with clones
for i in 0..10 {
    let sender = collector.clone();
    std::thread::spawn(move || {
        sender.send(format!("item_{}", i)).unwrap();
        // Thread completion → sender dropped automatically
    });
}

// Collection with timeout protection
let results = collector.stream_collect_blocking();
// ↑ Handles thread hangs gracefully with timeout
```

#### Ownership Flow

```
┌─────────────────────────────────────────────────────────────┐
│          CONCURRENT CLONES LIFECYCLE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Creation                                                │
│     collector = StreamingResultCollector::new()            │
│     └─> sender_count = 1 (original sender)                │
│     └─> receiver owned by collector                        │
│                                                             │
│  2. Clone Phase                                             │
│     for i in 0..N {                                        │
│         sender_clone = collector.clone()                   │
│         └─> sender_count++ (atomic increment)              │
│     }                                                       │
│     └─> sender_count = N + 1                               │
│                                                             │
│  3. Production Phase                                        │
│     threads spawn with sender clones                       │
│     └─> Each thread: send() → return → drop sender_clone  │
│     └─> sender_count decreases as threads complete        │
│                                                             │
│  4. Collection Phase (with Timeout)                        │
│     collector.stream_collect_blocking()                    │
│     └─> Drops main sender (sender_count: N+1 → N)        │
│     └─> recv_timeout(30s) loop:                           │
│         ├─> Consumes messages as they arrive              │
│         ├─> Timeout after 30s if threads hang              │
│         └─> Returns partial results on timeout             │
│                                                             │
│  5. Thread Lifecycle Management                            │
│     Thread completes → drops sender → sender_count--      │
│     Thread hangs → sender held → timeout triggers           │
│     └─> Graceful degradation instead of deadlock           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Critical Requirements

1. **Always use timeout protection**
   - Never use bare `recv()` - blocks indefinitely
   - Use `recv_timeout(Duration::from_secs(30))` or similar
   - Handle `RecvTimeoutError::Timeout` explicitly

2. **Thread lifecycle awareness**
   - Threads may hang due to I/O, deadlocks, or panics
   - Unhandled hangs = held sender clones = deadlock
   - Timeout protection prevents indefinite blocking

3. **Error handling strategy**
   - Distinguish between `Disconnected` (normal) and `Timeout` (degraded)
   - Log timeout events for debugging
   - Return partial results rather than panicking

---

## Part 2: Correct vs Incorrect Usage Examples

### Example 1: Basic Collection

#### ❌ INCORRECT: External receiver dropped prematurely

```rust
// WRONG: Underscore prefix drops receiver immediately
let (collector, _receiver) = StreamingCollector::<i32>::new();
//                          └──────────┘
//                          Dropped at end of statement

collector.send(1);
collector.send(2);

let results = collector.stream_collect()?;
// ❌ BLOCKS FOREVER: External receiver was dropped prematurely
// Channel close detection never completes (Condition #3 violated)
```

**Why this breaks:**
- Underscore prefix (`_receiver`) tells Rust to drop the variable immediately
- External receiver must outlive collection operations
- Channel close detection requires all three conditions: all senders dropped + empty buffer + no external receivers

#### ✅ CORRECT: Internal receiver only

```rust
// CORRECT: No external receiver exposed
let collector = StreamingCollector::<i32>::new();

collector.send(1);
collector.send(2);

let results = collector.stream_collect()?;
// ✅ WORKS: Internal receiver lifecycle managed automatically
// Channel close detection works correctly
```

**Why this works:**
- No external receiver ever created
- Internal receiver lifecycle managed by collector
- Close detection works with internal sender drop

---

### Example 2: Scope Boundary Issues

#### ❌ INCORRECT: Implicit drop at scope boundary

```rust
// WRONG: Receiver dropped at scope boundary
{
    let (collector, receiver) = StreamingCollector::<i32>::new();
    collector.send(1);
} // ← receiver dropped here (scope boundary)

let results = collector.stream_collect()?;
// ❌ BLOCKS: Receiver was dropped when scope ended
```

**Why this breaks:**
- Rust's drop semantics destroy variables at scope boundaries
- External receiver dropped before collection operation
- Channel close detection fails

#### ✅ CORRECT: Explicit lifecycle management

```rust
// CORRECT: Keep receiver alive until after collection
let (collector, receiver) = StreamingCollector::<i32>::new();

collector.send(1);

// Option A: Move receiver into collection
let results = collector.stream_collect_with_receiver(receiver)?;

// Option B: Drop receiver after explicit collection
drop(receiver); // Explicit drop after collection
let results = collector.stream_collect()?;
```

**Why this works:**
- Receiver kept alive until after collection
- Explicit drop order ensures proper lifecycle
- No implicit scope boundary issues

---

### Example 3: Concurrent Operations

#### ❌ INCORRECT: Blocking recv() without timeout

```rust
// WRONG: Indefinite blocking on recv()
let collector = StreamingResultCollector::<i32>::new();

for i in 0..10 {
    let sender = collector.clone();
    std::thread::spawn(move || {
        sender.send(i).unwrap();
        // Thread may hang here → sender never dropped ❌
    });
}

let results = collector.stream_collect_blocking();
// Implementation uses while let Ok(value) = receiver.recv()
// ❌ BLOCKS FOREVER if any thread hangs
```

**Why this breaks:**
- `recv()` blocks indefinitely until all sender clones dropped
- Thread hangs = sender held = deadlock
- No timeout or escape mechanism

#### ✅ CORRECT: Timeout protection with graceful degradation

```rust
// CORRECT: Timeout protection with recv_timeout()
let collector = StreamingResultCollector::<i32>::new();

for i in 0..10 {
    let sender = collector.clone();
    std::thread::spawn(move || {
        sender.send(i).unwrap();
    });
}

let results = collector.stream_collect_blocking();
// Implementation uses recv_timeout(30s)
// ✅ GRACEFUL: Returns partial results after timeout
```

**Why this works:**
- `recv_timeout(Duration::from_secs(30))` provides escape mechanism
- Timeout returns `Err(RecvTimeoutError::Timeout)` after 30 seconds
- Partial results returned rather than indefinite hang
- Logged warning for debugging

---

### Example 4: Thread Lifecycle Management

#### ❌ INCORRECT: Unmanaged thread lifecycle

```rust
// WRONG: Threads with no lifecycle management
let collector = StreamingResultCollector::<i32>::new();

for i in 0..10 {
    let sender = collector.clone();
    std::thread::spawn(move || {
        // Complex operation that may hang
        let result = expensive_operation();
        sender.send(result).unwrap();
        // No guarantee thread completes ❌
    });
}

// May deadlock if threads hang
let results = collector.stream_collect_blocking();
```

**Why this breaks:**
- Threads are unmanaged with no completion guarantees
- Expensive operations may hang due to I/O, locks, or resource exhaustion
- No timeout or thread lifecycle enforcement

#### ✅ CORRECT: Thread pool with explicit join

```rust
// CORRECT: Thread pool with lifecycle management
let collector = StreamingResultCollector::<i32>::new();
let mut handles = vec![];

for i in 0..10 {
    let sender = collector.clone();
    let handle = std::thread::spawn(move || {
        let result = expensive_operation();
        sender.send(result).unwrap();
    });
    handles.push(handle);
}

// Join all threads with timeout
for handle in handles {
    match handle.join().timeout(Duration::from_secs(30)) {
        Ok(Ok(())) => {}, // Thread completed successfully
        Ok(Err(_)) => eprintln!("Thread panicked"),
        Err(_) => eprintln!("Thread timeout"),
    }
}

// Now safe to collect with timeout backup
let results = collector.stream_collect_blocking();
```

**Why this works:**
- All threads explicitly joined before collection
- Timeout on thread join prevents indefinite waits
- Two-tier protection: thread join timeout + collection timeout
- Better error visibility and logging

---

## Part 3: Lifetime Validation Checklist

Use this checklist when reviewing code that uses streaming collectors or implementing new collector types.

### Phase 1: API Design Validation

- [ ] **Owned types only**: All fields are owned, no references
  - No `&'a T` fields in struct definitions
  - All channels use owned Sender/Receiver types
  - Smart pointers use Arc/Rc, not borrowed references

- [ ] **No lifetime parameters**: Structs don't require `<'a>` annotations
  - Generic bounds: `T: Send + 'static` (if needed for threads)
  - No lifetime parameters in struct definition
  - No lifetime parameters in impl blocks

- [ ] **Clear ownership semantics**: Who owns what, when
  - Constructor returns owned struct or tuple
  - All field ownership documented in API docs
  - Clear split between internal and external handles

### Phase 2: Test Code Validation

- [ ] **No underscore prefix drops**: Never use `_receiver` pattern
  ```rust
  // ❌ WRONG
  let (collector, _receiver) = StreamingCollector::new();
  
  // ✅ CORRECT
  let collector = StreamingCollector::new();
  ```

- [ ] **No scope boundary drops**: Receivers don't drop at implicit boundaries
  ```rust
  // ❌ WRONG
  { let (c, r) = new(); } // r dropped here
  let results = c.stream_collect();
  
  // ✅ CORRECT
  let (c, r) = new();
  let results = c.stream_collect_with_receiver(r)?;
  ```

- [ ] **Explicit lifecycle management**: All drops are intentional and visible
  - Use `drop(receiver)` for explicit drop timing
  - Move receivers into collection methods
  - No hidden drops in closures or async blocks

### Phase 3: Implementation Validation

- [ ] **Timeout protection on all blocking recv() calls**
  ```rust
  // ❌ WRONG
  while let Ok(value) = receiver.recv() {
      results.push(value);
  }
  
  // ✅ CORRECT
  loop {
      match receiver.recv_timeout(Duration::from_secs(30)) {
          Ok(value) => results.push(value),
          Err(RecvTimeoutError::Timeout) => break,
          Err(RecvTimeoutError::Disconnected) => break,
      }
  }
  ```

- [ ] **Thread lifecycle management**: All spawned threads have explicit completion
  - Join handles before collection
  - Use timeouts on thread joins
  - Log thread completion failures

- [ ] **Error handling for all timeout scenarios**
  - Distinguish Timeout vs Disconnected
  - Log timeout events for debugging
  - Return partial results on timeout

- [ ] **No indefinite blocking**: Every blocking operation has an escape
  - `recv()` → `recv_timeout()`
  - `join()` → `join().timeout()`
  - `lock()` → `try_lock()` or timeout mutex

### Phase 4: Documentation Validation

- [ ] **API docs clearly document lifetime requirements**
  - Constructor signature explains ownership
  - Methods document external receiver requirements
  - Examples show correct usage patterns

- [ ] **Comments explain non-obvious lifetime decisions**
  - Why external receiver is needed (if used)
  - Why timeout value was chosen
  - Why specific drop order is required

- [ ] **Test comments explain purpose of lifetime management**
  - Why specific pattern is used
  - What failure mode is being tested
  - Why this test needs timeout protection

---

## Part 4: Do's and Don'ts

### ✅ DO: Follow These Patterns

#### ✅ DO: Use internal receiver only for simple cases

```rust
let collector = StreamingCollector::<ItemType>::new();
collector.send(item1);
let results = collector.stream_collect()?;
```

**Why:** Simplest pattern, lowest risk, no lifetime complexity

---

#### ✅ DO: Add timeout protection to all blocking operations

```rust
match receiver.recv_timeout(Duration::from_secs(30)) {
    Ok(value) => results.push(value),
    Err(RecvTimeoutError::Timeout) => {
        eprintln!("Collection timeout, returning {} items", results.len());
        break;
    }
    Err(RecvTimeoutError::Disconnected) => break,
}
```

**Why:** Prevents indefinite hangs, provides graceful degradation, enables debugging

---

#### ✅ DO: Manage thread lifecycle explicitly

```rust
let mut handles = vec![];
for i in 0..N {
    let sender = collector.clone();
    let handle = std::thread::spawn(move || {
        sender.send(compute(i)).unwrap();
    });
    handles.push(handle);
}

// Join all threads before collection
for handle in handles {
    handle.join().timeout(Duration::from_secs(30))?;
}
```

**Why:** Prevents sender leaks from hung threads, provides predictable completion

---

#### ✅ DO: Use owned types only in struct definitions

```rust
pub struct StreamingCollector<T> {
    sender: ManuallyDrop<Sender<T>>,        // ✅ Owned
    receiver: Option<Receiver<T>>,          // ✅ Owned
    open: Arc<AtomicBool>,                  // ✅ Owned smart pointer
}
```

**Why:** No lifetime annotations needed, clean ownership semantics, no borrowing bugs

---

#### ✅ DO: Document ownership transfer in API docs

```rust
/// Creates a new streaming collector with internal receiver only.
///
/// # Ownership
/// - Returns owned StreamingCollector struct
/// - Internal receiver lifecycle managed automatically
/// - No external receiver exposed
///
/// # Example
/// ```
/// let collector = StreamingCollector::<i32>::new();
/// collector.send(1);
/// let results = collector.stream_collect()?;
/// ```
pub fn new() -> Self { ... }
```

**Why:** Makes ownership expectations clear, prevents misuse, documents intended usage

---

### ❌ DON'T: Avoid These Patterns

#### ❌ DON'T: Use underscore prefix for external receivers

```rust
// ❌ WRONG: Drops receiver immediately
let (collector, _receiver) = StreamingCollector::new();

// ✅ CORRECT: No external receiver
let collector = StreamingCollector::new();
```

**Why:** Underscore prefix drops immediately, breaks channel close detection, causes hangs

---

#### ❌ DON'T: Let external receivers drop at scope boundaries

```rust
// ❌ WRONG: Receiver dropped at scope end
{
    let (collector, receiver) = StreamingCollector::new();
    collector.send(1);
} // ← receiver dropped here
let results = collector.stream_collect()?;

// ✅ CORRECT: Explicit lifecycle
let (collector, receiver) = StreamingCollector::new();
collector.send(1);
let results = collector.stream_collect_with_receiver(receiver)?;
```

**Why:** Implicit drops are hard to see, cause timing bugs, violate ownership expectations

---

#### ❌ DON'T: Use bare recv() without timeout

```rust
// ❌ WRONG: Blocks forever if sender never dropped
while let Ok(value) = receiver.recv() {
    results.push(value);
}

// ✅ CORRECT: Timeout protection
loop {
    match receiver.recv_timeout(Duration::from_secs(30)) {
        Ok(value) => results.push(value),
        Err(RecvTimeoutError::Timeout) => break,
        Err(RecvTimeoutError::Disconnected) => break,
    }
}
```

**Why:** Indefinite blocking causes deadlocks, no escape from hung threads, no debugging info

---

#### ❌ DON'T: Spawn unmanaged threads in tests

```rust
// ❌ WRONG: Threads with no lifecycle management
for i in 0..N {
    let sender = collector.clone();
    std::thread::spawn(move || {
        sender.send(i).unwrap();
        // No guarantee thread completes ❌
    });
}
let results = collector.stream_collect_blocking();

// ✅ CORRECT: Thread pool with explicit joins
let mut handles = vec![];
for i in 0..N {
    let sender = collector.clone();
    let handle = std::thread::spawn(move || {
        sender.send(i).unwrap();
    });
    handles.push(handle);
}
for handle in handles {
    handle.join().timeout(Duration::from_secs(30))?;
}
let results = collector.stream_collect_blocking();
```

**Why:** Unmanaged threads cause non-deterministic failures, sender leaks, test flakiness

---

#### ❌ DON'T: Add lifetime parameters unless needed

```rust
// ❌ WRONG: Unnecessary lifetime parameter
pub struct StreamingCollector<'a, T> {
    sender: Sender<&'a T>,  // ❌ Unnecessary reference
    receiver: Receiver<&'a T>,
}

// ✅ CORRECT: Owned types only
pub struct StreamingCollector<T> {
    sender: ManuallyDrop<Sender<T>>,
    receiver: Option<Receiver<T>>,
}
```

**Why:** SIGIL collectors don't need lifetimes, owned types are simpler, no borrowing complexity

---

#### ❌ DON'T: Mix external and internal receivers without coordination

```rust
// ❌ WRONG: Unclear which receiver is used where
let (collector, receiver) = StreamingCollector::new();
collector.send(1);
let results = collector.stream_collect()?; // Uses internal?
drop(receiver); // When should this be dropped?

// ✅ CORRECT: Explicit coordination
let collector = StreamingCollector::new();
collector.send(1);
let results = collector.stream_collect()?;

// OR: Explicit external receiver usage
let (collector, receiver) = StreamingCollector::new();
collector.send(1);
let results = collector.stream_collect_with_receiver(receiver)?;
```

**Why:** Mixed usage causes confusion, race conditions, unclear ownership

---

#### ❌ DON'T: Assume channel close detection works automatically

```rust
// ❌ WRONG: Assumes close detection just works
let results = collector.stream_collect()?;
// May block if external receiver exists or senders not dropped

// ✅ CORRECT: Ensure proper conditions first
// Ensure no external receivers
let collector = StreamingCollector::new();

// Ensure all senders will be dropped
let results = collector.stream_collect()?;
```

**Why:** Channel close detection has three conditions, all must be met for proper operation

---

## Part 5: Common Pitfalls and Solutions

### Pitfall 1: Test-Only Collection Patterns

**Problem:** Tests use different patterns than production code

```rust
// ❌ WRONG: Test uses external receiver, production doesn't
#[test]
fn test_collection() {
    let (collector, _receiver) = StreamingCollector::new();
    // Test fails, but production code doesn't use this pattern
}

// ✅ CORRECT: Test uses same pattern as production
#[test]
fn test_collection() {
    let collector = StreamingCollector::new();
    // Test matches production usage
}
```

**Solution:** Always test the same patterns used in production

---

### Pitfall 2: CI vs Local Environment Differences

**Problem:** Tests pass locally but fail in CI due to thread scheduling

```rust
// ❌ WRONG: No timeout, assumes fast thread completion
for i in 0..10 {
    let sender = collector.clone();
    std::thread::spawn(move || {
        sender.send(expensive_operation(i)).unwrap();
    });
}
let results = collector.stream_collect_blocking();
```

**Solution:** Add timeout protection for all blocking operations

```rust
// ✅ CORRECT: Timeout protection handles variable thread speeds
let results = collector.stream_collect_blocking();
// Uses recv_timeout(30s) internally
```

---

### Pitfall 3: Forgotten Drop of External Receivers

**Problem:** External receiver dropped accidentally, causing hangs

```rust
// ❌ WRONG: Receiver dropped in closure
let (collector, receiver) = StreamingCollector::new();
let result = std::thread::spawn(move || {
    let _ = receiver.recv(); // receiver moved here, dropped when thread ends
});
let results = collector.stream_collect()?; // Blocks
```

**Solution:** Never move external receivers into closures without coordination

```rust
// ✅ CORRECT: Explicit lifecycle
let collector = StreamingCollector::new(); // Internal receiver only
let results = collector.stream_collect()?;
```

---

### Pitfall 4: Clone-Related Sender Leaks

**Problem:** Cloned senders not dropped due to thread lifecycle issues

```rust
// ❌ WRONG: Cloned sender held by hung thread
for i in 0..10 {
    let sender = collector.clone();
    std::thread::spawn(move || {
        sender.send(i).unwrap();
        std::thread::sleep(Duration::from_secs(100)); // Hang
    });
}
let results = collector.stream_collect_blocking(); // Deadlock
```

**Solution:** Use timeout protection + thread lifecycle management

```rust
// ✅ CORRECT: Thread pool with timeouts + recv_timeout
let mut handles = vec![];
for i in 0..10 {
    let sender = collector.clone();
    let handle = std::thread::spawn(move || {
        sender.send(i).unwrap();
    });
    handles.push(handle);
}

// Join with timeout
for handle in handles {
    handle.join().timeout(Duration::from_secs(30)).ok();
}

let results = collector.stream_collect_blocking(); // Has internal timeout
```

---

## Part 6: Implementation Guidelines

### Guideline 1: Prefer Owned Types

**Rule:** Always use owned types in struct definitions

```rust
// ✅ CORRECT: Owned types only
pub struct StreamingCollector<T> {
    sender: ManuallyDrop<Sender<T>>,
    receiver: Option<Receiver<T>>,
    open: Arc<AtomicBool>,
}
```

**Rationale:** No lifetime annotations needed, clean ownership semantics

---

### Guideline 2: Avoid Split Receiver APIs Unless Required

**Rule:** Prefer single struct return over tuple unless external access is needed

```rust
// ✅ CORRECT: Single struct for simple cases
pub fn new() -> Self { ... }

// ⚠️ ADVANCED: Split receiver only when external access is required
pub fn new_with_external() -> (Self, Receiver<T>) { ... }
```

**Rationale:** Simpler API, less room for lifetime errors

---

### Guideline 3: Always Provide Timeout-Based Blocking Methods

**Rule:** Never expose bare `recv()` in public API

```rust
// ❌ WRONG: Exposes blocking recv() without timeout
pub fn collect_blocking(&self) -> Vec<T> {
    while let Ok(value) = self.receiver.recv() { ... }
}

// ✅ CORRECT: Uses recv_timeout() with configurable duration
pub fn collect_blocking(&self, timeout: Duration) -> Vec<T> {
    loop {
        match self.receiver.recv_timeout(timeout) {
            Ok(value) => results.push(value),
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}
```

**Rationale:** Prevents indefinite hangs, provides graceful degradation

---

### Guideline 4: Document Ownership Transfers Explicitly

**Rule:** All methods that take ownership should document it

```rust
/// Collects results, consuming the collector and external receiver.
///
/// # Ownership
/// - Takes `self` (consumes collector)
/// - Takes `receiver` (consumes external receiver)
/// - Both are dropped after collection completes
///
/// # Arguments
/// * `receiver` - External receiver handle (ownership transferred)
///
/// # Returns
/// Collected results as Vec<T>
pub fn stream_collect_with_receiver(self, receiver: Receiver<T>) -> Result<Vec<T>> {
    ...
}
```

**Rationale:** Makes ownership expectations clear in API docs

---

### Guideline 5: Provide Non-Blocking Alternatives

**Rule:** Always offer a try_recv-based non-blocking method

```rust
// ✅ CORRECT: Non-blocking alternative
pub fn try_collect_now(&self) -> Vec<T> {
    let mut results = Vec::new();
    while let Ok(value) = self.receiver.try_recv() {
        results.push(value);
    }
    results // Returns currently buffered items only
}
```

**Rationale:** Provides flexibility for polling and non-blocking scenarios

---

## Part 7: Testing Best Practices

### Test Pattern 1: Test Internal Receiver Lifecycle

```rust
#[test]
fn test_internal_receiver_lifecycle() {
    let collector = StreamingCollector::<i32>::new();
    
    collector.send(1);
    collector.send(2);
    
    let results = collector.stream_collect().unwrap();
    
    assert_eq!(results, vec![1, 2]);
}
```

**Why:** Tests the common case, no external receivers, clean lifecycle

---

### Test Pattern 2: Test Timeout Protection

```rust
#[test]
fn test_timeout_protection() {
    let collector = StreamingResultCollector::<i32>::new();
    
    // Spawn thread that will hang
    let sender = collector.clone();
    std::thread::spawn(move || {
        sender.send(1).unwrap();
        std::thread::sleep(Duration::from_secs(100)); // Hang
    });
    
    // Collection should timeout and return partial results
    let start = std::time::Instant::now();
    let results = collector.stream_collect_blocking();
    let elapsed = start.elapsed();
    
    // Should timeout in ~30 seconds, not hang forever
    assert!(elapsed < Duration::from_secs(35));
    assert!(elapsed > Duration::from_secs(25));
}
```

**Why:** Validates timeout mechanism works, prevents hangs in CI

---

### Test Pattern 3: Test Thread Lifecycle Management

```rust
#[test]
fn test_thread_lifecycle_management() {
    let collector = StreamingResultCollector::<i32>::new();
    let mut handles = vec![];
    
    for i in 0..10 {
        let sender = collector.clone();
        let handle = std::thread::spawn(move || {
            sender.send(i).unwrap();
        });
        handles.push(handle);
    }
    
    // All threads should complete
    for handle in handles {
        handle.join().timeout(Duration::from_secs(5)).unwrap();
    }
    
    // Now safe to collect
    let results = collector.stream_collect_blocking();
    assert_eq!(results.len(), 10);
}
```

**Why:** Tests explicit thread lifecycle, validates join behavior

---

## Appendix: Related Documentation

### SIGIL-Specific Documentation

- **Receiver Lifetime Root Causes Analysis:** `docs/phase-N/receiver-lifetime-root-causes.md`
  - Detailed technical analysis of failure patterns
  - Code flow diagrams and execution timelines
  - Specific code locations causing issues

- **Lifetime Fix Plan:** `docs/phase-N/lifetime-fix-plan.md`
  - Specific code changes required
  - Step-by-step implementation guide
  - Test-fixing strategy for all 67 failures

- **Receiver Drop Root Cause:** `docs/receiver-drop-root-cause-analysis.md`
  - Original analysis of drop timing issues
  - Channel close detection mechanics

### General Rust Documentation

- **Rust Ownership System:** https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html
- **Rust Lifetimes:** https://doc.rust-lang.org/book/ch10-03-lifetime-syntax.html
- **std::sync::mpsc Documentation:** https://doc.rust-lang.org/std/sync/mpsc/
- **crossbeam_channel Documentation:** https://docs.rs/crossbeam-channel/latest/crossbeam_channel/

---

## Summary

**Key Takeaways:**

1. **Use owned types only** - No lifetime annotations needed for SIGIL collectors
2. **Prefer internal receiver pattern** - Simplest and safest for most use cases
3. **Always add timeout protection** - Prevent indefinite hangs in concurrent scenarios
4. **Manage thread lifetimes explicitly** - No unmanaged threads in production code
5. **Never use underscore prefix for receivers** - Causes immediate drops and hangs
6. **Document ownership transfers** - Make expectations clear in API docs

**Canonical Patterns:**

- **Simple collection:** Internal receiver only
- **Multi-producer:** Concurrent clones with timeout protection
- **External monitoring:** Explicit external receiver lifecycle management

**Validation Checklist:**

- Review API design for owned types only
- Check test code for underscore prefix drops
- Verify timeout protection on all blocking operations
- Ensure thread lifecycle management in concurrent scenarios
- Document ownership requirements in API docs

---

**Document Owner:** SIGIL Development Team  
**Last Updated:** 2026-07-13  
**Next Review:** After implementation of lifetime fixes from Phase N plan