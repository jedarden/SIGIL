# SIGIL Test Timing Capture - Research and Recommendations

## Executive Summary

**Research Date:** 2026-08-10  
**Purpose:** Evaluate cargo test timing capture options for SIGIL CI/CD pipeline  
**Recommendation:** Use cargo-nextest with structured JSON output for CI integration, supplemented by standard cargo test with JUnit conversion for compatibility.

---

## Available Methods for Test Timing Capture

### 1. **cargo-nextest** (RECOMMENDED)

**Overview:** Modern, actively-maintained test runner with built-in timing support.

**Key Features:**
- ✅ Built-in timing data collection per test
- ✅ Structured JSON output formats
- ✅ HTML timing reports
- ✅ Parallel test execution optimization
- ✅ Stable machine-readable output with versioning
- ✅ Direct integration with cargo workspace

**Installation:** Already available in SIGIL environment (`/home/coding/.cargo/bin/cargo-nextest`)

**Usage Examples:**

```bash
# Run with JSON output for CI integration
cargo nextest run --message-format libtest-json-plus --message-format-version 1

# Generate HTML timing report
cargo nextest run --timings=html

# Generate JSON timing data
cargo nextest run --timings=json

# Combined: Run tests and generate both machine-readable and human-readable reports
cargo nextest run --message-format libtest-json-plus --timings=html,json
```

**Output Format:** Structured JSON with timing metadata per test

**Pros:**
- Native timing support without external tools
- Active development and community support
- Excellent performance optimizations
- Multiple output formats for different use cases
- Designed for CI/CD integration
- Provides slowest test identification

**Cons:**
- Not installed by default in all environments
- Slightly different output format than libtest
- Some learning curve for configuration

**SIGIL Compatibility:** ✅ Excellent - already available and workspace-compatible

---

### 2. **Standard cargo test with JSON Output**

**Overview:** Use libtest's built-in JSON output format with timing inference.

**Key Features:**
- ✅ No additional dependencies
- ✅ Standard libtest JSON format
- ✅ Compatible with all cargo installations
- ⚠️ Timing requires start/end timestamp calculation

**Usage Examples:**

```bash
# Run tests with JSON output
cargo test -- --format=json -- --test-threads=1

# Capture with external timing
time cargo test -- --format=json -- --test-threads=1
```

**Output Format:** JSON stream with test events, but timing requires inference

**Pros:**
- Works everywhere cargo is available
- Standard Rust toolchain format
- No additional dependencies
- Well-documented format

**Cons:**
- Timing data requires calculation (start vs end timestamps)
- Single-threaded execution required for accurate timing
- JSON output can be verbose
- No built-in timing summaries

**SIGIL Compatibility:** ✅ Good - standard approach but less ideal than nextest

---

### 3. **JUnit XML Output**

**Overview:** Generate JUnit-compatible XML reports with timing data.

**Key Features:**
- ✅ Standard CI/CD integration format
- ✅ Includes execution time per test
- ✅ Human-readable when needed
- ⚠️ Requires external conversion tool

**Usage Examples:**

```bash
# Use cargo-junit for direct JUnit output
cargo install cargo-junit
cargo junit --output test-results.xml

# Or convert libtest JSON to JUnit
cargo test -- --format=json | jq '.' > test-results.json
# Convert using external tool (requires custom script)
```

**Output Format:** JUnit XML with `<testsuite>` and `<testcase>` elements including timing

**Pros:**
- Standard format for CI systems
- Most CI platforms have native JUnit support
- Includes timing data
- Human-readable when needed

**Cons:**
- Requires external conversion tool
- Additional dependency (cargo-junit)
- Less flexible than modern formats
- Not native to cargo ecosystem

**SIGIL Compatibility:** ✅ Good - works with Argo Workflows JUnit parsing

---

### 4. **Custom Test Harness**

**Overview:** Build a custom test harness with integrated timing collection.

**Key Features:**
- ✅ Complete control over timing collection
- ✅ Can include custom metadata
- ✅ Flexible output formats
- ❌ Requires significant development effort
- ❌ Maintenance overhead

**Implementation Example:**

```rust
// In tests/timing_harness.rs
use std::time::{Duration, Instant};

struct TimedTest {
    name: String,
    start: Instant,
    duration: Duration,
    result: TestResult,
}

impl TimedTest {
    fn run<F>(name: &str, test_fn: F) -> Self 
    where F: FnOnce() -> () 
    {
        let start = Instant::now();
        let result = test_fn();
        let duration = start.elapsed();
        
        Self {
            name: name.to_string(),
            start,
            duration,
            result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_with_timing() {
        let timed = TimedTest::run("my_test", || {
            // actual test code
            assert_eq!(2 + 2, 4);
        });
        
        println!("Test {} took {:?}", timed.name, timed.duration);
    }
}
```

**Pros:**
- Complete control over timing format
- Can integrate with existing test structure
- Customizable output for specific needs

**Cons:**
- High maintenance overhead
- Requires modifying existing tests
- Potential for timing inconsistencies
- Reinventing the wheel

**SIGIL Compatibility:** ⚠️ Not recommended - excessive development effort for minimal benefit

---

### 5. **Standard cargo test with --timings flag**

**Overview:** Use cargo's built-in (but unstable) timings flag.

**Key Features:**
- ✅ Native cargo support
- ✅ No external dependencies
- ⚠️ Unstable feature (requires nightly)
- ⚠️ Limited output options

**Usage Examples:**

```bash
# Requires nightly toolchain
cargo +nightly test --timings -- --test-threads=1

# With stable format
cargo test -Ztimings -- --test-threads=1
```

**Output Format:** Build timing summary, not individual test timing

**Pros:**
- Native cargo feature
- No external dependencies
- Part of standard toolchain

**Cons:**
- Unstable feature
- Requires nightly toolchain
- Focuses on build timing, not test timing
- Limited output format
- Not suitable for production CI

**SIGIL Compatibility:** ⚠️ Not recommended - unstable and limited utility

---

## Recommended Approach for SIGIL

### Primary Recommendation: **cargo-nextest with JSON output**

**Implementation Strategy:**

1. **CI Pipeline Integration:**
```bash
# In sigil-ci workflow template
cargo nextest run \
  --message-format libtest-json-plus \
  --message-format-version 1 \
  --timings=json \
  --failure-output immediate \
  --success-output immediate \
  | tee test-results.json

# Also generate human-readable report
cargo nextest run --timings=html --output-dir timing-reports/
```

2. **Timing Data Structure:**
```json
{
  "test": {
    "name": "tests::test_get_secret_success",
    "status": "passed",
    "exec_time": 0.023456,
    "start_time": "2026-08-10T12:34:56.789Z",
    "end_time": "2026-08-10T12:34:56.812Z"
  },
  "suite": {
    "name": "sigil-core",
    "total_tests": 11,
    "passed": 11,
    "failed": 0,
    "total_time": 0.156789
  }
}
```

3. **Argo Workflows Integration:**
```yaml
# In sigil-ci workflow template
- name: run-tests
  run: |
    cargo nextest run \
      --message-format libtest-json-plus \
      --message-format-version 1 \
      --no-fail-fast \
      > test-results.json
    
    # Parse for failures
    if jq -e '.[] | select(.status == "failed")' test-results.json; then
      echo "Tests failed"
      exit 1
    fi
    
    # Archive timing data
    gzip test-results.json
    artifacts: test-results.json.gz
```

### Fallback Option: **Standard cargo with custom timing script**

**When to use:** Environments where cargo-nextest is unavailable

**Implementation:**
```bash
#!/bin/bash
# Enhanced version of existing capture-test-timing.sh

set -e

echo "Starting test execution timing capture..."

# Use cargo test with --test-threads=1 for accurate timing
START_TIME=$(date +%s.%N)

cargo test -- --test-threads=1 --nocapture 2>&1 | tee test-output.log

END_TIME=$(date +%s.%N)
ELAPSED=$(awk "BEGIN {printf \"%.3f\", $END_TIME - $START_TIME}")

echo "Total execution time: $ELAPSED seconds"

# Parse individual test times from output
grep "test .* OK" test-output.log | while read -r line; do
  # Extract test name and timing information
  echo "$line" | awk '{print $1, $2}'
done > test-times.txt
```

---

## Comparison Matrix

| Method | Timing Accuracy | CI Integration | Maintenance | Output Formats | SIGIL Fit |
|--------|---------------|----------------|-------------|---------------|-----------|
| **cargo-nextest** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | JSON, HTML | ✅ Best |
| **cargo test JSON** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | JSON | ✅ Good |
| **JUnit XML** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | XML, HTML | ✅ Good |
| **Custom Harness** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐ | Custom | ⚠️ Poor |
| **cargo --timings** | ⭐⭐ | ⭐⭐ | ⭐⭐ | Text | ⚠️ Poor |

---

## Implementation Recommendations

### Immediate Actions

1. **Update CI Workflow Template:**
   - Add cargo-nextest as primary test runner
   - Include both JSON and HTML timing outputs
   - Archive timing data as workflow artifacts

2. **Enhance Existing Script:**
   - Update `capture-test-timing.sh` to use cargo-nextest
   - Add JSON output processing
   - Generate timing summary reports

3. **Add Pre-commit Hook:**
   ```bash
   # In .git/hooks/pre-commit
   cargo nextest run --message-format libtest-json-plus --failure-output immediate
   ```

### Long-term Enhancements

1. **Performance Tracking:**
   - Track test timing trends across CI runs
   - Alert on test performance degradation
   - Identify slowest tests for optimization

2. **Historical Analysis:**
   - Store timing data in structured format
   - Build timing dashboards
   - Correlate timing with code changes

3. **Parallel Execution:**
   - Leverage nextest's parallel execution
   - Optimize test suite performance
   - Reduce CI pipeline duration

---

## SIGIL-Specific Considerations

### CI Environment (Argo Workflows on iad-ci)

**Current Setup:**
- Cluster: Rackspace Spot, us-east-iad-1
- Platform: Linux (x86_64)
- Resources: 1000m CPU, 2Gi memory
- Current issues: Test execution not reaching full potential

**Recommended Configuration:**
```yaml
# In sigil-ci workflow template
- name: run-tests-with-timing
  container:
    image: rust:latest
  script:
    - |
      # Install nextest if not available
      if ! command -v cargo-nextest &> /dev/null; then
        cargo install cargo-nextest
      fi
      
      # Run tests with timing
      cargo nextest run \
        --message-format libtest-json-plus \
        --message-format-version 1 \
        --timings=json,html \
        --profile ci \
        > test-results.json
      
      # Archive results
      gzip test-results.json
  artifacts:
    - name: test-results
      path: test-results.json.gz
```

### Resource Constraints

**Memory/Time Considerations:**
- Nextest is memory-efficient for parallel test execution
- Current resource allocation should be sufficient
- HTML timing reports provide lightweight visualization
- JSON data is minimal and easily compressed

### Integration with Existing Monitoring

**Current SIGIL Monitoring:**
- Comprehensive health checks via `sigil doctor`
- Audit log for security events
- Performance tracking via benchmarks

**Test Timing Integration:**
```toml
# In .sigil/config.toml
[ci.test_timing]
enabled = true
format = "libtest-json-plus"
archive_results = true
max_test_duration = "5m"
slow_test_threshold = "1s"
```

---

## Conclusion and Next Steps

### Recommendation Summary

**Primary:** Use **cargo-nextest** with `libtest-json-plus` output format for CI integration, supplemented by HTML reports for human review.

**Fallback:** Maintain enhanced version of existing `capture-test-timing.sh` script using standard cargo test for environments where nextest is unavailable.

### Implementation Priority

1. **High Priority (This Week):**
   - Update sigil-ci workflow to use cargo-nextest
   - Modify existing timing capture script
   - Archive timing data as workflow artifacts

2. **Medium Priority (This Month):**
   - Add timing trend analysis
   - Create performance dashboards
   - Set up test performance alerting

3. **Low Priority (Next Quarter):**
   - Parallel test execution optimization
   - Historical timing database
   - Performance regression testing

### Expected Benefits

- **Improved CI Observability:** Detailed timing data per test
- **Performance Insights:** Identify slow tests and optimization targets  
- **Better Debugging:** Correlate test timing with system state
- **Enhanced Quality:** Track performance regressions over time
- **Developer Experience:** Fast feedback on test performance

---

**Research Completed:** 2026-08-10  
**Recommended Implementation:** cargo-nextest with JSON/HTML outputs  
**Estimated Implementation Time:** 2-4 hours for CI integration  
**Maintenance Overhead:** Low (uses existing tools)  
**Backward Compatibility:** High (fallback to standard cargo available)  

---

## Appendix: Sample Output Formats

### cargo-nextest JSON Output Example

```json
{
  "format_version": "1",
  "metadata": {
    "runner": "nextest",
    "version": "0.9.0",
    "timestamp": "2026-08-10T12:34:56.789Z"
  },
  "tests": [
    {
      "name": "tests::test_get_secret_success",
      "status": "passed",
      "exec_time": 0.023456,
      "start_time": "2026-08-10T12:34:56.789Z",
      "end_time": "2026-08-10T12:34:56.812Z",
      "stdout": "",
      "stderr": ""
    },
    {
      "name": "tests::test_list_secrets_success", 
      "status": "passed",
      "exec_time": 0.012345,
      "start_time": "2026-08-10T12:34:56.813Z",
      "end_time": "2026-08-10T12:34:56.825Z"
    }
  ],
  "summary": {
    "total": 11,
    "passed": 11,
    "failed": 0,
    "skipped": 0,
    "total_time": 0.156789,
    "slowest_tests": [
      {
        "name": "tests::test_cache_hit_behavior",
        "time": 0.045678
      },
      {
        "name": "tests::test_delete_secret_success", 
        "time": 0.034567
      }
    ]
  }
}
```

### cargo-nextest HTML Report Example

The HTML output generates an interactive dashboard with:
- Visual timeline of test execution
- Color-coded test results (green/red/yellow)
- Slowest test identification
- Filtering and sorting capabilities
- Timeline visualization of parallel execution

This provides an excellent human-readable complement to the machine-readable JSON data.