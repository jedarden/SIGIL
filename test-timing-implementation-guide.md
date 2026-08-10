# Test Timing Implementation Guide

## Quick Start

### Option 1: Use Enhanced Script (Recommended)

```bash
# Run with cargo-nextest (default)
./capture-test-timing.sh

# Run with standard cargo test
USE_NEXTEST=false ./capture-test-timing.sh

# View results
cat test-timing-results/summary_*.txt
open test-timing-results/timing-html_*/index.html  # macOS
xdg-open test-timing-results/timing-html_*/index.html  # Linux
```

### Option 2: Direct cargo-nextest Commands

```bash
# Generate JSON timing data for CI
cargo nextest run \
  --message-format libtest-json-plus \
  --message-format-version 1 \
  --timings=json \
  > test-results.json

# Generate HTML timing report for human review
cargo nextest run --timings=html --output-dir timing-reports/

# Combined approach
cargo nextest run \
  --message-format libtest-json-plus \
  --timings=json,html \
  --output-dir test-results/
```

### Option 3: Standard cargo test with timing script

```bash
# Falls back to standard cargo if nextest unavailable
USE_NEXTEST=false ./capture-test-timing.sh

# Or use cargo directly with timing
time cargo test -- --test-threads=1 --nocapture
```

## Integration with Argo Workflows

### Update sigil-ci Workflow Template

Add to the CI workflow template in declarative-config/k8s/iad-ci/argo-workflows/:

```yaml
# In the test execution step
- name: run-tests-with-timing
  container:
    image: rust:latest
  script:
    - |
      # Install nextest if needed
      if ! command -v cargo-nextest &> /dev/null; then
        cargo install cargo-nextest
      fi
      
      # Run tests with comprehensive timing
      ./capture-test-timing.sh
      
      # Archive results as workflow artifacts
      tar -czf test-timing-results.tar.gz test-timing-results/
      
      # Check for failures
      if [ -f test-timing-results/timing_*.json ]; then
        FAILED=$(jq '[.tests[] | select(.status == "failed")] | length' test-timing-results/timing_*.json)
        if [ "$FAILED" -gt 0 ]; then
          echo "Tests failed: $FAILED"
          exit 1
        fi
      fi
```

## Reading and Using Timing Data

### Parse JSON Data

```bash
# Get test summary
jq '.summary' test-timing-results/timing_*.json

# Find slowest tests
jq '.tests | sort_by(.exec_time) | reverse | .[0:5] | .[] | {name, exec_time}' test-timing-results/timing_*.json

# Get failed tests only
jq '.tests[] | select(.status == "failed")' test-timing-results/timing_*.json

# Calculate timing statistics
jq '{total: .summary.total_time, 
       average: (.summary.total_time / .summary.total),
       slowest: (.tests | max_by(.exec_time) | .exec_time)}' test-timing-results/timing_*.json
```

### Performance Analysis

```bash
# Compare timing between runs
TIMING_DIR="test-timing-results"

# Get latest and previous timing results
LATEST=$(ls -t "$TIMING_DIR"/timing_*.json | head -1)
PREVIOUS=$(ls -t "$TIMING_DIR"/timing_*.json | head -2 | tail -1)

# Compare total execution time
LATEST_TIME=$(jq '.summary.total_time' "$LATEST")
PREV_TIME=$(jq '.summary.total_time' "$PREVIOUS")

echo "Latest:   $LATEST_TIME seconds"
echo "Previous: $PREV_TIME seconds"
echo "Change:   $(echo "$LATEST_TIME - $PREV_TIME" | bc) seconds"
```

## Monitoring and Alerts

### Setup Performance Alerts

```bash
# Check for slow tests (>1 second)
jq '.tests[] | select(.exec_time > 1.0) | {name, exec_time}' test-timing-results/timing_*.json

# Check for test suite performance degradation
SLOW_THRESHOLD=5.0  # 5 seconds
TOTAL_TIME=$(jq '.summary.total_time' test-timing-results/timing_*.json)

if (( $(echo "$TOTAL_TIME > $SLOW_THRESHOLD" | bc -l) )); then
    echo "WARNING: Test suite taking longer than ${SLOW_THRESHOLD}s"
fi
```

### Generate Performance Report

```bash
# Create a simple performance report
cat > test-performance-report.md <<EOF
# Test Performance Report

**Generated:** $(date)  
**Test Runner:** cargo-nextest  
**Total Time:** $(jq '.summary.total_time' test-timing-results/timing_*.json) seconds  
**Total Tests:** $(jq '.summary.total' test-timing-results/timing_*.json)  
**Passed:** $(jq '.summary.passed' test-timing-results/timing_*.json)  

## Slowest Tests (Top 5)

$(jq -r '.tests | sort_by(.exec_time) | reverse | .[0:5] | .[] | "- \(.name): \(.exec_time)s"' test-timing-results/timing_*.json)

## Failed Tests

$(jq -r '.tests[] | select(.status == "failed") | "- \(.name)"' test-timing-results/timing_*.json)
EOF
```

## Troubleshooting

### Common Issues

**Issue:** "cargo-nextest: command not found"
```bash
# Solution: Install cargo-nextest
cargo install cargo-nextest

# Or use fallback mode
USE_NEXTEST=false ./capture-test-timing.sh
```

**Issue:** HTML report not generated
```bash
# Solution: Check if nextest supports HTML output
cargo nextest run --timings=html --help

# Or generate manually
cargo nextest run --timings=json | jq '.' > timing.json
# Convert JSON to HTML using external tool
```

**Issue:** Timing data inaccurate with parallel tests
```bash
# Solution: Run tests serially for accurate timing
cargo nextest run --threads 1 --message-format libtest-json-plus
```

**Issue:** CI timing different from local timing
```bash
# Solution: Account for CI resource constraints
# Check CI resource allocation
# Consider using --profile ci for CI-optimized settings
cargo nextest run --profile ci --message-format libtest-json-plus
```

## Maintenance

### Regular Cleanup

```bash
# Remove old timing results (keep last 10 runs)
cd test-timing-results
ls -t timing_*.json | tail -n +11 | xargs rm -f
ls -t timing-html_* | tail -n +11 | xargs rm -f
```

### Archive Historical Data

```bash
# Create archive of timing data for long-term analysis
tar -czf sigil-test-timing-archive-$(date +%Y%m).tar.gz test-timing-results/

# Store in separate location for historical tracking
mv sigil-test-timing-archive-*.tar.gz /path/to/storage/
```

---

**Implementation Complete:** 2026-08-10  
**Recommended Method:** cargo-nextest with JSON/HTML outputs  
**Fallback Method:** Enhanced timing capture script  
**Status:** Ready for CI integration