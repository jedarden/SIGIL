#!/bin/bash
# SIGIL Test Timing Capture Script (Enhanced)
# Supports both cargo-nextest and standard cargo test timing capture

set -e

# Configuration
OUTPUT_DIR="test-timing-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
USE_NEXTEST=${USE_NEXTEST:-true}  # Set to false to use standard cargo
PARALLEL_TESTS=${PARALLEL_TESTS:-false}  # Set to true for parallel execution

echo "Starting SIGIL test execution timing capture..."
echo "=============================================="

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Record start time
START_TIME=$(date +%s.%N)
START_DATE=$(date)

echo "Test execution started at: $START_DATE"
echo "Timing output directory: $OUTPUT_DIR"
echo "Using nextest: $USE_NEXTEST"
echo ""

# Function to run tests with nextest
run_nextest() {
    echo "Running: cargo nextest run with timing capture..."
    echo ""

    # Check if cargo-nextest is available
    if ! command -v cargo-nextest &> /dev/null; then
        echo "ERROR: cargo-nextest not found. Install with: cargo install cargo-nextest"
        exit 1
    fi

    # Enable experimental libtest JSON support
    export NEXTEST_EXPERIMENTAL_LIBTEST_JSON=1

    # Build base command
    NEXTEST_CMD="cargo nextest run --message-format libtest-json-plus --message-format-version 0.1 --failure-output immediate --success-output immediate --target-dir \"$OUTPUT_DIR\" --timings"

    # Add parallel execution if requested
    if [ "$PARALLEL_TESTS" = "true" ]; then
        NEXTEST_CMD="$NEXTEST_CMD --test-threads=auto"
        echo "Running with parallel test execution (--test-threads=auto)"
    else
        NEXTEST_CMD="$NEXTEST_CMD --test-threads=1"
        echo "Running with single-threaded execution for accurate timing"
    fi

    # Run tests with comprehensive timing data
    eval $NEXTEST_CMD > "$OUTPUT_DIR/nextest-output_${TIMESTAMP}.json" 2>&1
    TEST_EXIT_CODE=$?

    if [ -f "$OUTPUT_DIR/nextest-output_${TIMESTAMP}.json" ] && [ -s "$OUTPUT_DIR/nextest-output_${TIMESTAMP}.json" ]; then
        echo "✓ Nextest timing data saved to $OUTPUT_DIR/nextest-output_${TIMESTAMP}.json"
    else
        echo "⚠ Warning: Nextest output file is empty or was not created"
    fi

    return $TEST_EXIT_CODE
}

# Function to run tests with standard cargo
run_cargo() {
    echo "Running: cargo test with timing capture..."
    echo ""

    # Run tests with --test-threads=1 for accurate timing
    cargo test -- --test-threads=1 --nocapture 2>&1 | tee "$OUTPUT_DIR/test-output_${TIMESTAMP}.log"

    TEST_EXIT_CODE=$?

    # Parse individual test times from output
    if [ -f "$OUTPUT_DIR/test-output_${TIMESTAMP}.log" ]; then
        grep "test .* OK" "$OUTPUT_DIR/test-output_${TIMESTAMP}.log" | \
            awk '{print $1, $2}' > "$OUTPUT_DIR/test-times_${TIMESTAMP}.txt"
        echo "✓ Cargo test timing data saved to $OUTPUT_DIR/test-times_${TIMESTAMP}.txt"
    else
        echo "⚠ Warning: Test output file was not created"
    fi

    return $TEST_EXIT_CODE
}

# Run the appropriate test runner (capture exit code explicitly)
if [ "$USE_NEXTEST" = "true" ]; then
    run_nextest || TEST_EXIT_CODE=$?
    TEST_RUNNER="nextest"
else
    run_cargo || TEST_EXIT_CODE=$?
    TEST_RUNNER="cargo"
fi

# Record end time
END_TIME=$(date +%s.%N)
END_DATE=$(date)

# Calculate elapsed time
ELAPSED=$(awk "BEGIN {printf \"%.3f\", $END_TIME - $START_TIME}")

# Generate summary report
{
    echo ""
    echo "=============================================="
    echo "TIMING SUMMARY"
    echo "=============================================="
    echo "Test execution started at: $START_DATE"
    echo "Test execution ended at:   $END_DATE"
    echo "Total execution time:       $ELAPSED seconds"
    echo "Exit code:                  $TEST_EXIT_CODE"
    echo "Test runner:                $TEST_RUNNER"
    echo "Output directory:           $OUTPUT_DIR"
    echo "=============================================="

    # Include nextest-specific info if used
    if [ "$USE_NEXTEST" = "true" ]; then
        echo ""
        echo "Nextest outputs:"
        if [ -f "$OUTPUT_DIR/nextest-output_${TIMESTAMP}.json" ]; then
            echo "  JSON output:   $OUTPUT_DIR/nextest-output_${TIMESTAMP}.json"
            echo ""
            echo "Parse JSON data:   jq '.' $OUTPUT_DIR/nextest-output_${TIMESTAMP}.json"
            echo "Count tests:      jq '[.tests | length]' $OUTPUT_DIR/nextest-output_${TIMESTAMP}.json"
        else
            echo "  ⚠ No JSON output file created"
        fi
    else
        echo ""
        echo "Cargo test outputs:"
        if [ -f "$OUTPUT_DIR/test-output_${TIMESTAMP}.log" ]; then
            echo "  Test log:     $OUTPUT_DIR/test-output_${TIMESTAMP}.log"
        fi
        if [ -f "$OUTPUT_DIR/test-times_${TIMESTAMP}.txt" ]; then
            echo "  Test times:   $OUTPUT_DIR/test-times_${TIMESTAMP}.txt"
        fi
    fi
    echo "=============================================="
} | tee "$OUTPUT_DIR/summary_${TIMESTAMP}.txt"

echo ""
echo "✓ Timing data saved to $OUTPUT_DIR/"
echo "✓ Summary written to $OUTPUT_DIR/summary_${TIMESTAMP}.txt"
echo "✓ Total execution time: $ELAPSED seconds"
echo ""
echo "Quick commands:"
echo "  View timing data:  cat $OUTPUT_DIR/summary_${TIMESTAMP}.txt"
if [ "$USE_NEXTEST" = "true" ] && [ -f "$OUTPUT_DIR/nextest-output_${TIMESTAMP}.json" ]; then
    echo "  Parse JSON data:   jq '.' $OUTPUT_DIR/nextest-output_${TIMESTAMP}.json"
    echo "  Count tests:      jq '[.tests | length]' $OUTPUT_DIR/nextest-output_${TIMESTAMP}.json"
elif [ -f "$OUTPUT_DIR/test-times_${TIMESTAMP}.txt" ]; then
    echo "  View test times:  cat $OUTPUT_DIR/test-times_${TIMESTAMP}.txt"
fi

exit $TEST_EXIT_CODE