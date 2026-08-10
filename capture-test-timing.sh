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

    # Run tests with comprehensive timing data
    cargo nextest run \
        --message-format libtest-json-plus \
        --message-format-version 1 \
        --timings=json,html \
        --failure-output immediate \
        --success-output immediate \
        --output-dir "$OUTPUT_DIR"

    EXIT_CODE=$?

    # Rename output files with timestamp
    if [ -f "$OUTPUT_DIR/timing.json" ]; then
        mv "$OUTPUT_DIR/timing.json" "$OUTPUT_DIR/timing_${TIMESTAMP}.json"
    fi

    if [ -d "$OUTPUT_DIR/timing-html" ]; then
        mv "$OUTPUT_DIR/timing-html" "$OUTPUT_DIR/timing-html_${TIMESTAMP}"
    fi

    return $EXIT_CODE
}

# Function to run tests with standard cargo
run_cargo() {
    echo "Running: cargo test with timing capture..."
    echo ""

    # Run tests with --test-threads=1 for accurate timing
    cargo test -- --test-threads=1 --nocapture 2>&1 | tee "$OUTPUT_DIR/test-output_${TIMESTAMP}.log"

    EXIT_CODE=$?

    # Parse individual test times from output
    grep "test .* OK" "$OUTPUT_DIR/test-output_${TIMESTAMP}.log" | \
        awk '{print $1, $2}' > "$OUTPUT_DIR/test-times_${TIMESTAMP}.txt"

    return $EXIT_CODE
}

# Run the appropriate test runner
if [ "$USE_NEXTEST" = "true" ]; then
    run_nextest
else
    run_cargo
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
    echo "Exit code:                  $EXIT_CODE"
    echo "Output directory:           $OUTPUT_DIR"
    echo "=============================================="

    # Include nextest-specific info if used
    if [ "$USE_NEXTEST" = "true" ]; then
        echo ""
        echo "Nextest outputs:"
        echo "  JSON timing:   $OUTPUT_DIR/timing_${TIMESTAMP}.json"
        echo "  HTML report:  $OUTPUT_DIR/timing-html_${TIMESTAMP}/index.html"
        echo ""
        echo "View HTML report: file://$(pwd)/$OUTPUT_DIR/timing-html_${TIMESTAMP}/index.html"
    else
        echo ""
        echo "Cargo test outputs:"
        echo "  Test log:     $OUTPUT_DIR/test-output_${TIMESTAMP}.log"
        echo "  Test times:   $OUTPUT_DIR/test-times_${TIMESTAMP}.txt"
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
if [ "$USE_NEXTEST" = "true" ]; then
    echo "  Parse JSON data:   jq '.' $OUTPUT_DIR/timing_${TIMESTAMP}.json"
    echo "  Open HTML report: open $OUTPUT_DIR/timing-html_${TIMESTAMP}/index.html"
else
    echo "  View test times:  cat $OUTPUT_DIR/test-times_${TIMESTAMP}.txt"
fi

exit $EXIT_CODE