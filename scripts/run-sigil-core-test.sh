#!/bin/bash
# Run sigil-core tests with output redirection using tee and timing capture
# Captures both stdout and stderr to a file while displaying to terminal
# Adds timing information for total execution and per-test breakdown

set -o pipefail  # Ensure exit code from cargo test is captured, not tee

OUTPUT_FILE="/tmp/sigil-core-test-output.txt"
TIMING_FILE="/tmp/sigil-core-test-timings.txt"
MAIN_OUTPUT_FILE="./sigil-test-output.log"

echo "Running sigil-core tests with output redirection and timing capture..."
echo "Output will be written to: $OUTPUT_FILE"
echo "Timing data will be written to: $TIMING_FILE"
echo ""

# Record start time
START_TIME=$(date +%s.%N)
echo "Test execution started at: $(date)" > "$TIMING_FILE"
echo "" >> "$TIMING_FILE"

# Run tests with --timings flag for per-test timing breakdown
# Use time command to capture total execution time
{
    time cargo test -p sigil-core --timings 2>&1 | tee "$OUTPUT_FILE"
    TEST_EXIT_CODE=${PIPESTATUS[0]}
}

# Record end time
END_TIME=$(date +%s.%N)

# Calculate total time (use awk for floating point arithmetic if bc is not available)
if command -v bc >/dev/null 2>&1; then
    TOTAL_TIME=$(echo "$END_TIME - $START_TIME" | bc)
else
    TOTAL_TIME=$(awk "BEGIN {printf \"%.3f\", $END_TIME - $START_TIME}")
fi

echo ""
echo "Test execution completed."
echo "Exit code from cargo test: $TEST_EXIT_CODE"
echo "Output file size: $(wc -c < "$OUTPUT_FILE") bytes"

# Append timing summary to timing file
{
    echo ""
    echo "=========================================="
    echo "TIMING SUMMARY"
    echo "=========================================="
    echo "Total execution time: $TOTAL_TIME seconds"
    echo "Started at: $(date -d @$START_TIME 2>/dev/null || date -r $START_TIME 2>/dev/null || date)"
    echo "Ended at: $(date -d @$END_TIME 2>/dev/null || date -r $END_TIME 2>/dev/null || date)"
    echo ""
    echo "Per-test timing breakdown:"
    echo "=========================================="

    # Extract timing information from the output file
    # cargo --timings outputs table with test names and durations
    grep -A 100 "Test Execution Timings" "$OUTPUT_FILE" >> "$TIMING_FILE" 2>/dev/null || \
        grep -E "test result:|^\s+test\s+" "$OUTPUT_FILE" | tail -20 >> "$TIMING_FILE"

    echo "Timing data saved to: $TIMING_FILE"
} >> "$TIMING_FILE"

# Append timing summary to main output file
{
    echo ""
    echo "=========================================="
    echo "TIMING INFORMATION"
    echo "=========================================="
    echo "Total execution time: $TOTAL_TIME seconds"
    echo "Detailed timing breakdown: $TIMING_FILE"
    echo "=========================================="
} >> "$MAIN_OUTPUT_FILE" 2>/dev/null || true

# Display timing summary
cat "$TIMING_FILE"

# Exit with the actual test exit code, not tee's exit code
exit $TEST_EXIT_CODE
