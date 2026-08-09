#!/bin/bash
# Run sigil-core tests with output redirection using tee
# Captures both stdout and stderr to a file while displaying to terminal

set -o pipefail  # Ensure exit code from cargo test is captured, not tee

OUTPUT_FILE="/tmp/sigil-core-test-output.txt"

echo "Running sigil-core tests with output redirection..."
echo "Output will be written to: $OUTPUT_FILE"
echo ""

# Run tests with tee, capturing both streams
cargo test -p sigil-core 2>&1 | tee "$OUTPUT_FILE"
TEST_EXIT_CODE=${PIPESTATUS[0]}

echo ""
echo "Test execution completed."
echo "Exit code from cargo test: $TEST_EXIT_CODE"
echo "Output file size: $(wc -c < "$OUTPUT_FILE") bytes"

# Exit with the actual test exit code, not tee's exit code
exit $TEST_EXIT_CODE
