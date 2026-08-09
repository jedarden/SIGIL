#!/bin/bash
# Script to run cargo test with tee output redirection while preserving exit codes
# This ensures we get the actual test exit code, not tee's exit code

set -o pipefail

OUTPUT_FILE="${1:-/tmp/sigil-core-test-output.txt}"
TEST_COMMAND="cargo test -p sigil-core 2>&1"

echo "Running tests with output capture to: $OUTPUT_FILE"
echo "Command: $TEST_COMMAND"
echo "Exit code capture: enabled (pipefail)"

# Run the command with tee and capture the actual exit code
eval "$TEST_COMMAND | tee \"$OUTPUT_FILE\""
EXIT_CODE=$?

echo ""
echo "=========================================="
echo "Test Results Summary"
echo "=========================================="
echo "Exit code: $EXIT_CODE"
echo "Output saved to: $OUTPUT_FILE"
echo "Output file size: $(wc -c < "$OUTPUT_FILE") bytes"
echo "Output line count: $(wc -l < "$OUTPUT_FILE") lines"

if [ $EXIT_CODE -eq 0 ]; then
    echo "Status: All tests passed ✓"
else
    echo "Status: Some tests failed ✗"
    echo ""
    echo "Failed tests:"
    grep "FAILED" "$OUTPUT_FILE" || echo "No failures found in output"
fi

exit $EXIT_CODE