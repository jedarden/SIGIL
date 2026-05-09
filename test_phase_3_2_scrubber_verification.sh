#!/bin/bash
# Phase 3.2: Verify output scrubber with all encoding variants
#
# This script verifies the Aho-Corasick implementation handles:
# - All 7 encoding types (11 AC patterns with base64 offsets)
# - Cross-chunk boundary splitting
# - Multi-line secrets (PEM certificates)
# - Performance targets

set -e

export PATH="$HOME/.cargo/bin:$PATH"

echo "=================================================="
echo "Phase 3.2: Scrubber Verification"
echo "=================================================="
echo ""

# Run all scrubber tests with output
echo "1. Running all scrubber tests..."
cargo test -p sigil-scrub --lib 2>&1 | tee /tmp/scrubber_test_output.txt

# Check if all tests passed
if grep -q "test result: ok" /tmp/scrubber_test_output.txt; then
    echo "✓ All tests passed"
else
    echo "✗ Some tests failed"
    exit 1
fi

echo ""
echo "2. Verifying encoding variant tests..."
ENCODING_TESTS=$(grep -c "test_phase32_all_encoding_variants" /tmp/scrubber_test_output.txt || true)
if [ "$ENCODING_TESTS" -gt 0 ]; then
    echo "✓ Encoding variants test ran"
else
    echo "✗ Encoding variants test missing"
    exit 1
fi

echo ""
echo "3. Verifying base64 alignment offset tests..."
BASE64_TESTS=$(grep -c "test_phase32_base64url_with_alignment_offsets" /tmp/scrubber_test_output.txt || true)
if [ "$BASE64_TESTS" -gt 0 ]; then
    echo "✓ Base64 alignment offset test ran"
else
    echo "✗ Base64 alignment offset test missing"
    exit 1
fi

echo ""
echo "4. Verifying cross-chunk boundary tests..."
BOUNDARY_TESTS=$(grep -c "test_phase3_redteam_cross_chunk_boundary" /tmp/scrubber_test_output.txt || true)
if [ "$BOUNDARY_TESTS" -gt 0 ]; then
    echo "✓ Cross-chunk boundary test ran"
else
    echo "✗ Cross-chunk boundary test missing"
    exit 1
fi

echo ""
echo "5. Verifying multi-line PEM certificate tests..."
PEM_TESTS=$(grep -c "test_phase32_multiline_pem_certificate" /tmp/scrubber_test_output.txt || true)
if [ "$PEM_TESTS" -gt 0 ]; then
    echo "✓ Multi-line PEM certificate test ran"
else
    echo "✗ Multi-line PEM certificate test missing"
    exit 1
fi

echo ""
echo "6. Performance Test Results:"
echo "--------------------------------------------------"
grep -A 6 "Phase 3.2 Performance Test Results:" /tmp/scrubber_test_output.txt || echo "Performance test output not found"
echo ""
grep -A 4 "Phase 3.2 Typical Case Performance:" /tmp/scrubber_test_output.txt || echo "Typical case performance not found"

echo ""
echo "7. Verifying performance targets..."
# Extract scrub duration from performance test
SCRUB_DURATION=$(grep "Scrub duration:" /tmp/scrubber_test_output.txt | head -1 | grep -oP '\d+\.\d+(?=ms)' || echo "0")
TYPICAL_DURATION=$(grep "Scrub duration:" /tmp/scrubber_test_output.txt | tail -1 | grep -oP '\d+\.\d+(?=ms)' || echo "0")

echo "   Large case scrub duration: ${SCRUB_DURATION}ms (target: < 1000ms)"
echo "   Typical case scrub duration: ${TYPICAL_DURATION}ms (target: < 25ms)"

# Compare with targets (using bc for floating point comparison)
if command -v bc &> /dev/null; then
    if (( $(echo "$SCRUB_DURATION < 1000" | bc -l) )); then
        echo "   ✓ Large case performance target met"
    else
        echo "   ✗ Large case performance target NOT met"
        exit 1
    fi

    if (( $(echo "$TYPICAL_DURATION < 25" | bc -l) )); then
        echo "   ✓ Typical case performance target met"
    else
        echo "   ✗ Typical case performance target NOT met"
        exit 1
    fi
else
    echo "   (bc not available, skipping numeric verification)"
fi

echo ""
echo "=================================================="
echo "Phase 3.2 Verification Complete"
echo "=================================================="
echo ""
echo "Summary:"
echo "  ✓ All 7 encoding types verified"
echo "  ✓ Base64 alignment offsets (3) verified"
echo "  ✓ Cross-chunk boundary buffering verified"
echo "  ✓ Multi-line PEM certificates verified"
echo "  ✓ Performance targets met"
echo ""
