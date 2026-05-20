#!/bin/bash
# End-to-end test for SIGIL CLI commands
# Tests: init, add, get, list, edit, rm, export, import

set -e

SIGIL_BIN="./target/release/sigil"
TEST_DIR="/tmp/sigil-test-$$"
VAULT_DIR="$TEST_DIR/vault"
ARCHIVE_FILE="$TEST_DIR/test-export.sigil"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to print test results
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        ((TESTS_FAILED++))
    fi
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up test directory...${NC}"
    rm -rf "$TEST_DIR"
}

# Set trap to cleanup on exit
trap cleanup EXIT

echo "=========================================="
echo "SIGIL CLI End-to-End Test Suite"
echo "=========================================="
echo "Test directory: $TEST_DIR"
echo ""

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Export environment to use test vault
export SIGIL_VAULT_DIR="$VAULT_DIR"

# Test 1: sigil init
echo -e "\n${YELLOW}Test 1: Initialize vault${NC}"
"$SIGIL_BIN" init --passphrase "test123" --force
print_result $? "sigil init"

# Test 2: sigil add - Add multiple secrets
echo -e "\n${YELLOW}Test 2: Add secrets${NC}"

# Add a simple secret
echo "my-secret-value" | "$SIGIL_BIN" add api/key --value - 2>&1 | grep -q "Added secret"
print_result $? "sigil add (pipe)"

# Add a secret with --value flag
"$SIGIL_BIN" add database/url --value "postgresql://localhost:5432/db" 2>&1 | grep -q "Added secret"
print_result $? "sigil add (--value)"

# Add a secret with metadata
"$SIGIL_BIN" add aws/token --value "aws-secret-token" --description "AWS access token" 2>&1 | grep -q "Added secret"
print_result $? "sigil add (with metadata)"

# Test 3: sigil list
echo -e "\n${YELLOW}Test 3: List secrets${NC}"
LIST_OUTPUT=$("$SIGIL_BIN" list)
echo "$LIST_OUTPUT" | grep -q "api/key"
print_result $? "sigil list (api/key found)"
echo "$LIST_OUTPUT" | grep -q "database/url"
print_result $? "sigil list (database/url found)"
echo "$LIST_OUTPUT" | grep -q "aws/token"
print_result $? "sigil list (aws/token found)"

# Test 4: sigil get
echo -e "\n${YELLOW}Test 4: Get secrets${NC}"

# Get secret value
GET_OUTPUT=$("$SIGIL_BIN" get api/key)
echo "$GET_OUTPUT" | grep -q "my-secret-value"
print_result $? "sigil get (value retrieval)"

# Get with JSON output
JSON_OUTPUT=$("$SIGIL_BIN" get api/key --json)
echo "$JSON_OUTPUT" | grep -q '"value"'
print_result $? "sigil get --json"

# Get metadata
META_OUTPUT=$("$SIGIL_BIN" get aws/token --metadata)
echo "$META_OUTPUT" | grep -q "AWS access token"
print_result $? "sigil get --metadata"

# Test 5: sigil edit
echo -e "\n${YELLOW}Test 5: Edit secret${NC}"
"$SIGIL_BIN" edit api/key --value "new-secret-value" 2>&1 | grep -q "Updated"
print_result $? "sigil edit"

# Verify edit
GET_OUTPUT=$("$SIGIL_BIN" get api/key)
echo "$GET_OUTPUT" | grep -q "new-secret-value"
print_result $? "sigil edit (verification)"

# Test 6: sigil history
echo -e "\n${YELLOW}Test 6: Secret history${NC}"
HISTORY_OUTPUT=$("$SIGIL_BIN" history api/key)
echo "$HISTORY_OUTPUT" | grep -q "Version"
print_result $? "sigil history"

# Test 7: sigil export
echo -e "\n${YELLOW}Test 7: Export vault${NC}"
"$SIGIL_BIN" export --output "$ARCHIVE_FILE" --passphrase "export123"
print_result $? "sigil export"

# Verify archive exists
[ -f "$ARCHIVE_FILE" ]
print_result $? "sigil export (file exists)"

# Test 8: sigil import (first verify we can read the archive)
echo -e "\n${YELLOW}Test 8: Import vault verification${NC}"
"$SIGIL_BIN" import --source "$ARCHIVE_FILE" --passphrase "export123" --dry-run 2>&1 | grep -q "Would import"
print_result $? "sigil import --dry-run"

# Test 9: Verify import mode selection
echo -e "\n${YELLOW}Test 9: Import mode options${NC}"
# Test that import accepts different modes
"$SIGIL_BIN" import --help | grep -q "mode"
print_result $? "sigil import (mode option available)"

# Test 10: sigil rm
echo -e "\n${YELLOW}Test 10: Remove secret${NC}"
"$SIGIL_BIN" rm api/key --confirm
print_result $? "sigil rm"

# Verify removal
! "$SIGIL_BIN" get api/key 2>/dev/null
print_result $? "sigil rm (verification)"

# Test 11: Verify remaining secrets
echo -e "\n${YELLOW}Test 11: Verify remaining secrets${NC}"
REMAINING=$("$SIGIL_BIN" list | wc -l)
[ "$REMAINING" -ge 2 ]  # Should have at least 2 secrets left
print_result $? "sigil list (after removal)"

# Test 12: Batch operations
echo -e "\n${YELLOW}Test 12: Batch add operations${NC}"
for i in {1..5}; do
    echo "batch-secret-$i" | "$SIGIL_BIN" add "batch/secret$i" --value -
done
BATCH_COUNT=$("$SIGIL_BIN" list | grep -c "batch/")
[ "$BATCH_COUNT" -eq 5 ]
print_result $? "Batch operations (5 secrets added)"

# Test 13: Verify vault integrity
echo -e "\n${YELLOW}Test 13: Vault integrity check${NC}"
"$SIGIL_BIN" vault status 2>&1 | grep -q "Location"
print_result $? "sigil vault status"

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
echo "=========================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
