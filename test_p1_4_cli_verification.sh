#!/bin/bash
# End-to-end verification test for SIGIL CLI commands (Phase 1.4)
# Tests: init, add, get, list, edit, rm, export, import

set -e

SIGIL_BIN="./target/release/sigil"
TEST_DIR=$(mktemp -d)
VAULT_DIR="$TEST_DIR/vault"
ARCHIVE_FILE="$TEST_DIR/archive.sigil"
export SIGIL_HOME="$VAULT_DIR"

echo "=========================================="
echo "SIGIL CLI End-to-End Verification Test"
echo "=========================================="
echo "Test directory: $TEST_DIR"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_count=0
pass_count=0
fail_count=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expected_result="$3"  # "pass" or "fail"

    test_count=$((test_count + 1))
    echo -n "Test $test_count: $test_name ... "

    if eval "$test_cmd" > /dev/null 2>&1; then
        if [ "$expected_result" = "pass" ]; then
            echo -e "${GREEN}PASS${NC}"
            pass_count=$((pass_count + 1))
            return 0
        else
            echo -e "${RED}FAIL (expected failure but succeeded)${NC}"
            fail_count=$((fail_count + 1))
            return 1
        fi
    else
        if [ "$expected_result" = "fail" ]; then
            echo -e "${GREEN}PASS (expected failure)${NC}"
            pass_count=$((pass_count + 1))
            return 0
        else
            echo -e "${RED}FAIL${NC}"
            fail_count=$((fail_count + 1))
            return 1
        fi
    fi
}

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up test directory..."
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

echo "=== Test 1: INIT Command ==="
echo "Initializing vault..."
run_test "Init vault with passphrase" \
    "echo 'test123' | $SIGIL_BIN init" \
    "pass"

if [ ! -d "$VAULT_DIR/.sigil" ]; then
    echo -e "${RED}FAIL: Vault directory not created${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Vault directory created${NC}"

echo ""
echo "=== Test 2: ADD Command ==="
run_test "Add secret 'api/key'" \
    "echo 'my-secret-api-key' | $SIGIL_BIN add api/key" \
    "pass"

run_test "Add secret 'db/password'" \
    "echo 'db-password-123' | $SIGIL_BIN add db/password" \
    "pass"

run_test "Add secret 'user/token'" \
    "echo 'user-token-abc' | $SIGIL_BIN add user/token" \
    "pass"

run_test "Add nested secret 'prod/config/api'" \
    "echo 'prod-api-key' | $SIGIL_BIN add prod/config/api" \
    "pass"

echo -e "${GREEN}✓ Added 4 secrets${NC}"

echo ""
echo "=== Test 3: LIST Command ==="
run_test "List all secrets" \
    "$SIGIL_BIN list" \
    "pass"

# Capture list output
list_output=$($SIGIL_BIN list 2>&1)
echo "$list_output"
if echo "$list_output" | grep -q "api/key"; then
    echo -e "${GREEN}✓ list shows api/key${NC}"
else
    echo -e "${RED}✗ list missing api/key${NC}"
fi

echo ""
echo "=== Test 4: GET Command ==="
run_test "Get secret 'api/key'" \
    "$SIGIL_BIN get api/key" \
    "pass"

# Verify get output
get_output=$($SIGIL_BIN get api/key 2>&1)
if echo "$get_output" | grep -q "my-secret-api-key"; then
    echo -e "${GREEN}✓ get retrieves correct value${NC}"
else
    echo -e "${RED}✗ get returns incorrect value${NC}"
fi

run_test "Get non-existent secret (should fail)" \
    "$SIGIL_BIN get nonexistent/key" \
    "fail"

echo ""
echo "=== Test 5: EDIT Command ==="
run_test "Edit secret 'db/password'" \
    "echo 'new-db-password-456' | $SIGIL_BIN edit db/password" \
    "pass"

# Verify edit worked
edited_output=$($SIGIL_BIN get db/password 2>&1)
if echo "$edited_output" | grep -q "new-db-password-456"; then
    echo -e "${GREEN}✓ edit updated secret value${NC}"
else
    echo -e "${RED}✗ edit did not update value${NC}"
fi

echo ""
echo "=== Test 6: RM Command ==="
run_test "Remove secret 'user/token'" \
    "$SIGIL_BIN rm user/token" \
    "pass"

# Verify rm worked
run_test "Get removed secret (should fail)" \
    "$SIGIL_BIN get user/token" \
    "fail"

# Verify it's not in list
list_after_rm=$($SIGIL_BIN list 2>&1)
if echo "$list_after_rm" | grep -q "user/token"; then
    echo -e "${RED}✗ removed secret still in list${NC}"
else
    echo -e "${GREEN}✓ removed secret not in list${NC}"
fi

echo ""
echo "=== Test 7: EXPORT Command ==="
run_test "Export vault to archive" \
    "$SIGIL_BIN export \"$ARCHIVE_FILE\"" \
    "pass"

if [ -f "$ARCHIVE_FILE" ]; then
    archive_size=$(wc -c < "$ARCHIVE_FILE")
    echo -e "${GREEN}✓ Archive created (${archive_size} bytes)${NC}"
else
    echo -e "${RED}✗ Archive file not created${NC}"
fi

echo ""
echo "=== Test 8: IMPORT Command ==="
# Remove a secret first to test import restores it
$SIGIL_BIN rm api/key > /dev/null 2>&1 || true

run_test "Import from archive" \
    "$SIGIL_BIN import \"$ARCHIVE_FILE\"" \
    "pass"

# Verify import restored the secret
import_verify=$($SIGIL_BIN get api/key 2>&1)
if echo "$import_verify" | grep -q "my-secret-api-key"; then
    echo -e "${GREEN}✓ Import restored secrets correctly${NC}"
else
    echo -e "${RED}✗ Import did not restore secrets${NC}"
fi

echo ""
echo "=== Test 9: Final Verification ==="
final_list=$($SIGIL_BIN list 2>&1)
echo "Final secret list:"
echo "$final_list"

secret_count=$(echo "$final_list" | grep -c "Secret" || echo "0")
echo ""
echo "Total secrets in vault: $secret_count"

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Total tests: $test_count"
echo -e "Passed: ${GREEN}$pass_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"

if [ $fail_count -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ All tests PASSED!${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}✗ Some tests FAILED${NC}"
    exit 1
fi
