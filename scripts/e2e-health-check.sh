#!/bin/bash

# E2E Health Check for ZumrutAutomation
# Reads credentials from .env file

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Load environment variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Default values if not set
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@zumrutautomation.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin@12345!}"

# Counters
PASSED=0
FAILED=0

# Test function
run_test() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    
    if [ "$actual" == "$expected" ]; then
        echo -e "${GREEN}PASS${NC}: $test_name"
        ((PASSED++))
    else
        echo -e "${RED}FAIL${NC}: $test_name (expected: $expected, got: $actual)"
        ((FAILED++))
    fi
}

echo "=================================="
echo "E2E Health Check - RedTeam Automation"
echo "=================================="
echo ""

# Test 1: All 4 containers running
echo "Test 1: Checking containers..."
CONTAINER_COUNT=$(docker ps --filter "name=zumrutautomation" --format "{{.Names}}" | wc -l | tr -d ' ')
run_test "All 4 containers running" "4" "$CONTAINER_COUNT"

# Test 2: API health endpoint
echo "Test 2: API health endpoint..."
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/health)
run_test "GET /health returns 200" "200" "$HEALTH_STATUS"

# Test 3: Login with correct credentials
echo "Test 3: Login with correct credentials..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}")
LOGIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}")
run_test "Login with correct credentials returns 200" "200" "$LOGIN_STATUS"

# Extract token for subsequent tests
TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Test 4: Login with wrong password
echo "Test 4: Login with wrong password..."
WRONG_PASS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3001/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@zumrutautomation.com","password":"wrongpassword"}')
run_test "Login with wrong password returns 401" "401" "$WRONG_PASS_STATUS"

# Test 5: Access protected route without token
echo "Test 5: Access protected route without token..."
NO_TOKEN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/api/programs)
run_test "GET /programs without token returns 401" "401" "$NO_TOKEN_STATUS"

# Test 6: Access protected route with valid token
echo "Test 6: Access protected route with valid token..."
WITH_TOKEN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/api/programs \
    -H "Authorization: Bearer ${TOKEN}")
run_test "GET /programs with valid token returns 200" "200" "$WITH_TOKEN_STATUS"

# Test 7: Frontend accessible
echo "Test 7: Frontend accessible..."
FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:80)
run_test "GET / returns 200" "200" "$FRONTEND_STATUS"

# Summary
echo ""
echo "=================================="
echo -e "Summary: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}"
echo "=================================="

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
