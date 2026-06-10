#!/bin/bash

# Test script for all /app/* routes in Tamandua
# This script logs in and tests each route, capturing HTTP status codes

set -e

BASE_URL="${BASE_URL:-http://localhost:4000}"
COOKIE_FILE="/tmp/tamandua_cookies.txt"
RESULTS_FILE="/tmp/tamandua_route_results.txt"
FAILING_ROUTES_FILE="/tmp/tamandua_failing_routes.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "======================================"
echo "Tamandua /app/* Route Tester"
echo "======================================"
echo "Base URL: $BASE_URL"
echo ""

# Clean up old files
rm -f "$COOKIE_FILE" "$RESULTS_FILE" "$FAILING_ROUTES_FILE"

# First, get the login page to get a CSRF token
echo "Step 1: Fetching CSRF token from login page..."
LOGIN_PAGE=$(curl -s -c "$COOKIE_FILE" -b "$COOKIE_FILE" "$BASE_URL/login")

# Extract CSRF token from the form
CSRF_TOKEN=$(echo "$LOGIN_PAGE" | grep -oP 'name="_csrf_token"[^>]*value="\K[^"]+' || echo "")

if [ -z "$CSRF_TOKEN" ]; then
    # Try alternative extraction method
    CSRF_TOKEN=$(echo "$LOGIN_PAGE" | grep -oP 'csrf-token[^>]*content="\K[^"]+' || echo "")
fi

if [ -z "$CSRF_TOKEN" ]; then
    echo -e "${RED}ERROR: Could not extract CSRF token from login page${NC}"
    echo "Login page response (first 500 chars):"
    echo "$LOGIN_PAGE" | head -c 500
    exit 1
fi

echo "CSRF Token obtained: ${CSRF_TOKEN:0:20}..."

# Step 2: Login
echo ""
echo "Step 2: Logging in as admin@tamandua.local..."
LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "_csrf_token=$CSRF_TOKEN" \
    -d "user[email]=admin@tamandua.local" \
    -d "user[password]=admin123456")

LOGIN_STATUS=$(echo "$LOGIN_RESPONSE" | tail -n1)
LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n-1)

# 302 redirect is expected for successful login
if [ "$LOGIN_STATUS" -eq 302 ]; then
    echo -e "${GREEN}Login successful (redirecting, status: $LOGIN_STATUS)${NC}"
elif [ "$LOGIN_STATUS" -ge 400 ]; then
    echo -e "${RED}ERROR: Login failed with status $LOGIN_STATUS${NC}"
    echo "Response: $LOGIN_BODY"
    exit 1
else
    echo -e "${GREEN}Login successful (status: $LOGIN_STATUS)${NC}"
fi

# Step 3: Define all /app/* routes to test
echo ""
echo "Step 3: Testing all /app/* routes..."
echo ""

# List of all routes from the router
ROUTES=(
    "/app/"
    "/app/dashboard"
    "/app/process-tree"
    "/app/agents"
    "/app/alerts"
    "/app/events"
    "/app/mitre"
    "/app/hunt"
    "/app/network"
    "/app/settings"
    "/app/response"
    "/app/timeline"
    "/app/timeline/test-incident-1"
    "/app/ai-assistant"
    "/app/playbooks"
    "/app/playbooks/test-id-1"
    "/app/assets"
    "/app/assets/test-id-1"
    "/app/forensics"
    "/app/forensics/test-collection-1"
    "/app/behavioral"
    "/app/cloud"
    "/app/threat-intel"
    "/app/ai-security/attack-surface"
    "/app/ai-security/shadow-ai"
    "/app/ai-security/posture"
    "/app/ai-security/agents"
    "/app/analyst"
    "/app/analyst/investigations/test-inv-1"
    "/app/dynamic-detection"
    "/app/predictive"
    "/app/automation"
    "/app/automation/workflows/test-workflow-1"
    "/app/exposure"
    "/app/exposure/attack-paths"
    "/app/collaboration"
    "/app/nl-hunt"
    "/app/nl-hunt/sessions/test-session-1"
    "/app/ai-siem"
    "/app/mcp-servers"
    "/app/phishing-triage"
)

# Counters
TOTAL=0
SUCCESS=0
FAILED=0
ERRORS=()

printf "%-50s %s\n" "ROUTE" "STATUS"
printf "%-50s %s\n" "-----" "------"

for route in "${ROUTES[@]}"; do
    TOTAL=$((TOTAL + 1))

    # Make the request
    RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_FILE" -c "$COOKIE_FILE" "$BASE_URL$route" -L 2>/dev/null)
    STATUS=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)

    # Determine result
    if [ "$STATUS" -eq 200 ] || [ "$STATUS" -eq 302 ]; then
        printf "${GREEN}%-50s %s${NC}\n" "$route" "$STATUS"
        echo "$route,$STATUS,OK" >> "$RESULTS_FILE"
        SUCCESS=$((SUCCESS + 1))
    elif [ "$STATUS" -ge 500 ]; then
        printf "${RED}%-50s %s (SERVER ERROR)${NC}\n" "$route" "$STATUS"
        echo "$route,$STATUS,SERVER_ERROR" >> "$RESULTS_FILE"
        echo "$route" >> "$FAILING_ROUTES_FILE"
        ERRORS+=("$route (HTTP $STATUS)")
        FAILED=$((FAILED + 1))

        # Extract error message if present
        ERROR_MSG=$(echo "$BODY" | grep -oP '(?<=<pre>).*?(?=</pre>)' | head -1 || echo "")
        if [ -n "$ERROR_MSG" ]; then
            echo "  Error: ${ERROR_MSG:0:100}..."
        fi
    elif [ "$STATUS" -ge 400 ]; then
        printf "${YELLOW}%-50s %s (CLIENT ERROR)${NC}\n" "$route" "$STATUS"
        echo "$route,$STATUS,CLIENT_ERROR" >> "$RESULTS_FILE"
        echo "$route" >> "$FAILING_ROUTES_FILE"
        ERRORS+=("$route (HTTP $STATUS)")
        FAILED=$((FAILED + 1))
    else
        printf "%-50s %s\n" "$route" "$STATUS"
        echo "$route,$STATUS,OTHER" >> "$RESULTS_FILE"
    fi

    # Small delay to avoid overwhelming the server
    sleep 0.1
done

# Summary
echo ""
echo "======================================"
echo "SUMMARY"
echo "======================================"
echo "Total routes tested: $TOTAL"
echo -e "${GREEN}Successful (2xx/3xx): $SUCCESS${NC}"
echo -e "${RED}Failed (4xx/5xx): $FAILED${NC}"
echo ""

if [ $FAILED -gt 0 ]; then
    echo "======================================"
    echo "FAILING ROUTES"
    echo "======================================"
    for error in "${ERRORS[@]}"; do
        echo -e "${RED}  - $error${NC}"
    done
    echo ""
    echo "Failing routes saved to: $FAILING_ROUTES_FILE"
fi

echo "Full results saved to: $RESULTS_FILE"
echo ""

# Exit with error code if there were failures
if [ $FAILED -gt 0 ]; then
    exit 1
fi
