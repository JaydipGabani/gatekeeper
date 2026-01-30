#!/bin/bash
# Phase 1 POC Test Script
# Tests user authorization for pod creation across different namespaces

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Phase 1 POC: User Authorization for Pod Creation         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

# Step 1: Show current user
echo -e "\n${YELLOW}Step 1: Current User Identity${NC}"
echo "----------------------------------------"
kubectl auth whoami
echo ""

# Step 2: Create namespaces
echo -e "${YELLOW}Step 2: Creating test namespaces${NC}"
echo "----------------------------------------"
kubectl apply -f namespaces.yaml
echo ""

# Step 3: Apply ConstraintTemplate
echo -e "${YELLOW}Step 3: Applying ConstraintTemplate${NC}"
echo "----------------------------------------"
kubectl apply -f constraint-template.yaml
echo ""

# Wait for template to be ready
echo -e "${YELLOW}Waiting for ConstraintTemplate to be ready...${NC}"
sleep 3
kubectl wait --for=condition=Ready constrainttemplate/k8suserpodauthorization --timeout=60s || {
    echo -e "${RED}ConstraintTemplate not ready. Checking status...${NC}"
    kubectl get constrainttemplate k8suserpodauthorization -o yaml | tail -20
    exit 1
}
echo ""

# Step 4: Apply Constraints
echo -e "${YELLOW}Step 4: Applying Constraints${NC}"
echo "----------------------------------------"
kubectl apply -f constraints.yaml
echo ""

# Wait for constraints to be enforced
echo -e "${YELLOW}Waiting for constraints to be enforced...${NC}"
sleep 5
echo ""

# Step 5: Show constraint status
echo -e "${YELLOW}Step 5: Constraint Status${NC}"
echo "----------------------------------------"
kubectl get k8suserpodauthorization
echo ""

# Step 6: Test pod creation in ALLOWED namespace
echo -e "${YELLOW}Step 6: Testing pod creation in 'allowed-ns' (should SUCCEED)${NC}"
echo "----------------------------------------"
echo -e "Running: kubectl apply -f test-pod.yaml -n allowed-ns --dry-run=server"
echo ""

if kubectl apply -f test-pod.yaml -n allowed-ns --dry-run=server 2>&1; then
    echo -e "\n${GREEN}✅ SUCCESS: Pod creation ALLOWED in 'allowed-ns'${NC}"
    TEST1_RESULT="PASS"
else
    echo -e "\n${RED}❌ FAILED: Pod creation was denied in 'allowed-ns' (unexpected)${NC}"
    TEST1_RESULT="FAIL"
fi
echo ""

# Step 7: Test pod creation in RESTRICTED namespace
echo -e "${YELLOW}Step 7: Testing pod creation in 'restricted-ns' (should FAIL)${NC}"
echo "----------------------------------------"
echo -e "Running: kubectl apply -f test-pod.yaml -n restricted-ns --dry-run=server"
echo ""

if kubectl apply -f test-pod.yaml -n restricted-ns --dry-run=server 2>&1; then
    echo -e "\n${RED}❌ FAILED: Pod creation was allowed in 'restricted-ns' (unexpected)${NC}"
    TEST2_RESULT="FAIL"
else
    echo -e "\n${GREEN}✅ SUCCESS: Pod creation DENIED in 'restricted-ns' (as expected)${NC}"
    TEST2_RESULT="PASS"
fi
echo ""

# Step 8: Test impersonation
echo -e "${YELLOW}Step 8: Testing with impersonated users${NC}"
echo "----------------------------------------"

echo "Test: specific-admin@example.com in restricted-ns (should SUCCEED)"
if kubectl apply -f test-pod.yaml -n restricted-ns --as=specific-admin@example.com --as-group=system:masters --dry-run=server 2>&1; then
    echo -e "${GREEN}✅ PASS${NC}"
    TEST3_RESULT="PASS"
else
    echo -e "${RED}❌ FAIL${NC}"
    TEST3_RESULT="FAIL"
fi
echo ""

echo "Test: random-user in delete-protected-ns CREATE (should SUCCEED)"
if kubectl apply -f test-pod.yaml -n delete-protected-ns --as=random-user --as-group=system:masters --dry-run=server 2>&1; then
    echo -e "${GREEN}✅ PASS${NC}"
    TEST4_RESULT="PASS"
else
    echo -e "${RED}❌ FAIL${NC}"
    TEST4_RESULT="FAIL"
fi
echo ""

# Step 9: Summary
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                      Test Summary                            ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Current User: $(kubectl auth whoami 2>/dev/null | grep Username | awk '{print $2}')"
echo ""
echo -e "Test 1 - Pod in 'allowed-ns':                  ${TEST1_RESULT}"
echo -e "Test 2 - Pod in 'restricted-ns':               ${TEST2_RESULT}"
echo -e "Test 3 - specific-admin in 'restricted-ns':    ${TEST3_RESULT}"
echo -e "Test 4 - random-user CREATE in protected:      ${TEST4_RESULT}"
echo ""

if [[ "$TEST1_RESULT" == "PASS" && "$TEST2_RESULT" == "PASS" && "$TEST3_RESULT" == "PASS" && "$TEST4_RESULT" == "PASS" ]]; then
    echo -e "${GREEN}🎉 All tests PASSED! Phase 1 POC is working correctly.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests FAILED. Please check the output above.${NC}"
    exit 1
fi
