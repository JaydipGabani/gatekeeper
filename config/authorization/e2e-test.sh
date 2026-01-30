#!/bin/bash
# End-to-End Test Script for Gatekeeper Authorization Webhook
#
# This script sets up a Kind cluster with authorization webhook enabled,
# deploys Gatekeeper with authorization webhook, and runs tests.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEKEEPER_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CLUSTER_NAME="gatekeeper-authz-test"
IMAGE_NAME="gatekeeper:authz-test"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Gatekeeper Authorization Webhook End-to-End Test                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to cleanup
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/authz-webhook-config" 2>/dev/null || true
}

# Trap for cleanup on exit
trap cleanup EXIT

# Step 1: Prepare authorization webhook config directory
echo -e "${YELLOW}Step 1: Preparing authorization webhook configuration${NC}"
mkdir -p "$SCRIPT_DIR/authz-webhook-config"

# Create a simple webhook config that initially allows all (bootstrap)
# This will be updated after Gatekeeper is running
cat > "$SCRIPT_DIR/authz-webhook-config/authz-webhook-config.yaml" << 'EOF'
apiVersion: v1
kind: Config
clusters:
  - name: gatekeeper
    cluster:
      insecure-skip-tls-verify: true
      server: https://127.0.0.1:9443/v1/authorize
users:
  - name: gatekeeper
    user: {}
contexts:
  - name: default
    context:
      cluster: gatekeeper
      user: gatekeeper
current-context: default
EOF
echo "Created initial webhook config"

# Step 2: Build Gatekeeper image
echo -e "\n${YELLOW}Step 2: Building Gatekeeper Docker image${NC}"
cd "$GATEKEEPER_DIR"
docker build -t "$IMAGE_NAME" .
echo -e "${GREEN}Image built: $IMAGE_NAME${NC}"

# Step 3: Create Kind cluster
echo -e "\n${YELLOW}Step 3: Creating Kind cluster with authorization webhook${NC}"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

# Create cluster with custom config
cat > /tmp/kind-authz-config.yaml << EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 443
        hostPort: 9443
        protocol: TCP
EOF

kind create cluster --name "$CLUSTER_NAME" --config /tmp/kind-authz-config.yaml
echo -e "${GREEN}Cluster created: $CLUSTER_NAME${NC}"

# Step 4: Load Gatekeeper image into Kind
echo -e "\n${YELLOW}Step 4: Loading Gatekeeper image into Kind${NC}"
kind load docker-image "$IMAGE_NAME" --name "$CLUSTER_NAME"
echo -e "${GREEN}Image loaded${NC}"

# Step 5: Deploy Gatekeeper with authorization webhook enabled
echo -e "\n${YELLOW}Step 5: Deploying Gatekeeper${NC}"

# Create namespace
kubectl create namespace gatekeeper-system

# Deploy using kustomize or raw manifests
kubectl apply -f "$GATEKEEPER_DIR/deploy/gatekeeper.yaml" 2>/dev/null || \
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Patch deployment to use our image and enable authorization webhook
kubectl patch deployment gatekeeper-controller-manager -n gatekeeper-system --type=json -p='[
  {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "'$IMAGE_NAME'"},
  {"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--enable-authorization-webhook=true"}
]'

# Wait for rollout
echo -e "${YELLOW}Waiting for Gatekeeper to be ready...${NC}"
kubectl rollout status deployment/gatekeeper-controller-manager -n gatekeeper-system --timeout=120s
echo -e "${GREEN}Gatekeeper deployed${NC}"

# Step 6: Apply authorization ConstraintTemplate and Constraint
echo -e "\n${YELLOW}Step 6: Applying authorization policy${NC}"
kubectl apply -f "$GATEKEEPER_DIR/pkg/authztarget/examples/simple-authorization.yaml"

# Wait for constraint to be ready
sleep 5
kubectl get constrainttemplates
kubectl get k8ssimpleauthorization

# Step 7: Run authorization tests
echo -e "\n${YELLOW}Step 7: Running authorization tests${NC}"

# Test function
run_authz_test() {
    local user="$1"
    local verb="$2"
    local resource="$3"
    local namespace="$4"
    local expected="$5"
    
    echo -n "  Testing: $user can $verb $resource in $namespace... "
    
    # Create SubjectAccessReview
    result=$(kubectl create -f - <<EOF 2>&1
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: "$user"
  groups: ["system:authenticated"]
  resourceAttributes:
    namespace: "$namespace"
    verb: "$verb"
    resource: "$resource"
    version: "v1"
EOF
)
    
    if echo "$result" | grep -q '"allowed": true'; then
        actual="ALLOWED"
    else
        actual="DENIED"
    fi
    
    if [ "$actual" = "$expected" ]; then
        echo -e "${GREEN}PASS${NC} ($actual)"
        return 0
    else
        echo -e "${RED}FAIL${NC} (expected $expected, got $actual)"
        return 1
    fi
}

# Run test cases
echo ""
echo "Test Results:"
echo "─────────────────────────────────────────────────────────"

failed=0
run_authz_test "admin@example.com" "get" "pods" "default" "ALLOWED" || ((failed++))
run_authz_test "developer@example.com" "create" "pods" "default" "ALLOWED" || ((failed++))
run_authz_test "viewer@example.com" "create" "pods" "default" "DENIED" || ((failed++))
run_authz_test "bad-actor@example.com" "get" "secrets" "default" "DENIED" || ((failed++))
run_authz_test "alice@example.com" "get" "pods" "kube-system" "DENIED" || ((failed++))

echo "─────────────────────────────────────────────────────────"

if [ $failed -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests PASSED!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ $failed test(s) FAILED${NC}"
    exit 1
fi
