# POC: Gatekeeper OIDC-Based User Authorization Verification

## Overview

This POC explores using OPA Gatekeeper with ConstraintTemplates and Constraints to verify if a user is authorized to perform certain actions in Kubernetes, potentially leveraging OIDC providers for identity verification.

### Key Distinction: Admission vs. Authorization Webhooks

| Aspect | Admission Webhook (Phase 1) | Authorization Webhook (Phase 1.5) |
|--------|----------------------------|-----------------------------------|
| **Kubernetes API** | ValidatingAdmissionWebhook | SubjectAccessReview (authorization.k8s.io/v1) |
| **Operations** | CREATE, UPDATE, DELETE | **GET, LIST, WATCH, exec, logs, port-forward** |
| **Use Case** | Block resource creation/modification | **Control read access, pod exec, log viewing** |
| **Input** | `AdmissionReview` with full object | `SubjectAccessReview` with resource attributes |
| **When Called** | After authentication, during admission | During authorization (before admission) |

**Why Authorization Webhook Matters:**
- Admission webhooks **cannot** control read operations (GET, LIST, WATCH)
- Authorization webhooks intercept **all** API requests including `kubectl exec`, `kubectl logs`
- Critical for controlling sensitive operations like accessing secrets or exec into production pods

---

## POC Status Summary

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Admission-based authorization using `userInfo` | ✅ Documented |
| **Phase 1.5** | **Authorization Webhook for read/exec operations** | ✅ **Implemented & Tested** |
| Phase 2 | External Data Provider for OIDC | 📋 Designed |
| Phase 3 | Azure AD Integration | 📋 Designed |

---

## Open Source OIDC Providers Compatible with Kubernetes

| Provider | Description | Kubernetes Integration | License |
|----------|-------------|------------------------|---------|
| **Dex** | Federated OIDC provider, connects to multiple identity backends (LDAP, SAML, GitHub, etc.) | Native K8s OIDC support, widely used | Apache 2.0 |
| **Keycloak** | Full-featured IAM with OIDC/SAML support | Kubernetes API server OIDC, Operators available | Apache 2.0 |
| **Authentik** | Modern identity provider with flows | K8s OIDC integration | MIT |
| **Zitadel** | Cloud-native identity management | K8s OIDC support | Apache 2.0 |
| **Ory Hydra** | OAuth2/OIDC server (headless) | K8s deployment ready | Apache 2.0 |
| **Authelia** | SSO/2FA portal | K8s ingress integration | Apache 2.0 |
| **Vouch Proxy** | SSO for nginx/ingress | K8s ingress auth | MIT |
| **OAuth2 Proxy** | Reverse proxy with OIDC | K8s ingress integration | MIT |

**Recommended for POC:** **Dex** (lightweight, K8s-native) or **Keycloak** (full-featured)

---

## POC Phases

### Phase 1: Current Capabilities Assessment (No Code Changes)

#### 1.1 Understanding What Gatekeeper Receives

Gatekeeper, as a validating admission controller, receives `AdmissionReview` requests containing:

```yaml
# What Gatekeeper sees in the review object
request:
  uid: "unique-request-id"
  kind:
    group: ""
    version: "v1"
    kind: "Pod"
  resource:
    group: ""
    version: "v1"
    resource: "pods"
  operation: "CREATE"
  userInfo:
    username: "user@example.com"          # ✅ Available
    uid: "unique-user-id"                  # ✅ Available
    groups:                                # ✅ Available
      - "system:authenticated"
      - "developers"
    extra:                                 # ✅ Available (OIDC claims can be here)
      "email": ["user@example.com"]
      "preferred_username": ["john"]
  object: { ... }                          # The resource being created/modified
  oldObject: { ... }                       # Previous state (for UPDATE)
  dryRun: false
```

#### 1.2 Create Test ConstraintTemplate for User Authorization

**Step 1:** Create a ConstraintTemplate that checks user identity:

```yaml
# File: test/poc/user-authorization-template.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8suserauthorization
spec:
  crd:
    spec:
      names:
        kind: K8sUserAuthorization
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedUsers:
              type: array
              items:
                type: string
              description: "List of users allowed to perform this action"
            allowedGroups:
              type: array
              items:
                type: string
              description: "List of groups allowed to perform this action"
            deniedUsers:
              type: array
              items:
                type: string
              description: "List of users explicitly denied"
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8suserauthorization

        # Get user info from the admission request
        username := input.review.userInfo.username
        groups := input.review.userInfo.groups
        
        # Check if user is in denied list
        user_denied {
          some denied_user in input.parameters.deniedUsers
          denied_user == username
        }
        
        # Check if user is in allowed list
        user_allowed {
          some allowed_user in input.parameters.allowedUsers
          allowed_user == username
        }
        
        # Check if any user group is in allowed groups
        group_allowed {
          some user_group in groups
          some allowed_group in input.parameters.allowedGroups
          user_group == allowed_group
        }
        
        # Main violation rule
        violation[{"msg": msg}] {
          user_denied
          msg := sprintf("User '%s' is explicitly denied from performing this action", [username])
        }
        
        violation[{"msg": msg}] {
          not user_denied
          not user_allowed
          not group_allowed
          count(input.parameters.allowedUsers) > 0
          count(input.parameters.allowedGroups) > 0
          msg := sprintf("User '%s' (groups: %v) is not authorized. Allowed users: %v, Allowed groups: %v", 
            [username, groups, input.parameters.allowedUsers, input.parameters.allowedGroups])
        }
```

**Step 2:** Create a Constraint using the template:

```yaml
# File: test/poc/restrict-namespace-creation.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sUserAuthorization
metadata:
  name: restrict-namespace-creation
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
    operations: ["CREATE"]
  parameters:
    allowedUsers:
      - "admin@example.com"
      - "platform-admin@example.com"
    allowedGroups:
      - "platform-admins"
      - "namespace-admins"
    deniedUsers:
      - "blocked-user@example.com"
```

#### 1.3 Test Commands

```bash
# Deploy Gatekeeper (if not already running)
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Apply the ConstraintTemplate
kubectl apply -f test/poc/user-authorization-template.yaml

# Wait for template to be ready
kubectl wait --for=condition=Ready constrainttemplate/k8suserauthorization --timeout=60s

# Apply the Constraint
kubectl apply -f test/poc/restrict-namespace-creation.yaml

# Test: Try creating a namespace (will show your current user info in violation)
kubectl create namespace test-ns --dry-run=server

# Debug: Check what userInfo Gatekeeper receives
# Enable audit logging to see the full request
```

#### 1.4 Phase 1 Deliverables Checklist

- [ ] Verify `input.review.userInfo` contains expected fields
- [ ] Test with different users (service accounts, OIDC users)
- [ ] Document what OIDC claims are available in `userInfo.extra`
- [ ] Identify limitations of current approach

---

### Phase 1.5: Authorization Webhook for Read/Exec Operations (✅ IMPLEMENTED)

> **Status:** Implemented and tested on January 30, 2026

This phase extends Gatekeeper to handle **Kubernetes Authorization Webhooks** (`SubjectAccessReview`), enabling policy-based control over operations that admission webhooks cannot intercept.

#### 1.5.1 Why Authorization Webhooks?

**Admission webhooks have a critical limitation:** They only intercept mutating operations (CREATE, UPDATE, DELETE). They **cannot** control:

| Operation | Example | Admission Webhook | Authorization Webhook |
|-----------|---------|-------------------|----------------------|
| `kubectl get secret` | Read sensitive data | ❌ Cannot intercept | ✅ Can control |
| `kubectl exec -it pod -- bash` | Shell access to pod | ❌ Cannot intercept | ✅ Can control |
| `kubectl logs pod` | View application logs | ❌ Cannot intercept | ✅ Can control |
| `kubectl port-forward` | Network access | ❌ Cannot intercept | ✅ Can control |
| `kubectl cp` | Copy files to/from pod | ❌ Cannot intercept | ✅ Can control |

#### 1.5.2 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes API Server                                │
│                                                                              │
│  1. User Request: kubectl exec -it my-pod -- bash                           │
│                              │                                               │
│                              ▼                                               │
│  2. API Server creates SubjectAccessReview                                  │
│     {                                                                        │
│       "spec": {                                                              │
│         "user": "developer@example.com",                                    │
│         "groups": ["developers"],                                           │
│         "resourceAttributes": {                                             │
│           "namespace": "production",                                        │
│           "verb": "create",                                                 │
│           "resource": "pods",                                               │
│           "subresource": "exec"                                             │
│         }                                                                    │
│       }                                                                      │
│     }                                                                        │
│                              │                                               │
└──────────────────────────────┼───────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Gatekeeper Authorization Webhook                          │
│                    Endpoint: /v1/authorize                                   │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Handler: pkg/webhook/authzwebhook/handler.go                         │  │
│  │  1. Parse SubjectAccessReview                                         │  │
│  │  2. Convert to authorization.Review                                   │  │
│  │  3. Evaluate against ConstraintTemplates                              │  │
│  │  4. Return allowed/denied decision                                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                               │
│                              ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Constraint Client (OPA/Rego)                                         │  │
│  │  - Enforcement Point: authorization.k8s.gatekeeper.sh                 │  │
│  │  - Target: admission.k8s.gatekeeper.sh (reused)                       │  │
│  │  - Evaluates Rego policies against authorization context              │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 1.5.3 Implementation Details

**Code Changes Made:**

| File | Change |
|------|--------|
| `pkg/operations/operations.go` | Added `AuthorizationWebhook` operation |
| `pkg/util/enforcement_action.go` | Added `AuthorizationEnforcementPoint = "authorization.k8s.gatekeeper.sh"` |
| `pkg/target/target.go` | Modified `HandleReview()` to handle `authorization.Review` types |
| `pkg/target/authorization_adapter.go` | NEW: Wrapper to convert authorization review for Rego evaluation |
| `main.go` | Register authorization enforcement point with constraint client |
| `pkg/webhook/authzwebhook/handler.go` | Authorization webhook HTTP handler |

**Key Design Decision:** We reuse the existing `admission.k8s.gatekeeper.sh` target handler instead of creating a dedicated authorization target. The `HandleReview()` method detects `authorization.Review` types and wraps them appropriately.

#### 1.5.4 ConstraintTemplate for Authorization

```yaml
# File: demo/authorization/constraint-template-pod-exec.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8spodexecpolicy
spec:
  crd:
    spec:
      names:
        kind: K8sPodExecPolicy
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedNamespaces:
              type: array
              items:
                type: string
            deniedNamespaces:
              type: array
              items:
                type: string
            users:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spodexecpolicy

        # Deny exec in denied namespaces for specified users
        violation[{"msg": msg}] {
          input.review.resourceAttributes.subresource == "exec"
          input.review.resourceAttributes.resource == "pods"
          
          user := input.review.user
          input.parameters.users[_] == user
          
          namespace := input.review.resourceAttributes.namespace
          denied_ns := input.parameters.deniedNamespaces[_]
          namespace == denied_ns
          
          msg := sprintf("User '%v' is not allowed to exec into pods in namespace '%v'", [user, namespace])
        }

        # Deny exec in namespaces NOT in allowed list
        violation[{"msg": msg}] {
          input.review.resourceAttributes.subresource == "exec"
          input.review.resourceAttributes.resource == "pods"
          
          user := input.review.user
          input.parameters.users[_] == user
          
          count(input.parameters.allowedNamespaces) > 0
          namespace := input.review.resourceAttributes.namespace
          not namespace_allowed(namespace)
          
          msg := sprintf("User '%v' is only allowed to exec in namespaces: %v", [user, input.parameters.allowedNamespaces])
        }

        namespace_allowed(ns) {
          input.parameters.allowedNamespaces[_] == ns
        }
```

#### 1.5.5 Sample Constraint

```yaml
# File: demo/authorization/constraint-pod-exec-user.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPodExecPolicy
metadata:
  name: restrict-exec-by-namespace
spec:
  enforcementAction: deny
  parameters:
    users:
      - "exec-user"
    allowedNamespaces:
      - "a"
    deniedNamespaces:
      - "b"
```

#### 1.5.6 Test Results (January 30, 2026)

**Test Environment:**
- Kind cluster: `authz-poc`
- Gatekeeper branch: `authz-webhook-support-v2`

**Test Matrix:**

| Test Case | User | Namespace | Operation | Result |
|-----------|------|-----------|-----------|--------|
| Exec in allowed namespace | `exec-user` | `a` | pod exec | ✅ **ALLOWED** |
| Exec in denied namespace | `exec-user` | `b` | pod exec | ❌ **DENIED** |
| Other user in denied namespace | `admin-user` | `b` | pod exec | ✅ **ALLOWED** (not in policy) |
| Other user in denied namespace | `developer` | `b` | pod exec | ✅ **ALLOWED** (not in policy) |

**Sample Test Commands:**

```bash
# Test exec in namespace "a" - should be ALLOWED
kubectl run test-curl --image=curlimages/curl --rm -it --restart=Never -- \
  curl -k -s -X POST https://gatekeeper-webhook-service.gatekeeper-system.svc/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"exec-user","groups":["developers"],"resourceAttributes":{"namespace":"a","verb":"create","resource":"pods","subresource":"exec"}}}'

# Response: {"status":{"allowed":true,"reason":"Gatekeeper authorization passed"}}

# Test exec in namespace "b" - should be DENIED
kubectl run test-curl --image=curlimages/curl --rm -it --restart=Never -- \
  curl -k -s -X POST https://gatekeeper-webhook-service.gatekeeper-system.svc/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"exec-user","groups":["developers"],"resourceAttributes":{"namespace":"b","verb":"create","resource":"pods","subresource":"exec"}}}'

# Response: {"status":{"allowed":false,"denied":true,"reason":"Gatekeeper policy violation: [[restrict-exec-by-namespace] User 'exec-user' is not allowed to exec into pods in namespace 'b']"}}
```

#### 1.5.7 Phase 1.5 Deliverables Checklist

- [x] Authorization webhook endpoint `/v1/authorize` implemented
- [x] Enforcement point `authorization.k8s.gatekeeper.sh` registered
- [x] K8sValidationTarget handles authorization reviews
- [x] Demo ConstraintTemplate for pod exec policies
- [x] Demo Constraint for namespace-based exec restrictions
- [x] End-to-end tests passed (deny exec-user in namespace b, allow in namespace a)
- [x] Other users unaffected by targeted policy
- [ ] Integration with kube-apiserver authorization webhook configuration
- [ ] Helm chart updates for authorization webhook deployment
- [ ] Performance benchmarks (<100ms p99 latency)

#### 1.5.8 Limitations & Future Work

| Limitation | Description | Future Solution |
|------------|-------------|-----------------|
| Target reuse | Using `admission.k8s.gatekeeper.sh` target for authorization | Add dedicated `authorization.k8s.gatekeeper.sh` target in frameworks |
| No CEL support | Only Rego policies work currently | Add CEL engine support for authorization |
| Manual testing | Testing via curl, not integrated with kube-apiserver | Configure actual webhook in kube-apiserver |
| No audit | Authorization decisions not persisted | Add audit integration |

---

### Phase 2: Enhanced Authorization with External Data

#### 2.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Kubernetes API Server                            │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  AdmissionReview (contains userInfo from OIDC)              │    │
│  └─────────────────────────┬───────────────────────────────────┘    │
└────────────────────────────┼────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Gatekeeper                                    │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  ConstraintTemplate (Rego Policy)                           │    │
│  │  ┌───────────────────────────────────────────────────────┐  │    │
│  │  │  1. Extract userInfo.username                         │  │    │
│  │  │  2. Call External Data Provider                       │  │    │
│  │  │  3. Verify user authorization from OIDC provider      │  │    │
│  │  │  4. Return violation if unauthorized                  │  │    │
│  │  └───────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────┬───────────────────────────────────┘    │
└────────────────────────────┼────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│              External Data Provider (New Component)                  │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  OIDC Authorization Service                                 │    │
│  │  ┌───────────────────────────────────────────────────────┐  │    │
│  │  │  - Receives: username, requested action, resource     │  │    │
│  │  │  - Queries: OIDC provider for user claims/roles       │  │    │
│  │  │  - Returns: authorized (true/false) + details         │  │    │
│  │  └───────────────────────────────────────────────────────┘  │    │
│  └─────────────────────────┬───────────────────────────────────┘    │
└────────────────────────────┼────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    OIDC Provider (Dex/Keycloak)                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  - User directory                                           │    │
│  │  - Role/Group assignments                                   │    │
│  │  - Custom claims                                            │    │
│  │  - Token introspection endpoint                             │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

#### 2.2 External Data Provider Design

**Provider CRD:**

```yaml
# File: test/poc/external-data-provider.yaml
apiVersion: externaldata.gatekeeper.sh/v1beta1
kind: Provider
metadata:
  name: oidc-authorization-provider
spec:
  url: https://oidc-authz-provider.gatekeeper-system.svc:8443/validate
  timeout: 5
  caBundle: <base64-encoded-ca-cert>
```

**Provider Service Implementation (Go):**

```go
// pkg/externaldata/providers/oidc/provider.go

package oidc

import (
    "context"
    "encoding/json"
    "net/http"
    
    "github.com/coreos/go-oidc/v3/oidc"
)

type AuthorizationRequest struct {
    Username  string   `json:"username"`
    Groups    []string `json:"groups"`
    Action    string   `json:"action"`    // CREATE, UPDATE, DELETE
    Resource  string   `json:"resource"`  // pods, deployments, etc.
    Namespace string   `json:"namespace"`
}

type AuthorizationResponse struct {
    Authorized bool     `json:"authorized"`
    Reason     string   `json:"reason,omitempty"`
    Roles      []string `json:"roles,omitempty"`
}

type OIDCProvider struct {
    verifier *oidc.IDTokenVerifier
    config   *Config
}

type Config struct {
    IssuerURL     string
    ClientID      string
    ClientSecret  string
    // Role mappings
    RoleClaimPath string // e.g., "realm_access.roles" for Keycloak
}

func (p *OIDCProvider) ValidateAuthorization(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error) {
    // 1. Look up user in OIDC provider (via userinfo endpoint or token introspection)
    // 2. Extract roles/claims
    // 3. Check if user has required role for the action
    // 4. Return authorization decision
    
    // Implementation details...
    return nil, nil
}
```

#### 2.3 ConstraintTemplate with External Data

```yaml
# File: test/poc/user-authorization-external-template.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8suserauthorizationexternal
spec:
  crd:
    spec:
      names:
        kind: K8sUserAuthorizationExternal
      validation:
        openAPIV3Schema:
          type: object
          properties:
            requiredRoles:
              type: array
              items:
                type: string
              description: "OIDC roles required for this action"
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8suserauthorizationexternal

        import future.keywords.in
        
        # Extract user info
        username := input.review.userInfo.username
        groups := input.review.userInfo.groups
        operation := input.review.operation
        resource := input.review.resource.resource
        namespace := input.review.namespace
        
        # Prepare external data request
        external_data_request := {
          "username": username,
          "groups": groups,
          "action": operation,
          "resource": resource,
          "namespace": namespace,
          "requiredRoles": input.parameters.requiredRoles
        }
        
        # Call external data provider
        response := external_data.gatekeeper["oidc-authorization-provider"].response
        
        # Check authorization
        violation[{"msg": msg}] {
          not response.authorized
          msg := sprintf("User '%s' is not authorized: %s", [username, response.reason])
        }
```

---

### Phase 3: OIDC Provider Setup (Dex)

#### 3.1 Deploy Dex in Kubernetes

```yaml
# File: test/poc/dex/dex-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dex
  namespace: dex
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dex
  template:
    metadata:
      labels:
        app: dex
    spec:
      containers:
      - name: dex
        image: ghcr.io/dexidp/dex:v2.37.0
        ports:
        - containerPort: 5556
        volumeMounts:
        - name: config
          mountPath: /etc/dex/cfg
      volumes:
      - name: config
        configMap:
          name: dex-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: dex-config
  namespace: dex
data:
  config.yaml: |
    issuer: https://dex.example.com
    storage:
      type: kubernetes
      config:
        inCluster: true
    web:
      http: 0.0.0.0:5556
    
    # Static clients for testing
    staticClients:
    - id: gatekeeper-authz
      secret: gatekeeper-secret
      name: 'Gatekeeper Authorization'
      redirectURIs:
      - 'https://gatekeeper.example.com/callback'
    
    # Static users for POC testing
    enablePasswordDB: true
    staticPasswords:
    - email: "admin@example.com"
      hash: "$2a$10$..."  # bcrypt hash
      username: "admin"
      userID: "admin-001"
    - email: "developer@example.com"
      hash: "$2a$10$..."
      username: "developer"
      userID: "dev-001"
    
    # Connectors (for production: LDAP, GitHub, etc.)
    connectors: []
```

#### 3.2 Configure Kubernetes API Server for OIDC

```yaml
# API Server flags (add to kube-apiserver manifest)
spec:
  containers:
  - command:
    - kube-apiserver
    - --oidc-issuer-url=https://dex.example.com
    - --oidc-client-id=gatekeeper-authz
    - --oidc-username-claim=email
    - --oidc-groups-claim=groups
    - --oidc-ca-file=/etc/kubernetes/pki/oidc-ca.crt
```

---

### Phase 4: Implementation Steps

#### Step-by-Step Execution Plan

| Step | Task | Duration | Dependencies |
|------|------|----------|--------------|
| 1 | Set up Kind cluster with OIDC support | 1 hour | None |
| 2 | Deploy Dex with static users | 1 hour | Step 1 |
| 3 | Configure kubectl for OIDC auth | 30 min | Step 2 |
| 4 | Deploy Gatekeeper | 30 min | Step 1 |
| 5 | Create Phase 1 ConstraintTemplate | 1 hour | Step 4 |
| 6 | Test Phase 1 (userInfo-based auth) | 2 hours | Step 5 |
| 7 | Design External Data Provider spec | 2 hours | Step 6 |
| 8 | Implement External Data Provider | 4 hours | Step 7 |
| 9 | Create Phase 2 ConstraintTemplate | 2 hours | Step 8 |
| 10 | End-to-end testing | 4 hours | Step 9 |
| 11 | Documentation | 2 hours | Step 10 |

**Total Estimated Time: ~20 hours**

---

### Phase 5: Testing Matrix

| Test Case | User | Action | Resource | Expected Result |
|-----------|------|--------|----------|-----------------|
| TC-1 | admin@example.com | CREATE | Namespace | ✅ Allowed |
| TC-2 | developer@example.com | CREATE | Namespace | ❌ Denied |
| TC-3 | admin@example.com | DELETE | Namespace | ✅ Allowed |
| TC-4 | developer@example.com | CREATE | Deployment | ✅ Allowed |
| TC-5 | blocked-user@example.com | CREATE | Any | ❌ Denied |
| TC-6 | unknown-user | CREATE | Any | ❌ Denied |

---

## Quick Start Commands

```bash
# 1. Create Kind cluster
kind create cluster --name oidc-poc --config test/poc/kind-config.yaml

# 2. Deploy Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# 3. Wait for Gatekeeper to be ready
kubectl wait --for=condition=Ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=120s

# 4. Apply Phase 1 ConstraintTemplate
kubectl apply -f test/poc/user-authorization-template.yaml

# 5. Apply test Constraint
kubectl apply -f test/poc/restrict-namespace-creation.yaml

# 6. Test authorization
kubectl create namespace test-ns --dry-run=server -v=6

# 7. Check constraint status
kubectl get k8suserauthorization restrict-namespace-creation -o yaml
```

---

## Key Questions to Answer

1. **What userInfo fields are populated by different auth methods?**
   - Service Account tokens
   - OIDC tokens  
   - Client certificates
   - Webhook token auth

2. **What are the latency implications of external data calls?**
   - Acceptable latency for admission control (<100ms target)
   - Caching strategies

3. **How to handle provider unavailability?**
   - Fail-open vs fail-closed
   - Circuit breaker patterns

4. **What OIDC claims should drive authorization?**
   - Standard claims (sub, email, groups)
   - Custom claims (roles, permissions)

---

## Success Criteria

### Phase 1: Admission-based Authorization
- [ ] Phase 1: Successfully block/allow based on `userInfo.username`
- [ ] Phase 1: Successfully block/allow based on `userInfo.groups`

### Phase 1.5: Authorization Webhook (✅ COMPLETED)
- [x] Phase 1.5: Authorization webhook endpoint `/v1/authorize` working
- [x] Phase 1.5: Enforcement point registered with constraint client
- [x] Phase 1.5: ConstraintTemplate evaluates authorization requests
- [x] Phase 1.5: Successfully deny exec in specific namespaces for targeted users
- [x] Phase 1.5: Successfully allow exec in permitted namespaces
- [x] Phase 1.5: Non-targeted users unaffected by policy
- [ ] Phase 1.5: Integration with kube-apiserver webhook configuration
- [ ] Phase 1.5: Performance <100ms p99 latency

### Phase 2: External Data Provider
- [ ] Phase 2: External Data Provider returns authorization decisions
- [ ] Phase 2: ConstraintTemplate consumes external data correctly
- [ ] End-to-end: OIDC user identity flows through to Gatekeeper policy
- [ ] Performance: Admission latency <200ms with external data call

### Phase 3: Azure AD Integration
- [ ] Phase 3: Azure AD Provider deployed and working
- [ ] Phase 3: User group memberships retrieved from Microsoft Graph
- [ ] Phase 3: Authorization decisions based on Azure AD attributes

---

## Phase 3: Azure AD External Data Integration

This phase integrates Azure Active Directory (now Microsoft Entra ID) as an External Data Provider to enrich authorization decisions with real-time user information from Azure AD.

### 3.1 Why Azure AD for Kubernetes Authorization?

| Benefit | Description |
|---------|-------------|
| **Native AKS Integration** | AKS clusters can use Azure AD for OIDC authentication out-of-the-box |
| **Rich User Data** | Access to groups, roles, custom attributes, manager hierarchy |
| **Centralized Identity** | Single source of truth for enterprise identities |
| **Dynamic Groups** | Azure AD dynamic groups auto-update based on attributes |
| **Conditional Access** | Can factor in device compliance, location, risk level |

### 3.2 Architecture: Azure AD External Data Provider

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AKS Cluster (Azure AD Integrated)                    │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    Kubernetes API Server                               │  │
│  │  - OIDC configured with Azure AD                                      │  │
│  │  - userInfo contains Azure AD identity                                │  │
│  │    - username: user@tenant.onmicrosoft.com                           │  │
│  │    - groups: [azure-ad-group-ids...]                                 │  │
│  │    - oid: azure-ad-object-id                                         │  │
│  └───────────────────────────┬───────────────────────────────────────────┘  │
│                              │                                               │
│                              ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         Gatekeeper                                     │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  ConstraintTemplate (Rego)                                      │  │  │
│  │  │  1. Extract userInfo.username (UPN) or oid                      │  │  │
│  │  │  2. Call Azure AD External Data Provider                        │  │  │
│  │  │  3. Receive enriched user data (roles, attributes, groups)      │  │  │
│  │  │  4. Make authorization decision                                 │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────┬───────────────────────────────────────────┘  │
│                              │                                               │
│                              ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              Azure AD External Data Provider Service                   │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │  Deployment: gatekeeper-system/azure-ad-provider                │  │  │
│  │  │  - Authenticates to Microsoft Graph API                         │  │  │
│  │  │  - Queries user details, group memberships, app roles           │  │  │
│  │  │  - Caches responses (configurable TTL)                          │  │  │
│  │  │  - Returns authorization-relevant data                          │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────┬───────────────────────────────────────────┘  │
└──────────────────────────────┼───────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Microsoft Graph API (Azure AD)                            │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Endpoints Used:                                                       │  │
│  │  - GET /users/{id} - User profile                                     │  │
│  │  - GET /users/{id}/memberOf - Group memberships                       │  │
│  │  - GET /users/{id}/appRoleAssignments - App role assignments          │  │
│  │  - GET /users/{id}/manager - Manager (for hierarchy checks)           │  │
│  │  - GET /groups/{id}/members - Group members (for validation)          │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Azure AD App Registration Setup

**Step 1: Create App Registration in Azure AD**

```bash
# Create the app registration
az ad app create \
  --display-name "Gatekeeper AuthZ Provider" \
  --sign-in-audience "AzureADMyOrg"

# Note the Application (client) ID from output
APP_ID=$(az ad app list --display-name "Gatekeeper AuthZ Provider" --query "[0].appId" -o tsv)

# Create service principal
az ad sp create --id $APP_ID

# Create client secret
az ad app credential reset --id $APP_ID --append
# Save the password output - this is your CLIENT_SECRET
```

**Step 2: Grant Microsoft Graph API Permissions**

```bash
# Required permissions for authorization queries
# User.Read.All - Read all users' profiles
# GroupMember.Read.All - Read group memberships
# Application.Read.All - Read app role assignments

# Add permissions (requires admin consent)
az ad app permission add \
  --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    df021288-bdef-4463-88db-98f22de89214=Role \
    98830695-27a2-44f7-8c18-0c3ebc9698f6=Role \
    9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role

# Grant admin consent
az ad app permission admin-consent --id $APP_ID
```

**Required Permissions Summary:**

| Permission | Type | Purpose |
|------------|------|---------|
| `User.Read.All` | Application | Read user profiles and attributes |
| `GroupMember.Read.All` | Application | Read group memberships |
| `Application.Read.All` | Application | Read app role assignments |
| `Directory.Read.All` | Application | (Optional) Read directory objects |

### 3.4 External Data Provider Implementation

**Provider CRD:**

```yaml
# File: test/poc/azure-ad/provider.yaml
apiVersion: externaldata.gatekeeper.sh/v1beta1
kind: Provider
metadata:
  name: azure-ad-provider
spec:
  url: https://azure-ad-provider.gatekeeper-system.svc:8443/validate
  timeout: 10  # seconds - Graph API can be slow
  failurePolicy: Fail  # Fail-closed for security
  caBundle: <BASE64_ENCODED_CA_CERT>
```

**Provider Service (Go Implementation):**

```go
// File: cmd/azure-ad-provider/main.go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "sync"
    "time"

    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/microsoftgraph/msgraph-sdk-go"
    "github.com/patrickmn/go-cache"
)

// Request from Gatekeeper External Data
type ProviderRequest struct {
    APIVersion string              `json:"apiVersion"`
    Kind       string              `json:"kind"`
    Request    ExternalDataRequest `json:"request"`
}

type ExternalDataRequest struct {
    Provider string   `json:"provider"`
    Keys     []string `json:"keys"` // User identifiers (UPN or OID)
}

// Response to Gatekeeper
type ProviderResponse struct {
    APIVersion string               `json:"apiVersion"`
    Kind       string               `json:"kind"`
    Response   ExternalDataResponse `json:"response"`
}

type ExternalDataResponse struct {
    Items     []Item `json:"items"`
    SystemError string `json:"systemError,omitempty"`
}

type Item struct {
    Key   string      `json:"key"`
    Value interface{} `json:"value,omitempty"`
    Error string      `json:"error,omitempty"`
}

// User authorization data returned to Gatekeeper
type UserAuthzData struct {
    UserPrincipalName string   `json:"userPrincipalName"`
    ObjectID          string   `json:"objectId"`
    DisplayName       string   `json:"displayName"`
    Department        string   `json:"department,omitempty"`
    JobTitle          string   `json:"jobTitle,omitempty"`
    Groups            []string `json:"groups"`           // Group display names
    GroupIDs          []string `json:"groupIds"`         // Group object IDs
    AppRoles          []string `json:"appRoles"`         // Application roles
    ManagerUPN        string   `json:"managerUpn,omitempty"`
    AccountEnabled    bool     `json:"accountEnabled"`
    // Custom authorization attributes
    IsAdmin           bool     `json:"isAdmin"`
    AuthzLevel        string   `json:"authzLevel"`       // e.g., "read", "write", "admin"
}

type AzureADProvider struct {
    graphClient *msgraph.GraphServiceClient
    cache       *cache.Cache
    adminGroups map[string]bool  // Group IDs that grant admin
    mu          sync.RWMutex
}

func NewAzureADProvider() (*AzureADProvider, error) {
    // Use managed identity in AKS, or client credentials
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create credential: %w", err)
    }

    client, err := msgraph.NewGraphServiceClientWithCredentials(cred, []string{
        "https://graph.microsoft.com/.default",
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create graph client: %w", err)
    }

    // Configure admin groups from environment
    adminGroups := make(map[string]bool)
    if groups := os.Getenv("ADMIN_GROUP_IDS"); groups != "" {
        for _, g := range strings.Split(groups, ",") {
            adminGroups[strings.TrimSpace(g)] = true
        }
    }

    return &AzureADProvider{
        graphClient: client,
        cache:       cache.New(5*time.Minute, 10*time.Minute), // 5min TTL
        adminGroups: adminGroups,
    }, nil
}

func (p *AzureADProvider) GetUserAuthzData(ctx context.Context, userID string) (*UserAuthzData, error) {
    // Check cache first
    if cached, found := p.cache.Get(userID); found {
        return cached.(*UserAuthzData), nil
    }

    // Query Microsoft Graph
    user, err := p.graphClient.Users().ByUserId(userID).Get(ctx, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to get user: %w", err)
    }

    // Get group memberships
    memberOf, err := p.graphClient.Users().ByUserId(userID).MemberOf().Get(ctx, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to get memberships: %w", err)
    }

    groups := []string{}
    groupIDs := []string{}
    isAdmin := false
    for _, m := range memberOf.GetValue() {
        if group, ok := m.(*models.Group); ok {
            groups = append(groups, *group.GetDisplayName())
            gid := *group.GetId()
            groupIDs = append(groupIDs, gid)
            if p.adminGroups[gid] {
                isAdmin = true
            }
        }
    }

    // Get app role assignments
    appRoles := []string{}
    roleAssignments, err := p.graphClient.Users().ByUserId(userID).AppRoleAssignments().Get(ctx, nil)
    if err == nil {
        for _, ra := range roleAssignments.GetValue() {
            if ra.GetAppRoleId() != nil {
                appRoles = append(appRoles, ra.GetAppRoleId().String())
            }
        }
    }

    // Get manager
    managerUPN := ""
    manager, err := p.graphClient.Users().ByUserId(userID).Manager().Get(ctx, nil)
    if err == nil && manager != nil {
        if m, ok := manager.(*models.User); ok {
            managerUPN = *m.GetUserPrincipalName()
        }
    }

    // Determine authorization level
    authzLevel := "read"
    if isAdmin {
        authzLevel = "admin"
    } else if contains(groups, "Developers") || contains(groups, "Contributors") {
        authzLevel = "write"
    }

    data := &UserAuthzData{
        UserPrincipalName: *user.GetUserPrincipalName(),
        ObjectID:          *user.GetId(),
        DisplayName:       *user.GetDisplayName(),
        Department:        getStringValue(user.GetDepartment()),
        JobTitle:          getStringValue(user.GetJobTitle()),
        Groups:            groups,
        GroupIDs:          groupIDs,
        AppRoles:          appRoles,
        ManagerUPN:        managerUPN,
        AccountEnabled:    *user.GetAccountEnabled(),
        IsAdmin:           isAdmin,
        AuthzLevel:        authzLevel,
    }

    // Cache the result
    p.cache.Set(userID, data, cache.DefaultExpiration)

    return data, nil
}

func (p *AzureADProvider) HandleValidate(w http.ResponseWriter, r *http.Request) {
    var req ProviderRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    items := make([]Item, len(req.Request.Keys))
    for i, key := range req.Request.Keys {
        data, err := p.GetUserAuthzData(r.Context(), key)
        if err != nil {
            items[i] = Item{Key: key, Error: err.Error()}
        } else {
            items[i] = Item{Key: key, Value: data}
        }
    }

    resp := ProviderResponse{
        APIVersion: "externaldata.gatekeeper.sh/v1beta1",
        Kind:       "ProviderResponse",
        Response: ExternalDataResponse{
            Items: items,
        },
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

func main() {
    provider, err := NewAzureADProvider()
    if err != nil {
        log.Fatalf("Failed to create provider: %v", err)
    }

    http.HandleFunc("/validate", provider.HandleValidate)

    log.Println("Starting Azure AD Provider on :8443")
    log.Fatal(http.ListenAndServeTLS(":8443", "/certs/tls.crt", "/certs/tls.key", nil))
}
```

### 3.5 Kubernetes Deployment

```yaml
# File: test/poc/azure-ad/deployment.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: gatekeeper-system
---
apiVersion: v1
kind: Secret
metadata:
  name: azure-ad-provider-config
  namespace: gatekeeper-system
type: Opaque
stringData:
  AZURE_TENANT_ID: "<YOUR_TENANT_ID>"
  AZURE_CLIENT_ID: "<YOUR_APP_ID>"
  AZURE_CLIENT_SECRET: "<YOUR_CLIENT_SECRET>"
  ADMIN_GROUP_IDS: "<COMMA_SEPARATED_GROUP_IDS>"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: azure-ad-provider
  namespace: gatekeeper-system
  labels:
    app: azure-ad-provider
spec:
  replicas: 2
  selector:
    matchLabels:
      app: azure-ad-provider
  template:
    metadata:
      labels:
        app: azure-ad-provider
    spec:
      serviceAccountName: azure-ad-provider
      containers:
      - name: provider
        image: ghcr.io/your-org/azure-ad-provider:latest
        ports:
        - containerPort: 8443
          name: https
        envFrom:
        - secretRef:
            name: azure-ad-provider-config
        volumeMounts:
        - name: tls-certs
          mountPath: /certs
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 5
      volumes:
      - name: tls-certs
        secret:
          secretName: azure-ad-provider-tls
---
apiVersion: v1
kind: Service
metadata:
  name: azure-ad-provider
  namespace: gatekeeper-system
spec:
  selector:
    app: azure-ad-provider
  ports:
  - port: 8443
    targetPort: 8443
    name: https
---
# For AKS with Workload Identity (recommended over client secrets)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: azure-ad-provider
  namespace: gatekeeper-system
  annotations:
    azure.workload.identity/client-id: "<YOUR_APP_ID>"
```

### 3.6 ConstraintTemplate with Azure AD External Data

```yaml
# File: test/poc/azure-ad/authorization-template.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sazureadauthorization
  annotations:
    description: "Authorization using Azure AD user data via External Data"
spec:
  crd:
    spec:
      names:
        kind: K8sAzureADAuthorization
      validation:
        openAPIV3Schema:
          type: object
          properties:
            requiredGroups:
              type: array
              items:
                type: string
              description: "Azure AD groups required (display names)"
            requiredGroupIDs:
              type: array
              items:
                type: string
              description: "Azure AD group IDs required"
            requiredAuthzLevel:
              type: string
              enum: ["read", "write", "admin"]
              description: "Minimum authorization level required"
            allowedDepartments:
              type: array
              items:
                type: string
              description: "Departments allowed to perform this action"
            requireActiveAccount:
              type: boolean
              default: true
              description: "Require Azure AD account to be enabled"
            denyDisabledAccounts:
              type: boolean
              default: true
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sazureadauthorization

        import future.keywords.in

        # Get user identifier from admission request
        # AKS sets username to UPN: user@tenant.onmicrosoft.com
        # or to OID: 00000000-0000-0000-0000-000000000000
        user_id := input.review.userInfo.username

        # Call Azure AD External Data Provider
        azure_ad_response := external_data.gatekeeper["azure-ad-provider"]

        # Extract user data from response
        user_data := azure_ad_response.response.items[0].value {
          azure_ad_response.response.items[0].key == user_id
        }

        # Check if external data call failed
        external_data_error := azure_ad_response.response.items[0].error {
          azure_ad_response.response.items[0].error != ""
        }

        # Authorization level hierarchy
        authz_levels := {
          "read": 1,
          "write": 2,
          "admin": 3
        }

        # Helper: Check if user has required authorization level
        has_required_authz_level {
          required := input.parameters.requiredAuthzLevel
          user_level := user_data.authzLevel
          authz_levels[user_level] >= authz_levels[required]
        }

        # Helper: Check if user is in required groups
        has_required_groups {
          count(input.parameters.requiredGroups) == 0
        }
        has_required_groups {
          required := {g | g := input.parameters.requiredGroups[_]}
          user_groups := {g | g := user_data.groups[_]}
          count(required & user_groups) > 0
        }

        # Helper: Check if user is in required group IDs
        has_required_group_ids {
          count(input.parameters.requiredGroupIDs) == 0
        }
        has_required_group_ids {
          required := {g | g := input.parameters.requiredGroupIDs[_]}
          user_groups := {g | g := user_data.groupIds[_]}
          count(required & user_groups) > 0
        }

        # Helper: Check if user is in allowed departments
        in_allowed_department {
          count(input.parameters.allowedDepartments) == 0
        }
        in_allowed_department {
          user_data.department in input.parameters.allowedDepartments
        }

        # Helper: Check if account is enabled
        account_is_enabled {
          not input.parameters.denyDisabledAccounts
        }
        account_is_enabled {
          user_data.accountEnabled == true
        }

        # Violation: External data call failed
        violation[{"msg": msg}] {
          external_data_error
          msg := sprintf("Failed to retrieve Azure AD data for user '%s': %s", [user_id, external_data_error])
        }

        # Violation: Account is disabled
        violation[{"msg": msg}] {
          not external_data_error
          input.parameters.denyDisabledAccounts
          user_data.accountEnabled == false
          msg := sprintf("User '%s' (%s) has a disabled Azure AD account", [user_data.displayName, user_id])
        }

        # Violation: Insufficient authorization level
        violation[{"msg": msg}] {
          not external_data_error
          input.parameters.requiredAuthzLevel
          not has_required_authz_level
          msg := sprintf("User '%s' has authorization level '%s', but '%s' is required", 
            [user_data.displayName, user_data.authzLevel, input.parameters.requiredAuthzLevel])
        }

        # Violation: Not in required groups
        violation[{"msg": msg}] {
          not external_data_error
          count(input.parameters.requiredGroups) > 0
          not has_required_groups
          msg := sprintf("User '%s' is not a member of required groups: %v. User's groups: %v", 
            [user_data.displayName, input.parameters.requiredGroups, user_data.groups])
        }

        # Violation: Not in required group IDs
        violation[{"msg": msg}] {
          not external_data_error
          count(input.parameters.requiredGroupIDs) > 0
          not has_required_group_ids
          msg := sprintf("User '%s' is not a member of required group IDs: %v", 
            [user_data.displayName, input.parameters.requiredGroupIDs])
        }

        # Violation: Not in allowed department
        violation[{"msg": msg}] {
          not external_data_error
          count(input.parameters.allowedDepartments) > 0
          not in_allowed_department
          msg := sprintf("User '%s' is in department '%s', which is not in allowed departments: %v", 
            [user_data.displayName, user_data.department, input.parameters.allowedDepartments])
        }
```

### 3.7 Sample Constraints Using Azure AD

```yaml
# File: test/poc/azure-ad/constraints/production-namespace-restriction.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAzureADAuthorization
metadata:
  name: production-namespace-admin-only
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
    operations: ["CREATE", "DELETE"]
    namespaceSelector:
      matchLabels:
        environment: production
  parameters:
    requiredAuthzLevel: "admin"
    requiredGroups:
      - "Platform Admins"
      - "SRE Team"
    denyDisabledAccounts: true
---
# File: test/poc/azure-ad/constraints/secret-access-restriction.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAzureADAuthorization
metadata:
  name: secrets-security-team-only
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Secret"]
    operations: ["CREATE", "UPDATE", "DELETE"]
    namespaces:
      - "production"
      - "sensitive-data"
  parameters:
    requiredGroupIDs:
      - "00000000-0000-0000-0000-000000000001"  # Security Team group ID
    allowedDepartments:
      - "Security"
      - "Platform Engineering"
    denyDisabledAccounts: true
---
# File: test/poc/azure-ad/constraints/deployment-write-access.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAzureADAuthorization
metadata:
  name: deployment-write-access
spec:
  match:
    kinds:
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet", "DaemonSet"]
    operations: ["CREATE", "UPDATE", "PATCH", "DELETE"]
    excludedNamespaces:
      - "kube-system"
      - "gatekeeper-system"
  parameters:
    requiredAuthzLevel: "write"
    denyDisabledAccounts: true
```

### 3.8 AKS-Specific Configuration

**Enable Azure AD Integration on AKS:**

```bash
# Create AKS cluster with Azure AD integration
az aks create \
  --resource-group myResourceGroup \
  --name myAKSCluster \
  --enable-aad \
  --aad-admin-group-object-ids <ADMIN_GROUP_OBJECT_ID> \
  --enable-azure-rbac

# Or enable on existing cluster
az aks update \
  --resource-group myResourceGroup \
  --name myAKSCluster \
  --enable-aad \
  --aad-admin-group-object-ids <ADMIN_GROUP_OBJECT_ID>
```

**Configure kubectl for Azure AD:**

```bash
# Get credentials (will prompt for Azure AD login)
az aks get-credentials --resource-group myResourceGroup --name myAKSCluster

# Verify identity
kubectl auth whoami
# Output:
# ATTRIBUTE   VALUE
# Username    user@tenant.onmicrosoft.com
# Groups      [system:authenticated 00000000-... ...]
```

### 3.9 Testing Azure AD Integration

```bash
# 1. Deploy the External Data Provider
kubectl apply -f test/poc/azure-ad/deployment.yaml

# 2. Wait for provider to be ready
kubectl wait --for=condition=Ready pod -l app=azure-ad-provider -n gatekeeper-system --timeout=120s

# 3. Register the Provider with Gatekeeper
kubectl apply -f test/poc/azure-ad/provider.yaml

# 4. Apply the ConstraintTemplate
kubectl apply -f test/poc/azure-ad/authorization-template.yaml

# 5. Apply sample constraints
kubectl apply -f test/poc/azure-ad/constraints/

# 6. Test authorization (as your Azure AD user)
kubectl create namespace test-production --dry-run=server -v=6

# 7. Check audit logs for authorization decisions
kubectl logs -n gatekeeper-system -l gatekeeper.sh/operation=audit

# 8. View constraint status
kubectl get k8sazureadauthorization -o yaml
```

### 3.10 Caching & Performance Considerations

| Aspect | Recommendation |
|--------|----------------|
| **Cache TTL** | 5-15 minutes (balance freshness vs. latency) |
| **Cache invalidation** | Webhook from Azure AD (advanced) |
| **Graph API rate limits** | 10,000 requests per 10 minutes per app |
| **Timeout** | 10 seconds (Graph can be slow) |
| **Failure mode** | Fail-closed (deny if provider unavailable) |
| **Replicas** | 2+ for HA |

### 3.11 Security Considerations

| Risk | Mitigation |
|------|------------|
| **Credential exposure** | Use AKS Workload Identity (no secrets) |
| **Cache poisoning** | Sign/encrypt cache entries |
| **Provider compromise** | Restrict network policies, audit logs |
| **Stale data** | Short TTL, event-driven invalidation |
| **API key rotation** | Use managed identity where possible |

### 3.12 Azure AD Authorization Use Cases

| Use Case | Implementation |
|----------|---------------|
| Only admins create namespaces | `requiredAuthzLevel: admin` |
| Only Security team manages secrets | `requiredGroups: ["Security Team"]` |
| Block disabled accounts | `denyDisabledAccounts: true` |
| Department-based access | `allowedDepartments: ["Engineering"]` |
| Dynamic group membership | Azure AD groups sync automatically |
| Break-glass access | Separate admin constraint with emergency group |

---

## References

- [Gatekeeper External Data](https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata)
- [Kubernetes OIDC Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
- [Dex Documentation](https://dexidp.io/docs/)
- [OPA Rego Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [Microsoft Graph API - Users](https://learn.microsoft.com/en-us/graph/api/resources/user)
- [AKS Azure AD Integration](https://learn.microsoft.com/en-us/azure/aks/managed-aad)
- [Azure Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)

---

## Files Created in This POC

```
docs/poc/
└── oidc-authorization-verification.md    # This document

demo/authorization/                        # Phase 1.5: Authorization Webhook (✅ IMPLEMENTED)
├── constraint-template.yaml              # Basic user/group deny policy
├── constraint-template-pod-exec.yaml     # Pod exec namespace restriction policy
├── constraint-deny-guests-secrets.yaml   # Deny guests access to secrets
├── constraint-deny-kube-system.yaml      # Deny access to kube-system
└── constraint-pod-exec-user.yaml         # Restrict exec-user to namespace "a"

test/poc/
├── phase1-test/                          # Phase 1 test files
│   ├── constraint-template.yaml          # Phase 1 ConstraintTemplate (admission)
│   ├── constraints.yaml                  # Sample Constraints
│   ├── namespaces.yaml                   # Test namespaces
│   ├── run-test.sh                       # Test runner script
│   └── test-pod.yaml                     # Test pod definition
├── user-authorization-template.yaml      # Phase 1 ConstraintTemplate
├── restrict-namespace-creation.yaml      # Sample Constraint
├── user-authorization-external-template.yaml  # Phase 2 ConstraintTemplate
├── external-data-provider.yaml           # Provider CRD
├── kind-config.yaml                      # Kind cluster config
├── dex/
│   ├── dex-deployment.yaml               # Dex OIDC provider
│   └── dex-config.yaml                   # Dex configuration
└── azure-ad/
    ├── provider.yaml                     # Azure AD External Data Provider CRD
    ├── deployment.yaml                   # Provider deployment & service
    ├── authorization-template.yaml       # Azure AD ConstraintTemplate
    └── constraints/
        ├── production-namespace-restriction.yaml
        ├── secret-access-restriction.yaml
        └── deployment-write-access.yaml

pkg/                                       # Code changes for Phase 1.5
├── operations/operations.go              # Added AuthorizationWebhook operation
├── util/enforcement_action.go            # Added AuthorizationEnforcementPoint
├── target/target.go                      # Modified HandleReview for authz
├── target/authorization_adapter.go       # NEW: Authorization review wrapper
└── webhook/authzwebhook/handler.go       # Authorization webhook handler
```

