# Authorization Webhook Implementation Progress

**Last Updated:** January 17, 2026  
**Status:** ✅ Core Implementation Complete - Ready for Integration Testing

---

## Overview

This document captures the progress of implementing Kubernetes Authorization Webhook support in Gatekeeper, enabling policy-based authorization decisions using OPA/Rego. This feature allows Gatekeeper to act as an authorization webhook for the Kubernetes API server, similar to how it currently handles admission webhooks.

---

## What Was Implemented

### 1. Frameworks Repository (`open-policy-agent/frameworks`)

**Branch:** `authz-webhook-support-v2` (created from upstream/master)

#### New Files Created:

| File | Purpose |
|------|---------|
| `constraint/pkg/apis/authorization/authorization.go` | Core `Review` type wrapping `SubjectAccessReviewSpec`, with `ToRegoInput()` method and helper functions |
| `constraint/pkg/apis/authorization/authorization_test.go` | Unit tests for authorization package (8 test cases) |
| `constraint/pkg/handler/authzhandler/handler.go` | Interface definitions for `AuthorizationTargetHandler` and `AuthzMatcher` |

#### Key Types:

```go
// Review wraps SubjectAccessReviewSpec for Rego evaluation
type Review struct {
    Spec authorizationv1.SubjectAccessReviewSpec
}

// ToRegoInput converts to map for Rego input
func (r *Review) ToRegoInput() map[string]interface{}

// Helper methods
func (r *Review) GetUser() string
func (r *Review) GetGroups() []string
func (r *Review) GetNamespace() string
func (r *Review) GetResource() string
func (r *Review) GetVerb() string
func (r *Review) GetOID() string  // For Azure RBAC - extracts from extra["oid"]
func (r *Review) IsResourceRequest() bool
```

---

### 2. Gatekeeper Repository (`open-policy-agent/gatekeeper`)

**Branch:** `poc/oidc-authorization-verification`

#### New Packages Created:

| Package | Purpose |
|---------|---------|
| `pkg/authztarget/` | Kubernetes authorization target handler |
| `pkg/webhook/authzwebhook/` | HTTP handler for authorization webhook endpoint |
| `pkg/externaldata/azurerbac/` | Azure RBAC CheckAccess API integration (optional) |

#### Files in `pkg/authztarget/`:

| File | Purpose |
|------|---------|
| `target.go` | `K8sAuthorizationTarget` implementing `handler.TargetHandler` |
| `matcher.go` | `AuthzMatcher` for constraint matching with wildcards |
| `target_test.go` | Unit tests (8 test cases) |
| `examples/simple-authorization.yaml` | Example ConstraintTemplate + Constraint |
| `examples/azure-rbac-authorization.yaml` | Azure RBAC integration example |
| `examples/test_authz_cases.go` | Test program demonstrating 6 use cases |

#### Files in `pkg/webhook/authzwebhook/`:

| File | Purpose |
|------|---------|
| `handler.go` | HTTP handler for `/v1/authorize` endpoint |

#### Files in `pkg/externaldata/azurerbac/`:

| File | Purpose |
|------|---------|
| `provider.go` | Azure RBAC CheckAccess V2 API provider |
| `provider_test.go` | Unit tests (6 test suites) |

#### Modified Files:

| File | Change |
|------|--------|
| `main.go` | Added import for `authztarget` and registered `K8sAuthorizationTarget{}` alongside `K8sValidationTarget{}` |
| `Dockerfile` | Changed to `-mod=vendor` for build |
| `go.mod` | Added replace directive for local frameworks development |

---

## Authorization Target Details

### Target Name
```
authorization.k8s.gatekeeper.sh
```

### Rego Input Format

When a `SubjectAccessReview` is processed, the Rego input looks like:

```json
{
  "review": {
    "user": "alice@contoso.com",
    "groups": ["developers", "system:authenticated"],
    "resourceAttributes": {
      "namespace": "production",
      "verb": "create",
      "group": "apps",
      "resource": "deployments",
      "subresource": "",
      "name": "my-deployment"
    },
    "extra": {
      "oid": ["user-oid-12345"]
    }
  },
  "parameters": {
    // Constraint parameters
  }
}
```

### Constraint Matching

The `AuthzMatcher` supports:
- User matching (exact)
- Group matching (exact)
- Resource matching (wildcards, e.g., `pods/*`)
- Namespace matching (wildcards, e.g., `kube-*`)
- Namespace exclusions

---

## Azure RBAC Integration (Optional)

### Data Action Format (V2)

Matches the Guard patch format:

```
Microsoft.KubernetesAuthorization/resources/<group>/<resource>/<subresource>/<verb>/action
```

Examples:
- `GET pods` → `Microsoft.KubernetesAuthorization/resources/-/pods/-/get/action`
- `CREATE deployments` → `Microsoft.KubernetesAuthorization/resources/apps/deployments/-/create/action`
- `GET pods/log` → `Microsoft.KubernetesAuthorization/resources/-/pods/log/get/action`

### ABAC Attributes

| Attribute | Value |
|-----------|-------|
| `customResources:kind` | Full operation path (data action) |
| `customResources:group` | Namespace (for ABAC condition evaluation) |

---

## Current Cluster State

### Deployed Components

```bash
# Gatekeeper is deployed with authorization target
kubectl get pods -n gatekeeper-system
# NAME                                             READY   STATUS
# gatekeeper-audit-7fb6ff8488-bbnnz                1/1     Running
# gatekeeper-controller-manager-5cfc667f65-7w8r7   1/1     Running
# gatekeeper-controller-manager-5cfc667f65-ln7dj   1/1     Running
# gatekeeper-controller-manager-5cfc667f65-tzpks   1/1     Running
```

### Applied Resources

```bash
# ConstraintTemplate and Constraint are deployed
kubectl get constrainttemplates k8ssimpleauthorization
kubectl get k8ssimpleauthorization demo-authorization-policy
```

---

## Test Results

### Unit Tests

All tests pass:

```bash
# Frameworks - authorization package
cd /mount/d/go/src/github.com/open-policy-agent/frameworks/constraint
go test ./pkg/apis/authorization/... -v
# PASS: 8 tests

# Gatekeeper - authztarget package
cd /mount/d/go/src/github.com/open-policy-agent/gatekeeper
go test ./pkg/authztarget/... -v
# PASS: 8 tests

# Gatekeeper - Azure RBAC provider
go test ./pkg/externaldata/azurerbac/... -v
# PASS: 6 test suites
```

### Integration Test Cases (All Passed)

| # | Use Case | User | Groups | Action | Namespace | Expected | Result |
|---|----------|------|--------|--------|-----------|----------|--------|
| 1 | Denied User | `bad-actor@example.com` | `[developers]` | `get pods` | `default` | ❌ DENIED | ✅ PASS |
| 2 | Protected Namespace | `alice@example.com` | `[developers]` | `get pods` | `kube-system` | ❌ DENIED | ✅ PASS |
| 3 | Read-Only Write Attempt | `viewer@example.com` | `[viewers]` | `create pods` | `default` | ❌ DENIED | ✅ PASS |
| 4 | Read-Only Read Allowed | `auditor@example.com` | `[auditors]` | `list pods` | `default` | ✅ ALLOWED | ✅ PASS |
| 5 | Admin Bypass | `admin@example.com` | `[cluster-admins]` | `delete secrets` | `kube-system` | ✅ ALLOWED | ✅ PASS |
| 6 | Normal User Allowed | `developer@example.com` | `[developers]` | `create pods` | `default` | ✅ ALLOWED | ✅ PASS |

---

## Commands to Rebuild and Redeploy

### 1. Rebuild Docker Image

```bash
cd /mount/d/go/src/github.com/open-policy-agent/gatekeeper

# Vendor dependencies (includes local frameworks changes)
go mod vendor

# Build image
docker buildx build --platform linux/amd64 -t gatekeeper:authz-test --load .

# Load into kind cluster
kind load docker-image gatekeeper:authz-test --name kind
```

### 2. Redeploy to Cluster

```bash
# Restart deployments to pick up new image
kubectl rollout restart deployment -n gatekeeper-system gatekeeper-controller-manager gatekeeper-audit

# Wait for rollout
kubectl rollout status deployment/gatekeeper-controller-manager -n gatekeeper-system --timeout=120s
```

### 3. Apply Example Constraint

```bash
kubectl apply -f /mount/d/go/src/github.com/open-policy-agent/gatekeeper/pkg/authztarget/examples/simple-authorization.yaml
```

### 4. Run Test Cases

```bash
go run ./pkg/authztarget/examples/test_authz_cases.go
```

---

## Remaining Work / Next Steps

### High Priority

1. **Wire Authorization Webhook Endpoint in main.go**
   - The `authzwebhook.Handler` is implemented but not yet registered as an HTTP endpoint
   - Need to add `/v1/authorize` endpoint similar to how admission webhooks are registered

2. **Create AuthorizationWebhookConfiguration**
   - Kubernetes needs to be configured to call Gatekeeper for authorization
   - Requires creating appropriate webhook configuration

3. **End-to-End Testing**
   - Configure API server to use Gatekeeper as authorization webhook
   - Test actual SubjectAccessReview flow

### Medium Priority

4. **Add Metrics for Authorization Decisions**
   - Similar to admission metrics
   - Track allow/deny decisions, latency, etc.

5. **Add Audit Log for Authorization Decisions**
   - Log authorization decisions for compliance

6. **Documentation**
   - User-facing documentation for enabling authorization webhook
   - Example policies and use cases

### Low Priority

7. **CEL Support for Authorization**
   - Currently only Rego is supported for authorization policies
   - Could add CEL (K8sNativeValidation) support

---

## File Locations Summary

### Frameworks Repository
```
/mount/d/go/src/github.com/open-policy-agent/frameworks/
└── constraint/
    └── pkg/
        ├── apis/
        │   └── authorization/
        │       ├── authorization.go      # Core types
        │       └── authorization_test.go # Unit tests
        └── handler/
            └── authzhandler/
                └── handler.go            # Interfaces
```

### Gatekeeper Repository
```
/mount/d/go/src/github.com/open-policy-agent/gatekeeper/
├── main.go                               # Modified to register authztarget
├── Dockerfile                            # Modified for -mod=vendor
├── go.mod                                # Has replace directive for frameworks
├── pkg/
│   ├── authztarget/
│   │   ├── target.go                     # K8sAuthorizationTarget
│   │   ├── matcher.go                    # AuthzMatcher
│   │   ├── target_test.go                # Unit tests
│   │   └── examples/
│   │       ├── simple-authorization.yaml # Example policy
│   │       ├── azure-rbac-authorization.yaml
│   │       └── test_authz_cases.go       # Test program
│   ├── webhook/
│   │   └── authzwebhook/
│   │       └── handler.go                # HTTP handler
│   └── externaldata/
│       └── azurerbac/
│           ├── provider.go               # Azure RBAC provider
│           └── provider_test.go          # Unit tests
└── vendor/                               # Vendored dependencies
```

---

## Git Status

### Frameworks Repository

```bash
cd /mount/d/go/src/github.com/open-policy-agent/frameworks
git status
# Branch: authz-webhook-support-v2
# Changes committed
```

### Gatekeeper Repository

```bash
cd /mount/d/go/src/github.com/open-policy-agent/gatekeeper
git status
# Branch: poc/oidc-authorization-verification
# Many uncommitted changes (new files + modifications)
```

**Recommendation:** Commit the gatekeeper changes before leaving:

```bash
cd /mount/d/go/src/github.com/open-policy-agent/gatekeeper
git add pkg/authztarget/ pkg/webhook/authzwebhook/ pkg/externaldata/azurerbac/
git add main.go Dockerfile
git commit -m "Add authorization webhook support

- Add K8sAuthorizationTarget for authorization.k8s.gatekeeper.sh
- Add AuthzMatcher with wildcard support
- Add authzwebhook HTTP handler
- Add Azure RBAC CheckAccess provider (optional)
- Register authorization target in main.go
- Add example policies and test cases"
```

---

## Contact / Questions

This implementation enables Gatekeeper to make authorization decisions using OPA/Rego policies, similar to Guard but with the full power of Gatekeeper's constraint framework.

**Key differentiator:** Unlike Guard which is a separate binary, this integrates authorization directly into Gatekeeper, allowing:
- Unified policy management (admission + authorization)
- Shared constraint templates
- Single deployment
- Consistent audit logging

---

*Have a great trip! The tests are passing and the implementation is stable. 🚀*
