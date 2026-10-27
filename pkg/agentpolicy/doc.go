/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package agentpolicy implements an opt-in, non-evaluating Constraint target.
// A template's only target is agent.gatekeeper.sh and its only code engine is
// AgentPolicy. Native policy instances are generated, not supplied by customers.
//
// The exact source envelope is:
//
//	{
//	  "version": "v1alpha1",
//	  "outputs": [{
//	    "key": "tools",
//	    "kind": "AgentgatewayPolicy",
//	    "namespace": "default",
//	    "spec": {
//	      "targetRefs": [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "agent"}],
//	      "backend": {"mcp": {"authorization": {
//	        "action": "Require", "policy": {"matchExpressions": []}
//	      }}}
//	    },
//	    "bindings": [{
//	      "parameter": "allowedTools",
//	      "path": ["backend", "mcp", "authorization", "policy", "matchExpressions"],
//	      "format": "CELStringList",
//	      "variable": "mcp.tool.name"
//	    }]
//	  }]
//	}
//
// Source, output and binding properties are exact and case-sensitive. The only
// output kinds are AgentgatewayPolicy (agentgateway.dev/v1alpha1) and
// AgentAuthzPolicy (agentauthz.azure.com/v1alpha1). All native spec content is
// reviewed template-owned configuration; this package does not compile it or
// interpret gateway/PDP status. Source-provided extAuth/extProc attachments are
// supported. Native traffic.authorization and backend.mcp.authorization must
// explicitly use Require, including after binding, because independent Allow
// policies union rather than intersect.
//
// A binding writes a declared top-level Constraint parameter to an existing spec
// property through map keys only. Omitted or Value format preserves the
// JSON value's type (including a complete targetRefs array). CELStringList emits
// one JSON-escaped expression, mcp.tool.name in <JSON string array>. Its only
// variable is mcp.tool.name. Binding paths cannot overlap. AgentAuthzPolicy
// bindings are confined to spec.data: reviewed Rego modules remain verbatim.
// One source Constraint may own multiple AgentAuthzPolicy modules alongside
// AgentgatewayPolicy attachments, within the shared 1..16-output limit. There
// is one active temporal Constraint owner/set for the POC, not a multi-tenant
// policy merger. Conflicting cached or native owners/sets are rejected.
//
// Templates require a structural object parameters schema. Only declared
// parameters are accepted. Constraints must be cluster-scoped, use deny (the
// default when omitted), and omit match or use an empty object. Other enforcement
// actions, scopedEnforcementActions and selectors are rejected. Fixed native
// bindings and explicit identity parameters do not establish pod-bound identity.
//
// Limits are encoded JSON bytes: source and Constraint 256 KiB, parameters
// 64 KiB, each complete output including generated metadata 128 KiB; nesting is
// at most 64 levels. There are 1..16 unique DNS-label output slots, at most 64
// bindings/output and 1..16 map keys/path. CEL lists contain at most 256 UTF-8
// strings of at most 256 bytes each; the escaped expression is at most 16 KiB.
// Empty CEL lists are allowed and match no tools. Namespaces must be DNS labels;
// kube-*, gatekeeper-*, agentgateway-system, cert-manager, istio-system,
// flux-system and argocd are protected.
//
// Online callers must supply an uncached reader. Reconciliation inventories both
// native kinds across namespaces (bounded to 4096 objects), preflights the full
// set and refuses foreign ownership before writing. Objects have deterministic
// names derived from Constraint group/kind/name plus output slot, exact source
// metadata, and a controller owner reference to the source Constraint UID.
// Source API version, UID and output namespace are excluded from names so source
// recreation cannot evade collision checks. Updates preserve unrelated metadata
// and native status. Cleanup requires full provenance and owner UID, with UID
// and resourceVersion delete preconditions, never labels alone.
//
// AddTemplate and AddConstraint validate and cache desired state; the controller
// calls ReconcileConstraint to apply it. Invalid updates preserve cached valid
// state and native outputs. Obsolete slots, kinds and namespaces are removed only
// after every desired output has been reconciled. Kubernetes writes are not a
// transaction: partial application/cleanup is reported and retried without
// pretending that gateway/PDP enforcement was established. Template updates must
// trigger reconciliation of their Constraints. Same-UID objects are adopted
// after restart. UID-less deletion tombstones use cached source identity; without
// it, existing outputs are retained rather than guessing ownership. Template
// deletion can recover full provenance using the template UID after restart.
//
// Offline validation uses the same binding and spec checks. Dump is sorted,
// deterministic desired output under the agentPolicies key, not observed native
// state. Offline reconciliation is Pending; successful online writes are only
// Projected. Admission and audit objects are never agent tool checks.
package agentpolicy
