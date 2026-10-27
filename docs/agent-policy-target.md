# Agent-policy ConstraintTemplate target (opt-in POC)

The `agent.gatekeeper.sh` target validates a bounded, typed `AgentPolicy` source
and projects its outputs to native `AgentgatewayPolicy` (`agentgateway.dev`)
and `AgentAuthzPolicy` (`agentauthz.azure.com`) resources. Gatekeeper authors
these resources; it does **not** evaluate agent requests, become a policy
decision service, or supply workload identity. Native controllers and a
separate gateway/authorization service own enforcement.

## Enablement

Preinstall **both** native CRDs before starting Gatekeeper with this feature.
Startup fails if discovery cannot resolve either API; installing the CRDs
later requires restarting Gatekeeper. API faults during projection are retried
by the Constraint controller.

```sh
helm upgrade --install gatekeeper ./charts/gatekeeper \
  --namespace gatekeeper-system --create-namespace \
  --set enableAgentPolicyTarget=true
```

Alternatively, `config/agent-policy-target` is the opt-in Kustomize overlay.
Both paths set `--enable-agent-policy-target=true` on controller-manager and
audit, and grant explicit permissions only on the two native policy resources.
The flag and chart value default to `false`; disabled Gatekeeper rejects the
new target. Runtime target enablement and RBAC remain independent.

## Bounded authoring contract

Agent templates use only `agent.gatekeeper.sh`, engine `AgentPolicy`, and typed
source version `v1alpha1`. Sources fix the output bindings and allowlisted native
kinds. They are not Rego, CEL, arbitrary Kubernetes manifests, or a portable
identity model. This POC supports only `enforcementAction: deny` (also the
default) and an absent or empty `spec.match`. `warn`, `dryrun`, scoped actions,
and invented Kubernetes/workload selectors are rejected.
Empty match is not Kubernetes "match all": Gatekeeper does no agent request
matching. Native policy attachment comes from the declared output spec and
parameter bindings. Identity-like parameter values are policy data, not proof
of Pod identity or authenticated credentials.

## Lifecycle and status

The Constraint controller reconciles projections even when the Constraint is
already cached. Watches on both native policy kinds requeue their owning
Constraints to repair output drift. Deleting a Constraint or template removes
its owned projections through the driver; deletion failures are retried.
Gatekeeper does not adopt unrelated native resources.

Constraint pod status uses the `agent` enforcement point with `Pending`,
`Projected`, or `Error`. **`Projected` means the authoring handoff was written,
not that the native policy is accepted or enforcement is active.** Inspect
native controller status and exercise the gateway/authorization service to
prove enforcement. The legacy `status.enforced` bit still means Gatekeeper
accepted the Constraint into its cache.

Delete agent Constraints while the feature is still enabled, wait for their
owned projections to disappear, and then disable the flag to withdraw the POC.
Disabling the flag alone is not a policy-withdrawal mechanism.

## Known limitations of this local POC

This snapshot is retained for an isolated, mock-backed demonstration, not for
production deployment or public-release readiness. Pre-commit review identified
three unresolved issues:

* A template-only edit does not reliably enqueue its existing Constraints.
  Native outputs can remain stale until another relevant event occurs. The
  recorded demo changes Constraint parameters, not template definitions.
* The single temporal-owner check is not atomic across Gatekeeper processes.
  Concurrent creation of different temporal Constraints can admit multiple
  module sets. Use exactly one temporal Constraint; one controller replica alone
  does not remove this race because audit and rollout overlap can also project.
* Native deletion runs inside framework callbacks while the shared admission
  client lock is held. A slow native API can therefore delay unrelated admission
  requests. Keep this snapshot out of shared or production admission paths.

These are known code defects, not guarantees provided by a passing demo. They
must be addressed before broader reuse. Repository publication permission for
the native integration contract is a separate requirement.

## Offline validation

Gator registers an offline driver for the same source and Constraint validation;
it never writes native resources. Use `gator test` with agent templates and
Constraints to validate authoring. No agent review results are produced, and
zero violations are **not** proof that an agent request would be allowed.
`gator verify` rejects agent-target suites because admission-style assertions
cannot test native enforcement. Use the separate mock-backed demo for request
behavior; it is not proof of a production authorization service.
