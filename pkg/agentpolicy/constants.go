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

package agentpolicy

const (
	TargetName          = "agent.gatekeeper.sh"
	EngineName          = "AgentPolicy"
	EnforcementPoint    = "agent"
	SourceVersion       = "v1alpha1"
	ProjectionPending   = "Pending"
	ProjectionProjected = "Projected"
	ProjectionError     = "Error"
)

const (
	gatewayKind       = "AgentgatewayPolicy"
	gatewayAPIVersion = "agentgateway.dev/v1alpha1"
	authzKind         = "AgentAuthzPolicy"
	authzAPIVersion   = "agentauthz.azure.com/v1alpha1"
	constraintGroup   = "constraints.gatekeeper.sh"

	maxSourceBytes         = 256 * 1024
	maxConstraintBytes     = 256 * 1024
	maxParametersBytes     = 64 * 1024
	maxObjectBytes         = 128 * 1024
	maxOutputs             = 16
	maxBindings            = 64
	maxPathSegments        = 16
	maxJSONDepth           = 64
	maxStringListItems     = 256
	maxStringListItemBytes = 256
	maxCELExpressionBytes  = 16 * 1024
	maxListedPolicies      = 4096

	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "gatekeeper"
	targetLabel    = "agent.gatekeeper.sh/managed"

	sourceAPIVersionAnnotation = "agent.gatekeeper.sh/source-constraint-api-version"
	sourceKindAnnotation       = "agent.gatekeeper.sh/source-constraint-kind"
	sourceNameAnnotation       = "agent.gatekeeper.sh/source-constraint-name"
	sourceUIDAnnotation        = "agent.gatekeeper.sh/source-constraint-uid"
	sourceGenerationAnnotation = "agent.gatekeeper.sh/source-constraint-generation"
	templateNameAnnotation     = "agent.gatekeeper.sh/source-template-name"
	templateUIDAnnotation      = "agent.gatekeeper.sh/source-template-uid"
	outputKeyAnnotation        = "agent.gatekeeper.sh/output-key"
)
