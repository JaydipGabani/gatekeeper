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

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func moduleSetTemplate(t *testing.T) *templates.ConstraintTemplate {
	t.Helper()
	ct := temporalTemplate(t)
	ct.Name = "agentdataflow"
	ct.UID = "data-flow-template-uid"
	ct.Spec.CRD.Spec.Names.Kind = "AgentDataFlow"
	modules := []struct {
		key  string
		rego string
	}{
		{"decision", "package agent.decision\n\ndefault allow := false\nallow if { data.agent.business.allowed }\n"},
		{"common", "package agent.common\n\nis_read if { input.tool == \"read\" }\n"},
		{"context", "package agent.context\n\nsubject := input.subject\n"},
		{"business", "package agent.business\n\nallowed if { data.agent.common.is_read; data.agent.context.subject == \"fixture-agent\" }\n"},
	}
	outputs := make([]interface{}, 0, 6)
	for _, module := range modules {
		output := outputMap(t, temporalTemplate(t), 0)
		output["key"] = module.key
		require.NoError(t, unstructured.SetNestedField(output, module.rego, "spec", "rego"))
		outputs = append(outputs, output)
	}
	for _, attachment := range []struct{ key, field string }{{"attach-authz", "extAuth"}, {"attach-context", "extProc"}} {
		outputs = append(outputs, map[string]interface{}{
			"key": attachment.key, "kind": gatewayKind, "namespace": "default",
			"spec": map[string]interface{}{
				"targetRefs": []interface{}{map[string]interface{}{
					"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "agent",
				}},
				"traffic": map[string]interface{}{attachment.field: map[string]interface{}{
					"backendRef": map[string]interface{}{"name": "pdp", "port": int64(9000)},
				}},
			},
		})
	}
	sourceMap(t, ct)["outputs"] = outputs
	return ct
}

func TestTemporalModuleSetSingleOwnerLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ct := moduleSetTemplate(t)
	handled, err := ValidateTemplate(ct)
	require.NoError(t, err)
	require.True(t, handled)

	constraint := testConstraint()
	constraint.SetKind(ct.Spec.CRD.Spec.Names.Kind)
	constraint.SetName("data-flow")
	constraint.SetUID("data-flow-source-uid")
	settings := map[string]interface{}{"count": int64(3), "enabled": true}
	setParameter(t, constraint, "settings", settings)

	kube := testClient()
	driver := NewDriver(kube, kube)
	toolsTemplate, toolsConstraint := testTemplate(), testConstraint()
	require.NoError(t, driver.AddTemplate(ctx, toolsTemplate))
	projected(t, driver, toolsConstraint)
	toolsPolicy := listPolicies(t, kube)[0].DeepCopy()
	require.NoError(t, driver.AddTemplate(ctx, ct))
	require.NoError(t, driver.AddConstraint(ctx, constraint))
	projected(t, driver, constraint)

	expectedSpecs := make(map[string]map[string]interface{}, 6)
	for i := 0; i < 6; i++ {
		output := outputMap(t, ct, i)
		slot, ok := output["key"].(string)
		require.True(t, ok)
		spec, found, err := unstructured.NestedMap(output, "spec")
		require.NoError(t, err)
		require.True(t, found)
		if output["kind"] == authzKind {
			require.NoError(t, unstructured.SetNestedMap(spec, settings, "data", "settings"))
		}
		expectedSpecs[slot] = spec
	}
	policies := listPolicies(t, kube)
	require.Len(t, policies, 7, "six outputs from one temporal owner must coexist with the independent tool Constraint")
	names := make(map[string]bool, 6)
	counts := make(map[string]int, 2)
	for _, policy := range policies {
		if policy.GetOwnerReferences()[0].UID == toolsConstraint.GetUID() {
			require.Equal(t, toolsPolicy.Object, policy.Object)
			continue
		}
		require.NoError(t, verifyOwnership(policy, constraint))
		slot := policy.GetAnnotations()[outputKeyAnnotation]
		require.Contains(t, expectedSpecs, slot)
		require.Equal(t, expectedSpecs[slot], policy.Object["spec"], "module source and bound data must remain exact")
		require.False(t, names[policy.GetName()], "each module/attachment needs its own deterministic name")
		names[policy.GetName()] = true
		counts[policy.GetKind()]++
	}
	require.Len(t, names, 6)
	require.Equal(t, 4, counts[authzKind])
	require.Equal(t, 2, counts[gatewayKind])
	projected(t, driver, constraint)
	require.Equal(t, int64(7), kube.creates.Load())
	require.Zero(t, kube.updates.Load())

	offline := NewOfflineDriver()
	require.NoError(t, offline.AddTemplate(ctx, toolsTemplate))
	require.NoError(t, offline.AddConstraint(ctx, toolsConstraint))
	require.NoError(t, offline.AddTemplate(ctx, ct))
	require.NoError(t, offline.AddConstraint(ctx, constraint))
	onlineDump, err := driver.Dump(ctx)
	require.NoError(t, err)
	offlineDump, err := offline.Dump(ctx)
	require.NoError(t, err)
	require.Equal(t, onlineDump, offlineDump)

	other := constraint.DeepCopy()
	other.SetName("another-set")
	other.SetUID("another-source-uid")
	require.ErrorIs(t, driver.AddConstraint(ctx, other), ErrOwnership)
	require.ErrorIs(t, offline.AddConstraint(ctx, other), ErrOwnership)
	restarted := NewDriver(kube, kube)
	require.NoError(t, restarted.AddTemplate(ctx, ct))
	_, _, err = restarted.ReconcileConstraint(ctx, other)
	require.ErrorIs(t, err, ErrOwnership, "the uncached native inventory must reject a second temporal owner after restart")
	require.Equal(t, int64(7), kube.creates.Load())
	require.Zero(t, kube.updates.Load())
	require.Zero(t, kube.deletes.Load())

	restarted = NewDriver(kube, kube)
	require.NoError(t, restarted.AddTemplate(ctx, ct))
	projected(t, restarted, constraint)
	require.Equal(t, int64(7), kube.creates.Load(), "all four modules must be adopted for the same owner")
	require.Zero(t, kube.updates.Load())
	tombstone := constraint.DeepCopy()
	tombstone.SetUID("")
	delete(tombstone.Object, "spec")
	require.NoError(t, restarted.RemoveConstraint(ctx, tombstone))
	require.Equal(t, int64(6), kube.deletes.Load())
	remaining := listPolicies(t, kube)
	require.Len(t, remaining, 1)
	require.Equal(t, toolsPolicy.Object, remaining[0].Object)
}

func TestTemporalModuleSetBoundsAndCollisions(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, maxOutputs, maxOutputs + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			ct := temporalTemplate(t)
			outputs := make([]interface{}, size)
			for i := range outputs {
				output := outputMap(t, temporalTemplate(t), 0)
				output["key"] = fmt.Sprintf("module-%d", i)
				outputs[i] = output
			}
			sourceMap(t, ct)["outputs"] = outputs
			_, err := ValidateTemplate(ct)
			if size <= maxOutputs {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "outputs must contain")
			}
		})
	}

	ct := moduleSetTemplate(t)
	duplicate := ct.DeepCopy()
	outputMap(t, duplicate, 1)["key"] = outputMap(t, duplicate, 0)["key"]
	_, err := ValidateTemplate(duplicate)
	require.ErrorContains(t, err, "duplicate output key")

	constraint := testConstraint()
	constraint.SetKind(ct.Spec.CRD.Spec.Names.Kind)
	setParameter(t, constraint, "settings", map[string]interface{}{"count": int64(1), "enabled": true})
	desired := outputsForTest(t, ct, constraint)
	foreign := desired[len(desired)-1].DeepCopy()
	foreign.SetOwnerReferences(nil)
	foreign.SetLabels(nil)
	foreign.SetAnnotations(nil)
	kube := testClient(foreign)
	driver := NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(context.Background(), ct))
	_, _, err = driver.ReconcileConstraint(context.Background(), constraint)
	require.ErrorIs(t, err, ErrOwnership)
	require.Zero(t, kube.creates.Load(), "a collision anywhere in the coherent set must prevent all writes")
	require.Zero(t, kube.updates.Load())
	require.Zero(t, kube.deletes.Load())
	require.Len(t, listPolicies(t, kube), 1)
}
