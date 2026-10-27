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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type recordingClient struct {
	client.Client
	creates      atomic.Int64
	updates      atomic.Int64
	deletes      atomic.Int64
	failUpdate   atomic.Bool
	failDelete   atomic.Bool
	failKind     string
	beforeCreate func(context.Context, client.Object) error
	beforeDelete func(context.Context, client.Object, *client.DeleteOptions) error
}

func (c *recordingClient) Create(ctx context.Context, object client.Object, opts ...client.CreateOption) error {
	c.creates.Add(1)
	if c.beforeCreate != nil {
		if err := c.beforeCreate(ctx, object); err != nil {
			return err
		}
	}
	if object.GetObjectKind().GroupVersionKind().Kind == c.failKind {
		return errors.New("injected native create failure")
	}
	return c.Client.Create(ctx, object, opts...)
}

func (c *recordingClient) Update(ctx context.Context, object client.Object, opts ...client.UpdateOption) error {
	c.updates.Add(1)
	if c.failUpdate.Load() {
		return fmt.Errorf("injected update: %w", apierrors.NewConflict(schema.GroupResource{Group: "agentgateway.dev", Resource: "agentgatewaypolicies"}, object.GetName(), errors.New("conflict")))
	}
	return c.Client.Update(ctx, object, opts...)
}

func (c *recordingClient) Delete(ctx context.Context, object client.Object, opts ...client.DeleteOption) error {
	c.deletes.Add(1)
	options := &client.DeleteOptions{}
	for _, option := range opts {
		option.ApplyToDelete(options)
	}
	if c.beforeDelete != nil {
		if err := c.beforeDelete(ctx, object, options); err != nil {
			return err
		}
	}
	if c.failDelete.Load() {
		return errors.New("injected delete failure")
	}
	return c.Client.Delete(ctx, object, opts...)
}

func testClient(objects ...client.Object) *recordingClient {
	return &recordingClient{Client: fake.NewClientBuilder().WithScheme(runtime.NewScheme()).WithObjects(objects...).Build()}
}

func listPolicies(t *testing.T, reader client.Reader) []*unstructured.Unstructured {
	t.Helper()
	result := make([]*unstructured.Unstructured, 0)
	for _, kind := range []string{gatewayKind, authzKind} {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.FromAPIVersionAndKind(nativeAPIVersion(kind), kind+"List"))
		require.NoError(t, reader.List(context.Background(), list))
		for i := range list.Items {
			result = append(result, list.Items[i].DeepCopy())
		}
	}
	sortObjects(result)
	return result
}

func projected(t *testing.T, driver *Driver, constraint *unstructured.Unstructured) ProjectionStatus {
	t.Helper()
	status, handled, err := driver.ReconcileConstraint(context.Background(), constraint)
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, ProjectionProjected, status.State)
	require.Contains(t, status.Message, "enforcement are not established")
	return status
}

func TestFrameworkAndNonEvaluatingTarget(t *testing.T) {
	t.Parallel()
	require.Equal(t, "agent.gatekeeper.sh", TargetName)
	require.Equal(t, "AgentPolicy", EngineName)
	require.Equal(t, "agent", EnforcementPoint)
	require.Equal(t, "v1alpha1", SourceVersion)
	driver := NewOfflineDriver()
	target := NewTarget(driver)
	c, err := constraintclient.NewClient(
		constraintclient.Targets(target),
		constraintclient.Driver(driver),
		constraintclient.EnforcementPoints("gator.gatekeeper.sh"),
	)
	require.NoError(t, err)
	_, err = c.AddTemplate(context.Background(), testTemplate())
	require.NoError(t, err)
	_, err = c.AddConstraint(context.Background(), testConstraint())
	require.NoError(t, err)
	require.Equal(t, TargetName, target.GetName())
	require.Equal(t, EngineName, driver.Name())
	require.Equal(t, "object", target.MatchSchema().Type)
	require.Equal(t, int64(0), *target.MatchSchema().MaxProperties)
	for _, review := range []interface{}{
		&admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "audited"}},
		&unstructured.Unstructured{Object: map[string]interface{}{"kind": "Pod"}},
		map[string]interface{}{"mcp": map[string]interface{}{"tool": map[string]interface{}{"name": "read"}}},
	} {
		handled, result, err := target.HandleReview(review)
		require.NoError(t, err)
		require.False(t, handled)
		require.Nil(t, result)
		handled, path, data, err := target.ProcessData(review)
		require.NoError(t, err)
		require.False(t, handled)
		require.Nil(t, path)
		require.Nil(t, data)
		matcher, err := target.ToMatcher(testConstraint())
		require.NoError(t, err)
		matched, err := matcher.Match(review)
		require.NoError(t, err)
		require.False(t, matched)
		_, err = driver.Query(context.Background(), TargetName, []*unstructured.Unstructured{testConstraint()}, review)
		require.ErrorIs(t, err, ErrReviewUnsupported)
		response, err := driver.Query(context.Background(), TargetName, nil, review)
		require.NoError(t, err)
		require.Empty(t, response.Results)
	}
	watches := driver.WatchObjects()
	require.Len(t, watches, 2)
	require.Equal(t, schema.FromAPIVersionAndKind(gatewayAPIVersion, gatewayKind), watches[0].GetObjectKind().GroupVersionKind())
	require.Equal(t, schema.FromAPIVersionAndKind(authzAPIVersion, authzKind), watches[1].GetObjectKind().GroupVersionKind())
	watches[0].SetName("mutated")
	require.Empty(t, driver.WatchObjects()[0].GetName())
}

func TestProjectionExactSpecIdempotenceAndLastKnownGood(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kube := testClient()
	driver := NewDriver(kube, kube)
	ct, constraint := testTemplate(), testConstraint()
	require.NoError(t, driver.AddTemplate(ctx, ct))
	require.NoError(t, driver.AddConstraint(ctx, constraint))
	projected(t, driver, constraint)
	policies := listPolicies(t, kube)
	require.Len(t, policies, 1)
	policy := policies[0]
	require.Equal(t, gatewayAPIVersion, policy.GetAPIVersion())
	require.Equal(t, gatewayKind, policy.GetKind())
	require.Equal(t, "default", policy.GetNamespace())
	require.Equal(t, map[string]interface{}{
		"targetRefs": []interface{}{map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "agent"}},
		"backend": map[string]interface{}{"mcp": map[string]interface{}{"authorization": map[string]interface{}{
			"action": "Require", "policy": map[string]interface{}{"matchExpressions": []interface{}{`mcp.tool.name in ["read"]`}},
		}}},
	}, policy.Object["spec"])
	require.Len(t, policy.GetOwnerReferences(), 1)
	owner := policy.GetOwnerReferences()[0]
	require.Equal(t, constraint.GetAPIVersion(), owner.APIVersion)
	require.Equal(t, constraint.GetKind(), owner.Kind)
	require.Equal(t, constraint.GetName(), owner.Name)
	require.Equal(t, constraint.GetUID(), owner.UID)
	require.True(t, *owner.Controller)
	require.True(t, *owner.BlockOwnerDeletion)
	require.Equal(t, string(constraint.GetUID()), policy.GetAnnotations()[sourceUIDAnnotation])
	require.Equal(t, ct.Name, policy.GetAnnotations()[templateNameAnnotation])
	require.Equal(t, string(ct.UID), policy.GetAnnotations()[templateUIDAnnotation])
	require.Equal(t, "tools", policy.GetAnnotations()[outputKeyAnnotation])
	require.NoError(t, verifyOwnership(policy, constraint))

	policy.SetLabels(mergeMetadata(policy.GetLabels(), map[string]string{"custom": "preserved"}))
	policy.Object["status"] = map[string]interface{}{"accepted": true}
	require.NoError(t, kube.Client.Update(ctx, policy))
	projected(t, driver, constraint)
	require.Equal(t, int64(1), kube.creates.Load())
	require.Zero(t, kube.updates.Load())
	policy = listPolicies(t, kube)[0]
	require.Equal(t, "preserved", policy.GetLabels()["custom"])
	require.Equal(t, map[string]interface{}{"accepted": true}, policy.Object["status"])

	changed := constraint.DeepCopy()
	setParameter(t, changed, "allowedTools", []interface{}{"read", "search"})
	kube.failUpdate.Store(true)
	status, handled, err := driver.ReconcileConstraint(ctx, changed)
	require.Error(t, err)
	require.True(t, apierrors.IsConflict(err), "nested API errors must survive wrapping")
	require.True(t, handled)
	require.Equal(t, ProjectionError, status.State)
	require.Contains(t, status.Message, "partial apply")
	require.Equal(t, policy.Object, listPolicies(t, kube)[0].Object, "failed update must preserve stored policy")
	kube.failUpdate.Store(false)
	projected(t, driver, changed)
	current := listPolicies(t, kube)[0]
	expressions, found, err := unstructured.NestedSlice(current.Object, "spec", "backend", "mcp", "authorization", "policy", "matchExpressions")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []interface{}{`mcp.tool.name in ["read","search"]`}, expressions)
	dumpBefore, err := driver.Dump(ctx)
	require.NoError(t, err)
	invalid := changed.DeepCopy()
	setParameter(t, invalid, "allowedTools", "not-a-list")
	require.Error(t, driver.AddConstraint(ctx, invalid))
	status, _, err = driver.ReconcileConstraint(ctx, invalid)
	require.Error(t, err)
	require.Equal(t, ProjectionError, status.State)
	require.Equal(t, current.Object, listPolicies(t, kube)[0].Object)
	dumpAfter, err := driver.Dump(ctx)
	require.NoError(t, err)
	require.Equal(t, dumpBefore, dumpAfter)
	badTemplate := ct.DeepCopy()
	bindingMap(t, badTemplate)["parameter"] = "missing"
	require.Error(t, driver.AddTemplate(ctx, badTemplate))
	dumpAfter, err = driver.Dump(ctx)
	require.NoError(t, err)
	require.Equal(t, dumpBefore, dumpAfter)
}

func TestDeterministicNamesAndOfflineParity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ct := testTemplate()
	output := outputMap(t, testTemplate(), 0)
	output["key"] = "second"
	sourceMap(t, ct)["outputs"] = []interface{}{outputMap(t, ct, 0), output}
	constraint := testConstraint()
	outputs := outputsForTest(t, ct, constraint)
	require.NotEqual(t, outputs[0].GetName(), outputs[1].GetName())
	name := outputName(constraint, "tools")
	require.Equal(t, "gk-agent-dbc850e5626c0715a64a09d6f7e71509d14833fc0f3729f0", name)
	for _, mutate := range []func(*unstructured.Unstructured){
		func(c *unstructured.Unstructured) { c.SetUID(types.UID("new-uid")) },
		func(c *unstructured.Unstructured) { c.SetAPIVersion("constraints.gatekeeper.sh/v1alpha1") },
		func(c *unstructured.Unstructured) { c.SetGeneration(2) },
	} {
		candidate := constraint.DeepCopy()
		mutate(candidate)
		require.Equal(t, name, outputName(candidate, "tools"))
	}
	require.NotEqual(t, name, outputName(constraint, "other"))
	other := constraint.DeepCopy()
	other.SetKind("OtherTools")
	require.NotEqual(t, name, outputName(other, "tools"))
	other.SetKind("AgentTools")
	other.SetName("other")
	require.NotEqual(t, name, outputName(other, "tools"))

	offline := NewOfflineDriver()
	kube := testClient()
	online := NewDriver(kube, kube)
	for _, driver := range []*Driver{online, offline} {
		require.NoError(t, driver.AddTemplate(ctx, ct))
		for _, name := range []string{"z-last", "a-first"} {
			candidate := constraint.DeepCopy()
			candidate.SetName(name)
			candidate.SetUID(types.UID("uid-" + name))
			require.NoError(t, driver.AddConstraint(ctx, candidate))
			status, handled, err := driver.ReconcileConstraint(ctx, candidate)
			require.NoError(t, err)
			require.True(t, handled)
			if driver.offline {
				require.Equal(t, ProjectionPending, status.State)
			} else {
				require.Equal(t, ProjectionProjected, status.State)
			}
		}
	}
	offlineDump, err := offline.Dump(ctx)
	require.NoError(t, err)
	onlineDump, err := online.Dump(ctx)
	require.NoError(t, err)
	require.Equal(t, offlineDump, onlineDump)
	for i := 0; i < 5; i++ {
		dump, err := offline.Dump(ctx)
		require.NoError(t, err)
		require.Equal(t, offlineDump, dump)
	}
	var dump struct {
		Policies []unstructured.Unstructured `json:"agentPolicies"`
	}
	require.NoError(t, json.Unmarshal([]byte(offlineDump), &dump))
	require.Len(t, dump.Policies, 4)
	for i := 1; i < len(dump.Policies); i++ {
		require.Less(t, objectKey(&dump.Policies[i-1]), objectKey(&dump.Policies[i]))
	}
}

func TestOwnershipRefusalAndRestartAdoption(t *testing.T) {
	t.Parallel()
	mutations := []struct {
		name   string
		mutate func(*unstructured.Unstructured)
	}{
		{"foreign native object", func(object *unstructured.Unstructured) {
			object.SetLabels(nil)
			object.SetAnnotations(nil)
			object.SetOwnerReferences(nil)
		}},
		{"label only", func(object *unstructured.Unstructured) { object.SetOwnerReferences(nil) }},
		{"missing labels", func(object *unstructured.Unstructured) { object.SetLabels(nil) }},
		{"missing annotations", func(object *unstructured.Unstructured) { object.SetAnnotations(nil) }},
		{"wrong source UID", func(object *unstructured.Unstructured) {
			annotations := object.GetAnnotations()
			annotations[sourceUIDAnnotation] = "other"
			object.SetAnnotations(annotations)
		}},
		{"wrong owner UID", func(object *unstructured.Unstructured) {
			owners := object.GetOwnerReferences()
			owners[0].UID = "other"
			object.SetOwnerReferences(owners)
		}},
		{"non-controller owner", func(object *unstructured.Unstructured) {
			owners := object.GetOwnerReferences()
			value := false
			owners[0].Controller = &value
			object.SetOwnerReferences(owners)
		}},
		{"multiple owners", func(object *unstructured.Unstructured) {
			object.SetOwnerReferences(append(object.GetOwnerReferences(), metav1.OwnerReference{Name: "other"}))
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			ct, constraint := testTemplate(), testConstraint()
			foreign := outputsForTest(t, ct, constraint)[0]
			test.mutate(foreign)
			kube := testClient(foreign)
			driver := NewDriver(kube, kube)
			require.NoError(t, driver.AddTemplate(context.Background(), ct))
			_, handled, err := driver.ReconcileConstraint(context.Background(), constraint)
			require.True(t, handled)
			require.ErrorIs(t, err, ErrOwnership)
			require.Zero(t, kube.creates.Load())
			require.Zero(t, kube.updates.Load())
			require.Zero(t, kube.deletes.Load())
			require.Len(t, listPolicies(t, kube), 1)
		})
	}
	ct, constraint := testTemplate(), testConstraint()
	kube := testClient(outputsForTest(t, ct, constraint)[0])
	restarted := NewDriver(kube, kube)
	require.NoError(t, restarted.AddTemplate(context.Background(), ct))
	projected(t, restarted, constraint)
	require.Zero(t, kube.creates.Load())
	require.Zero(t, kube.updates.Load())
	recreated := constraint.DeepCopy()
	recreated.SetUID(types.UID("new-source-uid"))
	_, _, err := restarted.ReconcileConstraint(context.Background(), recreated)
	require.ErrorIs(t, err, ErrOwnership)
	restarted = NewDriver(kube, kube)
	require.NoError(t, restarted.AddTemplate(context.Background(), ct))
	_, _, err = restarted.ReconcileConstraint(context.Background(), recreated)
	require.ErrorIs(t, err, ErrOwnership)
	require.Len(t, listPolicies(t, kube), 1)
}

func TestCompleteSetCleanupAndTombstones(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ct, constraint := testTemplate(), testConstraint()
	second := outputMap(t, testTemplate(), 0)
	second["key"] = "second"
	sourceMap(t, ct)["outputs"] = []interface{}{outputMap(t, ct, 0), second}
	kube := testClient()
	driver := NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, ct))
	projected(t, driver, constraint)
	require.Len(t, listPolicies(t, kube), 2)

	changed := testTemplate()
	outputMap(t, changed, 0)["namespace"] = "agents"
	require.NoError(t, driver.AddTemplate(ctx, changed))
	// Restart before reconciliation: old slot/namespace discovery cannot depend
	// on an in-memory list of previously emitted native names.
	driver = NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, changed))
	projected(t, driver, constraint)
	policies := listPolicies(t, kube)
	require.Len(t, policies, 1)
	require.Equal(t, "agents", policies[0].GetNamespace())
	require.Equal(t, "tools", policies[0].GetAnnotations()[outputKeyAnnotation])
	require.Equal(t, int64(2), kube.deletes.Load())

	tombstone := &unstructured.Unstructured{}
	tombstone.SetAPIVersion(constraint.GetAPIVersion())
	tombstone.SetKind(constraint.GetKind())
	tombstone.SetName(constraint.GetName())
	kube.failDelete.Store(true)
	require.ErrorContains(t, driver.RemoveConstraint(ctx, tombstone), "partial cleanup")
	require.Len(t, listPolicies(t, kube), 1)
	kube.failDelete.Store(false)
	require.NoError(t, driver.RemoveConstraint(ctx, tombstone))
	require.Empty(t, listPolicies(t, kube))
	require.NoError(t, driver.RemoveConstraint(ctx, tombstone))
	dump, err := driver.Dump(ctx)
	require.NoError(t, err)
	require.JSONEq(t, `{"agentPolicies":[]}`, dump)

	projected(t, driver, constraint)
	driver = NewDriver(kube, kube)
	require.ErrorIs(t, driver.RemoveConstraint(ctx, tombstone), ErrOwnership, "UID-less tombstone must not guess after restart")
	require.Len(t, listPolicies(t, kube), 1)
	require.NoError(t, driver.RemoveConstraint(ctx, constraint))
	require.Empty(t, listPolicies(t, kube))
}

func TestTemplateRemovalAndRestartCleanup(t *testing.T) {
	t.Parallel()
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprint(restart), func(t *testing.T) {
			ctx := context.Background()
			ct, constraint := testTemplate(), testConstraint()
			kube := testClient()
			driver := NewDriver(kube, kube)
			require.NoError(t, driver.AddTemplate(ctx, ct))
			projected(t, driver, constraint)
			other := constraint.DeepCopy()
			other.SetName("other")
			other.SetUID("other-uid")
			projected(t, driver, other)
			if restart {
				driver = NewDriver(kube, kube)
			}
			tombstone := &templates.ConstraintTemplate{ObjectMeta: metav1.ObjectMeta{Name: ct.Name, UID: ct.UID}}
			require.NoError(t, driver.RemoveTemplate(ctx, tombstone))
			require.Empty(t, listPolicies(t, kube))
			_, handled, err := driver.ReconcileConstraint(ctx, constraint)
			require.NoError(t, err)
			require.False(t, handled)
			require.NoError(t, driver.RemoveTemplate(ctx, tombstone))
		})
	}
	ctx := context.Background()
	ct, constraint := testTemplate(), testConstraint()
	kube := testClient(outputsForTest(t, ct, constraint)[0])
	restarted := NewDriver(kube, kube)
	require.ErrorIs(t, restarted.RemoveTemplate(ctx, &templates.ConstraintTemplate{ObjectMeta: metav1.ObjectMeta{Name: ct.Name}}), ErrOwnership)
	require.Len(t, listPolicies(t, kube), 1)
	require.NoError(t, restarted.AddTemplate(ctx, ct))
	wrong := ct.DeepCopy()
	wrong.UID = "different-template"
	require.ErrorIs(t, restarted.RemoveTemplate(ctx, wrong), ErrOwnership)
	require.ErrorIs(t, restarted.AddTemplate(ctx, wrong), ErrOwnership)
	require.Len(t, listPolicies(t, kube), 1)
}

func TestCleanupRejectsLabelOnlyAndReplacementRaces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ct, constraint := testTemplate(), testConstraint()
	policy := outputsForTest(t, ct, constraint)[0]
	policy.SetOwnerReferences(nil)
	kube := testClient(policy)
	driver := NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, ct))
	require.NoError(t, driver.AddConstraint(ctx, constraint))
	require.ErrorIs(t, driver.RemoveConstraint(ctx, constraint), ErrOwnership)
	require.ErrorIs(t, driver.RemoveTemplate(ctx, ct), ErrOwnership)
	require.Zero(t, kube.deletes.Load())
	require.Len(t, listPolicies(t, kube), 1)

	policy = outputsForTest(t, ct, constraint)[0]
	policy.SetUID(types.UID("native-original"))
	kube = testClient(policy)
	var checked atomic.Bool
	kube.beforeDelete = func(ctx context.Context, object client.Object, opts *client.DeleteOptions) error {
		if opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != "native-original" || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion == "" {
			return errors.New("missing deletion preconditions")
		}
		checked.Store(true)
		current := nativeObject(object.GetObjectKind().GroupVersionKind().Kind)
		if err := kube.Client.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
			return err
		}
		current.Object["spec"] = map[string]interface{}{"replaced": true}
		return kube.Client.Update(ctx, current)
	}
	driver = NewDriver(kube, kube)
	require.Error(t, driver.RemoveConstraint(ctx, constraint))
	require.True(t, checked.Load())
	remaining := listPolicies(t, kube)
	require.Len(t, remaining, 1)
	require.Equal(t, map[string]interface{}{"replaced": true}, remaining[0].Object["spec"])
}

func TestTemporalSingleSetAndPartialApply(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ct := temporalTemplate(t)
	constraint := testConstraint()
	setParameter(t, constraint, "settings", map[string]interface{}{"count": int64(3), "enabled": true})
	temporal := outputMap(t, ct, 0)
	toolOutput := outputMap(t, testTemplate(), 0)
	sourceMap(t, ct)["outputs"] = []interface{}{temporal, toolOutput}
	kube := testClient()
	driver := NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, ct))
	projected(t, driver, constraint)
	require.Len(t, listPolicies(t, kube), 2)
	other := constraint.DeepCopy()
	other.SetName("other")
	other.SetUID("other-uid")
	require.ErrorIs(t, driver.AddConstraint(ctx, other), ErrOwnership)
	restarted := NewDriver(kube, kube)
	require.NoError(t, restarted.AddTemplate(ctx, ct))
	_, _, err := restarted.ReconcileConstraint(ctx, other)
	require.ErrorIs(t, err, ErrOwnership)
	require.Len(t, listPolicies(t, kube), 2)

	kube = testClient()
	// authz sorts before gateway; fail the second creation after the first write.
	kube.failKind = gatewayKind
	driver = NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, ct))
	status, handled, err := driver.ReconcileConstraint(ctx, constraint)
	require.ErrorContains(t, err, "partial apply: 1 writes, 1/2")
	require.True(t, handled)
	require.Equal(t, ProjectionError, status.State)
	policies := listPolicies(t, kube)
	require.Len(t, policies, 1)
	require.Equal(t, authzKind, policies[0].GetKind())
	kube.failKind = ""
	projected(t, driver, constraint)
	require.Len(t, listPolicies(t, kube), 2)

	// Removing a temporal output cleans its complete previously owned set.
	gatewayOnly := testTemplate()
	gatewayOnly.Spec.CRD.Spec.Validation = ct.Spec.CRD.Spec.Validation.DeepCopy()
	require.NoError(t, driver.AddTemplate(ctx, gatewayOnly))
	projected(t, driver, constraint)
	policies = listPolicies(t, kube)
	require.Len(t, policies, 1)
	require.Equal(t, gatewayKind, policies[0].GetKind())
}

func TestOutputKindChangeAndFailedReplacementRetainsOldSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ct, constraint := testTemplate(), testConstraint()
	kube := testClient()
	driver := NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, ct))
	projected(t, driver, constraint)
	old := listPolicies(t, kube)[0]
	changed := testTemplate()
	output := outputMap(t, changed, 0)
	output["kind"] = authzKind
	output["namespace"] = "agents"
	output["spec"] = map[string]interface{}{
		"rego": "package agent\n\ndefault allow := false\n",
		"data": map[string]interface{}{"allowedTools": []interface{}{}},
	}
	output["bindings"] = []interface{}{map[string]interface{}{
		"parameter": "allowedTools", "path": []interface{}{"data", "allowedTools"}, "format": "Value",
	}}
	require.NoError(t, driver.AddTemplate(ctx, changed))
	projected(t, driver, constraint)
	policies := listPolicies(t, kube)
	require.Len(t, policies, 1)
	require.Equal(t, authzKind, policies[0].GetKind())
	require.Equal(t, old.GetName(), policies[0].GetName())
	require.Equal(t, "agents", policies[0].GetNamespace())

	// A later failed replacement must not delete the still-valid obsolete set.
	second := outputMap(t, testTemplate(), 0)
	second["key"] = "replacement"
	sourceMap(t, changed)["outputs"] = []interface{}{output, second}
	require.NoError(t, driver.AddTemplate(ctx, changed))
	kube.failKind = gatewayKind
	_, _, err := driver.ReconcileConstraint(ctx, constraint)
	require.ErrorContains(t, err, "obsolete outputs retained")
	policies = listPolicies(t, kube)
	require.Len(t, policies, 1)
	require.Equal(t, authzKind, policies[0].GetKind())
	kube.failKind = ""
	projected(t, driver, constraint)
	require.Len(t, listPolicies(t, kube), 2)
}

type readForbiddenWriter struct {
	client.Client
}

func (readForbiddenWriter) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("writer must not be used for ownership reads")
}

func (readForbiddenWriter) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("writer must not be used for ownership lists")
}

func TestOwnershipUsesExplicitReaderAndPreflightsWholeSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ct, constraint := testTemplate(), testConstraint()
	kube := testClient()
	driver := NewDriver(readForbiddenWriter{Client: kube}, kube)
	require.NoError(t, driver.AddTemplate(ctx, ct))
	projected(t, driver, constraint)
	require.NoError(t, driver.RemoveConstraint(ctx, constraint))
	require.Empty(t, listPolicies(t, kube))

	second := outputMap(t, testTemplate(), 0)
	second["key"] = "second"
	sourceMap(t, ct)["outputs"] = []interface{}{outputMap(t, ct, 0), second}
	desired := outputsForTest(t, ct, constraint)
	foreign := desired[1]
	foreign.SetLabels(nil)
	foreign.SetOwnerReferences(nil)
	foreign.SetAnnotations(nil)
	kube = testClient(foreign)
	driver = NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, ct))
	_, _, err := driver.ReconcileConstraint(ctx, constraint)
	require.ErrorIs(t, err, ErrOwnership)
	require.Zero(t, kube.creates.Load(), "later ownership failure must prevent earlier output creation")
	require.Zero(t, kube.updates.Load())

	invalid := testTemplate()
	outputMap(t, invalid, 0)["key"] = "second"
	bindingMap(t, invalid)["format"] = "Value"
	delete(bindingMap(t, invalid), "variable")
	bindingMap(t, invalid)["path"] = []interface{}{"backend", "mcp", "authorization", "action"}
	sourceMap(t, ct)["outputs"] = []interface{}{outputMap(t, testTemplate(), 0), outputMap(t, invalid, 0)}
	kube = testClient()
	driver = NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, ct))
	_, _, err = driver.ReconcileConstraint(ctx, constraint)
	require.ErrorContains(t, err, "Require")
	require.Zero(t, kube.creates.Load(), "all bound specs must validate before any write")
}

func TestNilInvalidAndCancelledInputs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, driver := range []*Driver{nil, {}, NewDriver(nil, nil), NewDriver(testClient(), nil)} {
		require.Error(t, driver.AddTemplate(ctx, testTemplate()))
		require.Error(t, driver.RemoveTemplate(ctx, testTemplate()))
		require.Error(t, driver.AddConstraint(ctx, testConstraint()))
		require.Error(t, driver.RemoveConstraint(ctx, testConstraint()))
		_, err := driver.Dump(ctx)
		require.Error(t, err)
		_, _, err = driver.ReconcileConstraint(ctx, testConstraint())
		require.Error(t, err)
	}
	driver := NewOfflineDriver()
	require.Error(t, driver.AddTemplate(ctx, nil))
	require.Error(t, driver.RemoveTemplate(ctx, nil))
	require.Error(t, driver.AddConstraint(ctx, nil))
	require.Error(t, driver.RemoveConstraint(ctx, nil))
	require.Error(t, driver.AddData(ctx, TargetName, nil, nil))
	require.Error(t, driver.RemoveData(ctx, "", nil))
	_, _, err := driver.ReconcileConstraint(ctx, nil)
	require.Error(t, err)
	_, err = driver.Query(ctx, TargetName, []*unstructured.Unstructured{nil}, struct{}{})
	require.Error(t, err)
	_, err = driver.Query(ctx, "", nil, struct{}{})
	require.Error(t, err)
	_, err = driver.Query(ctx, TargetName, nil, nil)
	require.Error(t, err)
	_, err = driver.GetDescriptionForStat("")
	require.Error(t, err)
	target := NewTarget(driver)
	require.Error(t, target.ValidateConstraint(nil))
	_, err = target.ToMatcher(nil)
	require.Error(t, err)
	_, _, err = target.HandleReview(nil)
	require.Error(t, err)
	_, _, _, err = target.ProcessData(nil)
	require.Error(t, err)
	require.Error(t, NewTarget(nil).ValidateConstraint(testConstraint()))
	var nilTarget *Target
	require.Error(t, nilTarget.ValidateConstraint(testConstraint()))
	var nilConstraint *unstructured.Unstructured
	_, _, err = target.HandleReview(nilConstraint)
	require.Error(t, err)
	for _, inputCtx := range []context.Context{nil, cancelledContext()} {
		require.Error(t, driver.AddTemplate(inputCtx, testTemplate()))
		require.Error(t, driver.RemoveTemplate(inputCtx, testTemplate()))
		require.Error(t, driver.AddConstraint(inputCtx, testConstraint()))
		require.Error(t, driver.RemoveConstraint(inputCtx, testConstraint()))
		_, _, err := driver.ReconcileConstraint(inputCtx, testConstraint())
		require.Error(t, err)
		_, err = driver.Dump(inputCtx)
		require.Error(t, err)
	}
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestConcurrentDriverAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kube := testClient()
	driver := NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, testTemplate()))
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			constraint := testConstraint()
			constraint.SetName(fmt.Sprintf("tools-%02d", index))
			constraint.SetUID(types.UID(fmt.Sprintf("uid-%02d", index)))
			if err := driver.AddConstraint(ctx, constraint); err != nil {
				errs <- err
				return
			}
			if _, _, err := driver.ReconcileConstraint(ctx, constraint); err != nil {
				errs <- err
				return
			}
			if _, err := driver.Dump(ctx); err != nil {
				errs <- err
				return
			}
			if err := NewTarget(driver).ValidateConstraint(constraint); err != nil {
				errs <- err
				return
			}
			errs <- driver.RemoveConstraint(ctx, constraint)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Empty(t, listPolicies(t, kube))
	driver.mu.RLock()
	require.Empty(t, driver.gates)
	driver.mu.RUnlock()
}

func TestSlowProjectionDoesNotHoldCacheLock(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := make(chan struct{})
	resume := make(chan struct{})
	kube := testClient()
	kube.beforeCreate = func(ctx context.Context, _ client.Object) error {
		close(started)
		select {
		case <-resume:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	driver := NewDriver(kube, kube)
	require.NoError(t, driver.AddTemplate(ctx, testTemplate()))
	finished := make(chan error, 1)
	go func() {
		_, _, err := driver.ReconcileConstraint(ctx, testConstraint())
		finished <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		require.FailNow(t, "projection did not begin")
	}
	dumped := make(chan error, 1)
	go func() {
		_, err := driver.Dump(ctx)
		dumped <- err
	}()
	select {
	case err := <-dumped:
		require.NoError(t, err)
	case <-ctx.Done():
		require.FailNow(t, "Dump blocked on projection I/O")
	}
	otherTemplate := testTemplate()
	otherTemplate.Name = "othertools"
	otherTemplate.Spec.CRD.Spec.Names.Kind = "OtherTools"
	require.NoError(t, driver.AddTemplate(ctx, otherTemplate))
	cancelled, cancelWait := context.WithCancel(ctx)
	waiting := make(chan error, 1)
	go func() { waiting <- driver.RemoveConstraint(cancelled, testConstraint()) }()
	cancelWait()
	require.ErrorIs(t, <-waiting, context.Canceled)
	close(resume)
	require.NoError(t, <-finished)
	require.NoError(t, driver.RemoveConstraint(ctx, testConstraint()))
	require.Empty(t, listPolicies(t, kube))
}

func TestConcurrentCreateCannotBeAdoptedWithoutOwnership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, owned := range []bool{false, true} {
		t.Run(fmt.Sprint(owned), func(t *testing.T) {
			kube := testClient()
			kube.beforeCreate = func(ctx context.Context, object client.Object) error {
				copy := object.DeepCopyObject()
				native, ok := copy.(client.Object)
				if !ok {
					return errors.New("native object does not implement client.Object")
				}
				if !owned {
					native.SetOwnerReferences(nil)
				}
				return kube.Client.Create(ctx, native)
			}
			driver := NewDriver(kube, kube)
			require.NoError(t, driver.AddTemplate(ctx, testTemplate()))
			status, handled, err := driver.ReconcileConstraint(ctx, testConstraint())
			require.True(t, handled)
			if owned {
				require.NoError(t, err)
				require.Equal(t, ProjectionProjected, status.State)
			} else {
				require.ErrorIs(t, err, ErrOwnership)
				require.Equal(t, ProjectionError, status.State)
			}
			require.Zero(t, kube.updates.Load())
			require.Len(t, listPolicies(t, kube), 1)
		})
	}
}

func TestTemplateUpdatePreservesValidCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	driver := NewOfflineDriver()
	ct := testTemplate()
	require.NoError(t, driver.AddTemplate(ctx, ct))
	require.NoError(t, driver.AddConstraint(ctx, testConstraint()))
	before, err := driver.Dump(ctx)
	require.NoError(t, err)
	changed := testTemplate()
	prop := changed.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Properties["allowedTools"]
	prop.Type = "string"
	prop.Items = nil
	changed.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Properties["allowedTools"] = prop
	require.ErrorContains(t, driver.AddTemplate(ctx, changed), "invalidate cached Constraint")
	after, err := driver.Dump(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after)
	// Caller-owned maps must not mutate cached templates or Constraints.
	sourceMap(t, ct)["version"] = "invalid"
	require.NoError(t, NewTarget(driver).ValidateConstraint(testConstraint()))
	constraint := testConstraint()
	require.NoError(t, driver.AddConstraint(ctx, constraint))
	setParameter(t, constraint, "allowedTools", []interface{}{"mutated"})
	after, err = driver.Dump(ctx)
	require.NoError(t, err)
	require.False(t, strings.Contains(after, "mutated"))
}
