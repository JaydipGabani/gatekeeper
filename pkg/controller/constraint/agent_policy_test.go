package constraint

import (
	"context"
	"errors"
	"strings"
	"testing"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	constraintstatusv1beta1 "github.com/open-policy-agent/gatekeeper/v3/apis/status/v1beta1"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/agentpolicy"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	agentpolicytest "github.com/open-policy-agent/gatekeeper/v3/test/agentpolicy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type fakeAgentProjector struct {
	calls   int
	status  agentpolicy.ProjectionStatus
	handled bool
	err     error
}

func (f *fakeAgentProjector) ReconcileConstraint(context.Context, *unstructured.Unstructured) (agentpolicy.ProjectionStatus, bool, error) {
	f.calls++
	return f.status, f.handled, f.err
}

func (*fakeAgentProjector) WatchObjects() []client.Object {
	return agentpolicy.NewOfflineDriver().WatchObjects()
}

func agentConstraintStatus(t *testing.T, reader *fakeReader, instance *unstructured.Unstructured) *constraintstatusv1beta1.ConstraintPodStatus {
	t.Helper()
	name, err := constraintstatusv1beta1.KeyForConstraint("test-pod", instance)
	if err != nil {
		t.Fatal(err)
	}
	status, ok := reader.objects[types.NamespacedName{Name: name, Namespace: util.GetNamespace()}].(*constraintstatusv1beta1.ConstraintPodStatus)
	if !ok {
		t.Fatal("constraint pod status not stored")
	}
	return status
}

func TestReconcileAgentProjectionStatesForCachedConstraint(t *testing.T) {
	configureVAP(t, vapTestConfig{defaultGenerateVAPB: ptr.To(false)})
	instance := makeUnitConstraint()
	r, reader, writer, request := newConstraintUnitReconciler(t, makeUnitCELTemplate(), instance)
	projector := &fakeAgentProjector{handled: true}
	r.agentProjector = projector

	apiErr := errors.New("native policy API unavailable")
	for _, tc := range []struct {
		state   string
		message string
		err     error
	}{
		{state: agentpolicy.ProjectionPending, message: "waiting for authoring handoff"},
		{state: agentpolicy.ProjectionError, err: apiErr},
		{state: agentpolicy.ProjectionProjected, message: "native resources written; activation is external"},
	} {
		projector.status = agentpolicy.ProjectionStatus{State: tc.state, Message: tc.message}
		projector.err = tc.err
		result, err := r.Reconcile(context.Background(), request)
		if !errors.Is(err, tc.err) {
			t.Fatalf("Reconcile(%s) error = %v, want %v", tc.state, err, tc.err)
		}
		if tc.state == agentpolicy.ProjectionPending && result.RequeueAfter == 0 {
			t.Fatal("pending projection must be retried")
		}
		status := agentConstraintStatus(t, reader, instance)
		if !status.Status.Enforced {
			t.Fatal("legacy Enforced cache-acceptance bit was cleared")
		}
		if len(status.Status.EnforcementPointsStatus) != 1 {
			t.Fatalf("enforcement points = %#v, want only agent", status.Status.EnforcementPointsStatus)
		}
		ep := status.Status.EnforcementPointsStatus[0]
		if ep.EnforcementPoint != agentpolicy.EnforcementPoint || ep.State != tc.state || ep.ObservedGeneration != instance.GetGeneration() {
			t.Fatalf("agent status = %#v, want %s", ep, tc.state)
		}
		if tc.err == nil && ep.Message != tc.message {
			t.Fatalf("status message = %q, want %q", ep.Message, tc.message)
		}
	}
	writes := writer.updateAttempts
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if writer.updateAttempts != writes || projector.calls != 4 {
		t.Fatalf("stable cached reconciliation wrote status or skipped projection: writes=%d, calls=%d", writer.updateAttempts, projector.calls)
	}
	projector.handled = false
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if got := agentConstraintStatus(t, reader, instance).Status.EnforcementPointsStatus; len(got) != 0 {
		t.Fatalf("unhandled constraint retained agent status: %#v", got)
	}
}

func TestReconcilePreservesIndependentProjectionAndVAPFailures(t *testing.T) {
	for _, failStatus := range []bool{false, true} {
		t.Run(map[bool]string{false: "status written", true: "status write failed"}[failStatus], func(t *testing.T) {
			configureVAP(t, vapTestConfig{
				apiEnabled:          ptr.To(true),
				defaultGenerateVAP:  ptr.To(true),
				defaultGenerateVAPB: ptr.To(true),
			})
			instance := makeUnitConstraint()
			r, reader, writer, request := newConstraintUnitReconciler(t, makeUnitCELTemplate(), instance)
			runtimeErr := errors.New("runtime API unavailable")
			agentErr := errors.New("agent API unavailable")
			statusErr := errors.New("status API unavailable")
			r.runtimeProjector = &fakeRuntimeProjector{err: runtimeErr}
			r.agentProjector = &fakeAgentProjector{handled: true, err: agentErr}
			if failStatus {
				writer.updateErr = statusErr
			}
			_, err := r.Reconcile(context.Background(), request)
			if !errors.Is(err, runtimeErr) || !errors.Is(err, agentErr) || !strings.Contains(err.Error(), "annotation to wait for ValidatingAdmissionPolicyBinding generation not found") {
				t.Fatalf("independent reconciliation errors were lost: %v", err)
			}
			if failStatus {
				if !errors.Is(err, statusErr) {
					t.Fatalf("status failure was lost: %v", err)
				}
				return
			}
			status := agentConstraintStatus(t, reader, instance)
			if len(status.Status.Errors) != 3 {
				t.Fatalf("status errors = %v, want runtime, agent and VAP failures", status.Status.Errors)
			}
		})
	}
}

func TestReconcilePreservesAgentStatusOnTemplateReadFailure(t *testing.T) {
	configureVAP(t, vapTestConfig{defaultGenerateVAPB: ptr.To(false)})
	ct := makeUnitCELTemplate()
	instance := makeUnitConstraint()
	r, reader, _, request := newConstraintUnitReconciler(t, ct, instance)
	r.agentProjector = &fakeAgentProjector{
		handled: true,
		status:  agentpolicy.ProjectionStatus{State: agentpolicy.ProjectionProjected},
	}
	readErr := errors.New("template API unavailable")
	reader.getErrs[types.NamespacedName{Name: ct.GetName()}] = readErr
	if _, err := r.Reconcile(context.Background(), request); !errors.Is(err, readErr) {
		t.Fatalf("Reconcile() error = %v, want %v", err, readErr)
	}
	status := agentConstraintStatus(t, reader, instance)
	if len(status.Status.EnforcementPointsStatus) != 1 || status.Status.EnforcementPointsStatus[0].State != agentpolicy.ProjectionProjected {
		t.Fatalf("independent projection status was lost: %#v", status.Status)
	}
}

func TestReconcilePreservesTemplateReadAndStatusFailures(t *testing.T) {
	configureVAP(t, vapTestConfig{defaultGenerateVAPB: ptr.To(false)})
	ct := makeUnitCELTemplate()
	instance := makeUnitConstraint()
	r, reader, writer, request := newConstraintUnitReconciler(t, ct, instance)
	r.agentProjector = &fakeAgentProjector{
		handled: true,
		status:  agentpolicy.ProjectionStatus{State: agentpolicy.ProjectionProjected},
	}
	readErr := errors.New("template API unavailable")
	statusErr := errors.New("status API unavailable")
	reader.getErrs[types.NamespacedName{Name: ct.GetName()}] = readErr
	writer.updateErr = statusErr
	if _, err := r.Reconcile(context.Background(), request); !errors.Is(err, readErr) || !errors.Is(err, statusErr) {
		t.Fatalf("independent template read and status failures were lost: %v", err)
	}
}

func TestAgentPolicyChildrenRequeueOwningConstraint(t *testing.T) {
	objects := agentpolicy.NewOfflineDriver().WatchObjects()
	if len(objects) != 2 {
		t.Fatalf("watch objects = %d, want both native policy kinds", len(objects))
	}
	instance := makeUnitConstraint()
	for _, obj := range objects {
		t.Run(obj.GetObjectKind().GroupVersionKind().Kind, func(t *testing.T) {
			obj.SetNamespace("gateway")
			obj.SetOwnerReferences([]metav1.OwnerReference{{
				APIVersion: instance.GetAPIVersion(),
				Kind:       instance.GetKind(),
				Name:       instance.GetName(),
				UID:        instance.GetUID(),
				Controller: ptr.To(true),
			}})
			requests := eventPackerMapFuncFromOwnerRefs()(context.Background(), obj)
			if len(requests) != 1 {
				t.Fatalf("mapped requests = %v, want one", requests)
			}
			gvk, request, err := util.UnpackRequest(requests[0])
			if err != nil || gvk != instance.GroupVersionKind() || request != (reconcile.Request{NamespacedName: types.NamespacedName{Name: instance.GetName()}}) {
				t.Fatalf("unpacked owner = %v %v %v", gvk, request, err)
			}
		})
	}
}

type agentProjectionClient struct {
	client.Client
	createErr error
	deleteErr error
}

func (c *agentProjectionClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if c.createErr != nil {
		return c.createErr
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *agentProjectionClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if c.deleteErr != nil {
		return c.deleteErr
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func TestReconcileAgentPolicyProjectionLifecycle(t *testing.T) {
	configureVAP(t, vapTestConfig{
		apiEnabled:          ptr.To(true),
		defaultGenerateVAP:  ptr.To(true),
		defaultGenerateVAPB: ptr.To(true),
	})
	ctx := context.Background()
	ct := agentpolicytest.Template()
	instance := agentpolicytest.Constraint()
	r, reader, _, request := newConstraintUnitReconciler(t, ct, instance)
	apiErr := errors.New("native API unavailable")
	nativeClient := &agentProjectionClient{
		Client:    clientfake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build(),
		createErr: apiErr,
	}
	driver := agentpolicy.NewDriver(nativeClient, nativeClient)
	cf, err := constraintclient.NewClient(
		constraintclient.Targets(agentpolicy.NewTarget(driver)),
		constraintclient.Driver(driver),
		constraintclient.EnforcementPoints(util.WebhookEnforcementPoint),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cf.AddTemplate(ctx, ct); err != nil {
		t.Fatal(err)
	}
	r.cfClient = cf
	r.agentProjector = driver
	if _, err := r.Reconcile(ctx, request); !errors.Is(err, apiErr) {
		t.Fatalf("projection API failure was swallowed: %v", err)
	}
	if _, err := cf.GetConstraint(instance); err != nil {
		t.Fatalf("Constraint was not cached before failed projection: %v", err)
	}
	status := agentConstraintStatus(t, reader, instance)
	if len(status.Status.EnforcementPointsStatus) != 1 || status.Status.EnforcementPointsStatus[0].State != agentpolicy.ProjectionError {
		t.Fatalf("failed projection status = %#v", status.Status)
	}

	nativeClient.createErr = nil
	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatalf("cached Constraint did not recover: %v", err)
	}
	status = agentConstraintStatus(t, reader, instance)
	if !status.Status.Enforced || len(status.Status.Errors) != 0 || len(status.Status.EnforcementPointsStatus) != 1 {
		t.Fatalf("agent-only Constraint reported a VAP or cache error: %#v", status.Status)
	}
	if ep := status.Status.EnforcementPointsStatus[0]; ep.EnforcementPoint != agentpolicy.EnforcementPoint || ep.State != agentpolicy.ProjectionProjected {
		t.Fatalf("authoring handoff status = %#v, want agent Projected, not native active", ep)
	}

	var policy *unstructured.Unstructured
	for _, obj := range driver.WatchObjects() {
		if obj.GetObjectKind().GroupVersionKind().Kind == "AgentgatewayPolicy" {
			policy = &unstructured.Unstructured{}
			policy.SetGroupVersionKind(obj.GetObjectKind().GroupVersionKind())
		}
	}
	if policy == nil {
		t.Fatal("AgentgatewayPolicy child watch missing")
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(policy.GroupVersionKind().GroupVersion().WithKind(policy.GetKind() + "List"))
	if err := nativeClient.List(ctx, list); err != nil || len(list.Items) != 1 {
		t.Fatalf("projected policies = %v, error = %v", list.Items, err)
	}
	policy = list.Items[0].DeepCopy()
	key := client.ObjectKeyFromObject(policy)
	if err := unstructured.SetNestedStringSlice(policy.Object, []string{"false"}, "spec", "traffic", "authorization", "policy", "matchExpressions"); err != nil {
		t.Fatal(err)
	}
	if err := nativeClient.Update(ctx, policy); err != nil {
		t.Fatal(err)
	}
	requests := eventPackerMapFuncFromOwnerRefs()(ctx, policy)
	if len(requests) != 1 || requests[0] != request {
		t.Fatalf("native child event did not map to its Constraint: %v", requests)
	}
	if _, err := r.Reconcile(ctx, requests[0]); err != nil {
		t.Fatal(err)
	}
	if err := nativeClient.Get(ctx, key, policy); err != nil {
		t.Fatal(err)
	}
	expressions, _, err := unstructured.NestedStringSlice(policy.Object, "spec", "traffic", "authorization", "policy", "matchExpressions")
	if err != nil || len(expressions) != 1 || expressions[0] != "true" {
		t.Fatalf("output drift was not repaired: expressions=%v, err=%v", expressions, err)
	}
	if err := nativeClient.Delete(ctx, policy); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := nativeClient.Get(ctx, key, policy); err != nil {
		t.Fatalf("deleted native child was not recreated: %v", err)
	}

	delete(reader.objects, client.ObjectKeyFromObject(instance))
	nativeClient.deleteErr = apiErr
	if _, err := r.Reconcile(ctx, request); !errors.Is(err, apiErr) {
		t.Fatalf("driver RemoveConstraint failure was swallowed: %v", err)
	}
	if _, err := cf.GetConstraint(instance); err != nil {
		t.Fatalf("failed cleanup prematurely evicted Constraint: %v", err)
	}
	nativeClient.deleteErr = nil
	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if err := nativeClient.Get(ctx, key, policy); !apierrors.IsNotFound(err) {
		t.Fatalf("owned policy remains after Constraint removal: %v", err)
	}
	if _, err := cf.GetConstraint(instance); !errors.Is(err, constraintclient.ErrMissingConstraint) {
		t.Fatalf("Constraint cache remains after cleanup: %v", err)
	}
}
