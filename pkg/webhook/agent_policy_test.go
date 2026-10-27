package webhook

import (
	"context"
	"testing"

	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers/rego"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/agentpolicy"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	agentpolicytest "github.com/open-policy-agent/gatekeeper/v3/test/agentpolicy"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func agentAdmissionRequest(t *testing.T, obj *unstructured.Unstructured) *admission.Request {
	t.Helper()
	raw, err := obj.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	}}
}

func TestAgentTemplateWebhookValidationAndGate(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			driver, err := rego.New()
			if err != nil {
				t.Fatal(err)
			}
			targets := []handler.TargetHandler{&target.K8sValidationTarget{}}
			opts := []constraintclient.Opt{constraintclient.Driver(driver), constraintclient.EnforcementPoints(util.WebhookEnforcementPoint)}
			if enabled {
				agentDriver := agentpolicy.NewOfflineDriver()
				targets = append(targets, agentpolicy.NewTarget(agentDriver))
				opts = append(opts, constraintclient.Driver(agentDriver))
			}
			cf, err := constraintclient.NewClient(append(opts, constraintclient.Targets(targets...))...)
			if err != nil {
				t.Fatal(err)
			}
			h := validationHandler{opa: cf}
			template := agentpolicytest.Template()
			req := agentAdmissionRequest(t, agentpolicytest.TemplateObject(t, template))
			userErr, err := h.validateTemplate(context.Background(), req)
			if enabled && (err != nil || userErr) {
				t.Fatalf("enabled template validation = %v, %v", userErr, err)
			}
			if !enabled {
				if err == nil || !userErr {
					t.Fatalf("disabled target validation = %v, %v; want rejection", userErr, err)
				}
				return
			}
			if _, err := cf.AddTemplate(context.Background(), template); err != nil {
				t.Fatal(err)
			}
			if userErr, err := h.validateConstraint(agentAdmissionRequest(t, agentpolicytest.Constraint())); userErr || err != nil {
				t.Fatalf("valid agent constraint = %v, %v", userErr, err)
			}
			for _, action := range []string{"dryrun", "warn", "scoped"} {
				constraint := agentpolicytest.Constraint()
				if err := unstructured.SetNestedField(constraint.Object, action, "spec", "enforcementAction"); err != nil {
					t.Fatal(err)
				}
				if userErr, err := h.validateConstraint(agentAdmissionRequest(t, constraint)); !userErr || err == nil {
					t.Fatalf("agent action %q accepted: %v, %v", action, userErr, err)
				}
			}
			template.Spec.Targets[0].Code = nil
			template.Spec.Targets[0].Rego = "package agent"
			req = agentAdmissionRequest(t, agentpolicytest.TemplateObject(t, template))
			if userErr, err := h.validateTemplate(context.Background(), req); !userErr || err == nil {
				t.Fatalf("webhook accepted executable agent source: %v, %v", userErr, err)
			}
		})
	}
}
