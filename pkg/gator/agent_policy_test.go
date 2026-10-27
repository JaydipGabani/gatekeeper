package gator

import (
	"context"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/agentpolicy"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/target"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	agentpolicytest "github.com/open-policy-agent/gatekeeper/v3/test/agentpolicy"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestNewOPAClientValidatesAgentPolicyOfflineWithoutReviewing(t *testing.T) {
	for _, cel := range []bool{false, true} {
		t.Run(map[bool]string{false: "Rego", true: "Rego and CEL"}[cel], func(t *testing.T) {
			var opts []Opt
			if cel {
				opts = append(opts, WithK8sCEL())
			}
			client, err := NewOPAClient(false, opts...)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if _, err := client.AddTemplate(ctx, agentpolicytest.Template()); err != nil {
				t.Fatalf("offline AddTemplate: %v", err)
			}
			if _, err := client.AddConstraint(ctx, agentpolicytest.Constraint()); err != nil {
				t.Fatalf("offline AddConstraint: %v", err)
			}
			responses, err := client.Review(ctx, &target.AugmentedReview{AdmissionRequest: &admissionv1.AdmissionRequest{}}, reviews.EnforcementPoint(util.GatorEnforcementPoint))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := responses.ByTarget[agentpolicy.TargetName]; ok {
				t.Fatal("offline validation produced an agent admission review")
			}

			badTemplate := agentpolicytest.Template()
			badTemplate.Spec.Targets[0].Code = nil
			badTemplate.Spec.Targets[0].Rego = "package agent\nviolation contains {\"msg\": \"deny\"} if { true }"
			if _, err := client.AddTemplate(ctx, badTemplate); err == nil {
				t.Fatal("Gator accepted executable agent source")
			}
			badConstraint := agentpolicytest.Constraint()
			if err := unstructured.SetNestedField(badConstraint.Object, "dryrun", "spec", "enforcementAction"); err != nil {
				t.Fatal(err)
			}
			if _, err := client.AddConstraint(ctx, badConstraint); err == nil {
				t.Fatal("Gator accepted unsupported agent enforcement action")
			}
		})
	}
}
