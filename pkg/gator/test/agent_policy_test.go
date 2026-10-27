package test

import (
	"testing"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/agentpolicy"
	agentpolicytest "github.com/open-policy-agent/gatekeeper/v3/test/agentpolicy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestAgentPolicyOfflineAuthoring(t *testing.T) {
	template := agentpolicytest.TemplateObject(t, agentpolicytest.Template())
	constraint := agentpolicytest.Constraint()
	responses, err := Test([]*unstructured.Unstructured{template, constraint})
	if err != nil {
		t.Fatalf("offline agent validation: %v", err)
	}
	if _, ok := responses.ByTarget[agentpolicy.TargetName]; ok {
		t.Fatal("gator test fabricated agent review results")
	}
	badTemplate := agentpolicytest.Template()
	badTemplate.Spec.Targets[0].Code[0].Source.Value = map[string]interface{}{"version": "unsupported"}
	if _, err := Test([]*unstructured.Unstructured{agentpolicytest.TemplateObject(t, badTemplate), constraint}); err == nil {
		t.Fatal("gator test accepted invalid agent source")
	}
	badConstraint := constraint.DeepCopy()
	if err := unstructured.SetNestedMap(badConstraint.Object, map[string]interface{}{
		"namespaces": []interface{}{"gateway"},
	}, "spec", "match"); err != nil {
		t.Fatal(err)
	}
	if _, err := Test([]*unstructured.Unstructured{template, badConstraint}); err == nil {
		t.Fatal("gator test accepted a fabricated Kubernetes agent match")
	}
}
