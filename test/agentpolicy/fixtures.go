package agentpolicy

import (
	"encoding/json"
	"testing"

	templatesv1 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/templates/v1"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	constraintKind = "AgentTest"
	kindField      = "kind"
)

func Template() *templates.ConstraintTemplate {
	return &templates.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "agenttest"},
		Spec: templates.ConstraintTemplateSpec{
			CRD: templates.CRD{Spec: templates.CRDSpec{
				Names: templates.Names{Kind: constraintKind},
				Validation: &templates.Validation{OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
					Type: "object",
				}},
			}},
			Targets: []templates.Target{{
				Target: "agent.gatekeeper.sh",
				Code: []templates.Code{{
					Engine: "AgentPolicy",
					Source: &templates.Anything{Value: map[string]interface{}{
						"version": "v1alpha1",
						"outputs": []interface{}{map[string]interface{}{
							"key":       "gateway",
							kindField:   "AgentgatewayPolicy",
							"namespace": "gateway",
							"spec": map[string]interface{}{
								"targetRefs": []interface{}{map[string]interface{}{
									"group":   "gateway.networking.k8s.io",
									kindField: "Gateway",
									"name":    "agentgateway",
								}},
								"traffic": map[string]interface{}{
									"authorization": map[string]interface{}{
										"action": "Require",
										"policy": map[string]interface{}{
											"matchExpressions": []interface{}{"true"},
										},
									},
								},
							},
						}},
					}},
				}},
			}},
		},
	}
}

func Constraint() *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1",
		kindField:    constraintKind,
		"metadata": map[string]interface{}{
			"name":       "agent-policy",
			"uid":        "agent-policy-uid",
			"generation": int64(1),
		},
		"spec": map[string]interface{}{
			"enforcementAction": "deny",
			"parameters":        map[string]interface{}{},
		},
	}}
	obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "constraints.gatekeeper.sh", Version: "v1beta1", Kind: constraintKind})
	return obj
}

func TemplateObject(t testing.TB, template *templates.ConstraintTemplate) *unstructured.Unstructured {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := templatesv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	versioned := &templatesv1.ConstraintTemplate{}
	if err := scheme.Convert(template, versioned, nil); err != nil {
		t.Fatal(err)
	}
	versioned.APIVersion = "templates.gatekeeper.sh/v1"
	versioned.Kind = "ConstraintTemplate"
	raw, err := json.Marshal(versioned)
	if err != nil {
		t.Fatal(err)
	}
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	return obj
}
