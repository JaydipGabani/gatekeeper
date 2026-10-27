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
	"fmt"
	"strings"
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/stretchr/testify/require"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func testTemplate() *templates.ConstraintTemplate {
	return &templates.ConstraintTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "agenttools", UID: types.UID("template-uid")},
		Spec: templates.ConstraintTemplateSpec{
			CRD: templates.CRD{Spec: templates.CRDSpec{
				Names: templates.Names{Kind: "AgentTools"},
				Validation: &templates.Validation{OpenAPIV3Schema: &apiextensions.JSONSchemaProps{
					Type: "object", Required: []string{"allowedTools"},
					Properties: map[string]apiextensions.JSONSchemaProps{
						"allowedTools": {
							Type: "array", Items: &apiextensions.JSONSchemaPropsOrArray{Schema: &apiextensions.JSONSchemaProps{Type: "string"}},
						},
					},
				}},
			}},
			Targets: []templates.Target{{
				Target: TargetName, Code: []templates.Code{{
					Engine: EngineName, Source: &templates.Anything{Value: map[string]interface{}{
						"version": SourceVersion,
						"outputs": []interface{}{map[string]interface{}{
							"key": "tools", "kind": gatewayKind, "namespace": "default",
							"spec": map[string]interface{}{
								"targetRefs": []interface{}{map[string]interface{}{
									"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "agent",
								}},
								"backend": map[string]interface{}{"mcp": map[string]interface{}{"authorization": map[string]interface{}{
									"action": "Require", "policy": map[string]interface{}{"matchExpressions": []interface{}{}},
								}}},
							},
							"bindings": []interface{}{map[string]interface{}{
								"parameter": "allowedTools",
								"path":      []interface{}{"backend", "mcp", "authorization", "policy", "matchExpressions"},
								"format":    "CELStringList", "variable": "mcp.tool.name",
							}},
						}},
					}},
				}},
			}},
		},
	}
}

func testConstraint() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "constraints.gatekeeper.sh/v1beta1", "kind": "AgentTools",
		"metadata": map[string]interface{}{"name": "tools", "uid": "source-uid", "generation": int64(1)},
		"spec": map[string]interface{}{
			"enforcementAction": "deny", "match": map[string]interface{}{},
			"parameters": map[string]interface{}{"allowedTools": []interface{}{"read"}},
		},
	}}
}

func sourceMap(t *testing.T, ct *templates.ConstraintTemplate) map[string]interface{} {
	t.Helper()
	value, ok := ct.Spec.Targets[0].Code[0].Source.Value.(map[string]interface{})
	require.True(t, ok)
	return value
}

func outputMap(t *testing.T, ct *templates.ConstraintTemplate, index int) map[string]interface{} {
	t.Helper()
	outputs, ok := sourceMap(t, ct)["outputs"].([]interface{})
	require.True(t, ok)
	output, ok := outputs[index].(map[string]interface{})
	require.True(t, ok)
	return output
}

func bindingMap(t *testing.T, ct *templates.ConstraintTemplate) map[string]interface{} {
	t.Helper()
	bindings, ok := outputMap(t, ct, 0)["bindings"].([]interface{})
	require.True(t, ok)
	bind, ok := bindings[0].(map[string]interface{})
	require.True(t, ok)
	return bind
}

func setParameter(t *testing.T, constraint *unstructured.Unstructured, name string, value interface{}) {
	t.Helper()
	require.NoError(t, unstructured.SetNestedField(constraint.Object, value, "spec", "parameters", name))
}

func compileForTest(t *testing.T, ct *templates.ConstraintTemplate) *compiledTemplate {
	t.Helper()
	compiled, handled, err := compileTemplate(ct)
	require.NoError(t, err)
	require.True(t, handled)
	return compiled
}

func outputsForTest(t *testing.T, ct *templates.ConstraintTemplate, constraint *unstructured.Unstructured) []*unstructured.Unstructured {
	t.Helper()
	normalized, err := constraintIdentity(constraint)
	require.NoError(t, err)
	outputs, err := buildOutputs(compileForTest(t, ct), normalized)
	require.NoError(t, err)
	return outputs
}

func temporalTemplate(t *testing.T) *templates.ConstraintTemplate {
	t.Helper()
	ct := testTemplate()
	ct.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Properties["settings"] = apiextensions.JSONSchemaProps{
		Type: "object", Properties: map[string]apiextensions.JSONSchemaProps{
			"count": {Type: "integer"}, "enabled": {Type: "boolean"},
		},
	}
	sourceMap(t, ct)["outputs"] = []interface{}{map[string]interface{}{
		"key": "temporal", "kind": authzKind, "namespace": "default",
		"spec": map[string]interface{}{
			"rego": "package agent\n\ndefault allow := false\nallow if { input.tool == \"read\" }\n",
			"data": map[string]interface{}{"settings": map[string]interface{}{}},
		},
		"bindings": []interface{}{map[string]interface{}{
			"parameter": "settings", "path": []interface{}{"data", "settings"},
		}},
	}}
	return ct
}

func TestTemplateStrictSource(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*templates.ConstraintTemplate)
	}{
		{"multiple targets", func(ct *templates.ConstraintTemplate) {
			ct.Spec.Targets = append(ct.Spec.Targets, templates.Target{Target: "admission.k8s.gatekeeper.sh"})
		}},
		{"duplicate target", func(ct *templates.ConstraintTemplate) { ct.Spec.Targets = append(ct.Spec.Targets, ct.Spec.Targets[0]) }},
		{"rego", func(ct *templates.ConstraintTemplate) { ct.Spec.Targets[0].Rego = "package agent" }},
		{"libraries", func(ct *templates.ConstraintTemplate) { ct.Spec.Targets[0].Libs = []string{"package helper"} }},
		{"wrong engine", func(ct *templates.ConstraintTemplate) { ct.Spec.Targets[0].Code[0].Engine = "Rego" }},
		{"multiple engines", func(ct *templates.ConstraintTemplate) {
			ct.Spec.Targets[0].Code = append(ct.Spec.Targets[0].Code, ct.Spec.Targets[0].Code[0])
		}},
		{"missing source", func(ct *templates.ConstraintTemplate) { ct.Spec.Targets[0].Code[0].Source = nil }},
		{"null source", func(ct *templates.ConstraintTemplate) { ct.Spec.Targets[0].Code[0].Source.Value = nil }},
		{"source array", func(ct *templates.ConstraintTemplate) { ct.Spec.Targets[0].Code[0].Source.Value = []interface{}{} }},
		{"unknown source field", func(ct *templates.ConstraintTemplate) { sourceMap(t, ct)["metadata"] = map[string]interface{}{} }},
		{"source case mismatch", func(ct *templates.ConstraintTemplate) { sourceMap(t, ct)["Version"] = SourceVersion }},
		{"source unsupported version", func(ct *templates.ConstraintTemplate) { sourceMap(t, ct)["version"] = "v2" }},
		{"missing version", func(ct *templates.ConstraintTemplate) { delete(sourceMap(t, ct), "version") }},
		{"null outputs", func(ct *templates.ConstraintTemplate) { sourceMap(t, ct)["outputs"] = nil }},
		{"empty outputs", func(ct *templates.ConstraintTemplate) { sourceMap(t, ct)["outputs"] = []interface{}{} }},
		{"null output", func(ct *templates.ConstraintTemplate) { sourceMap(t, ct)["outputs"] = []interface{}{nil} }},
		{"arbitrary apiVersion", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["apiVersion"] = "v1" }},
		{"output metadata", func(ct *templates.ConstraintTemplate) {
			outputMap(t, ct, 0)["metadata"] = map[string]interface{}{"name": "chosen"}
		}},
		{"output name", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["name"] = "chosen" }},
		{"secret kind", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["kind"] = "Secret" }},
		{"pod kind", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["kind"] = "Pod" }},
		{"kind case mismatch", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["kind"] = "AgentGatewayPolicy" }},
		{"invalid slot", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["key"] = "../tools" }},
		{"slot length", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["key"] = strings.Repeat("a", 64) }},
		{"null spec", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["spec"] = nil }},
		{"empty spec", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["spec"] = map[string]interface{}{} }},
		{"native metadata envelope", func(ct *templates.ConstraintTemplate) {
			require.NoError(t, unstructured.SetNestedField(outputMap(t, ct, 0), "escape", "spec", "metadata"))
		}},
		{"unknown binding field", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["expression"] = "true" }},
		{"undeclared parameter", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["parameter"] = "undeclared" }},
		{"binding empty path", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["path"] = []interface{}{} }},
		{"binding null path", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["path"] = nil }},
		{"binding integer path", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["path"] = []interface{}{int64(0)} }},
		{"binding absent leaf", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["path"] = []interface{}{"doesNotExist"} }},
		{"binding array traversal", func(ct *templates.ConstraintTemplate) {
			bindingMap(t, ct)["path"] = []interface{}{"targetRefs", "0", "name"}
		}},
		{"binding unsupported format", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["format"] = "Template" }},
		{"binding empty format", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["format"] = "" }},
		{"binding format null", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["format"] = nil }},
		{"binding unsafe variable", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["variable"] = `mcp.tool.name) || true || (` }},
		{"binding missing variable", func(ct *templates.ConstraintTemplate) { delete(bindingMap(t, ct), "variable") }},
		{"value binding variable", func(ct *templates.ConstraintTemplate) { bindingMap(t, ct)["format"] = "Value" }},
		{"null bindings", func(ct *templates.ConstraintTemplate) { outputMap(t, ct, 0)["bindings"] = nil }},
		{"binding duplicate", func(ct *templates.ConstraintTemplate) {
			outputMap(t, ct, 0)["bindings"] = []interface{}{bindingMap(t, ct), bindingMap(t, ct)}
		}},
		{"binding ancestor overlap", func(ct *templates.ConstraintTemplate) {
			outputMap(t, ct, 0)["bindings"] = []interface{}{bindingMap(t, ct), map[string]interface{}{
				"parameter": "allowedTools", "path": []interface{}{"backend"},
			}}
		}},
		{"missing parameter schema", func(ct *templates.ConstraintTemplate) { ct.Spec.CRD.Spec.Validation = nil }},
		{"wrong parameter schema type", func(ct *templates.ConstraintTemplate) { ct.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Type = "array" }},
		{"wrong parameter property type", func(ct *templates.ConstraintTemplate) {
			ct.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Properties["allowedTools"] = apiextensions.JSONSchemaProps{Type: "invalid"}
		}},
		{"wrong template name", func(ct *templates.ConstraintTemplate) { ct.Name = "different" }},
		{"namespaced template", func(ct *templates.ConstraintTemplate) { ct.Namespace = "default" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ct := testTemplate()
			test.mutate(ct)
			handled, err := ValidateTemplate(ct)
			require.True(t, handled)
			require.Error(t, err)
		})
	}
	handled, err := ValidateTemplate(nil)
	require.False(t, handled)
	require.ErrorIs(t, err, ErrInvalidTemplate)
	require.False(t, IsAgentTemplate(nil))
	unrelated := testTemplate()
	unrelated.Spec.Targets[0].Target = "admission.k8s.gatekeeper.sh"
	handled, err = ValidateTemplate(unrelated)
	require.False(t, handled)
	require.NoError(t, err)
}

func TestSourceOutputAndNamespaceBoundaries(t *testing.T) {
	t.Parallel()
	for _, size := range []int{1, maxOutputs, maxOutputs + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			ct := testTemplate()
			outputs := make([]interface{}, size)
			for i := range outputs {
				output := outputMap(t, testTemplate(), 0)
				output["key"] = fmt.Sprintf("tools-%d", i)
				outputs[i] = output
			}
			sourceMap(t, ct)["outputs"] = outputs
			_, err := ValidateTemplate(ct)
			if size <= maxOutputs {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
	ct := testTemplate()
	sourceMap(t, ct)["outputs"] = []interface{}{outputMap(t, ct, 0), outputMap(t, testTemplate(), 0)}
	_, err := ValidateTemplate(ct)
	require.ErrorContains(t, err, "duplicate output key")
	for _, namespace := range []string{"", "UPPER", "a.b", "../default", strings.Repeat("a", 64), "kube-system", "kube-public", "kube-node-lease", "gatekeeper-system", "agentgateway-system", "istio-system", "cert-manager", "flux-system", "argocd"} {
		t.Run(namespace, func(t *testing.T) {
			ct := testTemplate()
			outputMap(t, ct, 0)["namespace"] = namespace
			_, err := ValidateTemplate(ct)
			require.Error(t, err)
		})
	}
	for _, namespace := range []string{"default", "agents", strings.Repeat("a", 63)} {
		ct := testTemplate()
		outputMap(t, ct, 0)["namespace"] = namespace
		_, err := ValidateTemplate(ct)
		require.NoError(t, err)
	}
}

func TestNativeAuthorizationRequiresIntersection(t *testing.T) {
	t.Parallel()
	for _, path := range [][]string{{"traffic", "authorization"}, {"backend", "mcp", "authorization"}} {
		for _, action := range []interface{}{"Require", "Allow", "Deny", "", nil, int64(1)} {
			t.Run(fmt.Sprint(path, action), func(t *testing.T) {
				ct := testTemplate()
				output := outputMap(t, ct, 0)
				delete(output, "bindings")
				spec := map[string]interface{}{}
				require.NoError(t, unstructured.SetNestedField(spec, map[string]interface{}{"action": action}, path...))
				output["spec"] = spec
				_, err := ValidateTemplate(ct)
				if action == "Require" {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, "Require")
				}
			})
		}
	}
	ct := testTemplate()
	ct.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Properties["action"] = apiextensions.JSONSchemaProps{Type: "string"}
	outputMap(t, ct, 0)["bindings"] = []interface{}{map[string]interface{}{
		"parameter": "action", "path": []interface{}{"backend", "mcp", "authorization", "action"},
	}}
	constraint := testConstraint()
	setParameter(t, constraint, "action", "Deny")
	_, err := buildOutputs(compileForTest(t, ct), constraint)
	require.ErrorContains(t, err, "Require")
	for _, attachment := range []string{"extAuth", "extProc"} {
		ct := testTemplate()
		output := outputMap(t, ct, 0)
		delete(output, "bindings")
		output["spec"] = map[string]interface{}{
			"traffic": map[string]interface{}{attachment: map[string]interface{}{"backendRef": map[string]interface{}{"name": "pdp", "port": int64(9000)}}},
		}
		_, err := ValidateTemplate(ct)
		require.NoError(t, err)
	}
}

func TestTypedBindingsAndVerbatimModules(t *testing.T) {
	t.Parallel()
	ct := temporalTemplate(t)
	constraint := testConstraint()
	settings := map[string]interface{}{"count": int64(7), "enabled": true}
	setParameter(t, constraint, "settings", settings)
	outputs := outputsForTest(t, ct, constraint)
	require.Len(t, outputs, 1)
	require.Equal(t, authzAPIVersion, outputs[0].GetAPIVersion())
	actual, found, err := unstructured.NestedFieldNoCopy(outputs[0].Object, "spec", "data", "settings")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, settings, actual)
	count, found, err := unstructured.NestedInt64(outputs[0].Object, "spec", "data", "settings", "count")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, int64(7), count)
	rego, found, err := unstructured.NestedString(outputs[0].Object, "spec", "rego")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "package agent\n\ndefault allow := false\nallow if { input.tool == \"read\" }\n", rego)
	outputMap(t, ct, 0)["bindings"] = []interface{}{map[string]interface{}{"parameter": "settings", "path": []interface{}{"rego"}}}
	_, err = ValidateTemplate(ct)
	require.ErrorContains(t, err, "spec.data")

	for _, format := range []interface{}{"Value", nil} {
		ct := testTemplate()
		ct.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Properties["targets"] = apiextensions.JSONSchemaProps{
			Type: "array", Items: &apiextensions.JSONSchemaPropsOrArray{Schema: &apiextensions.JSONSchemaProps{
				Type: "object", Properties: map[string]apiextensions.JSONSchemaProps{
					"group": {Type: "string"}, "kind": {Type: "string"}, "name": {Type: "string"},
				},
			}},
		}
		bind := map[string]interface{}{"parameter": "targets", "path": []interface{}{"targetRefs"}}
		if format != nil {
			bind["format"] = format
		}
		outputMap(t, ct, 0)["bindings"] = []interface{}{bind}
		targets := []interface{}{map[string]interface{}{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "different"}}
		constraint := testConstraint()
		setParameter(t, constraint, "targets", targets)
		outputs := outputsForTest(t, ct, constraint)
		actual, _, err := unstructured.NestedSlice(outputs[0].Object, "spec", "targetRefs")
		require.NoError(t, err)
		require.Equal(t, targets, actual)
		require.NoError(t, unstructured.SetNestedField(outputs[0].Object, "changed", "spec", "backend"))
		require.NotEqual(t, outputs[0].Object["spec"], outputMap(t, ct, 0)["spec"], "projection must not mutate source")
	}
}

func TestCELStringListEscapingAndBounds(t *testing.T) {
	t.Parallel()
	bind := binding{parameter: "tools", format: "CELStringList", variable: "mcp.tool.name"}
	values := []interface{}{`read" || true || "`, "new\nline", `back\slash`, "snowman ☃", "\u2028", "<script>"}
	actual, err := bindValue(bind, map[string]interface{}{"tools": values})
	require.NoError(t, err)
	require.Equal(t, []interface{}{`mcp.tool.name in ["read\" || true || \"","new\nline","back\\slash","snowman ☃","\u2028","\u003cscript\u003e"]`}, actual)
	actual, err = bindValue(bind, map[string]interface{}{"tools": []interface{}{}})
	require.NoError(t, err)
	require.Equal(t, []interface{}{`mcp.tool.name in []`}, actual)

	for _, input := range []interface{}{nil, "read", []interface{}{int64(1)}, []interface{}{"read", true}, []interface{}{strings.Repeat("x", maxStringListItemBytes+1)}, []interface{}{strings.Repeat("☃", 86)}, []interface{}{string([]byte{0xff})}} {
		_, err := bindValue(bind, map[string]interface{}{"tools": input})
		require.Error(t, err)
	}

	for _, count := range []int{maxStringListItems, maxStringListItems + 1} {
		values := make([]interface{}, count)
		for i := range values {
			values[i] = "read"
		}
		_, err := bindValue(bind, map[string]interface{}{"tools": values})
		if count == maxStringListItems {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
	_, err = bindValue(bind, map[string]interface{}{"tools": []interface{}{strings.Repeat("x", maxStringListItemBytes)}})
	require.NoError(t, err)
	for _, length := range []int{maxCELExpressionBytes - 1, maxCELExpressionBytes, maxCELExpressionBytes + 1} {
		values := make([]interface{}, 64)
		remaining := length - len("mcp.tool.name in ") - (3*len(values) + 1)
		for i := range values {
			n := min(maxStringListItemBytes, remaining)
			values[i] = strings.Repeat("x", n)
			remaining -= n
		}
		require.Zero(t, remaining)
		actual, err := bindValue(bind, map[string]interface{}{"tools": values})
		if length > maxCELExpressionBytes {
			require.ErrorContains(t, err, "expression exceeds")
		} else {
			require.NoError(t, err)
			array, ok := actual.([]interface{})
			require.True(t, ok)
			expression, ok := array[0].(string)
			require.True(t, ok)
			require.Len(t, expression, length)
		}
	}
}

func TestValueBindingPreservesJSONTypes(t *testing.T) {
	t.Parallel()
	for _, value := range []interface{}{
		nil, false, true, int64(42), float64(4.5), "text\n\"quoted\"",
		[]interface{}{}, []interface{}{int64(1), true, nil, "a"},
		map[string]interface{}{"list": []interface{}{false}, "integer": int64(7), "null": nil},
	} {
		actual, err := bindValue(binding{parameter: "value", format: "Value"}, map[string]interface{}{"value": value})
		require.NoError(t, err)
		require.Equal(t, value, actual)
	}
	_, err := bindValue(binding{parameter: "missing", format: "Value"}, map[string]interface{}{})
	require.Error(t, err)
}

func TestSourcePublicAPIRejectsInvalidJSONWithoutPanics(t *testing.T) {
	t.Parallel()
	ct := testTemplate()
	bindingMap(t, ct)["path"] = []string{"backend", "mcp", "authorization", "policy", "matchExpressions"}
	_, err := ValidateTemplate(ct)
	require.NoError(t, err)
	driver := NewOfflineDriver()
	require.NoError(t, driver.AddTemplate(context.Background(), ct))
	require.NoError(t, driver.AddConstraint(context.Background(), testConstraint()))
	for _, value := range []interface{}{func() {}, make(chan int), string([]byte{0xff})} {
		ct := testTemplate()
		sourceMap(t, ct)["invalid"] = value
		_, err := ValidateTemplate(ct)
		require.Error(t, err)
		require.NoError(t, driver.RemoveTemplate(context.Background(), ct), "removal must not copy or interpret invalid source")
	}
	ct = testTemplate()
	cyclic := map[string]interface{}{}
	cyclic["self"] = cyclic
	sourceMap(t, ct)["invalid"] = cyclic
	_, err = ValidateTemplate(ct)
	require.ErrorContains(t, err, "nesting")
}

func TestConstraintContract(t *testing.T) {
	t.Parallel()
	driver := NewOfflineDriver()
	require.NoError(t, driver.AddTemplate(context.Background(), testTemplate()))
	for _, action := range []interface{}{"dryrun", "warn", "scoped", "Enforce", "", nil, true} {
		constraint := testConstraint()
		require.NoError(t, unstructured.SetNestedField(constraint.Object, action, "spec", "enforcementAction"))
		require.ErrorContains(t, driver.AddConstraint(context.Background(), constraint), "deny")
	}
	for _, match := range []interface{}{nil, "all", []interface{}{}, map[string]interface{}{"namespaceSelector": map[string]interface{}{}}, map[string]interface{}{"subject": map[string]interface{}{}}} {
		constraint := testConstraint()
		require.NoError(t, unstructured.SetNestedField(constraint.Object, match, "spec", "match"))
		require.ErrorContains(t, driver.AddConstraint(context.Background(), constraint), "empty object")
	}
	for _, scoped := range []interface{}{nil, []interface{}{}, []interface{}{map[string]interface{}{"action": "deny"}}} {
		constraint := testConstraint()
		require.NoError(t, unstructured.SetNestedField(constraint.Object, scoped, "spec", "scopedEnforcementActions"))
		require.ErrorContains(t, driver.AddConstraint(context.Background(), constraint), "scopedEnforcementActions")
	}
	for _, mutate := range []func(*unstructured.Unstructured){
		func(c *unstructured.Unstructured) { c.SetNamespace("default") },
		func(c *unstructured.Unstructured) { c.SetAPIVersion("v1") },
		func(c *unstructured.Unstructured) { c.SetAPIVersion("constraints.gatekeeper.sh/v99") },
		func(c *unstructured.Unstructured) { c.SetKind("Pod") },
		func(c *unstructured.Unstructured) { c.SetName("") },
		func(c *unstructured.Unstructured) { c.SetUID(types.UID(" ")) },
		func(c *unstructured.Unstructured) { setParameter(t, c, "undeclared", true) },
		func(c *unstructured.Unstructured) { setParameter(t, c, "allowedTools", "read") },
		func(c *unstructured.Unstructured) {
			unstructured.RemoveNestedField(c.Object, "spec", "parameters", "allowedTools")
		},
		func(c *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedField(c.Object, nil, "spec", "parameters"))
		},
	} {
		constraint := testConstraint()
		mutate(constraint)
		require.Error(t, driver.AddConstraint(context.Background(), constraint))
	}
	constraint := testConstraint()
	unstructured.RemoveNestedField(constraint.Object, "spec", "enforcementAction")
	unstructured.RemoveNestedField(constraint.Object, "spec", "match")
	constraint.SetUID("")
	require.NoError(t, driver.AddConstraint(context.Background(), constraint))
}

func TestEncodedSourceAndParameterBoundaries(t *testing.T) {
	t.Parallel()
	for _, length := range []int{maxSourceBytes - 1, maxSourceBytes, maxSourceBytes + 1} {
		ct := testTemplate()
		outputs := []interface{}{}
		for i := 0; i < 3; i++ {
			output := outputMap(t, testTemplate(), 0)
			output["key"] = fmt.Sprintf("slot-%d", i)
			require.NoError(t, unstructured.SetNestedField(output, "", "spec", "padding"))
			outputs = append(outputs, output)
		}
		sourceMap(t, ct)["outputs"] = outputs
		encoded, err := json.Marshal(sourceMap(t, ct))
		require.NoError(t, err)
		remaining := length - len(encoded)
		for i := range outputs {
			n := min(90*1024, remaining)
			require.NoError(t, unstructured.SetNestedField(outputMap(t, ct, i), strings.Repeat("x", n), "spec", "padding"))
			remaining -= n
		}
		require.Zero(t, remaining)
		encoded, err = json.Marshal(sourceMap(t, ct))
		require.NoError(t, err)
		require.Len(t, encoded, length)
		_, err = ValidateTemplate(ct)
		if length > maxSourceBytes {
			require.ErrorContains(t, err, "encoded JSON exceeds")
		} else {
			require.NoError(t, err)
		}
	}
	ct := testTemplate()
	ct.Spec.CRD.Spec.Validation.OpenAPIV3Schema.Properties["padding"] = apiextensions.JSONSchemaProps{Type: "string"}
	compiled := compileForTest(t, ct)
	for _, length := range []int{maxParametersBytes - 1, maxParametersBytes, maxParametersBytes + 1} {
		constraint := testConstraint()
		setParameter(t, constraint, "padding", "")
		parameters, _, err := unstructured.NestedMap(constraint.Object, "spec", "parameters")
		require.NoError(t, err)
		encoded, err := json.Marshal(parameters)
		require.NoError(t, err)
		setParameter(t, constraint, "padding", strings.Repeat("x", length-len(encoded)))
		_, err = buildOutputs(compiled, constraint)
		if length > maxParametersBytes {
			require.ErrorContains(t, err, "encoded JSON exceeds")
		} else {
			require.NoError(t, err)
		}
	}
	for _, length := range []int{maxObjectBytes - 1, maxObjectBytes, maxObjectBytes + 1} {
		ct := testTemplate()
		require.NoError(t, unstructured.SetNestedField(outputMap(t, ct, 0), "", "spec", "padding"))
		baseline := outputsForTest(t, ct, testConstraint())
		encoded, err := json.Marshal(baseline[0].Object)
		require.NoError(t, err)
		require.NoError(t, unstructured.SetNestedField(outputMap(t, ct, 0), strings.Repeat("x", length-len(encoded)), "spec", "padding"))
		outputs, err := buildOutputs(compileForTest(t, ct), testConstraint())
		if length > maxObjectBytes {
			require.ErrorContains(t, err, "including metadata")
		} else {
			require.NoError(t, err)
			encoded, err := json.Marshal(outputs[0].Object)
			require.NoError(t, err)
			require.Len(t, encoded, length)
		}
	}
}
