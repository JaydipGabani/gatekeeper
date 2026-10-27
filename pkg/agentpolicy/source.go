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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	apivalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var (
	ErrInvalidTemplate   = errors.New("invalid agent ConstraintTemplate")
	ErrInvalidSource     = errors.New("invalid AgentPolicy source")
	ErrInvalidConstraint = errors.New("invalid agent Constraint")
	ErrOwnership         = errors.New("agent policy ownership conflict")
	ErrReviewUnsupported = errors.New("agent policies are projected, not evaluated against admission or audit reviews")

	kindPattern      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,62}$`)
	parameterPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

type outputSource struct {
	key       string
	kind      string
	namespace string
	spec      map[string]interface{}
	bindings  []binding
}

type binding struct {
	parameter string
	path      []string
	format    string
	variable  string
}

type compiledTemplate struct {
	template *templates.ConstraintTemplate
	outputs  []outputSource
	temporal bool
}

func IsAgentTemplate(ct *templates.ConstraintTemplate) bool {
	if ct == nil {
		return false
	}
	for _, target := range ct.Spec.Targets {
		if target.Target == TargetName {
			return true
		}
	}
	return false
}

func ValidateTemplate(ct *templates.ConstraintTemplate) (bool, error) {
	_, handled, err := compileTemplate(ct)
	return handled, err
}

func compileTemplate(ct *templates.ConstraintTemplate) (*compiledTemplate, bool, error) {
	if ct == nil {
		return nil, false, fmt.Errorf("%w: template is required", ErrInvalidTemplate)
	}
	if !IsAgentTemplate(ct) {
		return nil, false, nil
	}
	if len(ct.Spec.Targets) != 1 {
		return nil, true, fmt.Errorf("%w: an agent-only template with exactly one target is required", ErrInvalidTemplate)
	}
	if !kindPattern.MatchString(ct.Spec.CRD.Spec.Names.Kind) || ct.Name != strings.ToLower(ct.Spec.CRD.Spec.Names.Kind) || ct.Namespace != "" {
		return nil, true, fmt.Errorf("%w: a cluster-scoped template named after its lowercase Constraint kind is required", ErrInvalidTemplate)
	}
	target := ct.Spec.Targets[0]
	if target.Rego != "" || len(target.Libs) != 0 || len(target.Operations) != 0 {
		return nil, true, fmt.Errorf("%w: target Rego, libraries and admission operations are unsupported; native modules belong in source spec", ErrInvalidTemplate)
	}
	if len(target.Code) != 1 || target.Code[0].Engine != EngineName || target.Code[0].Source == nil {
		return nil, true, fmt.Errorf("%w: exactly one %s code block with source is required", ErrInvalidTemplate, EngineName)
	}
	validation := ct.Spec.CRD.Spec.Validation
	if validation == nil || validation.OpenAPIV3Schema == nil || validation.OpenAPIV3Schema.Type != "object" {
		return nil, true, fmt.Errorf("%w: parameters require an object OpenAPI v3 schema", ErrInvalidTemplate)
	}
	if err := checkParameterSchema(validation.OpenAPIV3Schema, 0); err != nil {
		return nil, true, fmt.Errorf("%w: parameters schema: %w", ErrInvalidTemplate, err)
	}
	structural, err := schema.NewStructural(validation.OpenAPIV3Schema)
	if err != nil {
		return nil, true, fmt.Errorf("%w: parameters schema: %w", ErrInvalidTemplate, err)
	}
	if errs := schema.ValidateStructural(field.NewPath("parameters"), structural); len(errs) != 0 {
		return nil, true, fmt.Errorf("%w: parameters schema: %s", ErrInvalidTemplate, errs.ToAggregate())
	}
	if _, _, err := apivalidation.NewSchemaValidator(validation.OpenAPIV3Schema); err != nil {
		return nil, true, fmt.Errorf("%w: parameters schema: %w", ErrInvalidTemplate, err)
	}

	// Anything.GetValue/DeepCopy panic on noncanonical Go values. Normalize the
	// public API input before using Kubernetes' JSON-only deep-copy routines.
	raw, err := jsonObject(target.Code[0].Source.Value, maxSourceBytes)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrInvalidSource, err)
	}
	if err := properties(raw, []string{"version", "outputs"}, nil); err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrInvalidSource, err)
	}
	if raw["version"] != SourceVersion {
		return nil, true, fmt.Errorf("%w: version must be %q", ErrInvalidSource, SourceVersion)
	}
	rawOutputs, ok := raw["outputs"].([]interface{})
	if !ok || len(rawOutputs) == 0 || len(rawOutputs) > maxOutputs {
		return nil, true, fmt.Errorf("%w: outputs must contain 1..%d objects", ErrInvalidSource, maxOutputs)
	}
	normalized := *ct
	normalized.Spec.Targets = []templates.Target{target}
	normalized.Spec.Targets[0].Code = []templates.Code{target.Code[0]}
	normalized.Spec.Targets[0].Code[0].Source = &templates.Anything{Value: raw}
	compiled := &compiledTemplate{template: normalized.DeepCopy()}
	keys := make(map[string]bool, len(rawOutputs))
	for i, value := range rawOutputs {
		output, err := parseOutput(value)
		if err != nil {
			return nil, true, fmt.Errorf("%w: outputs[%d]: %w", ErrInvalidSource, i, err)
		}
		if keys[output.key] {
			return nil, true, fmt.Errorf("%w: duplicate output key %q", ErrInvalidSource, output.key)
		}
		keys[output.key] = true
		if output.kind == authzKind {
			// The singleton is the owning Constraint's coherent module set,
			// not an individual AgentAuthzPolicy within that set.
			compiled.temporal = true
		}
		for _, bind := range output.bindings {
			if _, ok := validation.OpenAPIV3Schema.Properties[bind.parameter]; !ok {
				return nil, true, fmt.Errorf("%w: bound parameter %q must be declared in the parameters schema", ErrInvalidSource, bind.parameter)
			}
		}
		compiled.outputs = append(compiled.outputs, output)
	}
	return compiled, true, nil
}

func checkParameterSchema(value *apiextensions.JSONSchemaProps, depth int) error {
	if value == nil {
		return nil
	}
	if depth > maxJSONDepth {
		return errors.New("parameters schema nesting is too deep")
	}
	switch value.Type {
	case "", "object", "array", "string", "number", "integer", "boolean":
	default:
		return fmt.Errorf("unsupported schema type %q", value.Type)
	}
	for _, child := range value.Properties {
		if err := checkParameterSchema(&child, depth+1); err != nil {
			return err
		}
	}
	if value.Items != nil {
		if err := checkParameterSchema(value.Items.Schema, depth+1); err != nil {
			return err
		}
		for _, child := range value.Items.JSONSchemas {
			if err := checkParameterSchema(&child, depth+1); err != nil {
				return err
			}
		}
	}
	if value.AdditionalProperties != nil {
		if err := checkParameterSchema(value.AdditionalProperties.Schema, depth+1); err != nil {
			return err
		}
	}
	for _, children := range [][]apiextensions.JSONSchemaProps{value.AllOf, value.AnyOf, value.OneOf} {
		for _, child := range children {
			if err := checkParameterSchema(&child, depth+1); err != nil {
				return err
			}
		}
	}
	return checkParameterSchema(value.Not, depth+1)
}

func parseOutput(value interface{}) (outputSource, error) {
	raw, ok := value.(map[string]interface{})
	if !ok || raw == nil {
		return outputSource{}, errors.New("output must be an object")
	}
	if err := properties(raw, []string{"key", "kind", "namespace", "spec"}, []string{"bindings"}); err != nil {
		return outputSource{}, err
	}
	key, ok := raw["key"].(string)
	if !ok || !validSlot(key) {
		return outputSource{}, errors.New("key must be a DNS label of at most 63 characters")
	}
	kind, ok := raw["kind"].(string)
	if !ok || nativeAPIVersion(kind) == "" {
		return outputSource{}, errors.New("kind must be AgentgatewayPolicy or AgentAuthzPolicy")
	}
	namespace, ok := raw["namespace"].(string)
	if !ok {
		return outputSource{}, errors.New("namespace must be a string")
	}
	if err := validateNamespace(namespace); err != nil {
		return outputSource{}, err
	}
	spec, err := jsonObject(raw["spec"], maxObjectBytes)
	if err != nil {
		return outputSource{}, fmt.Errorf("spec: %w", err)
	}
	if err := validateNativeSpec(kind, spec); err != nil {
		return outputSource{}, err
	}
	output := outputSource{key: key, kind: kind, namespace: namespace, spec: spec}
	if rawBindings, found := raw["bindings"]; found {
		items, ok := rawBindings.([]interface{})
		if !ok || len(items) > maxBindings {
			return outputSource{}, fmt.Errorf("bindings must be an array of at most %d objects", maxBindings)
		}
		for _, item := range items {
			bind, err := parseBinding(item)
			if err != nil {
				return outputSource{}, err
			}
			if kind == authzKind && bind.path[0] != "data" {
				return outputSource{}, errors.New("AgentAuthzPolicy bindings must write only to spec.data; policy modules are template-owned")
			}
			if _, err := bindingParent(spec, bind.path); err != nil {
				return outputSource{}, err
			}
			for _, previous := range output.bindings {
				if overlappingPaths(previous.path, bind.path) {
					return outputSource{}, errors.New("binding paths must not overlap")
				}
			}
			output.bindings = append(output.bindings, bind)
		}
	}
	return output, nil
}

func parseBinding(value interface{}) (binding, error) {
	raw, ok := value.(map[string]interface{})
	if !ok || raw == nil {
		return binding{}, errors.New("binding must be an object")
	}
	if err := properties(raw, []string{"parameter", "path"}, []string{"format", "variable"}); err != nil {
		return binding{}, err
	}
	parameter, ok := raw["parameter"].(string)
	if !ok || !parameterPattern.MatchString(parameter) {
		return binding{}, errors.New("binding parameter must be an identifier of at most 128 characters")
	}
	pathValues, ok := raw["path"].([]interface{})
	if !ok || len(pathValues) == 0 || len(pathValues) > maxPathSegments {
		return binding{}, fmt.Errorf("binding path must contain 1..%d map keys", maxPathSegments)
	}
	bind := binding{parameter: parameter, format: "Value"}
	for _, value := range pathValues {
		key, ok := value.(string)
		if !ok || key == "" || len(key) > 256 || !utf8.ValidString(key) {
			return binding{}, errors.New("binding path entries must be nonempty UTF-8 map keys of at most 256 bytes")
		}
		bind.path = append(bind.path, key)
	}
	if value, found := raw["format"]; found {
		format, ok := value.(string)
		if !ok || (format != "Value" && format != "CELStringList") {
			return binding{}, errors.New("binding format must be Value or CELStringList")
		}
		bind.format = format
	}
	variable, hasVariable := raw["variable"]
	if bind.format == "CELStringList" {
		if variable != "mcp.tool.name" {
			return binding{}, errors.New("CELStringList variable must be mcp.tool.name")
		}
		bind.variable = "mcp.tool.name"
	} else if hasVariable {
		return binding{}, errors.New("variable is only supported with CELStringList")
	}
	return bind, nil
}

func bindingParent(spec map[string]interface{}, path []string) (map[string]interface{}, error) {
	parent := spec
	for _, key := range path[:len(path)-1] {
		next, ok := parent[key].(map[string]interface{})
		if !ok || next == nil {
			return nil, errors.New("binding path must traverse existing map keys, not arrays or scalars")
		}
		parent = next
	}
	if _, found := parent[path[len(path)-1]]; !found {
		return nil, errors.New("binding path must end at an existing spec property")
	}
	return parent, nil
}

func overlappingPaths(left, right []string) bool {
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func bindValue(bind binding, parameters map[string]interface{}) (interface{}, error) {
	value, found := parameters[bind.parameter]
	if !found {
		return nil, fmt.Errorf("bound parameter %q is required", bind.parameter)
	}
	if bind.format == "Value" {
		return cloneJSON(value, maxParametersBytes)
	}
	values, ok := value.([]interface{})
	if !ok || len(values) > maxStringListItems {
		return nil, fmt.Errorf("CELStringList parameter %q must be a string array with at most %d items", bind.parameter, maxStringListItems)
	}
	stringsValue := make([]string, len(values))
	for i, value := range values {
		item, ok := value.(string)
		if !ok || len(item) > maxStringListItemBytes || !utf8.ValidString(item) {
			return nil, fmt.Errorf("CELStringList parameter %q entries must be UTF-8 strings of at most %d bytes", bind.parameter, maxStringListItemBytes)
		}
		stringsValue[i] = item
	}
	encoded, err := json.Marshal(stringsValue)
	if err != nil {
		return nil, fmt.Errorf("encode CELStringList: %w", err)
	}
	expression := bind.variable + " in " + string(encoded)
	if len(expression) > maxCELExpressionBytes {
		return nil, fmt.Errorf("encoded CELStringList expression exceeds %d bytes", maxCELExpressionBytes)
	}
	return []interface{}{expression}, nil
}
