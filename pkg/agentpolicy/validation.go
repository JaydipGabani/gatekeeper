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
	"strings"
	"unicode/utf8"

	apivalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sjson "k8s.io/apimachinery/pkg/util/json"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func cloneJSON(value interface{}, limit int) (interface{}, error) {
	if err := checkJSONDepth(value, 0); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("value must be JSON encodable")
	}
	if len(encoded) > limit {
		return nil, fmt.Errorf("encoded JSON exceeds %d bytes", limit)
	}
	var result interface{}
	if err := k8sjson.Unmarshal(encoded, &result); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if err := checkJSONDepth(result, 0); err != nil {
		return nil, err
	}
	return result, nil
}

func checkJSONDepth(value interface{}, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
	}
	switch value := value.(type) {
	case map[string]interface{}:
		for key, child := range value {
			if !utf8.ValidString(key) {
				return errors.New("JSON object keys must be valid UTF-8")
			}
			if err := checkJSONDepth(child, depth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range value {
			if err := checkJSONDepth(child, depth+1); err != nil {
				return err
			}
		}
	case string:
		if !utf8.ValidString(value) {
			return errors.New("JSON strings must be valid UTF-8")
		}
	}
	return nil
}

func jsonObject(value interface{}, limit int) (map[string]interface{}, error) {
	copy, err := cloneJSON(value, limit)
	if err != nil {
		return nil, err
	}
	object, ok := copy.(map[string]interface{})
	if !ok || object == nil {
		return nil, errors.New("value must be a non-null object")
	}
	return object, nil
}

func properties(object map[string]interface{}, required, optional []string) error {
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = true
		if _, found := object[key]; !found {
			return fmt.Errorf("property %q is required", key)
		}
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return fmt.Errorf("unknown property %q", key)
		}
	}
	return nil
}

func validSlot(key string) bool {
	return len(utilvalidation.IsDNS1123Label(key)) == 0
}

func validateNamespace(namespace string) error {
	if len(utilvalidation.IsDNS1123Label(namespace)) != 0 {
		return errors.New("output namespace must be a DNS label of at most 63 characters")
	}
	if strings.HasPrefix(namespace, "kube-") || strings.HasPrefix(namespace, "gatekeeper-") {
		return fmt.Errorf("protected infrastructure namespace %q is unsupported", namespace)
	}
	switch namespace {
	case "agentgateway-system", "cert-manager", "istio-system", "flux-system", "argocd":
		return fmt.Errorf("protected infrastructure namespace %q is unsupported", namespace)
	default:
		return nil
	}
}

func nativeAPIVersion(kind string) string {
	switch kind {
	case gatewayKind:
		return gatewayAPIVersion
	case authzKind:
		return authzAPIVersion
	default:
		return ""
	}
}

func validateNativeSpec(kind string, spec map[string]interface{}) error {
	if nativeAPIVersion(kind) == "" || len(spec) == 0 {
		return errors.New("allowlisted native kind and nonempty spec are required")
	}
	for _, key := range []string{"apiVersion", "kind", "metadata", "status"} {
		if _, found := spec[key]; found {
			return fmt.Errorf("native spec cannot contain object envelope property %q", key)
		}
	}
	if kind != gatewayKind {
		return nil
	}
	// Independent Allow policies union at the gateway. Require intersects, so
	// another broad Allow cannot bypass a restrictive Constraint.
	for _, path := range [][]string{{"traffic", "authorization"}, {"backend", "mcp", "authorization"}} {
		raw, found, err := unstructured.NestedFieldNoCopy(spec, path...)
		if err != nil {
			return fmt.Errorf("native %s must traverse objects", strings.Join(path, "."))
		}
		if !found {
			continue
		}
		authorization, ok := raw.(map[string]interface{})
		if !ok || authorization["action"] != "Require" {
			return fmt.Errorf("native %s.action must explicitly be Require", strings.Join(path, "."))
		}
	}
	return nil
}

func constraintIdentity(input *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	if input == nil {
		return nil, fmt.Errorf("%w: object is required", ErrInvalidConstraint)
	}
	object, err := jsonObject(input.Object, maxConstraintBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConstraint, err)
	}
	constraint := &unstructured.Unstructured{Object: object}
	gv, err := schema.ParseGroupVersion(constraint.GetAPIVersion())
	if err != nil || gv.Group != constraintGroup || (gv.Version != "v1beta1" && gv.Version != "v1alpha1") {
		return nil, fmt.Errorf("%w: a constraints.gatekeeper.sh/v1beta1 or v1alpha1 object is required", ErrInvalidConstraint)
	}
	if !kindPattern.MatchString(constraint.GetKind()) {
		return nil, fmt.Errorf("%w: kind must be an alphanumeric identifier of at most 63 characters", ErrInvalidConstraint)
	}
	if len(utilvalidation.IsDNS1123Subdomain(constraint.GetName())) != 0 {
		return nil, fmt.Errorf("%w: name must be a DNS subdomain", ErrInvalidConstraint)
	}
	metadata, ok := object["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: metadata is required", ErrInvalidConstraint)
	}
	for _, key := range []string{"namespace", "uid", "resourceVersion"} {
		if value, found := metadata[key]; found {
			if _, ok := value.(string); !ok {
				return nil, fmt.Errorf("%w: metadata.%s must be a string", ErrInvalidConstraint, key)
			}
		}
	}
	if constraint.GetNamespace() != "" || len(constraint.GetUID()) > 128 || strings.TrimSpace(string(constraint.GetUID())) != string(constraint.GetUID()) {
		return nil, fmt.Errorf("%w: cluster-scoped identity with a UID of at most 128 bytes is required", ErrInvalidConstraint)
	}
	return constraint, nil
}

func constraintParameters(template *compiledTemplate, constraint *unstructured.Unstructured) (map[string]interface{}, error) {
	if constraint.GetKind() != template.template.Spec.CRD.Spec.Names.Kind {
		return nil, fmt.Errorf("%w: kind does not match the template", ErrInvalidConstraint)
	}
	spec, ok := constraint.Object["spec"].(map[string]interface{})
	if !ok || spec == nil {
		return nil, fmt.Errorf("%w: spec must be an object", ErrInvalidConstraint)
	}
	if err := properties(spec, nil, []string{"parameters", "enforcementAction", "match"}); err != nil {
		return nil, fmt.Errorf("%w: spec: %w", ErrInvalidConstraint, err)
	}
	if action, found := spec["enforcementAction"]; found && action != "deny" {
		return nil, fmt.Errorf("%w: only enforcementAction deny is supported", ErrInvalidConstraint)
	}
	if match, found := spec["match"]; found {
		object, ok := match.(map[string]interface{})
		if !ok || object == nil || len(object) != 0 {
			return nil, fmt.Errorf("%w: match must be an empty object; workload and namespace selectors are unsupported", ErrInvalidConstraint)
		}
	}
	parameters := map[string]interface{}{}
	if value, found := spec["parameters"]; found {
		var err error
		parameters, err = jsonObject(value, maxParametersBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: parameters: %w", ErrInvalidConstraint, err)
		}
	}
	parameterSchema := template.template.Spec.CRD.Spec.Validation.OpenAPIV3Schema
	for key := range parameters {
		if _, found := parameterSchema.Properties[key]; !found {
			return nil, fmt.Errorf("%w: undeclared parameter %q", ErrInvalidConstraint, key)
		}
	}
	validator, _, err := apivalidation.NewSchemaValidator(parameterSchema)
	if err != nil {
		return nil, fmt.Errorf("%w: parameters schema: %w", ErrInvalidConstraint, err)
	}
	if errs := apivalidation.ValidateCustomResource(field.NewPath("spec", "parameters"), parameters, validator); len(errs) != 0 {
		// Do not echo parameter values, which can contain identity information.
		return nil, fmt.Errorf("%w: %s does not satisfy the parameters schema (%s)", ErrInvalidConstraint, errs[0].Field, errs[0].Type)
	}
	return parameters, nil
}
