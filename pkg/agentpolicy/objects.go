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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func nativeObject(kind string) *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(schema.FromAPIVersionAndKind(nativeAPIVersion(kind), kind))
	return object
}

func outputName(constraint *unstructured.Unstructured, slot string) string {
	// This versioned naming contract intentionally excludes UID, namespace and
	// API version: recreation must encounter, not bypass, old-owner collisions.
	identity, _ := json.Marshal([]string{TargetName, constraintGroup, constraint.GetKind(), constraint.GetName(), slot})
	digest := sha256.Sum256(identity)
	return "gk-agent-" + hex.EncodeToString(digest[:24])
}

func buildOutputs(template *compiledTemplate, constraint *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	parameters, err := constraintParameters(template, constraint)
	if err != nil {
		return nil, err
	}
	outputs := make([]*unstructured.Unstructured, 0, len(template.outputs))
	for _, source := range template.outputs {
		spec, err := jsonObject(source.spec, maxObjectBytes)
		if err != nil {
			return nil, err
		}
		for _, bind := range source.bindings {
			value, err := bindValue(bind, parameters)
			if err != nil {
				return nil, fmt.Errorf("%w: output %q: %w", ErrInvalidConstraint, source.key, err)
			}
			parent, err := bindingParent(spec, bind.path)
			if err != nil {
				return nil, fmt.Errorf("%w: output %q: %w", ErrInvalidConstraint, source.key, err)
			}
			parent[bind.path[len(bind.path)-1]] = value
		}
		if err := validateNativeSpec(source.kind, spec); err != nil {
			return nil, fmt.Errorf("%w: output %q: %w", ErrInvalidConstraint, source.key, err)
		}
		object := nativeObject(source.kind)
		object.SetName(outputName(constraint, source.key))
		object.SetNamespace(source.namespace)
		object.SetLabels(map[string]string{managedByLabel: managedByValue, targetLabel: "true"})
		object.SetAnnotations(map[string]string{
			sourceAPIVersionAnnotation: constraint.GetAPIVersion(),
			sourceKindAnnotation:       constraint.GetKind(),
			sourceNameAnnotation:       constraint.GetName(),
			sourceUIDAnnotation:        string(constraint.GetUID()),
			sourceGenerationAnnotation: strconv.FormatInt(constraint.GetGeneration(), 10),
			templateNameAnnotation:     template.template.Name,
			templateUIDAnnotation:      string(template.template.UID),
			outputKeyAnnotation:        source.key,
		})
		if constraint.GetUID() != "" {
			controller, blockDeletion := true, true
			object.SetOwnerReferences([]metav1.OwnerReference{{
				APIVersion: constraint.GetAPIVersion(), Kind: constraint.GetKind(),
				Name: constraint.GetName(), UID: constraint.GetUID(),
				Controller: &controller, BlockOwnerDeletion: &blockDeletion,
			}})
		}
		object.Object["spec"] = spec
		if _, err := cloneJSON(object.Object, maxObjectBytes); err != nil {
			return nil, fmt.Errorf("%w: output %q including metadata: %w", ErrInvalidConstraint, source.key, err)
		}
		outputs = append(outputs, object)
	}
	sortObjects(outputs)
	return outputs, nil
}

func objectKey(object *unstructured.Unstructured) string {
	return object.GetAPIVersion() + "/" + object.GetKind() + "/" + object.GetNamespace() + "/" + object.GetName()
}

func sortObjects(objects []*unstructured.Unstructured) {
	sort.Slice(objects, func(i, j int) bool { return objectKey(objects[i]) < objectKey(objects[j]) })
}

func claimsConstraint(object, constraint *unstructured.Unstructured) bool {
	for _, owner := range object.GetOwnerReferences() {
		gv, err := schema.ParseGroupVersion(owner.APIVersion)
		if err == nil && gv.Group == constraintGroup && owner.Kind == constraint.GetKind() && owner.Name == constraint.GetName() {
			return true
		}
	}
	annotations := object.GetAnnotations()
	return annotations[sourceKindAnnotation] == constraint.GetKind() && annotations[sourceNameAnnotation] == constraint.GetName()
}

func verifyOwnership(object, constraint *unstructured.Unstructured) error {
	conflict := func() error {
		return fmt.Errorf("%w: %s is not owned by Constraint %s/%s with the expected UID", ErrOwnership, objectKey(object), constraint.GetKind(), constraint.GetName())
	}
	if constraint.GetUID() == "" || object.GetAPIVersion() != nativeAPIVersion(object.GetKind()) || nativeAPIVersion(object.GetKind()) == "" {
		return conflict()
	}
	if err := validateNamespace(object.GetNamespace()); err != nil {
		return conflict()
	}
	labels, annotations := object.GetLabels(), object.GetAnnotations()
	if labels[managedByLabel] != managedByValue || labels[targetLabel] != "true" ||
		annotations[sourceAPIVersionAnnotation] != constraint.GetAPIVersion() ||
		annotations[sourceKindAnnotation] != constraint.GetKind() ||
		annotations[sourceNameAnnotation] != constraint.GetName() ||
		annotations[sourceUIDAnnotation] != string(constraint.GetUID()) ||
		annotations[templateNameAnnotation] != strings.ToLower(constraint.GetKind()) ||
		!validSlot(annotations[outputKeyAnnotation]) ||
		object.GetName() != outputName(constraint, annotations[outputKeyAnnotation]) {
		return conflict()
	}
	owners := object.GetOwnerReferences()
	if len(owners) != 1 {
		return conflict()
	}
	owner := owners[0]
	if owner.Controller == nil || !*owner.Controller || owner.APIVersion != constraint.GetAPIVersion() ||
		owner.Kind != constraint.GetKind() || owner.Name != constraint.GetName() || owner.UID != constraint.GetUID() {
		return conflict()
	}
	return nil
}
