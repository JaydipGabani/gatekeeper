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
	"fmt"
	"reflect"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ProjectionStatus struct {
	State   string
	Message string
}

type Projector interface {
	ReconcileConstraint(context.Context, *unstructured.Unstructured) (ProjectionStatus, bool, error)
	WatchObjects() []client.Object
}

func (*Driver) WatchObjects() []client.Object {
	return []client.Object{nativeObject(gatewayKind), nativeObject(authzKind)}
}

func (d *Driver) listNative(ctx context.Context) ([]*unstructured.Unstructured, error) {
	objects := make([]*unstructured.Unstructured, 0)
	for _, kind := range []string{gatewayKind, authzKind} {
		continuation := ""
		for {
			list := &unstructured.UnstructuredList{}
			list.SetGroupVersionKind(schema.FromAPIVersionAndKind(nativeAPIVersion(kind), kind+"List"))
			if err := d.reader.List(ctx, list, &client.ListOptions{Limit: 256, Continue: continuation}); err != nil {
				return nil, fmt.Errorf("list %s for complete-set ownership reconciliation: %w", kind, err)
			}
			if len(objects)+len(list.Items) > maxListedPolicies {
				return nil, fmt.Errorf("native policy inventory exceeds POC limit of %d objects", maxListedPolicies)
			}
			for i := range list.Items {
				objects = append(objects, list.Items[i].DeepCopy())
			}
			next := list.GetContinue()
			if next == "" {
				break
			}
			if next == continuation {
				return nil, fmt.Errorf("list %s returned a non-advancing continuation token", kind)
			}
			continuation = next
		}
	}
	sortObjects(objects)
	return objects, nil
}

func (d *Driver) ownedObjects(constraint *unstructured.Unstructured, inventory []*unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	owned := make([]*unstructured.Unstructured, 0)
	for _, object := range inventory {
		if !claimsConstraint(object, constraint) {
			continue
		}
		if err := verifyOwnership(object, constraint); err != nil {
			return nil, err
		}
		owned = append(owned, object)
	}
	return owned, nil
}

type plannedOutput struct {
	desired *unstructured.Unstructured
	current *unstructured.Unstructured
}

func (d *Driver) project(ctx context.Context, constraint *unstructured.Unstructured, desired []*unstructured.Unstructured, temporal bool) (ProjectionStatus, error) {
	if d.offline {
		return ProjectionStatus{
			State: ProjectionPending, Message: fmt.Sprintf("validated %d native agent policies (offline; not applied or enforced)", len(desired)),
		}, nil
	}
	inventory, err := d.listNative(ctx)
	if err != nil {
		return ProjectionStatus{}, err
	}
	owned, err := d.ownedObjects(constraint, inventory)
	if err != nil {
		return ProjectionStatus{}, err
	}
	if temporal {
		for _, object := range inventory {
			if object.GetKind() == authzKind && !claimsConstraint(object, constraint) {
				return ProjectionStatus{}, fmt.Errorf("%w: only one active AgentAuthzPolicy source set is supported; %s already exists", ErrOwnership, objectKey(object))
			}
		}
	}
	plan := make([]plannedOutput, 0, len(desired))
	keys := make(map[string]bool, len(desired))
	// Validate the entire desired set and every ownership decision before the
	// first write. Native API/schema failures can still make application partial.
	for _, object := range desired {
		keys[objectKey(object)] = true
		current := nativeObject(object.GetKind())
		if err := d.reader.Get(ctx, client.ObjectKeyFromObject(object), current); err != nil {
			if !apierrors.IsNotFound(err) {
				return ProjectionStatus{}, fmt.Errorf("read desired %s: %w", objectKey(object), err)
			}
			current = nil
		} else if err := verifyOwnership(current, constraint); err != nil {
			return ProjectionStatus{}, err
		}
		plan = append(plan, plannedOutput{desired: object, current: current})
	}
	obsolete := make([]*unstructured.Unstructured, 0)
	for _, object := range owned {
		if !keys[objectKey(object)] {
			obsolete = append(obsolete, object)
		}
	}
	writes := 0
	for i, output := range plan {
		changed, err := d.applyOutput(ctx, constraint, output)
		if err != nil {
			return ProjectionStatus{}, fmt.Errorf("projection incomplete (partial apply: %d writes, %d/%d desired outputs reconciled; obsolete outputs retained): %w", writes, i, len(plan), err)
		}
		if changed {
			writes++
		}
	}
	if err := d.deleteObjects(ctx, obsolete); err != nil {
		return ProjectionStatus{}, fmt.Errorf("projection incomplete (partial apply: %d writes, %d/%d desired outputs reconciled): %w", writes, len(plan), len(plan), err)
	}
	return ProjectionStatus{
		State:   ProjectionProjected,
		Message: fmt.Sprintf("projected %d native agent policies; gateway/PDP acceptance, attachment and enforcement are not established by this write", len(desired)),
	}, nil
}

func (d *Driver) applyOutput(ctx context.Context, constraint *unstructured.Unstructured, output plannedOutput) (bool, error) {
	current := output.current
	if current == nil {
		if err := d.writer.Create(ctx, output.desired.DeepCopy()); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return false, fmt.Errorf("create %s: %w", objectKey(output.desired), err)
			}
			// A concurrent creator must pass the same uncached ownership checks.
			current = nativeObject(output.desired.GetKind())
			if err := d.reader.Get(ctx, client.ObjectKeyFromObject(output.desired), current); err != nil {
				return false, fmt.Errorf("read concurrently created %s: %w", objectKey(output.desired), err)
			}
			if err := verifyOwnership(current, constraint); err != nil {
				return false, err
			}
		} else {
			return true, nil
		}
	}
	updated := current.DeepCopy()
	updated.Object["spec"] = runtime.DeepCopyJSONValue(output.desired.Object["spec"])
	updated.SetOwnerReferences(output.desired.GetOwnerReferences())
	updated.SetLabels(mergeMetadata(current.GetLabels(), output.desired.GetLabels()))
	updated.SetAnnotations(mergeMetadata(current.GetAnnotations(), output.desired.GetAnnotations()))
	if reflect.DeepEqual(current.Object, updated.Object) {
		return false, nil
	}
	if err := d.writer.Update(ctx, updated); err != nil {
		return false, fmt.Errorf("update %s: %w", objectKey(output.desired), err)
	}
	return true, nil
}

func mergeMetadata(current, desired map[string]string) map[string]string {
	merged := make(map[string]string, len(current)+len(desired))
	for key, value := range current {
		merged[key] = value
	}
	for key, value := range desired {
		merged[key] = value
	}
	return merged
}

func (d *Driver) deleteObjects(ctx context.Context, objects []*unstructured.Unstructured) error {
	for i, object := range objects {
		// UID and resourceVersion preconditions close the read/delete race:
		// never delete an object replaced or edited after ownership was checked.
		uid, version := object.GetUID(), object.GetResourceVersion()
		options := &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version}}
		if err := d.writer.Delete(ctx, object, options); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("partial cleanup: deleted %d/%d outputs; delete %s: %w", i, len(objects), objectKey(object), err)
		}
	}
	return nil
}

func (d *Driver) deleteConstraintObjects(ctx context.Context, constraint *unstructured.Unstructured) error {
	if d.offline {
		return nil
	}
	inventory, err := d.listNative(ctx)
	if err != nil {
		return err
	}
	owned, err := d.ownedObjects(constraint, inventory)
	if err != nil {
		return err
	}
	return d.deleteObjects(ctx, owned)
}

func (d *Driver) deleteTemplateObjects(ctx context.Context, ct *templates.ConstraintTemplate, cached []*unstructured.Unstructured) error {
	if d.offline {
		return nil
	}
	inventory, err := d.listNative(ctx)
	if err != nil {
		return err
	}
	owned := make([]*unstructured.Unstructured, 0)
	for _, object := range inventory {
		var source *unstructured.Unstructured
		for _, constraint := range cached {
			if claimsConstraint(object, constraint) {
				source = constraint
				break
			}
		}
		annotations := object.GetAnnotations()
		if source == nil {
			if annotations[templateNameAnnotation] != ct.Name {
				continue
			}
			if ct.UID == "" {
				return fmt.Errorf("%w: template UID or cached Constraint identity is required for cleanup after restart", ErrOwnership)
			}
			if annotations[templateUIDAnnotation] != string(ct.UID) {
				continue
			}
			candidate := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": annotations[sourceAPIVersionAnnotation],
				"kind":       annotations[sourceKindAnnotation],
				"metadata": map[string]interface{}{
					"name": annotations[sourceNameAnnotation], "uid": annotations[sourceUIDAnnotation],
				},
			}}
			source, err = constraintIdentity(candidate)
			if err != nil {
				return fmt.Errorf("%w: invalid recorded Constraint identity on %s", ErrOwnership, objectKey(object))
			}
		}
		if strings.ToLower(source.GetKind()) != ct.Name ||
			(ct.UID != "" && annotations[templateUIDAnnotation] != string(ct.UID)) {
			return fmt.Errorf("%w: template provenance mismatch on %s", ErrOwnership, objectKey(object))
		}
		if err := verifyOwnership(object, source); err != nil {
			return err
		}
		owned = append(owned, object)
	}
	return d.deleteObjects(ctx, owned)
}
