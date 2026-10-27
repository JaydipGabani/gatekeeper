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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/opa/v1/storage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	_ drivers.Driver = &Driver{}
	_ Projector      = &Driver{}
)

// Driver caches immutable desired configuration. No cache mutex is held across
// Kubernetes calls. Context-cancellable, per-kind gates serialize lifecycle
// changes so a concurrent template/constraint deletion cannot resurrect outputs.
type Driver struct {
	mu          sync.RWMutex
	templates   map[string]*compiledTemplate
	constraints map[string]map[string]*unstructured.Unstructured
	gates       map[string]*operationGate
	writer      client.Client
	reader      client.Reader
	offline     bool
	initErr     error
}

type operationGate struct {
	token chan struct{}
	users int
}

// NewDriver requires a writer and an explicitly supplied uncached API reader.
// Invalid dependencies are reported by operations rather than silently enabling
// offline mode or using a potentially cached writer for ownership decisions.
func NewDriver(writer client.Client, reader client.Reader) *Driver {
	driver := newDriver()
	driver.writer, driver.reader = writer, reader
	if isNil(writer) || isNil(reader) {
		driver.initErr = errors.New("agent projection requires both a writer and an uncached reader; use NewOfflineDriver for offline validation")
	}
	return driver
}

func NewOfflineDriver() *Driver {
	driver := newDriver()
	driver.offline = true
	return driver
}

func newDriver() *Driver {
	return &Driver{
		templates:   make(map[string]*compiledTemplate),
		constraints: make(map[string]map[string]*unstructured.Unstructured),
		gates:       make(map[string]*operationGate),
	}
}

func isNil(value interface{}) bool {
	if value == nil {
		return true
	}
	switch reflect.ValueOf(value).Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}

func validContext(ctx context.Context) error {
	if isNil(ctx) {
		return errors.New("context is required")
	}
	return ctx.Err()
}

func (d *Driver) ready() error {
	if d == nil || d.templates == nil || d.constraints == nil || d.gates == nil {
		return errors.New("an initialized agent driver is required")
	}
	return d.initErr
}

func (d *Driver) check(ctx context.Context) error {
	if err := d.ready(); err != nil {
		return err
	}
	return validContext(ctx)
}

func (d *Driver) acquire(ctx context.Context, key string) (func(), error) {
	d.mu.Lock()
	gate := d.gates[key]
	if gate == nil {
		gate = &operationGate{token: make(chan struct{}, 1)}
		d.gates[key] = gate
	}
	gate.users++
	d.mu.Unlock()
	drop := func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		gate.users--
		if gate.users == 0 {
			delete(d.gates, key)
		}
	}
	select {
	case gate.token <- struct{}{}:
		release := func() {
			<-gate.token
			drop()
		}
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		return release, nil
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	}
}

func (*Driver) Name() string { return EngineName }

func (d *Driver) AddTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	if err := d.check(ctx); err != nil {
		return err
	}
	compiled, handled, err := compileTemplate(ct)
	if err != nil {
		return err
	}
	if !handled {
		return fmt.Errorf("%w: target must be %s", ErrInvalidTemplate, TargetName)
	}
	key := ct.Name
	release, err := d.acquire(ctx, key)
	if err != nil {
		return err
	}
	defer release()
	d.mu.RLock()
	old := d.templates[key]
	cached := make([]*unstructured.Unstructured, 0, len(d.constraints[key]))
	for _, constraint := range d.constraints[key] {
		cached = append(cached, constraint)
	}
	d.mu.RUnlock()
	if old != nil && old.template.UID != "" && old.template.UID != ct.UID {
		return fmt.Errorf("%w: remove the previous template UID before replacing it", ErrOwnership)
	}
	if compiled.temporal || (old != nil && old.temporal) {
		releaseTemporal, err := d.acquire(ctx, "#temporal")
		if err != nil {
			return err
		}
		defer releaseTemporal()
	}
	for _, constraint := range cached {
		if _, err := buildOutputs(compiled, constraint); err != nil {
			return fmt.Errorf("template update would invalidate cached Constraint %s/%s: %w", constraint.GetKind(), constraint.GetName(), err)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if compiled.temporal {
		if len(cached) > 1 || (len(cached) != 0 && d.hasOtherTemporalLocked(key, cached[0].GetName())) {
			return fmt.Errorf("%w: only one active AgentAuthzPolicy source set is supported", ErrOwnership)
		}
	}
	d.templates[key] = compiled
	if d.constraints[key] == nil {
		d.constraints[key] = make(map[string]*unstructured.Unstructured)
	}
	return nil
}

func (d *Driver) RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	if err := d.check(ctx); err != nil {
		return err
	}
	if ct == nil || len(utilvalidation.IsDNS1123Subdomain(ct.Name)) != 0 || ct.Namespace != "" {
		return fmt.Errorf("%w: cluster-scoped template identity is required", ErrInvalidTemplate)
	}
	if kind := ct.Spec.CRD.Spec.Names.Kind; kind != "" && (!kindPattern.MatchString(kind) || strings.ToLower(kind) != ct.Name) {
		return fmt.Errorf("%w: template kind must match its name", ErrInvalidTemplate)
	}
	key := ct.Name
	release, err := d.acquire(ctx, key)
	if err != nil {
		return err
	}
	defer release()
	d.mu.RLock()
	cachedTemplate := d.templates[key]
	cached := make([]*unstructured.Unstructured, 0, len(d.constraints[key]))
	for _, constraint := range d.constraints[key] {
		cached = append(cached, constraint)
	}
	d.mu.RUnlock()
	identity := &templates.ConstraintTemplate{ObjectMeta: *ct.ObjectMeta.DeepCopy()}
	if cachedTemplate != nil {
		if ct.UID != "" && cachedTemplate.template.UID != "" && ct.UID != cachedTemplate.template.UID {
			return fmt.Errorf("%w: stale template deletion UID", ErrOwnership)
		}
		identity = cachedTemplate.template
	}
	if err := d.deleteTemplateObjects(ctx, identity, cached); err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.templates, key)
	delete(d.constraints, key)
	d.mu.Unlock()
	return nil
}

func (d *Driver) AddConstraint(ctx context.Context, input *unstructured.Unstructured) error {
	if err := d.check(ctx); err != nil {
		return err
	}
	constraint, err := constraintIdentity(input)
	if err != nil {
		return err
	}
	key := strings.ToLower(constraint.GetKind())
	release, err := d.acquire(ctx, key)
	if err != nil {
		return err
	}
	defer release()
	template := d.templateFor(key)
	if template == nil {
		return fmt.Errorf("%w: no agent template for kind %q", ErrInvalidConstraint, constraint.GetKind())
	}
	if template.temporal {
		releaseTemporal, err := d.acquire(ctx, "#temporal")
		if err != nil {
			return err
		}
		defer releaseTemporal()
	}
	if _, err := buildOutputs(template, constraint); err != nil {
		return err
	}
	return d.acceptConstraint(template, constraint)
}

func (d *Driver) acceptConstraint(template *compiledTemplate, constraint *unstructured.Unstructured) error {
	if !d.offline && constraint.GetUID() == "" {
		return fmt.Errorf("%w: online projection requires a source Constraint UID", ErrInvalidConstraint)
	}
	key := strings.ToLower(constraint.GetKind())
	d.mu.Lock()
	defer d.mu.Unlock()
	if old := d.constraints[key][constraint.GetName()]; old != nil && old.GetUID() != "" && old.GetUID() != constraint.GetUID() {
		return fmt.Errorf("%w: remove the previous Constraint UID before replacing it", ErrOwnership)
	}
	if template.temporal && d.hasOtherTemporalLocked(key, constraint.GetName()) {
		return fmt.Errorf("%w: only one active AgentAuthzPolicy source set is supported", ErrOwnership)
	}
	if d.constraints[key] == nil {
		d.constraints[key] = make(map[string]*unstructured.Unstructured)
	}
	d.constraints[key][constraint.GetName()] = constraint
	return nil
}

func (d *Driver) hasOtherTemporalLocked(kind, name string) bool {
	for key, template := range d.templates {
		if !template.temporal {
			continue
		}
		for constraintName := range d.constraints[key] {
			if key != kind || constraintName != name {
				return true
			}
		}
	}
	return false
}

func (d *Driver) templateFor(key string) *compiledTemplate {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.templates[key]
}

func (d *Driver) validateConstraint(input *unstructured.Unstructured) error {
	if err := d.ready(); err != nil {
		return err
	}
	constraint, err := constraintIdentity(input)
	if err != nil {
		return err
	}
	template := d.templateFor(strings.ToLower(constraint.GetKind()))
	if template == nil {
		return fmt.Errorf("%w: no agent template for kind %q", ErrInvalidConstraint, constraint.GetKind())
	}
	_, err = buildOutputs(template, constraint)
	return err
}

func (d *Driver) RemoveConstraint(ctx context.Context, input *unstructured.Unstructured) error {
	if err := d.check(ctx); err != nil {
		return err
	}
	constraint, err := constraintIdentity(input)
	if err != nil {
		return err
	}
	key := strings.ToLower(constraint.GetKind())
	release, err := d.acquire(ctx, key)
	if err != nil {
		return err
	}
	defer release()
	d.mu.RLock()
	cached := d.constraints[key][constraint.GetName()]
	d.mu.RUnlock()
	if cached != nil {
		if constraint.GetUID() != "" && cached.GetUID() != "" && constraint.GetUID() != cached.GetUID() {
			return fmt.Errorf("%w: stale Constraint deletion UID", ErrOwnership)
		}
		constraint = cached
	}
	if err := d.deleteConstraintObjects(ctx, constraint); err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.constraints[key], constraint.GetName())
	d.mu.Unlock()
	return nil
}

func (d *Driver) AddData(ctx context.Context, target string, _ storage.Path, data interface{}) error {
	if err := d.check(ctx); err != nil {
		return err
	}
	if target == "" || isNil(data) {
		return errors.New("target and data are required")
	}
	return nil
}

func (d *Driver) RemoveData(ctx context.Context, target string, _ storage.Path) error {
	if err := d.check(ctx); err != nil {
		return err
	}
	if target == "" {
		return errors.New("target is required")
	}
	return nil
}

func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, _ ...reviews.ReviewOpt) (*drivers.QueryResponse, error) {
	if err := d.check(ctx); err != nil {
		return nil, err
	}
	if target == "" {
		return nil, errors.New("target is required")
	}
	for _, constraint := range constraints {
		if _, err := constraintIdentity(constraint); err != nil {
			return nil, err
		}
	}
	if target == TargetName && len(constraints) != 0 {
		return nil, ErrReviewUnsupported
	}
	if isNil(review) {
		return nil, errors.New("review is required")
	}
	return &drivers.QueryResponse{}, nil
}

func (d *Driver) Dump(ctx context.Context) (string, error) {
	if err := d.check(ctx); err != nil {
		return "", err
	}
	type entry struct {
		template   *compiledTemplate
		constraint *unstructured.Unstructured
	}
	d.mu.RLock()
	entries := make([]entry, 0)
	for key, byName := range d.constraints {
		for _, constraint := range byName {
			entries = append(entries, entry{template: d.templates[key], constraint: constraint})
		}
	}
	d.mu.RUnlock()
	outputs := make([]*unstructured.Unstructured, 0)
	for _, item := range entries {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		built, err := buildOutputs(item.template, item.constraint)
		if err != nil {
			return "", err
		}
		outputs = append(outputs, built...)
	}
	sortObjects(outputs)
	objects := make([]map[string]interface{}, 0, len(outputs))
	for _, output := range outputs {
		objects = append(objects, output.Object)
	}
	encoded, err := json.MarshalIndent(map[string]interface{}{"agentPolicies": objects}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (d *Driver) GetDescriptionForStat(name string) (string, error) {
	if err := d.ready(); err != nil {
		return "", err
	}
	if name == "" {
		return "", errors.New("statistic name is required")
	}
	return "", errors.New("agent driver does not expose evaluation statistics")
}

func (d *Driver) ReconcileConstraint(ctx context.Context, input *unstructured.Unstructured) (ProjectionStatus, bool, error) {
	fail := func(handled bool, err error) (ProjectionStatus, bool, error) {
		return ProjectionStatus{State: ProjectionError, Message: err.Error()}, handled, err
	}
	if err := d.check(ctx); err != nil {
		return fail(false, err)
	}
	constraint, err := constraintIdentity(input)
	if err != nil {
		return fail(false, err)
	}
	key := strings.ToLower(constraint.GetKind())
	release, err := d.acquire(ctx, key)
	if err != nil {
		return fail(false, err)
	}
	defer release()
	template := d.templateFor(key)
	if template == nil {
		return ProjectionStatus{}, false, nil
	}
	if template.temporal {
		releaseTemporal, err := d.acquire(ctx, "#temporal")
		if err != nil {
			return fail(true, err)
		}
		defer releaseTemporal()
	}
	if constraint.GetDeletionTimestamp() != nil {
		if err := d.deleteConstraintObjects(ctx, constraint); err != nil {
			return fail(true, err)
		}
		d.mu.Lock()
		delete(d.constraints[key], constraint.GetName())
		d.mu.Unlock()
		return ProjectionStatus{State: ProjectionPending, Message: "deleting source; owned projections removed"}, true, nil
	}
	desired, err := buildOutputs(template, constraint)
	if err != nil {
		return fail(true, err)
	}
	if err := d.acceptConstraint(template, constraint); err != nil {
		return fail(true, err)
	}
	status, err := d.project(ctx, constraint, desired, template.temporal)
	if err != nil {
		return fail(true, err)
	}
	return status, true, nil
}
