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
	"errors"

	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var _ handler.TargetHandler = &Target{}

type Target struct {
	driver *Driver
}

func NewTarget(driver *Driver) *Target { return &Target{driver: driver} }

func (*Target) GetName() string { return TargetName }

func (t *Target) ProcessData(data interface{}) (bool, []string, interface{}, error) {
	if t == nil || t.driver == nil || isNil(data) {
		return false, nil, nil, errors.New("agent target and data are required")
	}
	return false, nil, nil, nil
}

func (t *Target) HandleReview(review interface{}) (bool, interface{}, error) {
	if t == nil || t.driver == nil || isNil(review) {
		return false, nil, errors.New("agent target and review are required")
	}
	return false, nil, nil
}

func (*Target) MatchSchema() apiextensions.JSONSchemaProps {
	zero := int64(0)
	return apiextensions.JSONSchemaProps{
		Type: "object", MaxProperties: &zero,
	}
}

func (t *Target) ValidateConstraint(constraint *unstructured.Unstructured) error {
	if t == nil || t.driver == nil {
		return errors.New("agent target requires a driver")
	}
	return t.driver.validateConstraint(constraint)
}

func (t *Target) ToMatcher(constraint *unstructured.Unstructured) (constraints.Matcher, error) {
	if err := t.ValidateConstraint(constraint); err != nil {
		return nil, err
	}
	return noReviewMatcher{}, nil
}

type noReviewMatcher struct{}

func (noReviewMatcher) Match(review interface{}) (bool, error) {
	if isNil(review) {
		return false, errors.New("review is required")
	}
	return false, nil
}
