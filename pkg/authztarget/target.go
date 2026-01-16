/*
Package authztarget provides the Kubernetes authorization target handler for Gatekeeper.

This package implements the authorization webhook target that processes
SubjectAccessReview requests and evaluates them against Gatekeeper constraints.
It enables fine-grained authorization policies based on user identity, groups,
resource attributes, and external data sources like Azure RBAC.
*/
package authztarget

import (
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/authorization"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/authzhandler"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Name is the name of Gatekeeper's Kubernetes authorization target.
const Name = "authorization.k8s.gatekeeper.sh"

// K8sAuthorizationTarget handles SubjectAccessReview requests for Gatekeeper.
type K8sAuthorizationTarget struct{}

var (
	_ handler.TargetHandler                   = &K8sAuthorizationTarget{}
	_ authzhandler.AuthorizationTargetHandler = &K8sAuthorizationTarget{}
)

// GetName returns the name of the authorization target.
func (h *K8sAuthorizationTarget) GetName() string {
	return Name
}

// ProcessData handles data synchronization for the authorization target.
// For authorization, we typically don't need to cache objects in the same way
// as admission, but we can cache user/group/role information if needed.
func (h *K8sAuthorizationTarget) ProcessData(obj interface{}) (bool, []string, interface{}, error) {
	// Authorization target doesn't process inventory data the same way as admission
	// It primarily evaluates requests against external data sources
	return false, nil, nil, nil
}

// HandleReview processes incoming review requests and determines if this target
// should handle them.
func (h *K8sAuthorizationTarget) HandleReview(obj interface{}) (bool, interface{}, error) {
	switch data := obj.(type) {
	case authorization.Review:
		return h.handleAuthzReview(&data)
	case *authorization.Review:
		return h.handleAuthzReview(data)
	case authorizationv1.SubjectAccessReview:
		review := authorization.NewReview(data.Spec)
		return h.handleAuthzReview(review)
	case *authorizationv1.SubjectAccessReview:
		review := authorization.NewReview(data.Spec)
		return h.handleAuthzReview(review)
	case authorizationv1.SubjectAccessReviewSpec:
		review := authorization.NewReview(data)
		return h.handleAuthzReview(review)
	case *authorizationv1.SubjectAccessReviewSpec:
		review := authorization.NewReview(*data)
		return h.handleAuthzReview(review)
	default:
		return false, nil, nil
	}
}

// HandleAuthzReview implements the AuthorizationTargetHandler interface.
func (h *K8sAuthorizationTarget) HandleAuthzReview(review *authorization.Review) (bool, interface{}, error) {
	return h.handleAuthzReview(review)
}

// handleAuthzReview processes an authorization review and builds the input for policy evaluation.
func (h *K8sAuthorizationTarget) handleAuthzReview(review *authorization.Review) (bool, *authzReview, error) {
	return true, &authzReview{Review: review}, nil
}

// authzReview wraps an authorization review with additional context for Rego evaluation.
type authzReview struct {
	Review *authorization.Review
}

// MarshalJSON implements json.Marshaler for authzReview.
// This formats the review data for Rego input.
func (r *authzReview) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Review.ToRegoInput())
}

// MatchSchema returns the JSON schema for matching authorization constraints.
func (h *K8sAuthorizationTarget) MatchSchema() apiextensions.JSONSchemaProps {
	return authzMatchSchema()
}

// ValidateConstraint validates that a constraint is properly configured for authorization.
func (h *K8sAuthorizationTarget) ValidateConstraint(u *unstructured.Unstructured) error {
	if u == nil {
		return nil
	}

	// Validate the match configuration
	_, found, err := unstructured.NestedMap(u.Object, "spec", "match")
	if err != nil {
		return err
	}

	if found {
		// Additional validation for authorization-specific match fields can be added here
	}

	return nil
}

// ToMatcher converts a constraint to a matcher for authorization requests.
func (h *K8sAuthorizationTarget) ToMatcher(u *unstructured.Unstructured) (constraints.Matcher, error) {
	if u == nil {
		return nil, fmt.Errorf("constraint cannot be nil")
	}

	obj, found, err := unstructured.NestedMap(u.Object, "spec", "match")
	if err != nil {
		return nil, fmt.Errorf("error getting match from constraint: %w", err)
	}

	if found && obj != nil {
		m, err := convertToAuthzMatch(obj)
		if err != nil {
			return nil, fmt.Errorf("error converting match to AuthzMatch: %w", err)
		}
		return &AuthzMatcher{match: m}, nil
	}

	return &AuthzMatcher{}, nil
}

// authzMatchSchema returns the JSON schema for authorization constraint matching.
func authzMatchSchema() apiextensions.JSONSchemaProps {
	return apiextensions.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextensions.JSONSchemaProps{
			"users": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{Type: "string"},
				},
				Description: "List of users to match. Empty means match all users.",
			},
			"groups": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{Type: "string"},
				},
				Description: "List of groups to match. Empty means match all groups.",
			},
			"resources": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{
						Type: "object",
						Properties: map[string]apiextensions.JSONSchemaProps{
							"apiGroups": {
								Type: "array",
								Items: &apiextensions.JSONSchemaPropsOrArray{
									Schema: &apiextensions.JSONSchemaProps{Type: "string"},
								},
							},
							"resources": {
								Type: "array",
								Items: &apiextensions.JSONSchemaPropsOrArray{
									Schema: &apiextensions.JSONSchemaProps{Type: "string"},
								},
							},
							"verbs": {
								Type: "array",
								Items: &apiextensions.JSONSchemaPropsOrArray{
									Schema: &apiextensions.JSONSchemaProps{Type: "string"},
								},
							},
						},
					},
				},
				Description: "List of resource rules to match.",
			},
			"namespaces": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{Type: "string"},
				},
				Description: "List of namespaces to match. Empty means match all namespaces.",
			},
			"excludedNamespaces": {
				Type: "array",
				Items: &apiextensions.JSONSchemaPropsOrArray{
					Schema: &apiextensions.JSONSchemaProps{Type: "string"},
				},
				Description: "List of namespaces to exclude.",
			},
		},
	}
}
