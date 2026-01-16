package authztarget

import (
	"encoding/json"
	"strings"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/authorization"
	"github.com/pkg/errors"
)

// AuthzMatch defines the match criteria for authorization constraints.
type AuthzMatch struct {
	// Users is a list of users to match. Empty means match all.
	Users []string `json:"users,omitempty"`

	// Groups is a list of groups to match. Empty means match all.
	Groups []string `json:"groups,omitempty"`

	// Resources defines resource-based matching rules.
	Resources []ResourceRule `json:"resources,omitempty"`

	// Namespaces is a list of namespaces to match. Empty means match all.
	Namespaces []string `json:"namespaces,omitempty"`

	// ExcludedNamespaces is a list of namespaces to exclude.
	ExcludedNamespaces []string `json:"excludedNamespaces,omitempty"`
}

// ResourceRule defines a rule for matching resource requests.
type ResourceRule struct {
	// APIGroups is a list of API groups to match. "*" matches all.
	APIGroups []string `json:"apiGroups,omitempty"`

	// Resources is a list of resources to match. "*" matches all.
	Resources []string `json:"resources,omitempty"`

	// Verbs is a list of verbs to match. "*" matches all.
	Verbs []string `json:"verbs,omitempty"`
}

// AuthzMatcher implements the Matcher interface for authorization reviews.
type AuthzMatcher struct {
	match *AuthzMatch
}

// Match returns true if the review matches this constraint's criteria.
func (m *AuthzMatcher) Match(review interface{}) (bool, error) {
	switch r := review.(type) {
	case *authzReview:
		return m.matchAuthzReview(r.Review), nil
	case *authorization.Review:
		return m.matchAuthzReview(r), nil
	default:
		return false, nil
	}
}

// matchAuthzReview performs the actual matching logic.
func (m *AuthzMatcher) matchAuthzReview(review *authorization.Review) bool {
	if m.match == nil {
		return true
	}

	// Check user match
	if len(m.match.Users) > 0 {
		if !containsString(m.match.Users, review.GetUser()) {
			return false
		}
	}

	// Check group match
	if len(m.match.Groups) > 0 {
		if !hasCommonElement(m.match.Groups, review.GetGroups()) {
			return false
		}
	}

	// Check namespace match
	if len(m.match.Namespaces) > 0 {
		ns := review.GetNamespace()
		if !containsString(m.match.Namespaces, ns) && !matchesWildcard(m.match.Namespaces, ns) {
			return false
		}
	}

	// Check excluded namespaces
	if len(m.match.ExcludedNamespaces) > 0 {
		ns := review.GetNamespace()
		if containsString(m.match.ExcludedNamespaces, ns) || matchesWildcard(m.match.ExcludedNamespaces, ns) {
			return false
		}
	}

	// Check resource rules
	if len(m.match.Resources) > 0 && review.IsResourceRequest() {
		if !m.matchesResourceRules(review) {
			return false
		}
	}

	return true
}

// matchesResourceRules checks if the review matches any of the resource rules.
func (m *AuthzMatcher) matchesResourceRules(review *authorization.Review) bool {
	for _, rule := range m.match.Resources {
		if m.matchesResourceRule(rule, review) {
			return true
		}
	}
	return false
}

// matchesResourceRule checks if the review matches a specific resource rule.
func (m *AuthzMatcher) matchesResourceRule(rule ResourceRule, review *authorization.Review) bool {
	// Check API group
	if len(rule.APIGroups) > 0 {
		if !matchesPattern(rule.APIGroups, review.GetGroup()) {
			return false
		}
	}

	// Check resource
	if len(rule.Resources) > 0 {
		if !matchesPattern(rule.Resources, review.GetResource()) {
			return false
		}
	}

	// Check verb
	if len(rule.Verbs) > 0 {
		if !matchesPattern(rule.Verbs, review.GetVerb()) {
			return false
		}
	}

	return true
}

// containsString checks if a string slice contains a specific string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// hasCommonElement checks if two string slices have any common elements.
func hasCommonElement(a, b []string) bool {
	for _, item := range a {
		if containsString(b, item) {
			return true
		}
	}
	return false
}

// matchesPattern checks if a value matches any pattern in the list.
// Supports "*" as a wildcard that matches everything.
func matchesPattern(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == value {
			return true
		}
	}
	return false
}

// matchesWildcard checks if a value matches any wildcard pattern.
// Supports "*" suffix for prefix matching (e.g., "kube-*" matches "kube-system").
func matchesWildcard(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(value, prefix) {
				return true
			}
		}
	}
	return false
}

// convertToAuthzMatch converts a map to AuthzMatch.
func convertToAuthzMatch(obj map[string]interface{}) (*AuthzMatch, error) {
	j, err := json.Marshal(obj)
	if err != nil {
		return nil, errors.Wrap(err, "could not convert object to JSON")
	}
	match := &AuthzMatch{}
	if err := json.Unmarshal(j, match); err != nil {
		return nil, errors.Wrap(err, "could not convert JSON to AuthzMatch")
	}
	return match, nil
}
