package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/authorization"
	authorizationv1 "k8s.io/api/authorization/v1"
)

// TestCase represents a single authorization test case.
type TestCase struct {
	Name           string
	User           string
	Groups         []string
	Namespace      string
	Resource       string
	Verb           string
	ExpectAllowed  bool
	ExpectedReason string
}

func main() {
	// Define test cases
	testCases := []TestCase{
		{
			Name:           "USE CASE 1: Denied User - bad-actor@example.com",
			User:           "bad-actor@example.com",
			Groups:         []string{"developers"},
			Namespace:      "default",
			Resource:       "pods",
			Verb:           "get",
			ExpectAllowed:  false,
			ExpectedReason: "User is in deny list",
		},
		{
			Name:           "USE CASE 2: Protected Namespace - kube-system",
			User:           "alice@example.com",
			Groups:         []string{"developers"},
			Namespace:      "kube-system",
			Resource:       "pods",
			Verb:           "get",
			ExpectAllowed:  false,
			ExpectedReason: "Namespace is protected",
		},
		{
			Name:           "USE CASE 3: Read-Only Group Trying to Create",
			User:           "viewer@example.com",
			Groups:         []string{"viewers"},
			Namespace:      "default",
			Resource:       "pods",
			Verb:           "create",
			ExpectAllowed:  false,
			ExpectedReason: "Read-only group cannot create",
		},
		{
			Name:           "USE CASE 4: Read-Only Group Can List (Allowed)",
			User:           "auditor@example.com",
			Groups:         []string{"auditors"},
			Namespace:      "default",
			Resource:       "pods",
			Verb:           "list",
			ExpectAllowed:  true,
			ExpectedReason: "Read-only verb is allowed",
		},
		{
			Name:           "USE CASE 5: Admin Bypasses All Checks",
			User:           "admin@example.com",
			Groups:         []string{"cluster-admins"},
			Namespace:      "kube-system",
			Resource:       "secrets",
			Verb:           "delete",
			ExpectAllowed:  true,
			ExpectedReason: "Admin group bypasses all restrictions",
		},
		{
			Name:           "USE CASE 6: Normal User - Allowed in Default Namespace",
			User:           "developer@example.com",
			Groups:         []string{"developers"},
			Namespace:      "default",
			Resource:       "pods",
			Verb:           "create",
			ExpectAllowed:  true,
			ExpectedReason: "Normal user, no restrictions apply",
		},
	}

	fmt.Println("=" + repeatString("=", 79))
	fmt.Println("AUTHORIZATION WEBHOOK TEST CASES")
	fmt.Println("Testing the Simple Authorization Policy (No External Data Required)")
	fmt.Println("=" + repeatString("=", 79))
	fmt.Println()

	// Policy parameters
	params := map[string]interface{}{
		"deniedUsers":      []string{"bad-actor@example.com", "former-employee@example.com"},
		"deniedNamespaces": []string{"kube-system", "gatekeeper-system"},
		"readOnlyGroups":   []string{"viewers", "auditors"},
		"adminGroups":      []string{"cluster-admins", "platform-team"},
	}

	passed := 0
	failed := 0

	for _, tc := range testCases {
		fmt.Printf("### %s\n", tc.Name)
		fmt.Printf("    User: %s\n", tc.User)
		fmt.Printf("    Groups: %v\n", tc.Groups)
		fmt.Printf("    Action: %s %s in namespace '%s'\n", tc.Verb, tc.Resource, tc.Namespace)
		fmt.Printf("    Expected: %s\n", tc.ExpectedReason)

		// Create SubjectAccessReview
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   tc.User,
				Groups: tc.Groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: tc.Namespace,
					Resource:  tc.Resource,
					Verb:      tc.Verb,
				},
			},
		}

		// Convert to Review using the authorization package
		review := authorization.NewReview(sar.Spec)

		// Get Rego input
		input := review.ToRegoInput()

		// Simulate policy evaluation by checking the input against policy rules
		allowed, reason := evaluatePolicy(input, params)

		result := "✓ PASS"
		if allowed != tc.ExpectAllowed {
			result = "✗ FAIL"
			failed++
		} else {
			passed++
		}

		fmt.Printf("    Result: %s (Allowed: %v, Reason: %s)\n", result, allowed, reason)
		fmt.Println()
	}

	fmt.Println("=" + repeatString("=", 79))
	fmt.Printf("SUMMARY: %d PASSED, %d FAILED out of %d test cases\n", passed, failed, len(testCases))
	fmt.Println("=" + repeatString("=", 79))

	if failed > 0 {
		os.Exit(1)
	}
}

// evaluatePolicy simulates the Rego policy evaluation.
func evaluatePolicy(input map[string]interface{}, params map[string]interface{}) (bool, string) {
	user := input["user"].(string)
	groups := input["groups"].([]string)

	resourceAttrs, ok := input["resourceAttributes"].(map[string]interface{})
	if !ok {
		return true, "No resource attributes"
	}

	ns := ""
	if v, ok := resourceAttrs["namespace"]; ok && v != nil {
		ns = v.(string)
	}
	verb := ""
	if v, ok := resourceAttrs["verb"]; ok && v != nil {
		verb = v.(string)
	}

	// Check if admin
	adminGroups := params["adminGroups"].([]string)
	for _, g := range groups {
		for _, ag := range adminGroups {
			if g == ag {
				return true, "Admin group bypass"
			}
		}
	}

	// Check denied users
	deniedUsers := params["deniedUsers"].([]string)
	for _, du := range deniedUsers {
		if user == du {
			return false, "User in deny list"
		}
	}

	// Check denied namespaces
	deniedNs := params["deniedNamespaces"].([]string)
	for _, dns := range deniedNs {
		if ns == dns {
			return false, "Namespace protected"
		}
	}

	// Check read-only groups
	readOnlyGroups := params["readOnlyGroups"].([]string)
	isReadOnly := false
	for _, g := range groups {
		for _, rog := range readOnlyGroups {
			if g == rog {
				isReadOnly = true
				break
			}
		}
	}

	if isReadOnly {
		if verb != "get" && verb != "list" && verb != "watch" {
			return false, "Read-only group violation"
		}
	}

	return true, "Allowed"
}

func repeatString(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}

func prettyJSON(v interface{}) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
