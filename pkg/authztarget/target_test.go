package authztarget

import (
	"testing"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/authorization"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestK8sAuthorizationTarget_GetName(t *testing.T) {
	target := K8sAuthorizationTarget{}
	if got := target.GetName(); got != Name {
		t.Errorf("GetName() = %v, want %v", got, Name)
	}
}

func TestK8sAuthorizationTarget_ProcessData(t *testing.T) {
	target := K8sAuthorizationTarget{}
	// ProcessData should return handled=false for authorization target (no data caching needed)
	handled, _, _, err := target.ProcessData(nil)
	if err != nil {
		t.Errorf("ProcessData() error = %v, want nil", err)
	}
	if handled {
		t.Error("ProcessData() handled = true, want false")
	}
}

func TestK8sAuthorizationTarget_HandleReview(t *testing.T) {
	target := K8sAuthorizationTarget{}

	tests := []struct {
		name       string
		input      interface{}
		wantErr    bool
		wantHandle bool
	}{
		{
			name: "valid SubjectAccessReview",
			input: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "test-user",
					Groups: []string{"group1"},
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "default",
						Verb:      "get",
						Resource:  "pods",
					},
				},
			},
			wantErr:    false,
			wantHandle: true,
		},
		{
			name: "valid authorization.Review",
			input: &authorization.Review{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
				},
			},
			wantErr:    false,
			wantHandle: true,
		},
		{
			name:       "invalid input type",
			input:      "invalid",
			wantErr:    false,
			wantHandle: false,
		},
		{
			name:       "nil input",
			input:      nil,
			wantErr:    false,
			wantHandle: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handled, _, err := target.HandleReview(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("HandleReview() error = %v, wantErr %v", err, tt.wantErr)
			}
			if handled != tt.wantHandle {
				t.Errorf("HandleReview() handled = %v, want %v", handled, tt.wantHandle)
			}
		})
	}
}

func TestK8sAuthorizationTarget_HandleReview_ReviewContent(t *testing.T) {
	target := K8sAuthorizationTarget{}

	input := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   "test-user",
			Groups: []string{"group1", "group2"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "test-ns",
				Verb:      "create",
				Group:     "apps",
				Resource:  "deployments",
				Name:      "my-deployment",
			},
			Extra: map[string]authorizationv1.ExtraValue{
				"oid": {"user-oid-123"},
			},
		},
	}

	handled, result, err := target.HandleReview(input)
	if err != nil {
		t.Fatalf("HandleReview() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleReview() handled = false, want true")
	}

	// Result should be an authzReview wrapping the Review
	authzRev, ok := result.(*authzReview)
	if !ok {
		t.Fatalf("HandleReview() did not return *authzReview, got %T", result)
	}

	if authzRev.Review.GetUser() != "test-user" {
		t.Errorf("GetUser() = %v, want test-user", authzRev.Review.GetUser())
	}

	if authzRev.Review.GetNamespace() != "test-ns" {
		t.Errorf("GetNamespace() = %v, want test-ns", authzRev.Review.GetNamespace())
	}

	if authzRev.Review.GetOID() != "user-oid-123" {
		t.Errorf("GetOID() = %v, want user-oid-123", authzRev.Review.GetOID())
	}
}

func TestK8sAuthorizationTarget_MatchSchema(t *testing.T) {
	target := K8sAuthorizationTarget{}
	schema := target.MatchSchema()

	// Verify the schema has expected structure
	props := schema.Properties
	if props == nil {
		t.Fatal("MatchSchema() Properties is nil")
	}

	// Check for expected properties
	expectedProps := []string{"users", "groups", "resources", "namespaces", "excludedNamespaces"}
	for _, prop := range expectedProps {
		if _, ok := props[prop]; !ok {
			t.Errorf("MatchSchema() missing property: %s", prop)
		}
	}
}

func TestK8sAuthorizationTarget_ValidateConstraint(t *testing.T) {
	target := K8sAuthorizationTarget{}

	// ValidateConstraint should accept nil (no constraint)
	err := target.ValidateConstraint(nil)
	if err != nil {
		t.Errorf("ValidateConstraint(nil) error = %v", err)
	}

	// Test with a valid constraint
	constraint := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"match": map[string]interface{}{
					"users": []interface{}{"user1"},
				},
			},
		},
	}
	err = target.ValidateConstraint(constraint)
	if err != nil {
		t.Errorf("ValidateConstraint() error = %v", err)
	}
}

func TestK8sAuthorizationTarget_ToMatcher(t *testing.T) {
	target := K8sAuthorizationTarget{}

	tests := []struct {
		name       string
		constraint *unstructured.Unstructured
		wantErr    bool
	}{
		{
			name:       "nil constraint",
			constraint: nil,
			wantErr:    true, // nil constraint should error
		},
		{
			name: "valid constraint with match",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{
						"match": map[string]interface{}{
							"users":      []interface{}{"user1"},
							"groups":     []interface{}{"group1"},
							"namespaces": []interface{}{"default"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "constraint without match",
			constraint: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"spec": map[string]interface{}{},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := target.ToMatcher(tt.constraint)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToMatcher() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthzMatcher_Match(t *testing.T) {
	tests := []struct {
		name    string
		match   AuthzMatch
		review  *authorization.Review
		want    bool
		wantErr bool
	}{
		{
			name:  "empty match matches all",
			match: AuthzMatch{},
			review: &authorization.Review{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "any-user",
					Groups: []string{"any-group"},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "user match",
			match: AuthzMatch{
				Users: []string{"allowed-user"},
			},
			review: &authorization.Review{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "allowed-user",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "user mismatch",
			match: AuthzMatch{
				Users: []string{"allowed-user"},
			},
			review: &authorization.Review{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "other-user",
				},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "group match",
			match: AuthzMatch{
				Groups: []string{"allowed-group"},
			},
			review: &authorization.Review{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:   "any-user",
					Groups: []string{"allowed-group", "other-group"},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "namespace match",
			match: AuthzMatch{
				Namespaces: []string{"default", "kube-system"},
			},
			review: &authorization.Review{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "any-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "default",
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "excluded namespace",
			match: AuthzMatch{
				ExcludedNamespaces: []string{"kube-system"},
			},
			review: &authorization.Review{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "any-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "kube-system",
					},
				},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "wildcard namespace match",
			match: AuthzMatch{
				ExcludedNamespaces: []string{"kube-*"},
			},
			review: &authorization.Review{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "any-user",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "kube-public",
					},
				},
			},
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &AuthzMatcher{match: &tt.match}
			got, err := matcher.Match(tt.review)
			if (err != nil) != tt.wantErr {
				t.Errorf("Match() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}
