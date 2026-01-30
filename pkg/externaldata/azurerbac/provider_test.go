package azurerbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockTokenProvider implements TokenProvider for testing.
type mockTokenProvider struct {
	token string
	err   error
}

func (m *mockTokenProvider) GetToken(ctx context.Context) (string, error) {
	return m.token, m.err
}

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name            string
		azureResourceID string
		checkAccessURL  string
		wantErr         bool
	}{
		{
			name:            "valid inputs",
			azureResourceID: "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster",
			checkAccessURL:  "https://management.azure.com",
			wantErr:         false,
		},
		{
			name:            "invalid URL",
			azureResourceID: "/subscriptions/sub-id",
			checkAccessURL:  "://invalid",
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.azureResourceID, tt.checkAccessURL, &mockTokenProvider{token: "test-token"})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewProvider() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && provider == nil {
				t.Error("NewProvider() returned nil provider")
			}
		})
	}
}

func TestProvider_buildDataAction(t *testing.T) {
	provider := &Provider{
		AzureResourceID: "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster",
	}

	tests := []struct {
		name     string
		req      *AuthzRequest
		wantKind string
	}{
		{
			name: "resource request - pods get",
			req: &AuthzRequest{
				IsResourceRequest: true,
				Group:             "",
				Resource:          "pods",
				Subresource:       "",
				Verb:              "get",
				Namespace:         "default",
			},
			wantKind: "Microsoft.KubernetesAuthorization/resources/-/pods/-/get/action",
		},
		{
			name: "resource request - deployments create",
			req: &AuthzRequest{
				IsResourceRequest: true,
				Group:             "apps",
				Resource:          "deployments",
				Subresource:       "",
				Verb:              "create",
				Namespace:         "kube-system",
			},
			wantKind: "Microsoft.KubernetesAuthorization/resources/apps/deployments/-/create/action",
		},
		{
			name: "resource request with subresource",
			req: &AuthzRequest{
				IsResourceRequest: true,
				Group:             "",
				Resource:          "pods",
				Subresource:       "log",
				Verb:              "get",
				Namespace:         "default",
			},
			wantKind: "Microsoft.KubernetesAuthorization/resources/-/pods/log/get/action",
		},
		{
			name: "non-resource request - healthz",
			req: &AuthzRequest{
				IsResourceRequest: false,
				NonResourcePath:   "/healthz",
				Verb:              "get",
			},
			wantKind: "Microsoft.KubernetesAuthorization/nonresources/healthz/-/-/get/action",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := provider.buildDataAction(tt.req)

			if action.Id != "Microsoft.ContainerService/aks-guard-check-access" {
				t.Errorf("buildDataAction() Id = %v, want Microsoft.ContainerService/aks-guard-check-access", action.Id)
			}

			if !action.IsDataAction {
				t.Error("buildDataAction() IsDataAction = false, want true")
			}

			kind := action.Attributes["Microsoft.ContainerService/managedClusters/customResources:kind"]
			if kind != tt.wantKind {
				t.Errorf("buildDataAction() kind = %v, want %v", kind, tt.wantKind)
			}
		})
	}
}

func TestProvider_buildCheckAccessRequest(t *testing.T) {
	provider := &Provider{
		AzureResourceID: "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster",
	}

	tests := []struct {
		name    string
		req     *AuthzRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: &AuthzRequest{
				User:              "user@example.com",
				Groups:            []string{"group1", "system:authenticated"},
				OID:               "user-oid-123",
				Namespace:         "default",
				Resource:          "pods",
				Verb:              "get",
				IsResourceRequest: true,
			},
			wantErr: false,
		},
		{
			name: "missing OID",
			req: &AuthzRequest{
				User:              "user@example.com",
				Namespace:         "default",
				Resource:          "pods",
				Verb:              "get",
				IsResourceRequest: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkReq, err := provider.buildCheckAccessRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildCheckAccessRequest() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if checkReq.Subject.Attributes.ObjectId != tt.req.OID {
					t.Errorf("buildCheckAccessRequest() ObjectId = %v, want %v", checkReq.Subject.Attributes.ObjectId, tt.req.OID)
				}

				// Verify system groups are filtered
				for _, g := range checkReq.Subject.Attributes.Groups {
					if g == "system:authenticated" {
						t.Error("buildCheckAccessRequest() should filter out system: groups")
					}
				}

				if len(checkReq.Actions) != 1 {
					t.Errorf("buildCheckAccessRequest() Actions length = %v, want 1", len(checkReq.Actions))
				}
			}
		})
	}
}

func TestProvider_CheckAccess(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseBody   CheckAccessResponse
		wantAllowed    bool
		wantErr        bool
	}{
		{
			name:           "access allowed",
			responseStatus: http.StatusOK,
			responseBody: CheckAccessResponse{
				AccessDecisions: []AccessDecision{
					{ActionId: "action1", AccessDecision: "Allowed", IsDataAction: true},
				},
			},
			wantAllowed: true,
			wantErr:     false,
		},
		{
			name:           "access denied",
			responseStatus: http.StatusOK,
			responseBody: CheckAccessResponse{
				AccessDecisions: []AccessDecision{
					{ActionId: "action1", AccessDecision: "Denied", IsDataAction: true},
				},
			},
			wantAllowed: false,
			wantErr:     false,
		},
		{
			name:           "no decisions",
			responseStatus: http.StatusOK,
			responseBody: CheckAccessResponse{
				AccessDecisions: []AccessDecision{},
			},
			wantAllowed: false,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseStatus)
				json.NewEncoder(w).Encode(tt.responseBody)
			}))
			defer server.Close()

			provider, err := NewProvider(
				"/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster",
				server.URL,
				&mockTokenProvider{token: "test-token"},
			)
			if err != nil {
				t.Fatalf("NewProvider() error = %v", err)
			}

			allowed, _, err := provider.CheckAccess(context.Background(), &AuthzRequest{
				User:              "user@example.com",
				OID:               "user-oid-123",
				Namespace:         "default",
				Resource:          "pods",
				Verb:              "get",
				IsResourceRequest: true,
			})

			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAccess() error = %v, wantErr %v", err, tt.wantErr)
			}

			if allowed != tt.wantAllowed {
				t.Errorf("CheckAccess() allowed = %v, want %v", allowed, tt.wantAllowed)
			}
		})
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "-"},
		{"-", "*"},
		{"pods", "pods"},
		{"apps/v1", "*"},
		{"deployments", "deployments"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := sanitizePath(tt.input); got != tt.want {
				t.Errorf("sanitizePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilterValidGroups(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		want   int
	}{
		{
			name:   "filter system groups",
			groups: []string{"group1", "system:authenticated", "system:masters", "group2"},
			want:   2,
		},
		{
			name:   "no system groups",
			groups: []string{"group1", "group2"},
			want:   2,
		},
		{
			name:   "only system groups",
			groups: []string{"system:authenticated"},
			want:   0,
		},
		{
			name:   "empty groups",
			groups: []string{},
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterValidGroups(tt.groups)
			if len(filtered) != tt.want {
				t.Errorf("filterValidGroups() returned %d groups, want %d", len(filtered), tt.want)
			}
		})
	}
}
