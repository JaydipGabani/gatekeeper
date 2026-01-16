/*
Package azurerbac provides an external data provider for Azure RBAC integration.

This package implements a Gatekeeper external data provider that calls the
Azure RBAC CheckAccess API to evaluate authorization decisions. It enables
Gatekeeper authorization policies to leverage Azure RBAC with ABAC conditions
for fine-grained access control.

The provider converts Kubernetes SubjectAccessReview attributes into the
Azure RBAC format expected by the CheckAccess API, similar to how AKS Guard
handles authorization.
*/
package azurerbac

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-logr/logr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("azure-rbac-provider")

// Provider implements the external data provider interface for Azure RBAC.
type Provider struct {
	// AzureResourceID is the Azure resource ID of the AKS cluster.
	AzureResourceID string

	// CheckAccessURL is the URL for the Azure CheckAccess API.
	CheckAccessURL *url.URL

	// TokenProvider provides Azure AD tokens for authentication.
	TokenProvider TokenProvider

	// HTTPClient is the HTTP client for making requests.
	HTTPClient *http.Client

	// Logger for logging.
	Logger logr.Logger
}

// TokenProvider provides Azure AD tokens.
type TokenProvider interface {
	GetToken(ctx context.Context) (string, error)
}

// CheckAccessRequest is the request body for the Azure CheckAccess API.
type CheckAccessRequest struct {
	Subject  Subject                   `json:"Subject"`
	Actions  []AuthorizationActionInfo `json:"Actions"`
	Resource AuthorizationResourceInfo `json:"Resource"`
}

// Subject represents the user/principal making the request.
type Subject struct {
	Attributes SubjectAttributes `json:"Attributes"`
}

// SubjectAttributes contains the principal's identity information.
type SubjectAttributes struct {
	ObjectId string   `json:"ObjectId"`
	Groups   []string `json:"Groups,omitempty"`
}

// AuthorizationActionInfo represents an action to check access for.
type AuthorizationActionInfo struct {
	Id           string            `json:"Id"`
	IsDataAction bool              `json:"IsDataAction"`
	Attributes   map[string]string `json:"Attributes,omitempty"`
}

// AuthorizationResourceInfo represents the resource being accessed.
type AuthorizationResourceInfo struct {
	Id string `json:"Id"`
}

// CheckAccessResponse is the response from the Azure CheckAccess API.
type CheckAccessResponse struct {
	AccessDecisions []AccessDecision `json:"value"`
}

// AccessDecision represents an individual access decision.
type AccessDecision struct {
	ActionId       string `json:"actionId"`
	AccessDecision string `json:"accessDecision"`
	IsDataAction   bool   `json:"isDataAction"`
}

// AuthzRequest represents a Kubernetes authorization request for Azure RBAC evaluation.
type AuthzRequest struct {
	User              string
	Groups            []string
	OID               string
	Namespace         string
	Group             string
	Resource          string
	Subresource       string
	Verb              string
	Name              string
	NonResourcePath   string
	IsResourceRequest bool
}

// NewProvider creates a new Azure RBAC provider.
func NewProvider(azureResourceID string, checkAccessURL string, tokenProvider TokenProvider) (*Provider, error) {
	parsedURL, err := url.Parse(checkAccessURL)
	if err != nil {
		return nil, fmt.Errorf("invalid check access URL: %w", err)
	}

	return &Provider{
		AzureResourceID: azureResourceID,
		CheckAccessURL:  parsedURL,
		TokenProvider:   tokenProvider,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		Logger: log,
	}, nil
}

// CheckAccess evaluates the authorization request against Azure RBAC.
func (p *Provider) CheckAccess(ctx context.Context, req *AuthzRequest) (bool, string, error) {
	// Build the CheckAccess request
	checkAccessReq, err := p.buildCheckAccessRequest(req)
	if err != nil {
		return false, "", fmt.Errorf("failed to build check access request: %w", err)
	}

	// Get the Azure AD token
	token, err := p.TokenProvider.GetToken(ctx)
	if err != nil {
		return false, "", fmt.Errorf("failed to get token: %w", err)
	}

	// Make the CheckAccess API call
	response, err := p.callCheckAccessAPI(ctx, checkAccessReq, token)
	if err != nil {
		return false, "", fmt.Errorf("check access API call failed: %w", err)
	}

	// Process the response
	return p.processResponse(response)
}

// buildCheckAccessRequest builds the Azure CheckAccess request from a Kubernetes authz request.
func (p *Provider) buildCheckAccessRequest(req *AuthzRequest) (*CheckAccessRequest, error) {
	if req.OID == "" {
		return nil, fmt.Errorf("OID is required for Azure RBAC check")
	}

	// Build the action using the V2 format (matching Guard patch)
	action := p.buildDataAction(req)

	checkReq := &CheckAccessRequest{
		Subject: Subject{
			Attributes: SubjectAttributes{
				ObjectId: req.OID,
				Groups:   filterValidGroups(req.Groups),
			},
		},
		Actions: []AuthorizationActionInfo{action},
		Resource: AuthorizationResourceInfo{
			Id: p.AzureResourceID,
		},
	}

	return checkReq, nil
}

// buildDataAction builds the data action for Azure RBAC in the V2 format.
// Format: Microsoft.KubernetesAuthorization/resources/<group>/<resource>/<subresource>/<verb>/action
func (p *Provider) buildDataAction(req *AuthzRequest) AuthorizationActionInfo {
	var actionPath string
	var attributes map[string]string

	if req.IsResourceRequest {
		// Resource request format
		pathComponents := []string{
			"Microsoft.KubernetesAuthorization",
			"resources",
			sanitizePath(req.Group),
			sanitizePath(req.Resource),
			sanitizePath(req.Subresource),
			sanitizePath(req.Verb),
			"action",
		}
		actionPath = strings.Join(pathComponents, "/")
		attributes = map[string]string{
			"Microsoft.ContainerService/managedClusters/customResources:kind":  actionPath,
			"Microsoft.ContainerService/managedClusters/customResources:group": req.Namespace,
		}
	} else {
		// Non-resource request format
		pathComponents := []string{
			"Microsoft.KubernetesAuthorization",
			"nonresources",
			sanitizeNonResourcePath(req.NonResourcePath),
			sanitizePath(req.Verb),
			"action",
		}
		actionPath = strings.Join(pathComponents, "/")
		attributes = map[string]string{
			"Microsoft.ContainerService/managedClusters/customResources:kind":  actionPath,
			"Microsoft.ContainerService/managedClusters/customResources:group": req.NonResourcePath,
		}
	}

	return AuthorizationActionInfo{
		Id:           "Microsoft.ContainerService/aks-guard-check-access",
		IsDataAction: true,
		Attributes:   attributes,
	}
}

// callCheckAccessAPI makes the HTTP request to the Azure CheckAccess API.
func (p *Provider) callCheckAccessAPI(ctx context.Context, req *CheckAccessRequest, token string) (*CheckAccessResponse, error) {
	// Build the URL
	checkAccessURL := p.buildCheckAccessURL()

	// Marshal the request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	p.Logger.V(5).Info("calling Azure CheckAccess API",
		"url", checkAccessURL,
		"requestBody", string(reqBody),
	)

	// Create the HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, checkAccessURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	// Make the request
	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check access API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the response
	var checkAccessResp CheckAccessResponse
	if err := json.Unmarshal(respBody, &checkAccessResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &checkAccessResp, nil
}

// buildCheckAccessURL builds the URL for the CheckAccess API.
func (p *Provider) buildCheckAccessURL() string {
	// Format: https://management.azure.com/{resourceId}/providers/Microsoft.Authorization/checkAccess?api-version=2018-09-01-preview
	u := *p.CheckAccessURL
	u.Path = path.Join(p.AzureResourceID, "providers/Microsoft.Authorization/checkAccess")
	q := u.Query()
	q.Set("api-version", "2018-09-01-preview")
	u.RawQuery = q.Encode()
	return u.String()
}

// processResponse processes the CheckAccess API response.
func (p *Provider) processResponse(resp *CheckAccessResponse) (bool, string, error) {
	if len(resp.AccessDecisions) == 0 {
		return false, "no access decisions returned", nil
	}

	// Check if all actions are allowed
	for _, decision := range resp.AccessDecisions {
		if decision.AccessDecision != "Allowed" {
			return false, fmt.Sprintf("Azure RBAC denied: action %s is %s", decision.ActionId, decision.AccessDecision), nil
		}
	}

	return true, "Azure RBAC allowed", nil
}

// sanitizePath sanitizes a path component for Azure RBAC format.
func sanitizePath(attr string) string {
	if len(attr) == 0 {
		return "-"
	}
	if attr == "-" {
		return "*"
	}
	if strings.Contains(attr, "/") {
		return "*"
	}
	return attr
}

// sanitizeNonResourcePath sanitizes a non-resource path for Azure RBAC format.
func sanitizeNonResourcePath(attr string) string {
	segments := strings.Split(strings.Trim(attr, "/"), "/")
	for len(segments) < 3 {
		segments = append(segments, "-")
	}
	if len(segments) > 3 {
		segments = segments[:3]
	}
	return strings.Join(segments, "/")
}

// filterValidGroups filters groups to only include valid Azure AD security groups.
func filterValidGroups(groups []string) []string {
	var validGroups []string
	for _, g := range groups {
		// Filter out Kubernetes system groups
		if strings.HasPrefix(g, "system:") {
			continue
		}
		validGroups = append(validGroups, g)
	}
	return validGroups
}
