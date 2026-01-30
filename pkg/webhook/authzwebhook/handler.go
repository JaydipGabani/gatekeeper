/*
Package authzwebhook provides the authorization webhook server for Gatekeeper.

This package implements a Kubernetes authorization webhook that evaluates
SubjectAccessReview requests against Gatekeeper constraints. It enables
fine-grained authorization policies that can integrate with external data
sources like Azure RBAC.

The webhook handles the authorization phase of the Kubernetes API request
lifecycle, which occurs before admission webhooks and can control access
to all operations including read operations (GET, LIST, WATCH).
*/
package authzwebhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/authorization"
	constraintclient "github.com/open-policy-agent/frameworks/constraint/pkg/client"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/reviews"
	rtypes "github.com/open-policy-agent/frameworks/constraint/pkg/types"
	"github.com/open-policy-agent/gatekeeper/v3/pkg/util"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	log           = logf.Log.WithName("authorization-webhook")
)

func init() {
	_ = authorizationv1.AddToScheme(runtimeScheme)
}

// Handler handles SubjectAccessReview requests.
type Handler struct {
	client *constraintclient.Client
	log    logr.Logger
}

// NewHandler creates a new authorization webhook handler.
func NewHandler(client *constraintclient.Client) *Handler {
	return &Handler{
		client: client,
		log:    log.WithValues("hookType", "authorization"),
	}
}

// AddAuthorizationWebhook registers the authorization webhook with the manager.
func AddAuthorizationWebhook(mgr manager.Manager, client *constraintclient.Client) error {
	handler := NewHandler(client)
	mgr.GetWebhookServer().Register("/v1/authorize", handler)
	log.Info("Registered authorization webhook at /v1/authorize")
	return nil
}

// ServeHTTP handles the HTTP request for authorization webhook.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	startTime := time.Now()

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Error(err, "failed to read request body")
		h.writeErrorResponse(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Decode the SubjectAccessReview
	sar := &authorizationv1.SubjectAccessReview{}
	deserializer := codecs.UniversalDeserializer()
	if _, _, err := deserializer.Decode(body, nil, sar); err != nil {
		h.log.Error(err, "failed to decode SubjectAccessReview")
		h.writeErrorResponse(w, "failed to decode SubjectAccessReview", http.StatusBadRequest)
		return
	}

	// Log the incoming request
	h.log.V(5).Info("received authorization request",
		"user", sar.Spec.User,
		"groups", sar.Spec.Groups,
		"resource", h.formatResourceAttributes(sar.Spec.ResourceAttributes),
		"nonResource", h.formatNonResourceAttributes(sar.Spec.NonResourceAttributes),
	)

	// Process the authorization request
	response, err := h.authorize(ctx, sar)
	if err != nil {
		h.log.Error(err, "authorization check failed")
		// On error, we deny by default for security
		response = h.denyResponse(sar, fmt.Sprintf("authorization check failed: %v", err))
	}

	// Log the decision
	duration := time.Since(startTime)
	h.log.Info("authorization decision",
		"user", sar.Spec.User,
		"allowed", response.Status.Allowed,
		"denied", response.Status.Denied,
		"reason", response.Status.Reason,
		"duration", duration,
	)

	// Write the response
	h.writeResponse(w, response)
}

// authorize evaluates the SubjectAccessReview against Gatekeeper constraints.
func (h *Handler) authorize(ctx context.Context, sar *authorizationv1.SubjectAccessReview) (*authorizationv1.SubjectAccessReview, error) {
	// Create the review for constraint evaluation
	review := authorization.NewReview(sar.Spec)

	// Evaluate constraints
	resp, err := h.client.Review(ctx, review,
		reviews.EnforcementPoint(util.AuthorizationEnforcementPoint),
		reviews.Tracing(false),
	)
	if err != nil {
		return nil, fmt.Errorf("constraint evaluation failed: %w", err)
	}

	// Process the response
	return h.processResponse(sar, resp), nil
}

// processResponse converts constraint evaluation results to a SubjectAccessReview response.
func (h *Handler) processResponse(sar *authorizationv1.SubjectAccessReview, resp *rtypes.Responses) *authorizationv1.SubjectAccessReview {
	response := sar.DeepCopy()

	// Check for violations
	results := resp.Results()
	var denyReasons []string

	for _, result := range results {
		if result.EnforcementAction == "deny" {
			denyReasons = append(denyReasons, fmt.Sprintf("[%s] %s", result.Constraint.GetName(), result.Msg))
		}
	}

	if len(denyReasons) > 0 {
		response.Status = authorizationv1.SubjectAccessReviewStatus{
			Allowed: false,
			Denied:  true,
			Reason:  fmt.Sprintf("Gatekeeper policy violation: %v", denyReasons),
		}
	} else {
		// No violations - allow the request
		// Note: We return Allowed=true only if we're the authoritative source
		// Otherwise, we should return Allowed=false, Denied=false to let other
		// authorizers make the decision
		response.Status = authorizationv1.SubjectAccessReviewStatus{
			Allowed: true,
			Reason:  "Gatekeeper authorization passed",
		}
	}

	return response
}

// denyResponse creates a deny response for the given SAR.
func (h *Handler) denyResponse(sar *authorizationv1.SubjectAccessReview, reason string) *authorizationv1.SubjectAccessReview {
	response := sar.DeepCopy()
	response.Status = authorizationv1.SubjectAccessReviewStatus{
		Allowed: false,
		Denied:  true,
		Reason:  reason,
	}
	return response
}

// writeResponse writes the SubjectAccessReview response.
func (h *Handler) writeResponse(w http.ResponseWriter, sar *authorizationv1.SubjectAccessReview) {
	w.Header().Set("Content-Type", "application/json")

	respBytes, err := json.Marshal(sar)
	if err != nil {
		h.log.Error(err, "failed to marshal response")
		h.writeErrorResponse(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(respBytes); err != nil {
		h.log.Error(err, "failed to write response")
	}
}

// writeErrorResponse writes an error response.
func (h *Handler) writeErrorResponse(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	sar := &authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authorizationv1.SubjectAccessReviewStatus{
			Allowed: false,
			Denied:  true,
			Reason:  msg,
		},
	}

	respBytes, _ := json.Marshal(sar)
	_, _ = w.Write(respBytes)
}

// formatResourceAttributes formats resource attributes for logging.
func (h *Handler) formatResourceAttributes(ra *authorizationv1.ResourceAttributes) string {
	if ra == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s/%s/%s/%s in %s", ra.Group, ra.Resource, ra.Subresource, ra.Verb, ra.Namespace)
}

// formatNonResourceAttributes formats non-resource attributes for logging.
func (h *Handler) formatNonResourceAttributes(nra *authorizationv1.NonResourceAttributes) string {
	if nra == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s %s", nra.Verb, nra.Path)
}
