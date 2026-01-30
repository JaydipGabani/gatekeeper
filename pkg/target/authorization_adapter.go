package target

import (
	"encoding/json"

	"github.com/open-policy-agent/frameworks/constraint/pkg/apis/authorization"
)

// authzReview wraps an authorization.Review for Rego evaluation.
// This allows the K8sValidationTarget to also handle authorization reviews
// so that constraints can be shared between admission and authorization webhooks.
type authzReview struct {
	Review *authorization.Review
}

// MarshalJSON implements json.Marshaler for authzReview.
// This produces output in a format the Rego policies expect.
func (r *authzReview) MarshalJSON() ([]byte, error) {
	input := r.Review.ToRegoInput()
	return json.Marshal(input)
}
