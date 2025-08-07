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

package v1beta1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestNewProviderStatusForPod(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "gatekeeper-system",
			UID:       types.UID("test-pod-uid"),
		},
	}

	providerName := "test-provider"

	status, err := NewProviderStatusForPod(pod, providerName, scheme)
	require.NoError(t, err)

	// Check basic fields
	assert.Equal(t, "test-pod", status.Status.ID)
	assert.Equal(t, "gatekeeper-system", status.GetNamespace())

	// Check labels
	labels := status.GetLabels()
	assert.Equal(t, providerName, labels[ProviderNameLabel])
	assert.Equal(t, pod.Name, labels[PodLabel])

	// Check owner reference
	ownerRefs := status.GetOwnerReferences()
	require.Len(t, ownerRefs, 1)
	assert.Equal(t, pod.Name, ownerRefs[0].Name)
	assert.Equal(t, pod.UID, ownerRefs[0].UID)
}

func TestKeyForProvider(t *testing.T) {
	testCases := []struct {
		name         string
		podID        string
		providerName string
		expected     string
	}{
		{
			name:         "basic case",
			podID:        "test-pod",
			providerName: "TestProvider",
			expected:     "test-pod-provider-testprovider",
		},
		{
			name:         "with special characters",
			podID:        "pod-123",
			providerName: "My-Provider_Name",
			expected:     "pod-123-provider-my-provider_name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := KeyForProvider(tc.podID, tc.providerName)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestProviderErrorType(t *testing.T) {
	// Test error type constants
	assert.Equal(t, ProviderErrorType("conversion_error"), ConversionError)
	assert.Equal(t, ProviderErrorType("upsert_cache_error"), UpsertCacheError)
}

func TestProviderPodStatusDeepCopy(t *testing.T) {
	original := &ProviderPodStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-status",
			Namespace: "gatekeeper-system",
		},
		Status: ProviderPodStatusStatus{
			ID:                 "test-pod",
			ProviderUID:        types.UID("provider-uid"),
			Active:             true,
			ObservedGeneration: 1,
			Errors: []ProviderError{
				{
					Type:      ConversionError,
					Message:   "test error",
					Retryable: false,
				},
			},
		},
	}

	copy := original.DeepCopy()
	
	// Verify the copy is independent
	assert.Equal(t, original.Name, copy.Name)
	assert.Equal(t, original.Status.ID, copy.Status.ID)
	assert.Equal(t, original.Status.Active, copy.Status.Active)
	assert.Len(t, copy.Status.Errors, 1)
	assert.Equal(t, original.Status.Errors[0].Type, copy.Status.Errors[0].Type)

	// Modify copy and ensure original is unchanged
	copy.Status.Active = false
	copy.Status.Errors[0].Message = "modified"
	
	assert.True(t, original.Status.Active)
	assert.Equal(t, "test error", original.Status.Errors[0].Message)
}