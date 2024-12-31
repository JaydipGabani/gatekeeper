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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConnectionSpec is the configuration for the pubsub connection.
type ConnectionSpec struct {
	// Provider is the name of the pubsub provider
	// dapr/rabbitmq/redis/nats/
	Driver string            `json:"driver,omitempty"`
	Config map[string]string `json:"config,omitempty"`
}

// ConnectionStatus defines the observed state of Config.
type ConnectionStatus struct {
	ByPod []ByPodStatus `json:"byPod,omitempty"`
}
type ByPodStatus struct {
	// a unique identifier for the pod that wrote the status
	ID     string            `json:"id,omitempty"`
	Errors []ConnectionError `json:"errors,omitempty"`
}

type ConnectionError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// +kubebuilder:resource:scope=Namespaced
// +kubebuilder:object:root=true

// Connection is the Schema for the configs API.
type Connection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConnectionSpec   `json:"spec,omitempty"`
	Status ConnectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConnectionList contains a list of Config.
type ConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Connection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Connection{}, &ConnectionList{})
}
