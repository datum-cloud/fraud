/*
Copyright 2026.

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

// SecretReference contains the information needed to locate a Secret containing
// provider credentials.
type SecretReference struct {
	// name is the name of the Secret resource.
	// +required
	Name string `json:"name"`

	// namespace is the namespace of the Secret resource.
	// If omitted, defaults to the namespace of the FraudProvider (for namespaced
	// lookups) or the controller's configured namespace for cluster-scoped resources.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// accountIDKey is the key within the Secret data that contains the account ID.
	// +optional
	// +kubebuilder:default="accountID"
	AccountIDKey string `json:"accountIDKey,omitempty"`

	// licenseKeyKey is the key within the Secret data that contains the license key.
	// +optional
	// +kubebuilder:default="licenseKey"
	LicenseKeyKey string `json:"licenseKeyKey,omitempty"`
}

// FraudProviderConfig holds provider-specific configuration.
type FraudProviderConfig struct {
	// endpoint is an optional API endpoint URL override. Useful for testing
	// against mock servers or on-premise deployments.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// credentialsRef is a reference to a Secret containing the API credentials
	// required by the provider. Either credentialsRef or credentialsPath must
	// be specified.
	// +optional
	CredentialsRef SecretReference `json:"credentialsRef,omitempty"`

	// credentialsPath is the directory path where credential files are mounted.
	// The controller reads accountID and licenseKey files from this path.
	// Either credentialsRef or credentialsPath must be specified.
	// +optional
	CredentialsPath string `json:"credentialsPath,omitempty"`
}

// FraudProviderSpec defines the desired state of FraudProvider.
type FraudProviderSpec struct {
	// type is the fraud detection provider type. For v1, only "maxmind" is supported.
	// +required
	// +kubebuilder:validation:Enum=maxmind
	Type string `json:"type"`

	// config holds provider-specific configuration such as endpoint and credentials.
	// +required
	Config FraudProviderConfig `json:"config"`

	// failurePolicy determines the behavior when the provider is unreachable or
	// returns an error. FailOpen allows the request to proceed without a score;
	// FailClosed treats the failure as a high-risk signal.
	// +optional
	// +kubebuilder:default="FailOpen"
	// +kubebuilder:validation:Enum=FailOpen;FailClosed
	FailurePolicy string `json:"failurePolicy,omitempty"`
}

// FraudProviderStatus defines the observed state of FraudProvider.
type FraudProviderStatus struct {
	// conditions represent the current state of the FraudProvider resource.
	//
	// Standard condition types include:
	// - "Available": the provider is reachable and returning valid responses
	// - "Degraded": the provider is experiencing errors or elevated latency
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// lastSuccessfulCall is the timestamp of the most recent successful API call
	// to this provider.
	// +optional
	LastSuccessfulCall *metav1.Time `json:"lastSuccessfulCall,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// FraudProvider is the Schema for the fraudproviders API.
// It represents a fraud detection provider backend (e.g. MaxMind minFraud).
type FraudProvider struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of FraudProvider.
	// +required
	Spec FraudProviderSpec `json:"spec"`

	// status defines the observed state of FraudProvider.
	// +optional
	Status FraudProviderStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// FraudProviderList contains a list of FraudProvider.
type FraudProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FraudProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FraudProvider{}, &FraudProviderList{})
}
