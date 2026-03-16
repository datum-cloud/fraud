// SPDX-License-Identifier: AGPL-3.0-only
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ProviderReference is a reference to a FraudProvider resource.
type ProviderReference struct {
	// name is the name of the FraudProvider resource.
	// +required
	Name string `json:"name"`
}

// StageProvider identifies a provider to be invoked within a pipeline stage.
type StageProvider struct {
	// providerRef references a FraudProvider resource by name.
	// +required
	ProviderRef ProviderReference `json:"providerRef"`
}

// Threshold defines a score boundary and the action to take when the score
// meets or exceeds it.
type Threshold struct {
	// minScore is the minimum composite score (0-100) that triggers this action.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	MinScore int `json:"minScore"`

	// action is the enforcement action to take when the score meets or exceeds minScore.
	// +required
	// +kubebuilder:validation:Enum=REVIEW;DEACTIVATE
	Action string `json:"action"`
}

// ShortCircuitConfig controls whether subsequent non-required stages are skipped
// based on the result of the current stage.
type ShortCircuitConfig struct {
	// skipWhenBelow causes subsequent non-required stages to be skipped if the
	// maximum score produced by this stage is below this value.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	SkipWhenBelow int `json:"skipWhenBelow"`
}

// Stage defines a single step in the fraud evaluation pipeline.
type Stage struct {
	// name is a human-readable identifier for this stage.
	// +required
	Name string `json:"name"`

	// providers lists the fraud providers to invoke in this stage.
	// +required
	// +kubebuilder:validation:MinItems=1
	Providers []StageProvider `json:"providers"`

	// thresholds define score boundaries and their associated actions for this stage.
	// +required
	// +kubebuilder:validation:MinItems=1
	Thresholds []Threshold `json:"thresholds"`

	// required indicates whether this stage must always run, even if a previous
	// stage's short-circuit logic would otherwise skip it.
	// +optional
	// +kubebuilder:default=false
	Required bool `json:"required,omitempty"`

	// shortCircuit configures short-circuit behavior for this stage. If the
	// maximum score in this stage is below the configured threshold, subsequent
	// non-required stages are skipped.
	// +optional
	ShortCircuit *ShortCircuitConfig `json:"shortCircuit,omitempty"`
}

// EnforcementConfig controls how fraud evaluation results are acted upon.
type EnforcementConfig struct {
	// mode determines whether enforcement actions are automatically applied or
	// only observed (logged but not enforced).
	// +required
	// +kubebuilder:validation:Enum=OBSERVE;AUTO
	Mode string `json:"mode"`
}

// TriggerConfig defines what triggers a fraud evaluation.
type TriggerConfig struct {
	// type is the kind of trigger.
	// +required
	// +kubebuilder:validation:Enum=Event;Manual
	Type string `json:"type"`

	// event is the name of the event that triggers evaluation (e.g. "UserCreated").
	// Only applicable when type is "Event".
	// +optional
	Event string `json:"event,omitempty"`
}

// HistoryRetention controls how many historical evaluation entries are retained
// in the FraudEvaluation status.
type HistoryRetention struct {
	// maxEntries is the maximum number of evaluation history entries to retain
	// per FraudEvaluation resource.
	// +optional
	// +kubebuilder:default=50
	// +kubebuilder:validation:Minimum=1
	MaxEntries int `json:"maxEntries,omitempty"`
}

// FraudPolicySpec defines the desired state of FraudPolicy.
type FraudPolicySpec struct {
	// stages defines the ordered evaluation pipeline. Each stage is executed in
	// sequence unless short-circuited by a previous stage.
	// +required
	// +kubebuilder:validation:MinItems=1
	Stages []Stage `json:"stages"`

	// enforcement controls how fraud evaluation results are acted upon.
	// +required
	Enforcement EnforcementConfig `json:"enforcement"`

	// triggers defines what events or actions initiate a fraud evaluation.
	// +optional
	Triggers []TriggerConfig `json:"triggers,omitempty"`

	// historyRetention controls how many historical evaluation entries are
	// retained per FraudEvaluation resource.
	// +optional
	HistoryRetention *HistoryRetention `json:"historyRetention,omitempty"`
}

// FraudPolicyStatus defines the observed state of FraudPolicy.
type FraudPolicyStatus struct {
	// conditions represent the current state of the FraudPolicy resource.
	//
	// Standard condition types include:
	// - "Available": the policy is valid and all referenced providers are available
	// - "Degraded": one or more referenced providers are unavailable
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// FraudPolicy is the Schema for the fraudpolicies API.
// It defines the fraud evaluation pipeline including stages, thresholds,
// enforcement mode, and trigger configuration.
type FraudPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of FraudPolicy.
	// +required
	Spec FraudPolicySpec `json:"spec"`

	// status defines the observed state of FraudPolicy.
	// +optional
	Status FraudPolicyStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// FraudPolicyList contains a list of FraudPolicy.
type FraudPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FraudPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FraudPolicy{}, &FraudPolicyList{})
}
