// SPDX-License-Identifier: AGPL-3.0-only
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Decision values for FraudEvaluation.status.decision.
const (
	DecisionNone       = "NONE"
	DecisionReview     = "REVIEW"
	DecisionDeactivate = "DEACTIVATE"
)

// Phase values for FraudEvaluation.status.phase.
const (
	PhaseCompleted = "Completed"
)

// UserReference is a reference to the User being evaluated for fraud.
type UserReference struct {
	// name is the name of the User resource.
	// +required
	Name string `json:"name"`
}

// PolicyReference is a reference to the FraudPolicy used for evaluation.
type PolicyReference struct {
	// name is the name of the FraudPolicy resource.
	// +required
	Name string `json:"name"`

	// resourceVersion is the version of the FraudPolicy at the time of evaluation.
	// This allows auditing which version of the policy produced a given result.
	// +optional
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// FraudEvaluationSpec defines the desired state of FraudEvaluation.
type FraudEvaluationSpec struct {
	// userRef references the User being evaluated for fraud.
	// +required
	UserRef UserReference `json:"userRef"`

	// policyRef references the FraudPolicy used for this evaluation.
	// +required
	PolicyRef PolicyReference `json:"policyRef"`
}

// ProviderResult captures the output from a single fraud provider invocation.
type ProviderResult struct {
	// provider is the name of the FraudProvider that produced this result.
	Provider string `json:"provider"`

	// score is the fraud risk score returned by the provider (0-100).
	Score string `json:"score"`

	// error contains the error message if the provider call failed.
	// +optional
	Error string `json:"error,omitempty"`

	// failurePolicyApplied indicates which failure policy was applied when the
	// provider call failed (e.g. "FailOpen" or "FailClosed").
	// +optional
	FailurePolicyApplied string `json:"failurePolicyApplied,omitempty"`

	// rawResponse contains the raw JSON response from the provider for debugging purposes.
	// +optional
	RawResponse string `json:"rawResponse,omitempty"`

	// duration is the wall-clock time the provider call took (e.g. "245ms").
	// +optional
	Duration string `json:"duration,omitempty"`
}

// StageResult captures the outcome of a single pipeline stage execution.
type StageResult struct {
	// name is the name of the stage, matching the stage name in the FraudPolicy.
	Name string `json:"name"`

	// skipped indicates whether this stage was skipped due to short-circuit logic
	// from a previous stage.
	Skipped bool `json:"skipped"`

	// providerResults contains the results from each provider invoked in this stage.
	// This is empty when the stage was skipped.
	// +optional
	ProviderResults []ProviderResult `json:"providerResults,omitempty"`
}

// HistoryEntry records the outcome of a previous evaluation run for audit purposes.
type HistoryEntry struct {
	// timestamp is when this evaluation completed.
	Timestamp metav1.Time `json:"timestamp"`

	// compositeScore is the overall fraud score from this evaluation run.
	CompositeScore string `json:"compositeScore"`

	// decision is the fraud decision reached in this evaluation run.
	Decision string `json:"decision"`

	// trigger indicates what initiated this evaluation run.
	Trigger string `json:"trigger"`
}

// FraudEvaluationStatus defines the observed state of FraudEvaluation.
type FraudEvaluationStatus struct {
	// phase indicates the current lifecycle phase of the evaluation.
	// +optional
	// +kubebuilder:validation:Enum=Pending;Running;Completed;Error
	Phase string `json:"phase,omitempty"`

	// compositeScore is the overall fraud risk score (0-100), taken as the highest
	// score from all providers across all stages.
	// +optional
	CompositeScore string `json:"compositeScore,omitempty"`

	// decision is the final fraud decision based on the composite score and
	// policy thresholds.
	// +optional
	// +kubebuilder:validation:Enum=NONE;REVIEW;DEACTIVATE
	Decision string `json:"decision,omitempty"`

	// enforcementAction is the action that was actually taken as a result of
	// this evaluation. In OBSERVE mode, enforcement is logged but not applied.
	// +optional
	// +kubebuilder:validation:Enum=NONE;REVIEW_FLAGGED;DEACTIVATED;OBSERVED
	EnforcementAction string `json:"enforcementAction,omitempty"`

	// trigger indicates what initiated this evaluation (e.g. "UserCreated", "Manual").
	// +optional
	Trigger string `json:"trigger,omitempty"`

	// lastEvaluationTime is the timestamp of the most recent evaluation run.
	// +optional
	LastEvaluationTime *metav1.Time `json:"lastEvaluationTime,omitempty"`

	// stageResults contains the per-stage results from the most recent evaluation run.
	// +optional
	StageResults []StageResult `json:"stageResults,omitempty"`

	// history contains previous evaluation results for audit purposes. The number
	// of entries retained is controlled by the FraudPolicy's historyRetention setting.
	// +optional
	History []HistoryEntry `json:"history,omitempty"`

	// conditions represent the current state of the FraudEvaluation resource.
	//
	// Standard condition types include:
	// - "Available": the evaluation completed successfully
	// - "Degraded": the evaluation completed with provider errors
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`,description="Current evaluation phase"
// +kubebuilder:printcolumn:name="Score",type=string,JSONPath=`.status.compositeScore`,description="Composite fraud score (0-100)"
// +kubebuilder:printcolumn:name="Decision",type=string,JSONPath=`.status.decision`,description="Final fraud decision"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// FraudEvaluation is the Schema for the fraudevaluations API.
// It is a living resource representing the fraud evaluation state for a specific
// user, updated each time the evaluation pipeline runs.
type FraudEvaluation struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of FraudEvaluation.
	// +required
	Spec FraudEvaluationSpec `json:"spec"`

	// status defines the observed state of FraudEvaluation.
	// +optional
	Status FraudEvaluationStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// FraudEvaluationList contains a list of FraudEvaluation.
type FraudEvaluationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FraudEvaluation `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FraudEvaluation{}, &FraudEvaluationList{})
}
