// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
	"go.miloapis.com/fraud/internal/datasource"
	"go.miloapis.com/fraud/internal/provider"
)

const (
	defaultMaxHistoryEntries = 50

	// conditionEnforcementApplied is set on a FraudEvaluation once IAM
	// enforcement resources have been successfully created in the Milo API server.
	conditionEnforcementApplied = "EnforcementApplied"

	// enforcementResourcePrefix is prepended to the FraudEvaluation name when
	// naming IAM enforcement resources.
	enforcementResourcePrefix = "fraud-"

	// recentUserThreshold is the maximum age of a user for which the
	// reconciler will retry resolution of incomplete audit data.
	recentUserThreshold = 2 * time.Minute

	// auditDataRetryDelay is the requeue interval when waiting for
	// audit log data to become available for a recent user.
	auditDataRetryDelay = 5 * time.Second
)

// actionPriority maps decision strings to a numeric priority for comparison.
// Higher value means higher severity.
var actionPriority = map[string]int{
	fraudv1alpha1.DecisionAccepted:   0,
	fraudv1alpha1.DecisionReview:     1,
	fraudv1alpha1.DecisionDeactivate: 2,
}

// FraudEvaluationReconciler reconciles a FraudEvaluation object.
type FraudEvaluationReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
	Registry *provider.Registry
	Resolver *datasource.Resolver
}

// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudevaluations,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudevaluations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudevaluations/finalizers,verbs=update
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudproviders,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=userdeactivations,verbs=get;create;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=platformaccessapprovals,verbs=get;list;create
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=platformaccessrejections,verbs=get;create
// +kubebuilder:rbac:groups=activity.miloapis.com,resources=auditlogqueries,verbs=create

// Reconcile runs the fraud evaluation pipeline for a FraudEvaluation resource.
func (r *FraudEvaluationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Fetch the FraudEvaluation. If deleted, nothing to do.
	var eval fraudv1alpha1.FraudEvaluation
	if err := r.Get(ctx, req.NamespacedName, &eval); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	// 2. If already errored, do not re-process.
	if eval.Status.Phase == fraudv1alpha1.PhaseError {
		return ctrl.Result{}, nil
	}

	// 2a. If evaluation is already completed, skip the pipeline and apply
	// enforcement (which short-circuits if EnforcementApplied is already set).
	if eval.Status.Phase == fraudv1alpha1.PhaseCompleted {
		var policy fraudv1alpha1.FraudPolicy
		if err := r.Get(ctx, types.NamespacedName{Name: eval.Spec.PolicyRef.Name}, &policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to fetch FraudPolicy %q for enforcement: %w", eval.Spec.PolicyRef.Name, err)
		}

		return r.applyEnforcement(ctx, &eval, &policy)
	}

	// 3. Set phase to Running and update status.
	if eval.Status.Phase != fraudv1alpha1.PhaseRunning {
		eval.Status.Phase = fraudv1alpha1.PhaseRunning
		if err := r.Status().Update(ctx, &eval); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set phase to Running: %w", err)
		}
	}

	// 4. Fetch the referenced FraudPolicy.
	var policy fraudv1alpha1.FraudPolicy
	policyKey := types.NamespacedName{Name: eval.Spec.PolicyRef.Name}

	if err := r.Get(ctx, policyKey, &policy); err != nil {
		return r.setErrorPhase(ctx, &eval, fmt.Sprintf("failed to fetch FraudPolicy %q: %v", eval.Spec.PolicyRef.Name, err))
	}

	// Stamp the policy resource version for audit.
	eval.Spec.PolicyRef.ResourceVersion = policy.ResourceVersion

	// Determine history retention limit.
	maxEntries := defaultMaxHistoryEntries
	if policy.Spec.HistoryRetention != nil && policy.Spec.HistoryRetention.MaxEntries > 0 {
		maxEntries = policy.Spec.HistoryRetention.MaxEntries
	}

	// 5. Resolve provider input from platform data sources.
	input, retry := r.resolveInput(ctx, &eval)
	if retry != nil {
		return *retry, nil
	}

	// 6. Execute stages and determine decision.
	stageResults, compositeScore, allMatchedActions, done, doneResult, doneErr := r.runStages(ctx, &eval, &policy, input)
	if done {
		return doneResult, doneErr
	}

	// 7. Determine decision: highest severity action from all matched thresholds.
	decision := r.highestAction(allMatchedActions)

	// 8. Determine enforcement action based on policy mode.
	enforcementAction := r.determineEnforcement(policy.Spec.Enforcement.Mode, decision)

	// 9. Add to history (prepend, trim to maxEntries).
	now := metav1.Now()

	compositeScoreStr := strconv.FormatFloat(compositeScore, 'f', 2, 64)

	historyEntry := fraudv1alpha1.HistoryEntry{
		Timestamp:      now,
		CompositeScore: compositeScoreStr,
		Decision:       decision,
		Trigger:        eval.Status.Trigger,
	}

	eval.Status.History = append([]fraudv1alpha1.HistoryEntry{historyEntry}, eval.Status.History...)
	if len(eval.Status.History) > maxEntries {
		eval.Status.History = eval.Status.History[:maxEntries]
	}

	// 10. Set phase to Completed and update all status fields.
	eval.Status.Phase = fraudv1alpha1.PhaseCompleted
	eval.Status.CompositeScore = compositeScoreStr
	eval.Status.Decision = decision
	eval.Status.EnforcementAction = enforcementAction
	eval.Status.LastEvaluationTime = &now
	eval.Status.StageResults = stageResults

	meta.SetStatusCondition(&eval.Status.Conditions, metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionTrue,
		Reason:             "EvaluationCompleted",
		Message:            fmt.Sprintf("Evaluation completed with score %.2f, decision %s", compositeScore, decision),
		ObservedGeneration: eval.Generation,
	})

	if err := r.Status().Update(ctx, &eval); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status to Completed: %w", err)
	}

	log.Info("evaluation completed",
		"compositeScore", compositeScore,
		"decision", decision,
		"enforcementAction", enforcementAction,
		"stages", len(stageResults))

	// 11. Re-fetch to get the latest resourceVersion before patching status again.
	if err := r.Get(ctx, req.NamespacedName, &eval); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to re-fetch FraudEvaluation after completion: %w", err)
	}

	// 12. Apply enforcement based on policy mode and decision.
	return r.applyEnforcement(ctx, &eval, &policy)
}

// runStages executes each pipeline stage in order and returns the accumulated results.
// If a FailClosed provider error forces early termination, done is true and the caller
// should immediately return (doneResult, doneErr).
func (r *FraudEvaluationReconciler) runStages(
	ctx context.Context,
	eval *fraudv1alpha1.FraudEvaluation,
	policy *fraudv1alpha1.FraudPolicy,
	input provider.Input,
) (stageResults []fraudv1alpha1.StageResult, compositeScore float64, allMatchedActions []string, done bool, doneResult ctrl.Result, doneErr error) {
	log := logf.FromContext(ctx)
	stageResults = make([]fraudv1alpha1.StageResult, 0, len(policy.Spec.Stages))

	var shortCircuitActive bool

	for _, stage := range policy.Spec.Stages {
		sr := fraudv1alpha1.StageResult{Name: stage.Name}

		if shortCircuitActive && !stage.Required {
			sr.Skipped = true
			stageResults = append(stageResults, sr)
			log.V(1).Info("skipping stage due to short-circuit", "stage", stage.Name)

			continue
		}

		providerResults, maxStageScore, degraded, failClosedMsg := r.runProviders(ctx, stage, input)
		if failClosedMsg != "" {
			sr.ProviderResults = providerResults
			stageResults = append(stageResults, sr)
			eval.Status.StageResults = stageResults
			doneResult, doneErr = r.setErrorPhase(ctx, eval, failClosedMsg)

			return stageResults, 0, nil, true, doneResult, doneErr
		}

		sr.ProviderResults = providerResults
		stageResults = append(stageResults, sr)

		if maxStageScore > compositeScore {
			compositeScore = maxStageScore
		}

		matchedAction := r.evaluateThresholds(stage.Thresholds, int(maxStageScore))
		if matchedAction != "" {
			allMatchedActions = append(allMatchedActions, matchedAction)

			if r.Recorder != nil {
				r.Recorder.Eventf(eval, nil, corev1.EventTypeWarning, "ThresholdCrossed", "EvaluateThreshold",
					"Stage %q: score %.2f triggered %s threshold", stage.Name, maxStageScore, matchedAction)
			}
		}

		if stage.ShortCircuit != nil && int(maxStageScore) < stage.ShortCircuit.SkipWhenBelow {
			shortCircuitActive = true
			log.V(1).Info("short-circuit activated", "stage", stage.Name, "score", maxStageScore, "skipWhenBelow", stage.ShortCircuit.SkipWhenBelow)
		}

		if degraded {
			meta.SetStatusCondition(&eval.Status.Conditions, metav1.Condition{
				Type:               "Degraded",
				Status:             metav1.ConditionTrue,
				Reason:             "ProviderError",
				Message:            fmt.Sprintf("One or more providers in stage %q returned errors", stage.Name),
				ObservedGeneration: eval.Generation,
			})
		}
	}

	return stageResults, compositeScore, allMatchedActions, false, ctrl.Result{}, nil
}

// runProviders calls each provider in a stage and returns the results.
// If a FailClosed provider error occurs, failClosedMsg is non-empty and the caller
// should abort the evaluation pipeline.
func (r *FraudEvaluationReconciler) runProviders(
	ctx context.Context,
	stage fraudv1alpha1.Stage,
	input provider.Input,
) (results []fraudv1alpha1.ProviderResult, maxScore float64, degraded bool, failClosedMsg string) {
	log := logf.FromContext(ctx)

	for _, sp := range stage.Providers {
		var fp fraudv1alpha1.FraudProvider
		if err := r.Get(ctx, types.NamespacedName{Name: sp.ProviderRef.Name}, &fp); err != nil {
			return results, 0, false, fmt.Sprintf("failed to fetch FraudProvider %q: %v", sp.ProviderRef.Name, err)
		}

		impl, ok := r.Registry.Get(sp.ProviderRef.Name)
		if !ok {
			return results, 0, false, fmt.Sprintf("provider %q is not yet initialized (Available condition may be false)", sp.ProviderRef.Name)
		}

		start := time.Now()
		result := impl.Evaluate(ctx, input)

		pr := fraudv1alpha1.ProviderResult{
			Provider:    sp.ProviderRef.Name,
			Score:       strconv.FormatFloat(result.Score, 'f', 2, 64),
			RawResponse: result.RawResponse,
			Duration:    time.Since(start).Round(time.Millisecond).String(),
		}

		if result.Error != nil {
			failurePolicy := fp.Spec.FailurePolicy
			if failurePolicy == "" {
				failurePolicy = "FailOpen"
			}

			pr.Error = result.Error.Error()
			pr.FailurePolicyApplied = failurePolicy

			if failurePolicy == "FailClosed" {
				results = append(results, pr)
				return results, 0, false, fmt.Sprintf("provider %q failed with FailClosed policy: %v", sp.ProviderRef.Name, result.Error)
			}

			pr.Score = "0.00"
			degraded = true
			log.Info("provider error with FailOpen policy, continuing", "provider", sp.ProviderRef.Name, "error", result.Error)
		}

		results = append(results, pr)

		if result.Score > maxScore {
			maxScore = result.Score
		}
	}

	return results, maxScore, degraded, ""
}

// resolveInput resolves the provider input from platform data sources. If audit
// data is missing and the user was created recently, it returns a requeue result
// so the reconciler can retry. Otherwise it returns the (possibly partial) input.
func (r *FraudEvaluationReconciler) resolveInput(
	ctx context.Context,
	eval *fraudv1alpha1.FraudEvaluation,
) (provider.Input, *ctrl.Result) {
	log := logf.FromContext(ctx)

	if r.Resolver == nil {
		return provider.Input{}, nil
	}

	input, err := r.Resolver.Resolve(ctx, eval.Spec.UserRef.Name)
	if err == nil {
		return input, nil
	}

	// Audit data is incomplete. For recent users, requeue to allow the
	// data to become available before calling providers.
	var user iamv1alpha1.User
	if userErr := r.Get(ctx, types.NamespacedName{Name: eval.Spec.UserRef.Name}, &user); userErr == nil {
		if time.Since(user.CreationTimestamp.Time) < recentUserThreshold {
			log.Info("audit data incomplete for recent user, will retry",
				"user", eval.Spec.UserRef.Name,
				"userAge", time.Since(user.CreationTimestamp.Time).Round(time.Second))

			return input, &ctrl.Result{RequeueAfter: auditDataRetryDelay}
		}
	}

	log.V(1).Info("data source resolution had errors, continuing with partial input", "error", err)

	return input, nil
}

// evaluateThresholds finds the highest matching threshold action for the given score.
// Thresholds are matched when the score >= threshold.MinScore. Among all matching
// thresholds, the one with the highest MinScore is selected.
func (r *FraudEvaluationReconciler) evaluateThresholds(thresholds []fraudv1alpha1.Threshold, score int) string {
	// Sort thresholds by MinScore descending to find the highest matching one first.
	sorted := make([]fraudv1alpha1.Threshold, len(thresholds))
	copy(sorted, thresholds)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].MinScore > sorted[j].MinScore
	})

	for _, t := range sorted {
		if score >= t.MinScore {
			return t.Action
		}
	}

	return ""
}

// highestAction returns the most severe action from a list of matched actions.
// Severity order: DEACTIVATE > REVIEW > ACCEPTED.
func (r *FraudEvaluationReconciler) highestAction(actions []string) string {
	if len(actions) == 0 {
		return fraudv1alpha1.DecisionAccepted
	}

	highest := fraudv1alpha1.DecisionAccepted

	for _, a := range actions {
		if actionPriority[a] > actionPriority[highest] {
			highest = a
		}
	}

	return highest
}

// determineEnforcement maps the decision to an enforcement action based on policy mode.
func (r *FraudEvaluationReconciler) determineEnforcement(mode, _ string) string {
	if mode == fraudv1alpha1.EnforcementModeObserve {
		return fraudv1alpha1.EnforcementActionObserved
	}
	return fraudv1alpha1.EnforcementActionEnforced
}

// setErrorPhase sets the evaluation to the Error phase with the given message
// and returns a terminal result.
func (r *FraudEvaluationReconciler) setErrorPhase(ctx context.Context, eval *fraudv1alpha1.FraudEvaluation, message string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Error(fmt.Errorf("%s", message), "evaluation failed")

	eval.Status.Phase = fraudv1alpha1.PhaseError

	meta.SetStatusCondition(&eval.Status.Conditions, metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionFalse,
		Reason:             "EvaluationFailed",
		Message:            message,
		ObservedGeneration: eval.Generation,
	})

	if err := r.Status().Update(ctx, eval); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to set Error phase: %w", err)
	}

	return ctrl.Result{}, nil
}

// applyEnforcement creates IAM enforcement resources for a completed evaluation.
// It is idempotent: if the EnforcementApplied condition is already True, it returns immediately.
// Enforcement is only applied in AUTO mode; OBSERVE mode skips resource creation.
func (r *FraudEvaluationReconciler) applyEnforcement(ctx context.Context, eval *fraudv1alpha1.FraudEvaluation, policy *fraudv1alpha1.FraudPolicy) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Short-circuit if enforcement has already been applied.
	if meta.IsStatusConditionTrue(eval.Status.Conditions, conditionEnforcementApplied) {
		return ctrl.Result{}, nil
	}

	// OBSERVE mode: log but do not create enforcement resources.
	if policy.Spec.Enforcement.Mode == fraudv1alpha1.EnforcementModeObserve {
		log.Info("enforcement skipped (OBSERVE mode)", "decision", eval.Status.Decision)
		return r.setEnforcementAppliedCondition(ctx, eval, "ObserveMode", "Enforcement skipped: policy is in OBSERVE mode")
	}

	resourceName := enforcementResourcePrefix + eval.Name

	switch eval.Status.Decision {
	case fraudv1alpha1.DecisionDeactivate:
		deactivation := &iamv1alpha1.UserDeactivation{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName},
			Spec: iamv1alpha1.UserDeactivationSpec{
				UserRef:       iamv1alpha1.UserReference{Name: eval.Spec.UserRef.Name},
				Reason:        "fraud-deactivate",
				Description:   fmt.Sprintf("Automated deactivation from FraudEvaluation %q (score: %s)", eval.Name, eval.Status.CompositeScore),
				DeactivatedBy: "fraud-operator",
			},
		}

		if err := r.Create(ctx, deactivation); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("failed to create UserDeactivation %q: %w", resourceName, err)
		}

		log.Info("UserDeactivation ensured", "name", resourceName, "user", eval.Spec.UserRef.Name)

	case fraudv1alpha1.DecisionReview:
		rejection := &iamv1alpha1.PlatformAccessRejection{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName},
			Spec: iamv1alpha1.PlatformAccessRejectionSpec{
				UserRef: iamv1alpha1.UserReference{Name: eval.Spec.UserRef.Name},
				Reason:  "fraud-review",
			},
		}

		if err := r.Create(ctx, rejection); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("failed to create PlatformAccessRejection %q: %w", resourceName, err)
		}

		log.Info("PlatformAccessRejection ensured", "name", resourceName, "user", eval.Spec.UserRef.Name)

	case fraudv1alpha1.DecisionAccepted:
		approval := &iamv1alpha1.PlatformAccessApproval{
			ObjectMeta: metav1.ObjectMeta{Name: resourceName},
			Spec: iamv1alpha1.PlatformAccessApprovalSpec{
				SubjectRef: iamv1alpha1.SubjectReference{
					UserRef: &iamv1alpha1.UserReference{Name: eval.Spec.UserRef.Name},
				},
			},
		}

		if err := r.Create(ctx, approval); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, fmt.Errorf("failed to create PlatformAccessApproval %q: %w", resourceName, err)
		}

		log.Info("PlatformAccessApproval ensured", "name", resourceName, "user", eval.Spec.UserRef.Name)

	default:
		// Unknown or legacy decision value — log and skip enforcement rather than error-looping.
		log.Info("skipping enforcement for unrecognised decision", "decision", eval.Status.Decision)
		return r.setEnforcementAppliedCondition(ctx, eval, "SkippedUnknownDecision", fmt.Sprintf("Enforcement skipped: unrecognised decision %q", eval.Status.Decision))
	}

	return r.setEnforcementAppliedCondition(ctx, eval, "EnforcementApplied", fmt.Sprintf("Enforcement applied for decision %s", eval.Status.Decision))
}

// setEnforcementAppliedCondition patches the EnforcementApplied condition onto the evaluation status.
func (r *FraudEvaluationReconciler) setEnforcementAppliedCondition(ctx context.Context, eval *fraudv1alpha1.FraudEvaluation, reason, message string) (ctrl.Result, error) {
	base := eval.DeepCopy()

	meta.SetStatusCondition(&eval.Status.Conditions, metav1.Condition{
		Type:               conditionEnforcementApplied,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: eval.Generation,
	})

	if err := r.Status().Patch(ctx, eval, client.MergeFrom(base)); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to patch EnforcementApplied condition: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FraudEvaluationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&fraudv1alpha1.FraudEvaluation{}).
		Named("fraudevaluation").
		Complete(r)
}
