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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
	"go.miloapis.com/fraud/internal/datasource"
	"go.miloapis.com/fraud/internal/provider"
)

const (
	defaultMaxHistoryEntries = 50

	actionNone = "NONE"

	// conditionEnforcementApplied is set on a FraudEvaluation once IAM
	// enforcement resources have been successfully created in the Milo API server.
	conditionEnforcementApplied = "EnforcementApplied"

	// enforcementResourcePrefix is prepended to the FraudEvaluation name when
	// naming IAM enforcement resources.
	enforcementResourcePrefix = "fraud-"
)

// actionPriority maps decision strings to a numeric priority for comparison.
// Higher value means higher severity.
var actionPriority = map[string]int{
	actionNone:   0,
	"REVIEW":     1,
	"DEACTIVATE": 2,
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
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=platformaccessapprovals,verbs=get;create
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
	if eval.Status.Phase == "Error" {
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
	eval.Status.Phase = "Running"
	if err := r.Status().Update(ctx, &eval); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to set phase to Running: %w", err)
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
	var input provider.Input
	if r.Resolver != nil {
		resolved, err := r.Resolver.Resolve(ctx, eval.Spec.UserRef.Name)
		if err != nil {
			log.V(1).Info("data source resolution had errors, continuing with partial input", "error", err)
		}

		input = resolved
	}

	// 6. Execute stages in order.
	stageResults := make([]fraudv1alpha1.StageResult, 0, len(policy.Spec.Stages))

	var (
		shortCircuitActive bool
		allMatchedActions  []string
		compositeScore     float64
	)

	for _, stage := range policy.Spec.Stages {
		sr := fraudv1alpha1.StageResult{
			Name: stage.Name,
		}

		// Check short-circuit: skip non-required stages when short-circuit is active.
		if shortCircuitActive && !stage.Required {
			sr.Skipped = true
			stageResults = append(stageResults, sr)
			log.V(1).Info("skipping stage due to short-circuit", "stage", stage.Name)

			continue
		}

		var (
			maxStageScore    float64
			providerResults  []fraudv1alpha1.ProviderResult
			providerDegraded bool
		)

		for _, sp := range stage.Providers {
			// Look up the FraudProvider CR.
			var fp fraudv1alpha1.FraudProvider
			fpKey := types.NamespacedName{Name: sp.ProviderRef.Name}

			if err := r.Get(ctx, fpKey, &fp); err != nil {
				return r.setErrorPhase(ctx, &eval, fmt.Sprintf("failed to fetch FraudProvider %q: %v", sp.ProviderRef.Name, err))
			}

			// Get the provider implementation from the registry by CR name.
			impl, ok := r.Registry.Get(sp.ProviderRef.Name)
			if !ok {
				return r.setErrorPhase(ctx, &eval, fmt.Sprintf("provider %q is not yet initialized (Available condition may be false)", sp.ProviderRef.Name))
			}

			// Call the provider.
			start := time.Now()
			result := impl.Evaluate(ctx, input)
			duration := time.Since(start)

			pr := fraudv1alpha1.ProviderResult{
				Provider:    sp.ProviderRef.Name,
				Score:       strconv.FormatFloat(result.Score, 'f', 2, 64),
				RawResponse: result.RawResponse,
				Duration:    duration.Round(time.Millisecond).String(),
			}

			if result.Error != nil {
				failurePolicy := fp.Spec.FailurePolicy
				if failurePolicy == "" {
					failurePolicy = "FailOpen"
				}

				pr.Error = result.Error.Error()
				pr.FailurePolicyApplied = failurePolicy

				if failurePolicy == "FailClosed" {
					// FailClosed: abort the entire evaluation with an error.
					providerResults = append(providerResults, pr)
					sr.ProviderResults = providerResults
					stageResults = append(stageResults, sr)
					eval.Status.StageResults = stageResults

					return r.setErrorPhase(ctx, &eval,
						fmt.Sprintf("provider %q failed with FailClosed policy: %v", sp.ProviderRef.Name, result.Error))
				}

				// FailOpen: record the error, continue with score = 0.
				pr.Score = "0.00"
				providerDegraded = true

				log.Info("provider error with FailOpen policy, continuing", "provider", sp.ProviderRef.Name, "error", result.Error)
			}

			providerResults = append(providerResults, pr)

			if result.Score > maxStageScore {
				maxStageScore = result.Score
			}
		}

		sr.ProviderResults = providerResults
		stageResults = append(stageResults, sr)

		// Track composite score as the max across all non-skipped stages.
		if maxStageScore > compositeScore {
			compositeScore = maxStageScore
		}

		// Check thresholds: find the highest matching threshold.
		matchedAction := r.evaluateThresholds(stage.Thresholds, int(maxStageScore))
		if matchedAction != "" {
			allMatchedActions = append(allMatchedActions, matchedAction)

			// Record event for threshold crossing.
			if r.Recorder != nil {
				r.Recorder.Eventf(&eval, nil, corev1.EventTypeWarning, "ThresholdCrossed", "EvaluateThreshold",
					"Stage %q: score %.2f triggered %s threshold", stage.Name, maxStageScore, matchedAction)
			}
		}

		// Check short-circuit configuration.
		if stage.ShortCircuit != nil && int(maxStageScore) < stage.ShortCircuit.SkipWhenBelow {
			shortCircuitActive = true
			log.V(1).Info("short-circuit activated", "stage", stage.Name, "score", maxStageScore, "skipWhenBelow", stage.ShortCircuit.SkipWhenBelow)
		}

		// Set degraded condition if any provider had an error.
		if providerDegraded {
			meta.SetStatusCondition(&eval.Status.Conditions, metav1.Condition{
				Type:               "Degraded",
				Status:             metav1.ConditionTrue,
				Reason:             "ProviderError",
				Message:            fmt.Sprintf("One or more providers in stage %q returned errors", stage.Name),
				ObservedGeneration: eval.Generation,
			})
		}
	}

	// 6. Composite score is already computed as max across non-skipped stages.

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
	eval.Status.Phase = "Completed"
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

	// 11. Apply enforcement based on policy mode and decision.
	return r.applyEnforcement(ctx, &eval, &policy)
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
// Severity order: DEACTIVATE > REVIEW > NONE.
func (r *FraudEvaluationReconciler) highestAction(actions []string) string {
	if len(actions) == 0 {
		return actionNone
	}

	highest := actionNone

	for _, a := range actions {
		if actionPriority[a] > actionPriority[highest] {
			highest = a
		}
	}

	return highest
}

// determineEnforcement maps the decision to an enforcement action based on policy mode.
func (r *FraudEvaluationReconciler) determineEnforcement(mode, decision string) string {
	if mode == "OBSERVE" {
		return "OBSERVED"
	}

	// AUTO mode.
	switch decision {
	case "DEACTIVATE":
		return "DEACTIVATED"
	case "REVIEW":
		return "REVIEW_FLAGGED"
	default:
		return actionNone
	}
}

// setErrorPhase sets the evaluation to the Error phase with the given message
// and returns a terminal result.
func (r *FraudEvaluationReconciler) setErrorPhase(ctx context.Context, eval *fraudv1alpha1.FraudEvaluation, message string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Error(fmt.Errorf("%s", message), "evaluation failed")

	eval.Status.Phase = "Error"

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
	if policy.Spec.Enforcement.Mode == "OBSERVE" {
		log.Info("enforcement skipped (OBSERVE mode)", "decision", eval.Status.Decision)
		return r.setEnforcementAppliedCondition(ctx, eval, "ObserveMode", "Enforcement skipped: policy is in OBSERVE mode")
	}

	resourceName := enforcementResourcePrefix + eval.Name

	switch eval.Status.Decision {
	case fraudv1alpha1.DecisionDeactivate:
		deactivation := &iamv1alpha1.UserDeactivation{}
		deactivation.Name = resourceName

		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, deactivation, func() error {
			deactivation.Spec = iamv1alpha1.UserDeactivationSpec{
				UserRef:       iamv1alpha1.UserReference{Name: eval.Spec.UserRef.Name},
				Reason:        "fraud-deactivate",
				Description:   fmt.Sprintf("Automated deactivation from FraudEvaluation %q (score: %s)", eval.Name, eval.Status.CompositeScore),
				DeactivatedBy: "fraud-operator",
			}
			return nil
		})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create UserDeactivation %q: %w", resourceName, err)
		}

		log.Info("UserDeactivation created", "name", resourceName, "user", eval.Spec.UserRef.Name)

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

		log.Info("PlatformAccessRejection created", "name", resourceName, "user", eval.Spec.UserRef.Name)

	default: // DecisionNone
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

		log.Info("PlatformAccessApproval created", "name", resourceName, "user", eval.Spec.UserRef.Name)
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
