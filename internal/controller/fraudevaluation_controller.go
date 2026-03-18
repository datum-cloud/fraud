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

	actionNone = "NONE"

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

	// 2. If already completed or errored, do not re-process.
	if eval.Status.Phase == "Completed" || eval.Status.Phase == "Error" {
		return ctrl.Result{}, nil
	}

	// 3. Set phase to Running and update status.
	if eval.Status.Phase != "Running" {
		eval.Status.Phase = "Running"
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

	// 6. Execute stages and evaluate thresholds.
	stageResults, compositeScore, decision, err := r.executeStages(ctx, &eval, policy.Spec.Stages, input)
	eval.Status.StageResults = stageResults

	if err != nil {
		return r.setErrorPhase(ctx, &eval, err.Error())
	}

	// 7. Determine enforcement action based on policy mode.
	enforcementAction := r.determineEnforcement(policy.Spec.Enforcement.Mode, decision)

	// 8. Add to history (prepend, trim to maxEntries).
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

	// 9. Set phase to Completed and update all status fields.
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

	return ctrl.Result{}, nil
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

// executeStages runs all policy stages against the resolved input and returns
// the stage results, composite score, and final decision.
func (r *FraudEvaluationReconciler) executeStages(
	ctx context.Context,
	eval *fraudv1alpha1.FraudEvaluation,
	stages []fraudv1alpha1.Stage,
	input provider.Input,
) ([]fraudv1alpha1.StageResult, float64, string, error) {
	log := logf.FromContext(ctx)

	stageResults := make([]fraudv1alpha1.StageResult, 0, len(stages))

	var (
		shortCircuitActive bool
		allMatchedActions  []string
		compositeScore     float64
	)

	for _, stage := range stages {
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
			pr, score, err := r.evaluateProvider(ctx, sp, input)
			if err != nil {
				providerResults = append(providerResults, pr)
				sr.ProviderResults = providerResults
				stageResults = append(stageResults, sr)

				return stageResults, compositeScore, "", err
			}

			providerResults = append(providerResults, pr)

			if pr.Error != "" {
				providerDegraded = true
			}

			if score > maxStageScore {
				maxStageScore = score
			}
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

	decision := r.highestAction(allMatchedActions)

	return stageResults, compositeScore, decision, nil
}

// evaluateProvider calls a single provider and returns its result, score, and
// any fatal error (FailClosed). For FailOpen errors the result includes the
// error string but the returned error is nil.
func (r *FraudEvaluationReconciler) evaluateProvider(
	ctx context.Context,
	sp fraudv1alpha1.StageProvider,
	input provider.Input,
) (fraudv1alpha1.ProviderResult, float64, error) {
	log := logf.FromContext(ctx)

	var fp fraudv1alpha1.FraudProvider
	if err := r.Get(ctx, types.NamespacedName{Name: sp.ProviderRef.Name}, &fp); err != nil {
		return fraudv1alpha1.ProviderResult{},
			0,
			fmt.Errorf("failed to fetch FraudProvider %q: %w", sp.ProviderRef.Name, err)
	}

	impl, ok := r.Registry.Get(sp.ProviderRef.Name)
	if !ok {
		return fraudv1alpha1.ProviderResult{},
			0,
			fmt.Errorf("provider %q is not yet initialized (Available condition may be false)", sp.ProviderRef.Name)
	}

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
			return pr, 0, fmt.Errorf("provider %q failed with FailClosed policy: %w", sp.ProviderRef.Name, result.Error)
		}

		pr.Score = "0.00"

		log.Info("provider error with FailOpen policy, continuing",
			"provider", sp.ProviderRef.Name, "error", result.Error)

		return pr, 0, nil
	}

	return pr, result.Score, nil
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

// SetupWithManager sets up the controller with the Manager.
func (r *FraudEvaluationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&fraudv1alpha1.FraudEvaluation{}).
		Named("fraudevaluation").
		Complete(r)
}
