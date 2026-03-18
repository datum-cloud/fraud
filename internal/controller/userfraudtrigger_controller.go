// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
)

// UserFraudTriggerReconciler watches User resources and automatically creates
// FraudEvaluation resources when a FraudPolicy with a UserCreated trigger is
// active and no evaluation exists for the user yet.
type UserFraudTriggerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get;list;watch
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudevaluations,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudpolicies,verbs=get;list;watch

// Reconcile checks whether a FraudEvaluation should be created for the given
// User. It looks for an active FraudPolicy with a UserCreated trigger and
// creates a FraudEvaluation if one doesn't already exist for this user.
func (r *UserFraudTriggerReconciler) Reconcile(
	ctx context.Context,
	req ctrl.Request,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Fetch the User resource.
	var user iamv1alpha1.User
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	// 2. Find an active FraudPolicy with a UserCreated trigger.
	policy, err := r.findTriggeredPolicy(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}

	if policy == nil {
		// No policy with UserCreated trigger — nothing to do.
		return ctrl.Result{}, nil
	}

	// 3. Check if a FraudEvaluation already exists for this user.
	exists, err := r.evaluationExists(ctx, user.Name, policy.Name)
	if err != nil {
		return ctrl.Result{}, err
	}

	if exists {
		return ctrl.Result{}, nil
	}

	// 4. Create the FraudEvaluation.
	eval := &fraudv1alpha1.FraudEvaluation{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "eval-",
		},
		Spec: fraudv1alpha1.FraudEvaluationSpec{
			UserRef:   fraudv1alpha1.UserReference{Name: user.Name},
			PolicyRef: fraudv1alpha1.PolicyReference{Name: policy.Name},
		},
	}

	if err := r.Create(ctx, eval); err != nil {
		return ctrl.Result{}, fmt.Errorf(
			"failed to create FraudEvaluation for user %q: %w",
			user.Name, err,
		)
	}

	log.Info("created FraudEvaluation for user",
		"user", user.Name,
		"evaluation", eval.Name,
		"policy", policy.Name)

	return ctrl.Result{}, nil
}

// findTriggeredPolicy lists all FraudPolicies and returns the first one that
// has a trigger of type "Event" with event "UserCreated". Returns nil if no
// such policy exists.
func (r *UserFraudTriggerReconciler) findTriggeredPolicy(
	ctx context.Context,
) (*fraudv1alpha1.FraudPolicy, error) {
	var policies fraudv1alpha1.FraudPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return nil, fmt.Errorf("failed to list FraudPolicies: %w", err)
	}

	for i := range policies.Items {
		for _, trigger := range policies.Items[i].Spec.Triggers {
			if trigger.Type == "Event" && trigger.Event == "UserCreated" {
				return &policies.Items[i], nil
			}
		}
	}

	return nil, nil
}

// evaluationExists checks whether a FraudEvaluation already exists for the
// given user and policy combination.
func (r *UserFraudTriggerReconciler) evaluationExists(
	ctx context.Context,
	userName, policyName string,
) (bool, error) {
	var evals fraudv1alpha1.FraudEvaluationList
	if err := r.List(ctx, &evals); err != nil {
		return false, fmt.Errorf("failed to list FraudEvaluations: %w", err)
	}

	for _, e := range evals.Items {
		if e.Spec.UserRef.Name == userName &&
			e.Spec.PolicyRef.Name == policyName {
			return true, nil
		}
	}

	return false, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *UserFraudTriggerReconciler) SetupWithManager(
	mgr ctrl.Manager,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&iamv1alpha1.User{}).
		Named("userfraudtrigger").
		WithEventFilter(predicate.Funcs{
			// Only reconcile on create and periodic re-sync (for backfill).
			// Updates and deletes of Users don't need re-evaluation.
			CreateFunc: func(_ event.CreateEvent) bool { return true },
			UpdateFunc: func(_ event.UpdateEvent) bool { return false },
			DeleteFunc: func(_ event.DeleteEvent) bool { return false },
			GenericFunc: func(_ event.GenericEvent) bool {
				return true
			},
		}).
		Complete(r)
}
