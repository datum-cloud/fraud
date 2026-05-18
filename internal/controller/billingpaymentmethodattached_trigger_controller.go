// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	billingv1alpha1 "go.miloapis.com/billing/api/v1alpha1"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
	"go.miloapis.com/fraud/internal/datasource"
)

// BillingPaymentMethodAttachedTriggerReconciler watches BillingAccount
// resources and creates a FraudEvaluation when the account's
// PaymentMethodAttached condition flips to True, provided a FraudPolicy
// with a `BillingPaymentMethodAttached` trigger is active. The owning
// user is resolved via the OwnerUserLabel.
type BillingPaymentMethodAttachedTriggerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=billing.miloapis.com,resources=billingaccounts,verbs=get;list;watch

func (r *BillingPaymentMethodAttachedTriggerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var account billingv1alpha1.BillingAccount
	if err := r.Get(ctx, req.NamespacedName, &account); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !isPaymentMethodAttached(&account) {
		// Not yet attached — nothing to do; the next status change will
		// re-trigger this reconciler.
		return ctrl.Result{}, nil
	}

	userUID := account.Labels[datasource.OwnerUserLabel]
	if userUID == "" {
		log.Info("BillingAccount has no owner-user label; skipping fraud trigger",
			"account", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	policy, err := r.findTriggeredPolicy(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	if policy == nil {
		return ctrl.Result{}, nil
	}

	exists, err := r.evaluationExists(ctx, userUID, policy.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	if exists {
		return ctrl.Result{}, nil
	}

	eval := &fraudv1alpha1.FraudEvaluation{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "eval-"},
		Spec: fraudv1alpha1.FraudEvaluationSpec{
			UserRef:   fraudv1alpha1.UserReference{Name: userUID},
			PolicyRef: fraudv1alpha1.PolicyReference{Name: policy.Name},
		},
	}
	if err := r.Create(ctx, eval); err != nil {
		return ctrl.Result{}, fmt.Errorf(
			"failed to create FraudEvaluation for user %q: %w", userUID, err)
	}

	log.Info("created FraudEvaluation from BillingPaymentMethodAttached trigger",
		"user", userUID,
		"billingAccount", req.NamespacedName,
		"evaluation", eval.Name,
		"policy", policy.Name)

	return ctrl.Result{}, nil
}

func isPaymentMethodAttached(a *billingv1alpha1.BillingAccount) bool {
	c := apimeta.FindStatusCondition(a.Status.Conditions, billingv1alpha1.BillingAccountConditionPaymentMethodAttached)
	return c != nil && c.Status == metav1.ConditionTrue
}

func (r *BillingPaymentMethodAttachedTriggerReconciler) findTriggeredPolicy(ctx context.Context) (*fraudv1alpha1.FraudPolicy, error) {
	var policies fraudv1alpha1.FraudPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return nil, fmt.Errorf("failed to list FraudPolicies: %w", err)
	}
	for i := range policies.Items {
		for _, trigger := range policies.Items[i].Spec.Triggers {
			if trigger.Type == "Event" && trigger.Event == fraudv1alpha1.TriggerEventBillingPaymentMethodAttached {
				return &policies.Items[i], nil
			}
		}
	}
	return nil, nil
}

func (r *BillingPaymentMethodAttachedTriggerReconciler) evaluationExists(ctx context.Context, userName, policyName string) (bool, error) {
	var evals fraudv1alpha1.FraudEvaluationList
	if err := r.List(ctx, &evals); err != nil {
		return false, fmt.Errorf("failed to list FraudEvaluations: %w", err)
	}
	for _, e := range evals.Items {
		if e.Spec.UserRef.Name == userName && e.Spec.PolicyRef.Name == policyName {
			return true, nil
		}
	}
	return false, nil
}

// SetupWithManager wires the reconciler. It only fires on create and on
// updates that change the PaymentMethodAttached condition — generic
// status changes (e.g. LinkedProjectsCount) are filtered out.
func (r *BillingPaymentMethodAttachedTriggerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&billingv1alpha1.BillingAccount{}).
		Named("billingpaymentmethodattachedtrigger").
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				if ba, ok := e.Object.(*billingv1alpha1.BillingAccount); ok {
					return isPaymentMethodAttached(ba)
				}
				return false
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				oldBA, oldOK := e.ObjectOld.(*billingv1alpha1.BillingAccount)
				newBA, newOK := e.ObjectNew.(*billingv1alpha1.BillingAccount)
				if !oldOK || !newOK {
					return false
				}
				return !isPaymentMethodAttached(oldBA) && isPaymentMethodAttached(newBA)
			},
			DeleteFunc:  func(_ event.DeleteEvent) bool { return false },
			GenericFunc: func(_ event.GenericEvent) bool { return false },
		}).
		Complete(r)
}
