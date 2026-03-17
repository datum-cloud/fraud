// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
)

const (
	// conditionEnforcementApplied is set on the FraudEvaluation once IAM
	// enforcement resources have been successfully created in the Milo API server.
	conditionEnforcementApplied = "EnforcementApplied"

	// enforcementResourcePrefix is prepended to the FraudEvaluation name when
	// naming the IAM enforcement resources.
	enforcementResourcePrefix = "fraud-"
)

// FraudEnforcementReconciler watches FraudEvaluation resources and creates the
// corresponding Milo IAM enforcement resources once an evaluation reaches the
// Completed phase.
type FraudEnforcementReconciler struct {
	// Client is used to read FraudEvaluation resources and update their status.
	client.Client
	// MiloClient is used to create IAM resources in the Milo API server.
	MiloClient client.Client
	Scheme     *runtime.Scheme
}

// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudevaluations,verbs=get;list;watch
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudevaluations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=platformaccessapprovals,verbs=get;create
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=platformaccessrejections,verbs=get;create
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=userdeactivations,verbs=get;create

// Reconcile creates the appropriate Milo IAM enforcement resource for a
// completed FraudEvaluation.
func (r *FraudEnforcementReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var eval fraudv1alpha1.FraudEvaluation
	if err := r.Get(ctx, req.NamespacedName, &eval); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("failed to fetch FraudEvaluation %q: %w", req.Name, err)
	}

	// Only act on completed evaluations.
	if eval.Status.Phase != "Completed" {
		return ctrl.Result{}, nil
	}

	// Short-circuit: enforcement already applied.
	if meta.IsStatusConditionTrue(eval.Status.Conditions, conditionEnforcementApplied) {
		return ctrl.Result{}, nil
	}

	resourceName := enforcementResourcePrefix + eval.Name
	userName := eval.Spec.UserRef.Name

	log.Info("applying enforcement",
		"evaluation", eval.Name,
		"decision", eval.Status.Decision,
		"user", userName,
		"iamResource", resourceName)

	if err := r.applyEnforcement(ctx, &eval, resourceName, userName); err != nil {
		return ctrl.Result{}, err
	}

	// Record that enforcement has been applied so subsequent reconcile loops
	// short-circuit without making additional API calls.
	meta.SetStatusCondition(&eval.Status.Conditions, metav1.Condition{
		Type:               conditionEnforcementApplied,
		Status:             metav1.ConditionTrue,
		Reason:             "EnforcementResourceCreated",
		Message:            fmt.Sprintf("IAM enforcement resource %q created for decision %s", resourceName, eval.Status.Decision),
		ObservedGeneration: eval.Generation,
	})

	if err := r.Status().Update(ctx, &eval); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update EnforcementApplied condition on FraudEvaluation %q: %w", eval.Name, err)
	}

	log.Info("enforcement applied",
		"evaluation", eval.Name,
		"decision", eval.Status.Decision,
		"iamResource", resourceName)

	return ctrl.Result{}, nil
}

// applyEnforcement creates the correct IAM resource in the Milo API server
// based on the evaluation decision. Uses CreateOrUpdate so the call is safe to
// retry on transient failures.
func (r *FraudEnforcementReconciler) applyEnforcement(ctx context.Context, eval *fraudv1alpha1.FraudEvaluation, resourceName, userName string) error {
	switch eval.Status.Decision {
	case "NONE":
		return r.applyApproval(ctx, resourceName, userName)
	case "REVIEW":
		return r.applyRejection(ctx, resourceName, userName)
	case "DEACTIVATE":
		return r.applyDeactivation(ctx, resourceName, userName)
	default:
		return fmt.Errorf("unknown decision %q on FraudEvaluation %q", eval.Status.Decision, eval.Name)
	}
}

func (r *FraudEnforcementReconciler) applyApproval(ctx context.Context, resourceName, userName string) error {
	approval := &iamv1alpha1.PlatformAccessApproval{
		ObjectMeta: metav1.ObjectMeta{
			Name: resourceName,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.MiloClient, approval, func() error {
		// Spec is immutable on PlatformAccessApproval; only set on creation.
		if approval.CreationTimestamp.IsZero() {
			approval.Spec = iamv1alpha1.PlatformAccessApprovalSpec{
				SubjectRef: iamv1alpha1.SubjectReference{
					UserRef: &iamv1alpha1.UserReference{
						Name: userName,
					},
				},
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create PlatformAccessApproval %q for user %q: %w", resourceName, userName, err)
	}

	if result != controllerutil.OperationResultNone {
		logf.FromContext(ctx).Info("PlatformAccessApproval reconciled",
			"resource", resourceName,
			"operation", result)
	}

	return nil
}

func (r *FraudEnforcementReconciler) applyRejection(ctx context.Context, resourceName, userName string) error {
	rejection := &iamv1alpha1.PlatformAccessRejection{
		ObjectMeta: metav1.ObjectMeta{
			Name: resourceName,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.MiloClient, rejection, func() error {
		// Spec is immutable on PlatformAccessRejection; only set on creation.
		if rejection.CreationTimestamp.IsZero() {
			rejection.Spec = iamv1alpha1.PlatformAccessRejectionSpec{
				UserRef: iamv1alpha1.UserReference{
					Name: userName,
				},
				Reason: "fraud-review",
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create PlatformAccessRejection %q for user %q: %w", resourceName, userName, err)
	}

	if result != controllerutil.OperationResultNone {
		logf.FromContext(ctx).Info("PlatformAccessRejection reconciled",
			"resource", resourceName,
			"operation", result)
	}

	return nil
}

func (r *FraudEnforcementReconciler) applyDeactivation(ctx context.Context, resourceName, userName string) error {
	deactivation := &iamv1alpha1.UserDeactivation{
		ObjectMeta: metav1.ObjectMeta{
			Name: resourceName,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.MiloClient, deactivation, func() error {
		// Only set spec fields on creation; UserDeactivation spec is also
		// effectively immutable once the deactivation has been processed.
		if deactivation.CreationTimestamp.IsZero() {
			deactivation.Spec = iamv1alpha1.UserDeactivationSpec{
				UserRef: iamv1alpha1.UserReference{
					Name: userName,
				},
				Reason:        "fraud-deactivate",
				DeactivatedBy: "fraud-operator",
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to create UserDeactivation %q for user %q: %w", resourceName, userName, err)
	}

	if result != controllerutil.OperationResultNone {
		logf.FromContext(ctx).Info("UserDeactivation reconciled",
			"resource", resourceName,
			"operation", result)
	}

	return nil
}

// SetupWithManager registers the controller with the Manager.
func (r *FraudEnforcementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&fraudv1alpha1.FraudEvaluation{}).
		Named("fraudenforcement").
		Complete(r)
}
