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

package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
)

// FraudPolicyReconciler reconciles a FraudPolicy object.
type FraudPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudproviders,verbs=get;list;watch

// Reconcile validates the FraudPolicy resource by checking that all referenced
// FraudProvider resources exist and are available, then sets conditions accordingly.
func (r *FraudPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var policy fraudv1alpha1.FraudPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	// Collect all unique provider references across all stages.
	providerNames := make(map[string]struct{})
	for _, stage := range policy.Spec.Stages {
		for _, sp := range stage.Providers {
			providerNames[sp.ProviderRef.Name] = struct{}{}
		}
	}

	// Validate each referenced provider exists and is available.
	var (
		missingProviders     []string
		unavailableProviders []string
	)

	for name := range providerNames {
		var fp fraudv1alpha1.FraudProvider
		fpKey := types.NamespacedName{Name: name}

		if err := r.Get(ctx, fpKey, &fp); err != nil {
			if apierrors.IsNotFound(err) {
				missingProviders = append(missingProviders, name)
			} else {
				return ctrl.Result{}, fmt.Errorf("failed to fetch FraudProvider %q: %w", name, err)
			}

			continue
		}

		// Check if the provider has a ready Available condition.
		availCond := meta.FindStatusCondition(fp.Status.Conditions, "Available")
		if availCond == nil || availCond.Status != metav1.ConditionTrue {
			unavailableProviders = append(unavailableProviders, name)
		}
	}

	// Set conditions based on validation results.
	if len(missingProviders) > 0 {
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Available",
			Status:             metav1.ConditionFalse,
			Reason:             "MissingProviders",
			Message:            fmt.Sprintf("referenced FraudProvider resources not found: %v", missingProviders),
			ObservedGeneration: policy.Generation,
		})

		if err := r.Status().Update(ctx, &policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
		}

		return ctrl.Result{}, nil
	}

	if len(unavailableProviders) > 0 {
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Degraded",
			Status:             metav1.ConditionTrue,
			Reason:             "ProvidersUnavailable",
			Message:            fmt.Sprintf("referenced FraudProvider resources are not available: %v", unavailableProviders),
			ObservedGeneration: policy.Generation,
		})

		// Still set Available to true since the policy itself is valid,
		// but mark it as degraded.
		meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
			Type:               "Available",
			Status:             metav1.ConditionTrue,
			Reason:             "PolicyValidDegraded",
			Message:            "policy is valid but some referenced providers are unavailable",
			ObservedGeneration: policy.Generation,
		})

		if err := r.Status().Update(ctx, &policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
		}

		return ctrl.Result{}, nil
	}

	// All providers present and available -- clear degraded, set available.
	meta.RemoveStatusCondition(&policy.Status.Conditions, "Degraded")

	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionTrue,
		Reason:             "PolicyReady",
		Message:            fmt.Sprintf("policy is valid and all %d referenced providers are available", len(providerNames)),
		ObservedGeneration: policy.Generation,
	})

	if err := r.Status().Update(ctx, &policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("policy validated", "providers", len(providerNames))

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FraudPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&fraudv1alpha1.FraudPolicy{}).
		Named("fraudpolicy").
		Complete(r)
}
