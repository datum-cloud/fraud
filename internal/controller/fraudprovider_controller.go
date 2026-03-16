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
	"os"
	"path/filepath"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
	"go.miloapis.com/fraud/internal/provider"
	"go.miloapis.com/fraud/internal/provider/maxmind"
)

// supportedProviderTypes lists the valid provider type values.
var supportedProviderTypes = map[string]bool{
	"maxmind": true,
}

// FraudProviderReconciler reconciles a FraudProvider object.
type FraudProviderReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Registry *provider.Registry
}

// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudproviders,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudproviders/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=fraud.miloapis.com,resources=fraudproviders/finalizers,verbs=update

// Reconcile validates the FraudProvider resource, bootstraps a provider client
// from its credentials, and registers it in the shared provider registry.
func (r *FraudProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var fp fraudv1alpha1.FraudProvider
	if err := r.Get(ctx, req.NamespacedName, &fp); err != nil {
		if apierrors.IsNotFound(err) {
			// CR deleted — remove from registry.
			r.Registry.Deregister(req.Name)
			log.Info("provider deregistered", "name", req.Name)

			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	// Validate provider type.
	if !supportedProviderTypes[fp.Spec.Type] {
		return r.setProviderError(ctx, &fp, "UnsupportedType",
			fmt.Sprintf("provider type %q is not supported", fp.Spec.Type))
	}

	// Load credentials from the path declared in the FraudProvider spec.
	credPath := fp.Spec.Config.CredentialsPath
	if credPath == "" {
		return r.setProviderError(ctx, &fp, "CredentialsNotConfigured",
			"spec.config.credentialsPath is not set")
	}

	accountIDBytes, err := os.ReadFile(filepath.Join(credPath, "accountID"))
	if err != nil {
		return r.setProviderError(ctx, &fp, "CredentialsReadError",
			fmt.Sprintf("failed to read accountID from %s: %v", credPath, err))
	}

	licenseKeyBytes, err := os.ReadFile(filepath.Join(credPath, "licenseKey"))
	if err != nil {
		return r.setProviderError(ctx, &fp, "CredentialsReadError",
			fmt.Sprintf("failed to read licenseKey from %s: %v", credPath, err))
	}

	accountID := strings.TrimSpace(string(accountIDBytes))
	licenseKey := strings.TrimSpace(string(licenseKeyBytes))

	if accountID == "" || licenseKey == "" {
		return r.setProviderError(ctx, &fp, "InvalidCredentials", "credentials are missing accountID and/or licenseKey")
	}

	// Bootstrap the provider client based on type.
	var impl provider.Provider

	switch fp.Spec.Type {
	case "maxmind":
		impl = maxmind.NewClient(fp.Spec.Config.Endpoint, accountID, licenseKey)
	default:
		// Already validated above, but be defensive.
		return ctrl.Result{}, fmt.Errorf("unsupported provider type %q", fp.Spec.Type)
	}

	r.Registry.Register(fp.Name, impl)

	// All checks passed — set Available to true.
	meta.SetStatusCondition(&fp.Status.Conditions, metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionTrue,
		Reason:             "ProviderReady",
		Message:            fmt.Sprintf("provider type %q is valid and client initialized", fp.Spec.Type),
		ObservedGeneration: fp.Generation,
	})

	if err := r.Status().Update(ctx, &fp); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
	}

	log.Info("provider registered", "name", fp.Name, "type", fp.Spec.Type)

	return ctrl.Result{}, nil
}

// setProviderError deregisters the provider and sets a failed condition.
func (r *FraudProviderReconciler) setProviderError(ctx context.Context, fp *fraudv1alpha1.FraudProvider, reason, message string) (ctrl.Result, error) {
	r.Registry.Deregister(fp.Name)

	meta.SetStatusCondition(&fp.Status.Conditions, metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: fp.Generation,
	})

	if err := r.Status().Update(ctx, fp); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FraudProviderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&fraudv1alpha1.FraudProvider{}).
		Named("fraudprovider").
		Complete(r)
}
