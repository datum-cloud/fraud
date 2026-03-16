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
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
	"go.miloapis.com/fraud/internal/provider"
)

var _ = Describe("FraudProvider Controller", func() {
	ctx := context.Background()

	var registry *provider.Registry

	BeforeEach(func() {
		registry = provider.NewRegistry()
	})

	AfterEach(func() {
		providerList := &fraudv1alpha1.FraudProviderList{}
		Expect(k8sClient.List(ctx, providerList)).To(Succeed())
		for i := range providerList.Items {
			_ = k8sClient.Delete(ctx, &providerList.Items[i])
		}
	})

	It("should set Available condition and register provider for valid config", func() {
		credDir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(credDir, "accountID"), []byte("12345"), 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(credDir, "licenseKey"), []byte("abc"), 0o600)).To(Succeed())

		fp := &fraudv1alpha1.FraudProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "provider-valid"},
			Spec: fraudv1alpha1.FraudProviderSpec{
				Type: "maxmind",
				Config: fraudv1alpha1.FraudProviderConfig{
					CredentialsPath: credDir,
				},
			},
		}
		Expect(k8sClient.Create(ctx, fp)).To(Succeed())

		reconciler := &FraudProviderReconciler{
			Client:   k8sClient,
			Scheme:   k8sClient.Scheme(),
			Registry: registry,
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "provider-valid"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "provider-valid"}, fp)).To(Succeed())
		cond := meta.FindStatusCondition(fp.Status.Conditions, "Available")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
		Expect(cond.Reason).To(Equal("ProviderReady"))

		// Verify the provider was registered.
		impl, ok := registry.Get("provider-valid")
		Expect(ok).To(BeTrue())
		Expect(impl.Name()).To(Equal("maxmind"))
	})

	It("should set Available=False when credentialsPath is not set", func() {
		fp := &fraudv1alpha1.FraudProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "provider-no-path"},
			Spec: fraudv1alpha1.FraudProviderSpec{
				Type:   "maxmind",
				Config: fraudv1alpha1.FraudProviderConfig{},
			},
		}
		Expect(k8sClient.Create(ctx, fp)).To(Succeed())

		reconciler := &FraudProviderReconciler{
			Client:   k8sClient,
			Scheme:   k8sClient.Scheme(),
			Registry: registry,
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "provider-no-path"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "provider-no-path"}, fp)).To(Succeed())
		cond := meta.FindStatusCondition(fp.Status.Conditions, "Available")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal("CredentialsNotConfigured"))

		_, ok := registry.Get("provider-no-path")
		Expect(ok).To(BeFalse())
	})

	It("should set Available=False when credential files are missing", func() {
		credDir := GinkgoT().TempDir()
		// Empty directory — no credential files.

		fp := &fraudv1alpha1.FraudProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "provider-no-files"},
			Spec: fraudv1alpha1.FraudProviderSpec{
				Type: "maxmind",
				Config: fraudv1alpha1.FraudProviderConfig{
					CredentialsPath: credDir,
				},
			},
		}
		Expect(k8sClient.Create(ctx, fp)).To(Succeed())

		reconciler := &FraudProviderReconciler{
			Client:   k8sClient,
			Scheme:   k8sClient.Scheme(),
			Registry: registry,
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "provider-no-files"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "provider-no-files"}, fp)).To(Succeed())
		cond := meta.FindStatusCondition(fp.Status.Conditions, "Available")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal("CredentialsReadError"))

		_, ok := registry.Get("provider-no-files")
		Expect(ok).To(BeFalse())
	})

	It("should set Available=False when credential files are empty", func() {
		credDir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(credDir, "accountID"), []byte("12345"), 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(credDir, "licenseKey"), []byte(""), 0o600)).To(Succeed())

		fp := &fraudv1alpha1.FraudProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "provider-empty-key"},
			Spec: fraudv1alpha1.FraudProviderSpec{
				Type: "maxmind",
				Config: fraudv1alpha1.FraudProviderConfig{
					CredentialsPath: credDir,
				},
			},
		}
		Expect(k8sClient.Create(ctx, fp)).To(Succeed())

		reconciler := &FraudProviderReconciler{
			Client:   k8sClient,
			Scheme:   k8sClient.Scheme(),
			Registry: registry,
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "provider-empty-key"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "provider-empty-key"}, fp)).To(Succeed())
		cond := meta.FindStatusCondition(fp.Status.Conditions, "Available")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal("InvalidCredentials"))

		_, ok := registry.Get("provider-empty-key")
		Expect(ok).To(BeFalse())
	})

	It("should deregister provider when CR is deleted", func() {
		// Pre-populate the registry to simulate a previously reconciled provider.
		registry.Register("provider-deleted", &mockProvider{name: "maxmind"})

		reconciler := &FraudProviderReconciler{
			Client:   k8sClient,
			Scheme:   k8sClient.Scheme(),
			Registry: registry,
		}

		// Reconcile a non-existent CR (simulates deletion).
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "provider-deleted"},
		})
		Expect(err).NotTo(HaveOccurred())

		_, ok := registry.Get("provider-deleted")
		Expect(ok).To(BeFalse())
	})

	It("should use custom endpoint from FraudProvider config", func() {
		credDir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(credDir, "accountID"), []byte("12345"), 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(credDir, "licenseKey"), []byte("abc"), 0o600)).To(Succeed())

		fp := &fraudv1alpha1.FraudProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "provider-custom-ep"},
			Spec: fraudv1alpha1.FraudProviderSpec{
				Type: "maxmind",
				Config: fraudv1alpha1.FraudProviderConfig{
					Endpoint:        "https://mock.example.com/minfraud",
					CredentialsPath: credDir,
				},
			},
		}
		Expect(k8sClient.Create(ctx, fp)).To(Succeed())

		reconciler := &FraudProviderReconciler{
			Client:   k8sClient,
			Scheme:   k8sClient.Scheme(),
			Registry: registry,
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "provider-custom-ep"},
		})
		Expect(err).NotTo(HaveOccurred())

		impl, ok := registry.Get("provider-custom-ep")
		Expect(ok).To(BeTrue())
		Expect(impl.Name()).To(Equal("maxmind"))
	})
})
