// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
)

var _ = Describe("FraudPolicy Controller", func() {
	ctx := context.Background()

	AfterEach(func() {
		policyList := &fraudv1alpha1.FraudPolicyList{}
		Expect(k8sClient.List(ctx, policyList)).To(Succeed())
		for i := range policyList.Items {
			_ = k8sClient.Delete(ctx, &policyList.Items[i])
		}
		providerList := &fraudv1alpha1.FraudProviderList{}
		Expect(k8sClient.List(ctx, providerList)).To(Succeed())
		for i := range providerList.Items {
			_ = k8sClient.Delete(ctx, &providerList.Items[i])
		}
	})

	It("should set Available when all referenced providers exist and are available", func() {
		// Create a FraudProvider and mark it available.
		fp := &fraudv1alpha1.FraudProvider{
			ObjectMeta: metav1.ObjectMeta{Name: "maxmind-policy-test"},
			Spec: fraudv1alpha1.FraudProviderSpec{
				Type: "maxmind",
			},
		}
		Expect(k8sClient.Create(ctx, fp)).To(Succeed())
		// Set Available condition on the provider.
		meta.SetStatusCondition(&fp.Status.Conditions, metav1.Condition{
			Type:   "Available",
			Status: metav1.ConditionTrue,
			Reason: "ProviderReady",
		})
		Expect(k8sClient.Status().Update(ctx, fp)).To(Succeed())

		policy := &fraudv1alpha1.FraudPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-valid"},
			Spec: fraudv1alpha1.FraudPolicySpec{
				Stages: []fraudv1alpha1.Stage{
					{
						Name: "risk",
						Providers: []fraudv1alpha1.StageProvider{
							{ProviderRef: fraudv1alpha1.ProviderReference{Name: "maxmind-policy-test"}},
						},
						Thresholds: []fraudv1alpha1.Threshold{
							{MinScore: 70, Action: "REVIEW"},
						},
					},
				},
				Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
			},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		reconciler := &FraudPolicyReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "policy-valid"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "policy-valid"}, policy)).To(Succeed())
		cond := meta.FindStatusCondition(policy.Status.Conditions, "Available")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionTrue))
	})

	It("should set Available=False when referenced provider does not exist", func() {
		policy := &fraudv1alpha1.FraudPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-missing-provider"},
			Spec: fraudv1alpha1.FraudPolicySpec{
				Stages: []fraudv1alpha1.Stage{
					{
						Name: "risk",
						Providers: []fraudv1alpha1.StageProvider{
							{ProviderRef: fraudv1alpha1.ProviderReference{Name: "nonexistent"}},
						},
						Thresholds: []fraudv1alpha1.Threshold{
							{MinScore: 70, Action: "REVIEW"},
						},
					},
				},
				Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
			},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())

		reconciler := &FraudPolicyReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		_, err := reconciler.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "policy-missing-provider"},
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "policy-missing-provider"}, policy)).To(Succeed())
		cond := meta.FindStatusCondition(policy.Status.Conditions, "Available")
		Expect(cond).NotTo(BeNil())
		Expect(cond.Status).To(Equal(metav1.ConditionFalse))
		Expect(cond.Reason).To(Equal("MissingProviders"))
	})
})
