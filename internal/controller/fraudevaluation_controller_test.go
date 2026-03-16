// SPDX-License-Identifier: AGPL-3.0-only
package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	fraudv1alpha1 "go.miloapis.com/fraud/api/v1alpha1"
	"go.miloapis.com/fraud/internal/provider"
)

// mockProvider is a test implementation of provider.Provider.
type mockProvider struct {
	name   string
	result provider.Result
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Evaluate(_ context.Context, _ provider.Input) provider.Result {
	return m.result
}

var _ = Describe("FraudEvaluation Controller", func() {
	ctx := context.Background()

	Context("Full pipeline evaluation", func() {
		var (
			reconciler *FraudEvaluationReconciler
			registry   *provider.Registry
			policyName string
			provName   string
		)

		BeforeEach(func() {
			provName = "maxmind-test"
			policyName = "test-policy"
			registry = provider.NewRegistry()
		})

		AfterEach(func() {
			// Clean up all resources. Ignore not-found errors.
			evalList := &fraudv1alpha1.FraudEvaluationList{}
			Expect(k8sClient.List(ctx, evalList)).To(Succeed())
			for i := range evalList.Items {
				_ = k8sClient.Delete(ctx, &evalList.Items[i])
			}

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

		createResources := func(score float64, failurePolicy string, mode string) {
			// Create FraudProvider CR.
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: failurePolicy,
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			// Create FraudPolicy CR.
			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "risk-analysis",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
								{MinScore: 90, Action: "DEACTIVATE"},
							},
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: mode},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Register the mock provider in the registry under the CR name.
			registry.Register(provName, &mockProvider{
				name:   "maxmind",
				result: provider.Result{Score: score, RawResponse: `{"risk_score": 50}`},
			})

			// Set up reconciler with the registry.
			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}
		}

		It("should complete with NONE decision for low score", func() {
			createResources(15, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-low"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-1"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-low"},
			})
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch to see status.
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-low"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.CompositeScore).To(Equal("15.00"))
			Expect(eval.Status.Decision).To(Equal("NONE"))
			Expect(eval.Status.EnforcementAction).To(Equal("OBSERVED"))
			Expect(eval.Status.StageResults).To(HaveLen(1))
			Expect(eval.Status.StageResults[0].ProviderResults).To(HaveLen(1))
			Expect(eval.Status.StageResults[0].ProviderResults[0].Score).To(Equal("15.00"))
			Expect(eval.Status.History).To(HaveLen(1))
		})

		It("should trigger REVIEW for score above 70", func() {
			createResources(75, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-review"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-2"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-review"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-review"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.CompositeScore).To(Equal("75.00"))
			Expect(eval.Status.Decision).To(Equal("REVIEW"))
			Expect(eval.Status.EnforcementAction).To(Equal("OBSERVED"))
		})

		It("should trigger DEACTIVATE for score above 90", func() {
			createResources(95, "FailOpen", "AUTO")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-deactivate"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-3"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-deactivate"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-deactivate"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.Decision).To(Equal("DEACTIVATE"))
			Expect(eval.Status.EnforcementAction).To(Equal("DEACTIVATED"))
		})

		It("should use OBSERVED enforcement in OBSERVE mode even for high scores", func() {
			createResources(95, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-observe"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-4"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-observe"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-observe"}, eval)).To(Succeed())
			Expect(eval.Status.Decision).To(Equal("DEACTIVATE"))
			Expect(eval.Status.EnforcementAction).To(Equal("OBSERVED"))
		})

		It("should handle provider failure with FailOpen", func() {
			// Create resources but use an error-returning provider.
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailOpen",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "risk-analysis",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
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

			registry.Register(provName, &mockProvider{
				name: "maxmind",
				result: provider.Result{
					Error: fmt.Errorf("connection refused"),
				},
			})

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-failopen"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-5"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-failopen"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-failopen"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.CompositeScore).To(Equal("0.00"))
			Expect(eval.Status.Decision).To(Equal("NONE"))
			Expect(eval.Status.StageResults[0].ProviderResults[0].Error).To(ContainSubstring("connection refused"))
			Expect(eval.Status.StageResults[0].ProviderResults[0].FailurePolicyApplied).To(Equal("FailOpen"))
		})

		It("should set Error phase on provider failure with FailClosed", func() {
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailClosed",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "risk-analysis",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
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

			registry.Register(provName, &mockProvider{
				name: "maxmind",
				result: provider.Result{
					Error: fmt.Errorf("connection refused"),
				},
			})

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-failclosed"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-6"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-failclosed"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-failclosed"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Error"))
		})

		It("should skip stages when short-circuit is active", func() {
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailOpen",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			// Two stages: first with short-circuit at 30, second is not required.
			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "stage-1",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
							},
							ShortCircuit: &fraudv1alpha1.ShortCircuitConfig{
								SkipWhenBelow: 30,
							},
						},
						{
							Name: "stage-2",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 80, Action: "DEACTIVATE"},
							},
							Required: false,
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Score of 10 is below short-circuit threshold of 30.
			registry.Register(provName, &mockProvider{
				name:   "maxmind",
				result: provider.Result{Score: 10},
			})

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-shortcircuit"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-7"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-shortcircuit"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-shortcircuit"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))
			Expect(eval.Status.StageResults).To(HaveLen(2))
			Expect(eval.Status.StageResults[0].Skipped).To(BeFalse())
			Expect(eval.Status.StageResults[1].Skipped).To(BeTrue())
		})

		It("should not skip required stages even when short-circuit is active", func() {
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailOpen",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "stage-1",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 70, Action: "REVIEW"},
							},
							ShortCircuit: &fraudv1alpha1.ShortCircuitConfig{
								SkipWhenBelow: 30,
							},
						},
						{
							Name: "stage-2-required",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
							},
							Thresholds: []fraudv1alpha1.Threshold{
								{MinScore: 80, Action: "DEACTIVATE"},
							},
							Required: true,
						},
					},
					Enforcement: fraudv1alpha1.EnforcementConfig{Mode: "OBSERVE"},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			registry.Register(provName, &mockProvider{
				name:   "maxmind",
				result: provider.Result{Score: 10},
			})

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry,
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-required"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-8"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-required"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-required"}, eval)).To(Succeed())
			Expect(eval.Status.StageResults).To(HaveLen(2))
			Expect(eval.Status.StageResults[0].Skipped).To(BeFalse())
			Expect(eval.Status.StageResults[1].Skipped).To(BeFalse())
		})

		It("should not re-process completed evaluations", func() {
			createResources(50, "FailOpen", "OBSERVE")

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-completed"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-9"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			// First reconcile: should complete.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-completed"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-completed"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Completed"))

			// Second reconcile: should be a no-op.
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-completed"},
			})
			Expect(err).NotTo(HaveOccurred())

			// History should still have only 1 entry.
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-completed"}, eval)).To(Succeed())
			Expect(eval.Status.History).To(HaveLen(1))
		})

		It("should set Error phase when provider is not registered", func() {
			// Create resources but do NOT register anything in the registry.
			fp := &fraudv1alpha1.FraudProvider{
				ObjectMeta: metav1.ObjectMeta{Name: provName},
				Spec: fraudv1alpha1.FraudProviderSpec{
					Type:          "maxmind",
					FailurePolicy: "FailOpen",
				},
			}
			Expect(k8sClient.Create(ctx, fp)).To(Succeed())

			policy := &fraudv1alpha1.FraudPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName},
				Spec: fraudv1alpha1.FraudPolicySpec{
					Stages: []fraudv1alpha1.Stage{
						{
							Name: "risk-analysis",
							Providers: []fraudv1alpha1.StageProvider{
								{ProviderRef: fraudv1alpha1.ProviderReference{Name: provName}},
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

			reconciler = &FraudEvaluationReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: events.NewFakeRecorder(10),
				Registry: registry, // empty registry
			}

			eval := &fraudv1alpha1.FraudEvaluation{
				ObjectMeta: metav1.ObjectMeta{Name: "eval-no-provider"},
				Spec: fraudv1alpha1.FraudEvaluationSpec{
					UserRef:   fraudv1alpha1.UserReference{Name: "user-10"},
					PolicyRef: fraudv1alpha1.PolicyReference{Name: policyName},
				},
			}
			Expect(k8sClient.Create(ctx, eval)).To(Succeed())

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "eval-no-provider"},
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "eval-no-provider"}, eval)).To(Succeed())
			Expect(eval.Status.Phase).To(Equal("Error"))
		})
	})
})
