//go:build e2e
// +build e2e

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

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"go.miloapis.com/fraud-operator/test/utils"
)

// namespace where the project is deployed in
const namespace = "fraud-operator-system"

var _ = Describe("Fraud Operator", Ordered, func() {
	var controllerPodName string

	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, _ = utils.Run(cmd) // may already exist

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	AfterAll(func() {
		By("undeploying the controller-manager")
		cmd := exec.Command("make", "undeploy", "ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall", "ignore-not-found=true")
		_, _ = utils.Run(cmd)
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "--all-namespaces", "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Controller startup", func() {
		It("should have the controller-manager pod running", func() {
			verifyControllerUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace)
				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]

				cmd = exec.Command("kubectl", "get", "pods", controllerPodName,
					"-o", "jsonpath={.status.phase}", "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"))
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})
	})

	Context("CRD installation", func() {
		It("should have all fraud CRDs installed", func() {
			for _, crd := range []string{
				"fraudproviders.fraud.miloapis.com",
				"fraudpolicies.fraud.miloapis.com",
				"fraudevaluations.fraud.miloapis.com",
			} {
				cmd := exec.Command("kubectl", "get", "crd", crd)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "CRD %s should exist", crd)
			}
		})
	})

	Context("Fraud evaluation pipeline", func() {
		AfterEach(func() {
			// Clean up CRs.
			cmds := [][]string{
				{"kubectl", "delete", "fraudevaluation", "test-user-1", "--ignore-not-found"},
				{"kubectl", "delete", "fraudpolicy", "e2e-policy", "--ignore-not-found"},
				{"kubectl", "delete", "fraudprovider", "e2e-maxmind", "--ignore-not-found"},
				{"kubectl", "delete", "secret", "e2e-maxmind-creds", "-n", namespace, "--ignore-not-found"},
			}
			for _, args := range cmds {
				cmd := exec.Command(args[0], args[1:]...)
				_, _ = utils.Run(cmd)
			}
		})

		It("should create and reconcile a FraudProvider", func() {
			By("creating a dummy credentials secret")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "e2e-maxmind-creds",
				"--namespace", namespace,
				"--from-literal=accountID=123456",
				"--from-literal=licenseKey=test-key")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("creating a FraudProvider")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = jsonReader(map[string]interface{}{
				"apiVersion": "fraud.miloapis.com/v1alpha1",
				"kind":       "FraudProvider",
				"metadata":   map[string]interface{}{"name": "e2e-maxmind"},
				"spec": map[string]interface{}{
					"type": "maxmind",
					"config": map[string]interface{}{
						"credentialsRef": map[string]interface{}{
							"name":      "e2e-maxmind-creds",
							"namespace": namespace,
						},
					},
					"failurePolicy": "FailOpen",
				},
			})
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the FraudProvider becomes Available")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "fraudprovider", "e2e-maxmind",
					"-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"))
			}).Should(Succeed())
		})

		It("should create and reconcile a FraudPolicy", func() {
			By("creating prerequisite FraudProvider")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "e2e-maxmind-creds",
				"--namespace", namespace,
				"--from-literal=accountID=123456",
				"--from-literal=licenseKey=test-key")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = jsonReader(map[string]interface{}{
				"apiVersion": "fraud.miloapis.com/v1alpha1",
				"kind":       "FraudProvider",
				"metadata":   map[string]interface{}{"name": "e2e-maxmind"},
				"spec": map[string]interface{}{
					"type": "maxmind",
					"config": map[string]interface{}{
						"credentialsRef": map[string]interface{}{
							"name":      "e2e-maxmind-creds",
							"namespace": namespace,
						},
					},
					"failurePolicy": "FailOpen",
				},
			})
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			// Wait for provider to be available first.
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "fraudprovider", "e2e-maxmind",
					"-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"))
			}).Should(Succeed())

			By("creating a FraudPolicy")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = jsonReader(map[string]interface{}{
				"apiVersion": "fraud.miloapis.com/v1alpha1",
				"kind":       "FraudPolicy",
				"metadata":   map[string]interface{}{"name": "e2e-policy"},
				"spec": map[string]interface{}{
					"stages": []map[string]interface{}{
						{
							"name": "risk-analysis",
							"providers": []map[string]interface{}{
								{"providerRef": map[string]interface{}{"name": "e2e-maxmind"}},
							},
							"thresholds": []map[string]interface{}{
								{"minScore": 70, "action": "REVIEW"},
								{"minScore": 90, "action": "DEACTIVATE"},
							},
						},
					},
					"enforcement": map[string]interface{}{"mode": "OBSERVE"},
				},
			})
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the FraudPolicy becomes Available")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "fraudpolicy", "e2e-policy",
					"-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"))
			}).Should(Succeed())
		})

		It("should create a FraudEvaluation and reconcile it", func() {
			By("creating prerequisite resources")
			cmd := exec.Command("kubectl", "create", "secret", "generic", "e2e-maxmind-creds",
				"--namespace", namespace,
				"--from-literal=accountID=123456",
				"--from-literal=licenseKey=test-key")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = jsonReader(map[string]interface{}{
				"apiVersion": "fraud.miloapis.com/v1alpha1",
				"kind":       "FraudProvider",
				"metadata":   map[string]interface{}{"name": "e2e-maxmind"},
				"spec": map[string]interface{}{
					"type": "maxmind",
					"config": map[string]interface{}{
						"credentialsRef": map[string]interface{}{
							"name":      "e2e-maxmind-creds",
							"namespace": namespace,
						},
					},
					"failurePolicy": "FailOpen",
				},
			})
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = jsonReader(map[string]interface{}{
				"apiVersion": "fraud.miloapis.com/v1alpha1",
				"kind":       "FraudPolicy",
				"metadata":   map[string]interface{}{"name": "e2e-policy"},
				"spec": map[string]interface{}{
					"stages": []map[string]interface{}{
						{
							"name": "risk-analysis",
							"providers": []map[string]interface{}{
								{"providerRef": map[string]interface{}{"name": "e2e-maxmind"}},
							},
							"thresholds": []map[string]interface{}{
								{"minScore": 70, "action": "REVIEW"},
								{"minScore": 90, "action": "DEACTIVATE"},
							},
						},
					},
					"enforcement": map[string]interface{}{"mode": "OBSERVE"},
				},
			})
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("creating a FraudEvaluation for a test user")
			cmd = exec.Command("kubectl", "apply", "-f", "-")
			cmd.Stdin = jsonReader(map[string]interface{}{
				"apiVersion": "fraud.miloapis.com/v1alpha1",
				"kind":       "FraudEvaluation",
				"metadata":   map[string]interface{}{"name": "test-user-1"},
				"spec": map[string]interface{}{
					"userRef":   map[string]interface{}{"name": "test-user-1"},
					"policyRef": map[string]interface{}{"name": "e2e-policy"},
				},
			})
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("verifying the FraudEvaluation is reconciled by the controller")
			// The controller will attempt to evaluate but no MaxMind provider
			// implementation is registered at runtime yet (dynamic provider
			// bootstrap from CRs is a future enhancement). The evaluation
			// should reach Error phase because the provider type has no
			// registered implementation.
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "fraudevaluation", "test-user-1",
					"-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Or(Equal("Completed"), Equal("Error")),
					"phase should reach a terminal state")
			}).Should(Succeed())

			By("checking the FraudEvaluation status has conditions set by the controller")
			cmd = exec.Command("kubectl", "get", "fraudevaluation", "test-user-1",
				"-o", "jsonpath={.status.conditions[0].reason}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			// The controller sets a condition regardless of success or failure.
			Expect(output).NotTo(BeEmpty(), "condition reason should be set")

			By("verifying kubectl get fraudevaluations works with print columns")
			cmd = exec.Command("kubectl", "get", "fraudevaluations")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(output).To(ContainSubstring("test-user-1"))
		})
	})
})

// jsonReader creates an io.Reader from a map by marshaling to JSON.
func jsonReader(obj map[string]interface{}) io.Reader {
	data, _ := json.Marshal(obj)
	return bytes.NewReader(data)
}
