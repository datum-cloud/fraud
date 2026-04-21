// SPDX-License-Identifier: AGPL-3.0-only
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var ProviderCallsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "fraud_provider_calls_total",
		Help: "Total number of fraud provider calls, partitioned by provider name and result.",
	},
	[]string{"provider", "result"},
)

func init() {
	ctrlmetrics.Registry.MustRegister(ProviderCallsTotal)
}
