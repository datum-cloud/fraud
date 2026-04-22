// SPDX-License-Identifier: AGPL-3.0-only
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// ProviderCallDuration tracks the duration of fraud provider API calls.
// The _count suffix gives call totals; use result="failure" to compute error rate.
var ProviderCallDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "fraud_provider_call_duration_seconds",
		Help:    "Duration of fraud provider API calls in seconds, partitioned by provider and result.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	},
	[]string{"provider", "result"},
)

func init() {
	ctrlmetrics.Registry.MustRegister(ProviderCallDuration)
}
