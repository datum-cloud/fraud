# Fraud Service

A Kubernetes operator for fraud detection and risk evaluation, built with [Kubebuilder](https://book.kubebuilder.io). It provides a pipeline-based approach to evaluating user fraud risk using pluggable providers (currently [MaxMind minFraud](https://www.maxmind.com/en/solutions/minfraud-services)).

## Architecture

The service is composed of three Custom Resource Definitions (CRDs) that work together:

```
FraudProvider          FraudPolicy              FraudEvaluation
┌──────────────┐      ┌───────────────────┐     ┌──────────────────────┐
│ Configures a │◄─────│ Defines pipeline  │◄────│ Evaluates a user     │
│ provider     │      │ stages, thresholds│     │ against the policy   │
│ (e.g.MaxMind)│      │ & enforcement mode│     │ and records results  │
└──────────────┘      └───────────────────┘     └──────────────────────┘
```

### CRDs

#### FraudProvider

Configures a fraud detection provider backend.

| Field | Description |
|-------|-------------|
| `spec.type` | Provider type (`maxmind`) |
| `spec.failurePolicy` | Behavior on provider failure — `FailOpen` (score 0) or `FailClosed` (high risk) |
| `spec.config.endpoint` | Optional API endpoint override |
| `spec.config.credentialsRef` | Reference to a Secret containing API credentials |

#### FraudPolicy

Defines the evaluation pipeline — stages, score thresholds, enforcement mode, and history retention. Typically a singleton per cluster.

| Field | Description |
|-------|-------------|
| `spec.stages[]` | Ordered evaluation pipeline stages |
| `spec.stages[].providers[]` | Provider references to invoke in this stage |
| `spec.stages[].thresholds[]` | Score thresholds that trigger actions (`REVIEW`, `DEACTIVATE`) |
| `spec.stages[].shortCircuit.skipWhenBelow` | Skip subsequent non-required stages if max score is below this value |
| `spec.enforcement.mode` | `OBSERVE` (log only) or `AUTO` (enforce actions) |
| `spec.historyRetention.maxEntries` | Max evaluation history entries to retain (default: 50) |

#### FraudEvaluation

Represents the fraud evaluation state for a specific user. Created to trigger an evaluation, then updated with results as the pipeline runs.

| Field | Description |
|-------|-------------|
| `spec.userRef.name` | User being evaluated |
| `spec.policyRef.name` | Policy to evaluate against |
| `status.phase` | `Pending` → `Running` → `Completed` or `Error` |
| `status.compositeScore` | Overall risk score (0–100, highest across all providers) |
| `status.decision` | `NONE`, `REVIEW`, or `DEACTIVATE` |
| `status.enforcementAction` | Action taken: `NONE`, `OBSERVED`, `REVIEW_FLAGGED`, `DEACTIVATED` |
| `status.stageResults[]` | Per-stage and per-provider detailed results |
| `status.history[]` | Previous evaluation results for audit |

### Controllers

- **FraudProviderReconciler** — Validates provider config, loads credentials, and registers providers in a shared in-memory registry.
- **FraudPolicyReconciler** — Validates that all referenced providers exist and are available, sets policy conditions accordingly.
- **FraudEvaluationReconciler** — Executes the evaluation pipeline: invokes providers, computes composite scores, applies thresholds, enforces decisions, and maintains evaluation history.

## Getting Started

### Prerequisites

- Go 1.24+
- Docker 17.03+
- kubectl v1.11.3+
- Access to a Kubernetes cluster

### Development

```sh
# Install CRDs into the cluster
make install

# Run the controller locally
make run

# Apply sample resources
kubectl apply -k config/samples/
```

### Deployment

```sh
# Build and push the controller image
make docker-build docker-push IMG=<registry>/fraud:tag

# Deploy to the cluster
make deploy IMG=<registry>/fraud:tag
```

### Testing

```sh
# Run unit tests
make test

# Run e2e tests (requires a running cluster)
make test-e2e
```

### Uninstall

```sh
kubectl delete -k config/samples/   # Remove sample CRs
make uninstall                       # Remove CRDs
make undeploy                        # Remove the controller
```

## Project Structure

```
├── api/v1alpha1/          # CRD type definitions
├── cmd/                   # Controller entrypoint
├── config/
│   ├── crd/               # Generated CRD manifests
│   ├── default/           # Default Kustomize deployment
│   ├── iam/               # IAM protected resources & roles
│   ├── manager/           # Controller manager deployment
│   ├── rbac/              # RBAC roles for CRD access
│   └── samples/           # Example CR manifests
├── internal/
│   ├── controller/        # Reconcilers for each CRD
│   ├── datasource/        # User data resolution
│   └── provider/          # Provider interface & implementations
│       └── maxmind/       # MaxMind minFraud provider
└── test/                  # E2E tests
```

## License

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
