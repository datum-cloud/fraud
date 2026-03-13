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

package provider

import "context"

// Input holds the merged input data from all data sources.
type Input struct {
	EmailAddress   string
	EmailDomain    string
	FirstName      string
	LastName       string
	IPAddress      string
	UserAgent      string
	AcceptLanguage string
}

// Result holds the output of a provider evaluation.
// Error is embedded in the struct (rather than returned separately) so that
// callers can inspect both the partial result and the error — this is required
// for FailOpen semantics where we log the error but continue with score=0.
type Result struct {
	// Score is the normalized fraud risk score (0-100).
	Score int
	// RawResponse is the raw provider response for debugging.
	RawResponse string
	// Error is set if the provider call failed.
	Error error
}

// Provider is the interface that fraud detection providers implement.
type Provider interface {
	// Name returns the provider name (e.g. "maxmind").
	Name() string
	// Evaluate runs the fraud check with the given input and returns a result.
	Evaluate(ctx context.Context, input Input) Result
}
