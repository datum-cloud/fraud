// SPDX-License-Identifier: AGPL-3.0-only
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
	Score float64
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
