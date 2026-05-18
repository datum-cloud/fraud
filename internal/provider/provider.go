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
	// TrackingToken is the MaxMind minFraud device-tracking token captured by
	// the browser SDK and attached to the Zitadel session at signup. The
	// resolver reads it from the Session annotation written by
	// auth-provider-zitadel; providers forward it as device.tracking_token.
	TrackingToken string

	// CreditCard carries sanitized card metadata sourced from the
	// BillingAccount's attached payment method. All fields are
	// individually optional — providers forward whatever is present.
	CreditCard CreditCard
}

// CreditCard is the sanitized payment-method metadata fed into provider
// scoring. Raw PAN is never carried here; only BIN, last4, and
// verification results that issuers return as part of authorization.
type CreditCard struct {
	// IssuerIDNumber is the card BIN (first 6-8 digits). MaxMind names
	// this `issuer.iin`.
	IssuerIDNumber string
	// LastDigits is the last 4 digits of the PAN.
	LastDigits string
	// Country is the ISO 3166-1 alpha-2 country of the issuer.
	Country string
	// AVSResult is the Address Verification System result from the
	// issuer (single character: Y/N/A/Z/…).
	AVSResult string
	// CVVResult is the CVV verification result from the issuer
	// (Y/N/P/X/U).
	CVVResult string
}

// HasAny reports whether the CreditCard has any field populated.
func (c CreditCard) HasAny() bool {
	return c.IssuerIDNumber != "" || c.LastDigits != "" || c.Country != "" ||
		c.AVSResult != "" || c.CVVResult != ""
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
