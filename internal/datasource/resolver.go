// SPDX-License-Identifier: AGPL-3.0-only
package datasource

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	billingv1alpha1 "go.miloapis.com/billing/api/v1alpha1"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"

	"go.miloapis.com/fraud/internal/provider"
)

// OwnerUserLabel is the label used on BillingAccount to identify the
// owning user. The auto-billing-account controller (in milo) writes this
// label at creation time. The fraud resolver uses it to find the user's
// billing account when assembling the provider input.
const OwnerUserLabel = "iam.miloapis.com/owner-user"

// MaxMindTrackingTokenAnnotation is the milo Session annotation key that
// auth-provider-zitadel populates from Zitadel session metadata. The
// resolver reads it from the latest Session and forwards the value to
// MaxMind as device.tracking_token. Missing annotation is non-fatal —
// fraud evaluation continues with the other signals.
const MaxMindTrackingTokenAnnotation = "iam.miloapis.com/maxmind-tracking-token"

// Resolver fetches data from the platform's User CRD and the identity Sessions
// API to build a provider.Input for the fraud evaluation pipeline.
type Resolver struct {
	client client.Client
}

// NewResolver creates a new data source resolver.
func NewResolver(c client.Client) *Resolver {
	return &Resolver{client: c}
}

// Resolve fetches the User resource and the most recent Session for the given
// user, returning a populated provider.Input.
//
// Missing data is handled gracefully — if the User or Session is unavailable,
// the corresponding fields are simply empty. Providers handle missing fields
// on their own.
func (r *Resolver) Resolve(ctx context.Context, userUID string) (provider.Input, error) {
	log := logf.FromContext(ctx)

	var input provider.Input

	if err := r.resolveUser(ctx, userUID, &input); err != nil {
		log.Info("failed to resolve user data, continuing with empty user fields", "user", userUID, "error", err)
	}

	var sessionErr error
	if err := r.resolveSession(ctx, userUID, &input); err != nil {
		log.Info("failed to resolve session data, continuing with empty session fields", "user", userUID, "error", err)
		sessionErr = err
	}

	if err := r.resolvePaymentMethod(ctx, userUID, &input); err != nil {
		log.Info("failed to resolve payment-method data, continuing with empty card fields", "user", userUID, "error", err)
	}

	log.Info("resolved provider input",
		"user", userUID,
		"email", input.EmailAddress,
		"emailDomain", input.EmailDomain,
		"ip", input.IPAddress,
		"userAgent", input.UserAgent,
		"hasTrackingToken", input.TrackingToken != "",
		"hasCreditCard", input.CreditCard.HasAny(),
	)

	return input, sessionErr
}

// resolvePaymentMethod finds the user's BillingAccount and copies its
// attached payment-method metadata into input.CreditCard. Lookup is by the
// `iam.miloapis.com/owner-user=<uid>` label written by the
// auto-billing-account controller. Missing data is non-fatal.
func (r *Resolver) resolvePaymentMethod(ctx context.Context, userUID string, input *provider.Input) error {
	var accounts billingv1alpha1.BillingAccountList
	if err := r.client.List(ctx, &accounts, client.MatchingLabels{OwnerUserLabel: userUID}); err != nil {
		return fmt.Errorf("listing BillingAccounts for user %q: %w", userUID, err)
	}
	if len(accounts.Items) == 0 {
		return fmt.Errorf("no BillingAccount found for user %q", userUID)
	}
	// When more than one BA is owned by the user, prefer one with a
	// payment method attached; otherwise take the most recent.
	pick := accounts.Items[0]
	for i := range accounts.Items {
		if accounts.Items[i].Status.PaymentMethod != nil {
			pick = accounts.Items[i]
			break
		}
		if accounts.Items[i].CreationTimestamp.After(pick.CreationTimestamp.Time) {
			pick = accounts.Items[i]
		}
	}
	if pick.Status.PaymentMethod == nil {
		return fmt.Errorf("BillingAccount %s/%s has no attached payment method", pick.Namespace, pick.Name)
	}
	pm := pick.Status.PaymentMethod
	input.CreditCard = provider.CreditCard{
		IssuerIDNumber: pm.BIN,
		LastDigits:     pm.Last4,
		Country:        pm.Country,
		AVSResult:      pm.AVSResult,
		CVVResult:      pm.CVCResult,
	}
	return nil
}

// resolveUser fetches the User CR and populates email and name fields.
func (r *Resolver) resolveUser(ctx context.Context, userUID string, input *provider.Input) error {
	var user iamv1alpha1.User
	if err := r.client.Get(ctx, client.ObjectKey{Name: userUID}, &user); err != nil {
		return fmt.Errorf("failed to get User %q: %w", userUID, err)
	}

	input.EmailAddress = user.Spec.Email
	input.FirstName = user.Spec.GivenName
	input.LastName = user.Spec.FamilyName

	if parts := strings.SplitN(user.Spec.Email, "@", 2); len(parts) == 2 {
		input.EmailDomain = parts[1]
	}

	return nil
}

// resolveSession lists the user's Sessions from the identity API, picks the
// most recent one (LastUpdatedAt desc, then CreatedAt desc), and copies the
// IP and UserAgent into input.
//
// The Sessions API is an aggregated apiserver; the manager client is configured
// to bypass the cache for this type via Cache.DisableFor in main.go.
func (r *Resolver) resolveSession(ctx context.Context, userUID string, input *provider.Input) error {
	var sessions identityv1alpha1.SessionList
	if err := r.client.List(ctx, &sessions, client.MatchingFields{"status.userUID": userUID}); err != nil {
		return fmt.Errorf("failed to list Sessions for user %q: %w", userUID, err)
	}

	if len(sessions.Items) == 0 {
		return fmt.Errorf("no sessions found for user %q", userUID)
	}

	sort.Slice(sessions.Items, func(i, j int) bool {
		ai, aj := sessions.Items[i].Status, sessions.Items[j].Status
		ti := ai.CreatedAt.Time
		if ai.LastUpdatedAt != nil {
			ti = ai.LastUpdatedAt.Time
		}
		tj := aj.CreatedAt.Time
		if aj.LastUpdatedAt != nil {
			tj = aj.LastUpdatedAt.Time
		}
		return ti.After(tj)
	})

	latest := sessions.Items[0]
	input.IPAddress = latest.Status.IP
	input.UserAgent = latest.Status.UserAgent
	if token := latest.Annotations[MaxMindTrackingTokenAnnotation]; token != "" {
		input.TrackingToken = token
	}

	return nil
}
