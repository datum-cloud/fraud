// SPDX-License-Identifier: AGPL-3.0-only
package datasource

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	identityv1alpha1 "go.miloapis.com/milo/pkg/apis/identity/v1alpha1"

	"go.miloapis.com/fraud/internal/provider"
)

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

	log.Info("resolved provider input",
		"user", userUID,
		"email", input.EmailAddress,
		"emailDomain", input.EmailDomain,
		"ip", input.IPAddress,
		"userAgent", input.UserAgent,
	)

	return input, sessionErr
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

	latest := sessions.Items[0].Status
	input.IPAddress = latest.IP
	input.UserAgent = latest.UserAgent

	return nil
}
