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

package datasource

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	activityv1alpha1 "go.miloapis.com/activity/pkg/apis/activity/v1alpha1"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"

	"go.miloapis.com/fraud/internal/provider"
)

// Resolver fetches data from the platform's User CRD and audit log API
// to build a provider.Input for the fraud evaluation pipeline.
type Resolver struct {
	client client.Client
}

// NewResolver creates a new data source resolver.
func NewResolver(c client.Client) *Resolver {
	return &Resolver{client: c}
}

// Resolve fetches the User resource and the most recent audit log entry
// for the given user, returning a populated provider.Input.
//
// Missing data is handled gracefully — if the User or audit log is
// unavailable, the corresponding fields are simply empty. Providers
// handle missing fields on their own.
func (r *Resolver) Resolve(ctx context.Context, userName string) (provider.Input, error) {
	log := logf.FromContext(ctx)

	var input provider.Input

	// Fetch the User resource.
	if err := r.resolveUser(ctx, userName, &input); err != nil {
		log.Info("failed to resolve user data, continuing with empty user fields", "user", userName, "error", err)
	}

	// Fetch the most recent audit log entry for the user.
	if err := r.resolveAuditLog(ctx, userName, &input); err != nil {
		log.Info("failed to resolve audit log data, continuing with empty audit fields", "user", userName, "error", err)
	}

	log.Info("resolved provider input",
		"user", userName,
		"email", input.EmailAddress,
		"emailDomain", input.EmailDomain,
		"ip", input.IPAddress,
		"userAgent", input.UserAgent,
	)

	return input, nil
}

// resolveUser fetches the User CR and populates email and name fields.
func (r *Resolver) resolveUser(ctx context.Context, userName string, input *provider.Input) error {
	var user iamv1alpha1.User
	if err := r.client.Get(ctx, types.NamespacedName{Name: userName}, &user); err != nil {
		return fmt.Errorf("failed to get User %q: %w", userName, err)
	}

	input.EmailAddress = user.Spec.Email
	input.FirstName = user.Spec.GivenName
	input.LastName = user.Spec.FamilyName

	// Extract domain from email address.
	if parts := strings.SplitN(user.Spec.Email, "@", 2); len(parts) == 2 {
		input.EmailDomain = parts[1]
	}

	return nil
}

// resolveAuditLog creates an AuditLogQuery to find the most recent audit
// event for the user and extracts IP address and user agent.
func (r *Resolver) resolveAuditLog(ctx context.Context, userName string, input *provider.Input) error {
	query := &activityv1alpha1.AuditLogQuery{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fraud-eval-",
		},
		Spec: activityv1alpha1.AuditLogQuerySpec{
			StartTime: "now-30d",
			EndTime:   "now",
			Filter:    fmt.Sprintf("user.uid == '%s'", userName),
			Limit:     1,
		},
	}

	if err := r.client.Create(ctx, query); err != nil {
		return fmt.Errorf("failed to create AuditLogQuery for user %q: %w", userName, err)
	}

	if len(query.Status.Results) == 0 {
		return fmt.Errorf("no audit log entries found for user %q", userName)
	}

	event := query.Status.Results[0]

	if len(event.SourceIPs) > 0 {
		input.IPAddress = event.SourceIPs[0]
	}

	input.UserAgent = event.UserAgent

	return nil
}
