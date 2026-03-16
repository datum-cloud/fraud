// SPDX-License-Identifier: AGPL-3.0-only
package provider

import "sync"

// Registry is a thread-safe store of named provider instances.
// The FraudProvider controller registers/deregisters entries as CRs are
// created, updated, or deleted. The FraudEvaluation controller reads
// entries by CR name during pipeline execution.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry returns an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register adds or replaces a provider under the given name.
func (r *Registry) Register(name string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.providers[name] = p
}

// Deregister removes a provider by name. It is a no-op if the name is absent.
func (r *Registry) Deregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.providers, name)
}

// Get returns the provider registered under name and whether it was found.
func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[name]

	return p, ok
}
