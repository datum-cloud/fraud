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

package testserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RecordedRequest captures details of a request received by the mock server.
type RecordedRequest struct {
	Body      map[string]interface{}
	AuthUser  string
	AuthPass  string
	Timestamp time.Time
}

// Server is a mock MaxMind minFraud API server for testing.
type Server struct {
	// server is the underlying httptest.Server.
	server *httptest.Server
	// Responses maps email addresses to risk scores for deterministic testing.
	// If an email is not in the map, a default score is returned.
	Responses map[string]float64
	// DefaultScore is returned when no specific response is configured.
	DefaultScore float64
	// FailNext causes the next N requests to return 500 errors.
	FailNext int
	// Requests records all received requests for assertion in tests.
	Requests []RecordedRequest
	// mu protects mutable fields.
	mu sync.Mutex
}

// New creates and starts a new mock MaxMind minFraud server.
func New() *Server {
	s := &Server{
		Responses:    make(map[string]float64),
		DefaultScore: 10.0,
	}

	s.server = httptest.NewServer(http.HandlerFunc(s.handler))

	return s
}

// Close shuts down the mock server.
func (s *Server) Close() {
	s.server.Close()
}

// URL returns the base URL of the mock server.
func (s *Server) URL() string {
	return s.server.URL
}

func (s *Server) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate Basic auth is present.
	authUser, authPass, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"code":"AUTHORIZATION_INVALID","error":"Invalid auth"}`)

		return
	}

	// Parse request body.
	var body map[string]interface{}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"code":"JSON_INVALID","error":"invalid JSON: %s"}`, err.Error())

		return
	}

	// Record the request.
	s.Requests = append(s.Requests, RecordedRequest{
		Body:      body,
		AuthUser:  authUser,
		AuthPass:  authPass,
		Timestamp: time.Now(),
	})

	// Check if we should fail this request.
	if s.FailNext > 0 {
		s.FailNext--
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"code":"SERVER_ERROR","error":"internal server error"}`)

		return
	}

	// Determine the risk score based on email address lookup.
	riskScore := s.DefaultScore

	if emailObj, ok := body["email"].(map[string]interface{}); ok {
		if addr, ok := emailObj["address"].(string); ok {
			if score, exists := s.Responses[addr]; exists {
				riskScore = score
			}
		}
	}

	// Determine IP risk (use half of risk_score as a simple heuristic).
	ipRisk := riskScore / 2

	// Build the minFraud Score response.
	resp := map[string]interface{}{
		"id":                uuid.New().String(),
		"risk_score":        riskScore,
		"funds_remaining":   100.00,
		"queries_remaining": 10000,
		"ip_address": map[string]interface{}{
			"risk": ipRisk,
		},
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		w.WriteHeader(http.StatusInternalServerError)

		return
	}
}
