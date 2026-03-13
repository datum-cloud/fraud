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

package maxmind

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.miloapis.com/fraud-operator/internal/provider"
)

func TestEvaluate_Scores(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		riskScore float64
		wantScore int
	}{
		{"HighRisk", 85.0, 85},
		{"LowRisk", 2.5, 3},        // rounds up from 2.5
		{"MinScore", 0.01, 0},      // rounds down to 0
		{"MaxScore", 99.0, 99},     // stays at 99
		{"MidRound", 50.4, 50},     // rounds down
		{"UpperRound", 50.5, 51},   // rounds up (banker's: .5 rounds to even, but math.Round always rounds .5 up)
		{"OverHundred", 150.0, 100}, // clamped to 100
		{"Negative", -5.0, 0},      // clamped to 0
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"risk_score": %v, "id": "test-id"}`, tt.riskScore)
			}))
			defer srv.Close()

			client := NewClient(srv.URL, "acct123", "key456")
			result := client.Evaluate(context.Background(), provider.Input{IPAddress: "1.2.3.4"})

			if result.Error != nil {
				t.Fatalf("unexpected error: %v", result.Error)
			}

			if result.Score != tt.wantScore {
				t.Errorf("score = %d, want %d", result.Score, tt.wantScore)
			}
		})
	}
}

func TestEvaluate_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantRawBody bool // whether RawResponse should be non-empty
	}{
		{
			"ServerError",
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = fmt.Fprint(w, `{"error": "internal server error"}`)
			},
			true,
		},
		{
			"InvalidJSON",
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprint(w, `{invalid json}`)
			},
			true,
		},
		{
			"Unauthorized",
			func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = fmt.Fprint(w, `{"code":"AUTHORIZATION_INVALID"}`)
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			client := NewClient(srv.URL, "acct123", "key456")
			result := client.Evaluate(context.Background(), provider.Input{IPAddress: "1.2.3.4"})

			if result.Error == nil {
				t.Fatal("expected error")
			}

			if tt.wantRawBody && result.RawResponse == "" {
				t.Error("expected raw response to be populated on error")
			}
		})
	}
}

func TestEvaluate_Timeout(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	defer func() {
		close(done)
		srv.Close()
	}()

	client := NewClient(srv.URL, "acct123", "key456")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result := client.Evaluate(ctx, provider.Input{IPAddress: "1.2.3.4"})

	if result.Error == nil {
		t.Fatal("expected error for timeout")
	}
}

func TestEvaluate_AllFieldsSent(t *testing.T) {
	t.Parallel()

	var receivedBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"risk_score": 10.0, "id": "test-id"}`)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "acct123", "key456")
	client.Evaluate(context.Background(), provider.Input{
		IPAddress:      "1.2.3.4",
		EmailAddress:   "user@example.com",
		EmailDomain:    "example.com",
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
	})

	device, ok := receivedBody["device"].(map[string]interface{})
	if !ok {
		t.Fatal("expected device field in request body")
	}

	want := map[string]string{
		"ip_address":      "1.2.3.4",
		"user_agent":      "Mozilla/5.0",
		"accept_language": "en-US",
	}
	for k, v := range want {
		if device[k] != v {
			t.Errorf("device.%s = %v, want %q", k, device[k], v)
		}
	}

	email, ok := receivedBody["email"].(map[string]interface{})
	if !ok {
		t.Fatal("expected email field in request body")
	}

	if email["address"] != "user@example.com" {
		t.Errorf("email.address = %v, want %q", email["address"], "user@example.com")
	}

	if email["domain"] != "example.com" {
		t.Errorf("email.domain = %v, want %q", email["domain"], "example.com")
	}
}

func TestEvaluate_PartialInput(t *testing.T) {
	t.Parallel()

	var receivedBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedBody)

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"risk_score": 50.0, "id": "test-id"}`)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "acct123", "key456")
	client.Evaluate(context.Background(), provider.Input{IPAddress: "192.168.1.1"})

	if _, ok := receivedBody["device"]; !ok {
		t.Fatal("expected device field in request body")
	}

	if _, ok := receivedBody["email"]; ok {
		t.Error("expected email field to be absent for IP-only input")
	}
}

func TestEvaluate_EmptyInput(t *testing.T) {
	t.Parallel()

	var requestReceived bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestReceived = true

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"risk_score": 0.01, "id": "test-id"}`)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "acct123", "key456")
	result := client.Evaluate(context.Background(), provider.Input{})

	if !requestReceived {
		t.Fatal("expected request to be sent even with empty input")
	}

	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}

	if result.Score != 0 {
		t.Errorf("score = %d, want 0 (rounded from 0.01)", result.Score)
	}
}

func TestEvaluate_AuthHeader(t *testing.T) {
	t.Parallel()

	var gotUser, gotPass string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, _ = r.BasicAuth()

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"risk_score": 10.0, "id": "test-id"}`)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "myaccount", "mysecret")
	client.Evaluate(context.Background(), provider.Input{IPAddress: "1.2.3.4"})

	if gotUser != "myaccount" {
		t.Errorf("auth user = %q, want %q", gotUser, "myaccount")
	}

	if gotPass != "mysecret" {
		t.Errorf("auth pass = %q, want %q", gotPass, "mysecret")
	}
}

func TestName(t *testing.T) {
	t.Parallel()

	client := NewClient("", "acct", "key")
	if client.Name() != "maxmind" {
		t.Errorf("Name() = %q, want %q", client.Name(), "maxmind")
	}
}

func TestNewClient_DefaultEndpoint(t *testing.T) {
	t.Parallel()

	client := NewClient("", "acct", "key")
	if client.endpoint != defaultEndpoint {
		t.Errorf("endpoint = %q, want %q", client.endpoint, defaultEndpoint)
	}
}

func TestNewClient_CustomEndpoint(t *testing.T) {
	t.Parallel()

	client := NewClient("https://custom.example.com/score", "acct", "key")
	if client.endpoint != "https://custom.example.com/score" {
		t.Errorf("endpoint = %q, want custom", client.endpoint)
	}
}

func TestNewClient_DefaultTimeout(t *testing.T) {
	t.Parallel()

	client := NewClient("", "acct", "key")
	if client.httpClient.Timeout != defaultTimeout {
		t.Errorf("timeout = %v, want %v", client.httpClient.Timeout, defaultTimeout)
	}
}

func TestNewClient_WithHTTPClient(t *testing.T) {
	t.Parallel()

	custom := &http.Client{Timeout: 30 * time.Second}
	client := NewClient("", "acct", "key", WithHTTPClient(custom))

	if client.httpClient != custom {
		t.Error("expected custom http client to be used")
	}
}

func TestNewClient_WithTimeout(t *testing.T) {
	t.Parallel()

	client := NewClient("", "acct", "key", WithTimeout(5*time.Second))
	if client.httpClient.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", client.httpClient.Timeout)
	}
}
