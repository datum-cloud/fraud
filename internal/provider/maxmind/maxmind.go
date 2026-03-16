// SPDX-License-Identifier: AGPL-3.0-only
package maxmind

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.miloapis.com/fraud/internal/provider"
)

const (
	defaultEndpoint = "https://minfraud.maxmind.com/minfraud/v2.0/score"
	defaultTimeout  = 10 * time.Second
)

// Client is a MaxMind minFraud Score API client.
type Client struct {
	httpClient *http.Client
	endpoint   string
	accountID  string
	licenseKey string
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets a custom http.Client, replacing the default.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) {
		cl.httpClient = c
	}
}

// WithTimeout sets the timeout on the default http.Client.
// Ignored if WithHTTPClient is also used (set the timeout on your client instead).
func WithTimeout(d time.Duration) Option {
	return func(cl *Client) {
		cl.httpClient.Timeout = d
	}
}

// NewClient creates a new MaxMind minFraud client. If endpoint is empty,
// the production minFraud Score endpoint is used.
func NewClient(endpoint, accountID, licenseKey string, opts ...Option) *Client {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	c := &Client{
		httpClient: &http.Client{Timeout: defaultTimeout},
		endpoint:   endpoint,
		accountID:  accountID,
		licenseKey: licenseKey,
	}

	for _, o := range opts {
		o(c)
	}

	return c
}

// Name returns the provider name.
func (c *Client) Name() string {
	return "maxmind"
}

// minfraudRequest represents the minFraud API request body.
type minfraudRequest struct {
	Device *deviceField `json:"device,omitempty"`
	Email  *emailField  `json:"email,omitempty"`
}

type deviceField struct {
	IPAddress      string `json:"ip_address,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	AcceptLanguage string `json:"accept_language,omitempty"`
}

type emailField struct {
	Address string `json:"address,omitempty"`
	Domain  string `json:"domain,omitempty"`
}

// minfraudResponse represents the relevant fields from a minFraud Score response.
type minfraudResponse struct {
	RiskScore float64 `json:"risk_score"`
}

// Evaluate runs the minFraud Score check with the given input and returns a result.
func (c *Client) Evaluate(ctx context.Context, input provider.Input) provider.Result {
	reqBody := buildRequest(input)

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return provider.Result{Error: fmt.Errorf("maxmind: failed to marshal request: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return provider.Result{Error: fmt.Errorf("maxmind: failed to create request: %w", err)}
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.accountID, c.licenseKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return provider.Result{Error: fmt.Errorf("maxmind: request failed: %w", err)}
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return provider.Result{Error: fmt.Errorf("maxmind: failed to read response body: %w", err)}
	}

	rawResponse := string(respBody)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return provider.Result{
			RawResponse: rawResponse,
			Error:       fmt.Errorf("maxmind: unexpected status code %d: %s", resp.StatusCode, rawResponse),
		}
	}

	var mfResp minfraudResponse
	if err := json.Unmarshal(respBody, &mfResp); err != nil {
		return provider.Result{
			RawResponse: rawResponse,
			Error:       fmt.Errorf("maxmind: failed to parse response: %w", err),
		}
	}

	score := mfResp.RiskScore
	if score < 0 {
		score = 0
	}

	if score > 100 {
		score = 100
	}

	return provider.Result{
		Score:       score,
		RawResponse: rawResponse,
	}
}

// buildRequest constructs the minFraud request from the provider input,
// only including non-empty fields.
func buildRequest(input provider.Input) minfraudRequest {
	var req minfraudRequest

	// Build device field if any device-related input is provided.
	if input.IPAddress != "" || input.UserAgent != "" || input.AcceptLanguage != "" {
		req.Device = &deviceField{
			IPAddress:      input.IPAddress,
			UserAgent:      input.UserAgent,
			AcceptLanguage: input.AcceptLanguage,
		}
	}

	// Build email field if any email-related input is provided.
	if input.EmailAddress != "" || input.EmailDomain != "" {
		req.Email = &emailField{
			Address: input.EmailAddress,
			Domain:  input.EmailDomain,
		}
	}

	return req
}

// Compile-time check that Client implements provider.Provider.
var _ provider.Provider = (*Client)(nil)
