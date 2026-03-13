/*
Package warden provides a Go client for the Shadow Warden AI security gateway.

Quick start:

	client, err := warden.New("http://localhost:8001", "sk_your_api_key")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	result, err := client.Filter(ctx, "Summarise the contract for client@example.com", nil)
	if err != nil {
		var blocked *warden.BlockedError
		if errors.As(err, &blocked) {
			log.Printf("blocked: %s", blocked.Reason)
			return
		}
		log.Fatal(err)
	}
	// result.FilteredContent has secrets redacted, safe to forward to AI
	fmt.Println(result.FilteredContent)
*/
package warden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultTimeout   = 30 * time.Second
	defaultUserAgent = "ShadowWardenGo/1.0"
)

// FilterOptions controls per-call behaviour for Filter().
type FilterOptions struct {
	// TenantID overrides the client-level tenant for this call.
	TenantID string
	// Strict enables strict PII redaction (passport numbers etc.).
	Strict bool
	// RaiseOnBlock controls whether a blocked response returns a BlockedError
	// (default: true). Set false to inspect the FilterResult directly.
	RaiseOnBlock *bool
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithTimeout sets the HTTP request timeout (default: 30 s).
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// WithTenantID sets a default tenant_id for all requests.
func WithTenantID(id string) ClientOption {
	return func(c *Client) { c.tenantID = id }
}

// WithHTTPClient replaces the underlying *http.Client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// Client is a Shadow Warden gateway client. It is safe for concurrent use.
type Client struct {
	baseURL    string
	apiKey     string
	tenantID   string
	httpClient *http.Client
}

// New creates a new Client.
//
//	baseURL – e.g. "http://localhost:8001" (no trailing slash)
//	apiKey  – the X-API-Key value; pass "" to disable auth (dev mode)
func New(baseURL, apiKey string, opts ...ClientOption) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return nil, &WardenError{"baseURL must not be empty"}
	}
	c := &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Close releases any resources held by the client. Currently a no-op but
// included for forward-compatibility.
func (c *Client) Close() {}

// ── Filter ────────────────────────────────────────────────────────────────────

// Filter sends content through the Shadow Warden input-filter pipeline.
// Returns a BlockedError when the request is blocked and opts.RaiseOnBlock
// is nil or true.
func (c *Client) Filter(ctx context.Context, content string, opts *FilterOptions) (FilterResult, error) {
	tenantID, strict, raiseOnBlock := c.resolveFilterOpts(opts)

	body := filterRequest{
		Content:  content,
		TenantID: tenantID,
		Strict:   strict,
	}

	var result FilterResult
	if err := c.post(ctx, "/filter", body, &result); err != nil {
		return FilterResult{}, err
	}

	if !result.Allowed && raiseOnBlock {
		return result, &BlockedError{
			RiskLevel: result.RiskLevel,
			Reason:    result.Reason,
			Flags:     result.SemanticFlags,
		}
	}
	return result, nil
}

// ── FilterOutput ──────────────────────────────────────────────────────────────

// FilterOutput scans an AI-generated output for OWASP LLM02/LLM06/LLM08
// vulnerabilities (XSS, HTML injection, prompt leakage, shell commands, etc.).
func (c *Client) FilterOutput(ctx context.Context, output string, tenantID string) (OutputScanResult, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	body := outputScanRequest{Output: output, TenantID: tenantID}
	var result OutputScanResult
	if err := c.post(ctx, "/filter/output", body, &result); err != nil {
		return OutputScanResult{}, err
	}
	return result, nil
}

// ── FilterBatch ───────────────────────────────────────────────────────────────

// FilterBatch sends up to 50 items through the filter in a single round-trip.
func (c *Client) FilterBatch(ctx context.Context, items []BatchItem) ([]BatchResult, error) {
	reqs := make([]filterRequest, len(items))
	for i, item := range items {
		tid := item.TenantID
		if tid == "" {
			tid = c.tenantID
		}
		reqs[i] = filterRequest{Content: item.Content, TenantID: tid}
	}

	var raw struct {
		Results []BatchResult `json:"results"`
	}
	if err := c.post(ctx, "/filter/batch", batchRequest{Items: reqs}, &raw); err != nil {
		return nil, err
	}
	return raw.Results, nil
}

// ── Health ────────────────────────────────────────────────────────────────────

// Health calls GET /health and returns the gateway status map.
func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, &GatewayError{StatusCode: resp.StatusCode, Body: string(b)}
	}
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("warden: decode health response: %w", err)
	}
	return result, nil
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func (c *Client) resolveFilterOpts(opts *FilterOptions) (tenantID string, strict bool, raiseOnBlock bool) {
	tenantID = c.tenantID
	raiseOnBlock = true
	if opts == nil {
		return
	}
	if opts.TenantID != "" {
		tenantID = opts.TenantID
	}
	strict = opts.Strict
	if opts.RaiseOnBlock != nil {
		raiseOnBlock = *opts.RaiseOnBlock
	}
	return
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("warden: marshal request: %w", err)
	}
	req, err := c.newRequest(ctx, http.MethodPost, path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("warden: read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return &GatewayError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("warden: decode response: %w", err)
	}
	return nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("warden: build request: %w", err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	return req, nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return nil, &TimeoutError{Cause: err}
		}
		return nil, fmt.Errorf("warden: http: %w", err)
	}
	return resp, nil
}
