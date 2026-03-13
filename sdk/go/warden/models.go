// Package warden provides a Go client for the Shadow Warden AI security gateway.
package warden

import "encoding/json"

// RiskLevel represents the risk classification of a filter decision.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
	RiskBlock  RiskLevel = "block"
)

// SecretFinding describes a single detected credential or PII item.
type SecretFinding struct {
	Kind  string `json:"kind"`
	Token string `json:"token"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// SemanticFlag describes a single semantic risk signal raised by the filter.
type SemanticFlag struct {
	Flag   string  `json:"flag"`
	Score  float64 `json:"score"`
	Detail string  `json:"detail"`
}

// FilterResult is the parsed response from POST /filter.
type FilterResult struct {
	Allowed         bool                   `json:"allowed"`
	RiskLevel       RiskLevel              `json:"risk_level"`
	FilteredContent string                 `json:"filtered_content"`
	SecretsFound    []SecretFinding        `json:"secrets_found"`
	SemanticFlags   []SemanticFlag         `json:"semantic_flags"`
	ProcessingMs    map[string]float64     `json:"processing_ms"`
	Explanation     string                 `json:"explanation"`
	Reason          string                 `json:"reason"`

	// Raw response payload for forward-compatibility
	Raw json.RawMessage `json:"-"`
}

// Blocked returns true when the request was blocked (Allowed == false).
func (r FilterResult) Blocked() bool { return !r.Allowed }

// OutputScanResult is the parsed response from POST /filter/output.
type OutputScanResult struct {
	Safe            bool               `json:"safe"`
	RiskLevel       RiskLevel          `json:"risk_level"`
	SanitizedOutput string             `json:"sanitized_output"`
	SemanticFlags   []SemanticFlag     `json:"semantic_flags"`
	ProcessingMs    map[string]float64 `json:"processing_ms"`
	Explanation     string             `json:"explanation"`
}

// BatchItem is a single item in a batch filter request.
type BatchItem struct {
	Content  string `json:"content"`
	TenantID string `json:"tenant_id,omitempty"`
}

// BatchResult is the result for one item in a batch filter response.
type BatchResult struct {
	Index  int          `json:"index"`
	Result FilterResult `json:"result"`
}

// filterRequest is the internal JSON body for POST /filter.
type filterRequest struct {
	Content  string `json:"content"`
	TenantID string `json:"tenant_id,omitempty"`
	Strict   bool   `json:"strict,omitempty"`
}

// outputScanRequest is the internal JSON body for POST /filter/output.
type outputScanRequest struct {
	Output   string `json:"output"`
	TenantID string `json:"tenant_id,omitempty"`
}

// batchRequest is the internal JSON body for POST /filter/batch.
type batchRequest struct {
	Items []filterRequest `json:"items"`
}
