package warden

import "fmt"

// WardenError is the base error type for all SDK errors.
type WardenError struct {
	Message string
}

func (e *WardenError) Error() string { return e.Message }

// BlockedError is returned when Shadow Warden blocks a request.
// Inspect RiskLevel and Reason for details.
type BlockedError struct {
	RiskLevel RiskLevel
	Reason    string
	Flags     []SemanticFlag
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("warden: request blocked (risk=%s): %s", e.RiskLevel, e.Reason)
}

// GatewayError is returned when the Shadow Warden gateway returns an HTTP error.
type GatewayError struct {
	StatusCode int
	Body       string
}

func (e *GatewayError) Error() string {
	return fmt.Sprintf("warden: gateway error %d: %s", e.StatusCode, e.Body)
}

// TimeoutError is returned when the HTTP request to the gateway times out.
type TimeoutError struct {
	Cause error
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("warden: request timed out: %v", e.Cause)
}

func (e *TimeoutError) Unwrap() error { return e.Cause }
