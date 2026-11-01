package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
)

// Every failure is one of: Halt (the server cannot be reached, or asks the agent to wait: the round of work ends),
// Later (this request only, sent again later), Never (refused for good: the engine said so with its code), Removed.
func TestTheRetryTable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Retry
		// inventory: a heartbeat that carried the inventory is refused for that inventory.
		inventory bool
	}{
		{"400 invalid_json", &APIError{Status: 400, Code: "invalid_json"}, Never, false},
		{"400 from a proxy", &APIError{Status: 400}, Later, false},
		{"401 unauthorized, also while the server cannot check nonces", &APIError{Status: 401, Code: "unauthorized"}, Halt, false},
		{"401 from a proxy", &APIError{Status: 401}, Halt, false},
		{"401 clock skew", &ErrClockSkew{}, Halt, false},
		{"401 clock skew without the server's time", &APIError{Status: 401, Code: "clock_skew"}, Halt, false},
		{"403 that is not a signed removal", &APIError{Status: 403, Code: "agent_removed"}, Later, false},
		{"403 forbidden", &APIError{Status: 403}, Later, false},
		{"404 not_found", &APIError{Status: 404, Code: "not_found"}, Never, false},
		{"404 from a proxy's default backend", &APIError{Status: 404}, Later, false},
		{"408 request timeout", &APIError{Status: 408}, Later, false},
		{"409 target_changed", &APIError{Status: 409, Code: "target_changed"}, Never, false},
		{"409 from a proxy", &APIError{Status: 409}, Later, false},
		{"410 join_code_invalid", &APIError{Status: 410, Code: "join_code_invalid"}, Never, false},
		{"410 from a proxy", &APIError{Status: 410}, Later, false},
		{"413 body_too_large", &APIError{Status: 413, Code: "body_too_large"}, Later, true},
		{"413 from a proxy's own size limit", &APIError{Status: 413}, Later, true},
		{"415 unsupported_media_type", &APIError{Status: 415, Code: "unsupported_media_type"}, Later, false},
		{"422 invalid_inventory", &APIError{Status: 422, Code: "invalid_inventory"}, Never, true},
		{"422 inventory_too_large", &APIError{Status: 422, Code: "inventory_too_large"}, Never, true},
		{"422 invalid_request: not the inventory's fault", &APIError{Status: 422, Code: "invalid_request"}, Never, false},
		{"422 from a proxy", &APIError{Status: 422}, Later, false},
		{"429 rate limited", &APIError{Status: 429, Code: "rate_limited"}, Halt, false},
		{"429 from a proxy", &APIError{Status: 429}, Halt, false},
		{"500", &APIError{Status: 500}, Later, false},
		{"502 from a proxy", &APIError{Status: 502}, Later, false},
		{"503", &APIError{Status: 503, Code: "agents_not_configured"}, Later, false},
		{"a redirect", &APIError{Status: 302}, Later, false},
		{"an unlisted status", &APIError{Status: 418}, Later, false},
		{"the network", &url.Error{Op: "Post", URL: "https://agents.example.test", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}, Halt, false},
		{"a dial error", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, Halt, false},
		{"a timeout", context.DeadlineExceeded, Halt, false},
		{"an answer not signed by the server", ErrBadServerSignature, Later, false},
		{"an answer that is not JSON", fmt.Errorf("the bundle is not JSON: %w", errors.New("unexpected end of JSON input")), Later, false},
		{"an id that is not an assignment id (nothing sent)", fmt.Errorf("%q is %w", "../x", ErrNotAnAssignmentID), Never, false},
		{"removed", ErrRemoved, Removed, false},
		{"wrapped", fmt.Errorf("sending: %w", &APIError{Status: 404, Code: "not_found"}), Never, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RetryOf(c.err); got != c.want {
				t.Errorf("RetryOf = %v, want %v", got, c.want)
			}
			if got := InventoryRefused(c.err); got != c.inventory {
				t.Errorf("InventoryRefused = %v, want %v", got, c.inventory)
			}
		})
	}
	if RetryOf(nil) != Done {
		t.Error("no error is not Done")
	}
}
