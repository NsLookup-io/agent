package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
)

// Retry is what a failed call means for the request it made, and for the other requests of the same round of work.
type Retry int

const (
	// Done: the call succeeded.
	Done Retry = iota
	// Halt: the server cannot be reached, or asks the agent to wait (the network, a timeout, 401 for its clock or
	// nonce check, 429). Nothing else is sent until the next heartbeat; the request is kept and sent again then.
	Halt
	// Later: this request only was not taken (a server error, a proxy's answer, a 403 not signed as a removal, an
	// answer that is not the server's): keep it and send it again later, and go on with the other requests.
	Later
	// Never: the server refuses this request for good, saying so with its code, or it was never sent; sending it again
	// gets the same answer.
	Never
	// Removed: the server removed this agent; no request is sent again.
	Removed
)

func (r Retry) String() string {
	switch r {
	case Done:
		return "done"
	case Halt:
		return "halt"
	case Later:
		return "later"
	case Never:
		return "never"
	case Removed:
		return "removed"
	}
	return "unknown"
}

// refusalRule is one row of the retry table.
type refusalRule struct {
	status int
	retry  Retry
	// coded: the retry holds only when the answer carries the server's JSON code; without one (a proxy's own page)
	// the request is sent again later.
	coded bool
}

// retryTable says, for each status the server (or a proxy before it) refuses a request with, what it means. A status
// that is not listed is Later.
//
//	400 invalid_json, invalid_request         never (later without the server's code)
//	401 unauthorized, clock_skew              halt: the server answers unauthorized while it cannot check nonces,
//	                                          and clock_skew until this machine's clock is right
//	403 not a signed agent_removed            later: a proxy could have sent it (a signed one is Removed)
//	404 not_found                             never (later without the server's code: a proxy's default backend)
//	408 request timeout                       later
//	409 conflict, target_changed, no_key      never (later without the server's code)
//	410 gone                                  never (later without the server's code)
//	413 body_too_large                        later; a heartbeat's inventory is refused (InventoryRefused)
//	415 unsupported_media_type                later
//	422 invalid_inventory, invalid_request    never (later without the server's code)
//	429 rate limited                          halt
//	5xx                                       later
var retryTable = []refusalRule{
	{http.StatusBadRequest, Never, true},
	{http.StatusUnauthorized, Halt, false},
	{http.StatusForbidden, Later, false},
	{http.StatusNotFound, Never, true},
	{http.StatusRequestTimeout, Later, false},
	{http.StatusConflict, Never, true},
	{http.StatusGone, Never, true},
	{http.StatusRequestEntityTooLarge, Later, false},
	{http.StatusUnsupportedMediaType, Later, false},
	{http.StatusUnprocessableEntity, Never, true},
	{http.StatusTooManyRequests, Halt, false},
}

func retryOfRefusal(e *APIError) Retry {
	for _, r := range retryTable {
		if r.status == e.Status {
			if r.coded && e.Code == "" {
				return Later
			}
			return r.retry
		}
	}
	return Later
}

// RetryOf says what err, returned by a call of this client, means: Done (nil), Halt (the network, a timeout, the
// clock, a 401 or a 429: end the round of work), Later (this request only: a refusal the table calls temporary, an
// answer not signed by the server or not readable), Never (a refusal for good, with the server's code, or an id that
// is not an assignment id: nothing was sent) or Removed.
func RetryOf(err error) Retry {
	var refused *APIError
	var skew *ErrClockSkew
	var urlErr *url.Error
	var netErr net.Error
	switch {
	case err == nil:
		return Done
	case errors.Is(err, ErrRemoved):
		return Removed
	case errors.Is(err, ErrNotAnAssignmentID):
		return Never
	case errors.As(err, &refused):
		return retryOfRefusal(refused)
	case errors.As(err, &skew), errors.As(err, &urlErr), errors.As(err, &netErr), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled), errors.Is(err, io.ErrUnexpectedEOF):
		return Halt
	}
	return Later
}

// inventoryCodes are the server's codes for a heartbeat refused for its inventory.
var inventoryCodes = []string{"invalid_inventory", "inventory_too_large", "body_too_large"}

// InventoryRefused reports whether err refuses a heartbeat for the inventory it carried: the server's codes
// invalid_inventory, inventory_too_large and body_too_large, or a 413 without a code (a proxy's own size limit). Sent
// again, the same inventory would be refused again; another (or none) may pass. Any other refusal (invalid_request:
// the facts, say) says nothing about the inventory.
func InventoryRefused(err error) bool {
	var refused *APIError
	if !errors.As(err, &refused) {
		return false
	}
	return slices.Contains(inventoryCodes, refused.Code) || (refused.Status == http.StatusRequestEntityTooLarge && refused.Code == "")
}
