// Package agent is what the agent does once installed: join the server once, then the run loop (heartbeats, the
// inventory, installing the certificates the server assigns).
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nslookup-io/agent/internal/client"
	"github.com/nslookup-io/agent/internal/identity"
	"github.com/nslookup-io/agent/internal/protocol"
)

// AlreadyJoinedError: an identity is stored already. Joining again would replace a working agent, so it is refused.
type AlreadyJoinedError struct {
	AgentID string
}

func (e *AlreadyJoinedError) Error() string { return "already joined as " + e.AgentID }

// Join spends a join code on server (an origin, checked by the caller): it makes the agent's keys, sends the join and,
// only once the answer's MAC verified, pins the server's signing key and saves the identity in store. The code is
// trimmed of surrounding whitespace first. A stored identity is never replaced (*AlreadyJoinedError), and one that
// cannot be read is left as it is: nothing is sent then.
func Join(ctx context.Context, store identity.Store, server, code string, kind protocol.AgentKind, name *string, facts protocol.AgentFacts) (*identity.Identity, error) {
	existing, err := store.Load()
	switch {
	case err == nil:
		return nil, &AlreadyJoinedError{AgentID: existing.AgentID}
	case !errors.Is(err, identity.ErrNotFound):
		return nil, fmt.Errorf("the stored identity cannot be read, so it is left as it is: %w", err)
	}
	code = strings.TrimSpace(code)
	if _, _, ok := protocol.SplitJoinCode(code); !ok {
		return nil, client.ErrMalformedJoinCode
	}
	id, err := identity.Generate()
	if err != nil {
		return nil, err
	}
	joined, err := client.New(server, id).Join(ctx, code, kind, name, facts)
	if err != nil {
		return nil, err
	}
	// Join returned the answer only after its MAC verified, with a usable server key.
	key, err := protocol.ParseSignPublicKey(joined.ServerSignPublicKey)
	if err != nil {
		return nil, err
	}
	id.AgentID, id.Server, id.ServerSignPublicKey = joined.AgentID, server, key
	if err := store.Save(id); err != nil {
		return nil, fmt.Errorf("joined as agent %s, but its identity could not be saved (%w); the join code is spent: remove the agent in the portal and create a new code", joined.AgentID, err)
	}
	return id, nil
}
