// Package version holds the agent's version, set when the binary is built:
//
//	go build -ldflags "-X github.com/nslookup-io/agent/internal/version.Version=1.0.0" ./cmd/...
package version

// Version is the agent's version, x.y.z. A build without -ldflags says 0.0.0-dev, which the server counts as below
// every minimum version (it sends such an agent no work).
var Version = "0.0.0-dev"
