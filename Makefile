VERSION ?= dev
LDFLAGS := -s -w -X github.com/nslookup-io/agent/internal/version.Version=$(VERSION)

.PHONY: test build lint

test:
	go test ./...

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/nslookup-agent ./cmd/nslookup-agent

lint:
	go vet ./...
