# The agent's image, one for Docker and Kubernetes. It runs `nslookup-agent run` in Docker mode (NSL_MODE=docker:
# folder certificates written to /certs) as root, because the folder mounted at /certs normally belongs to root and the
# agent writes only in folders that root or its own user owns; with --user, mount a folder that user owns (README).
# The Helm chart runs it with --mode=kubernetes as the non-root user 65532 with a read-only root file system.
#
#   docker build --build-arg VERSION=1.2.3 -t nslookup-agent .
#
# Releases build the release stage instead (goreleaser, .goreleaser.yaml), from the binaries of the release.

# Both images are pinned by digest (the tag they had when pinned is beside it), so a build is the same build later.
FROM --platform=$BUILDPLATFORM golang:1.24.13@sha256:d2d2bc1c84f7e60d7d2438a3836ae7d0c847f4888464e7ec9ba3a1339a1ee804 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/nslookup-io/agent/internal/version.Version=$VERSION" \
    -o /out/nslookup-agent ./cmd/nslookup-agent

# distroless/static: CA certificates and an /etc/passwd with root and nonroot (65532), no shell (static-debian12:latest).
FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2 AS base
ENV NSL_MODE=docker
# The agent's identity and what it installed: keep it in a named volume (-v nslookup-agent:/var/lib/nslookup-agent),
# so that a new container of a newer image keeps the identity.
VOLUME ["/var/lib/nslookup-agent"]
ENTRYPOINT ["/nslookup-agent"]
CMD ["run"]

# goreleaser (dockers_v2) puts each platform's binary in the build context under $TARGETPLATFORM/.
FROM base AS release
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/nslookup-agent /nslookup-agent

FROM base
COPY --from=build /out/nslookup-agent /nslookup-agent
