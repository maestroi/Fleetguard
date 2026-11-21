GO ?= go
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
# Set BUILD_DATE explicitly (e.g. SOURCE_DATE_EPOCH converted to RFC3339) when needed.
# Leaving it unknown makes repeat builds with identical inputs deterministic.
BUILD_DATE ?= unknown
LDFLAGS = -buildid= -X github.com/maestroi/Fleetguard/internal/buildinfo.Version=$(VERSION) -X github.com/maestroi/Fleetguard/internal/buildinfo.Commit=$(COMMIT) -X github.com/maestroi/Fleetguard/internal/buildinfo.BuildDate=$(BUILD_DATE)

.PHONY: fmt fmt-check test vet tidy-check check build smoke simulate clean

fmt:
	gofmt -w cmd internal pkg

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd internal pkg -name '*.go' -type f))" || { echo 'Go files need gofmt'; exit 1; }

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

tidy-check:
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

check: fmt-check tidy-check vet test

build:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/fleetguard-agent ./cmd/fleetguard-agent
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/fleetguard-controller ./cmd/fleetguard-controller
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o dist/fleetguardctl ./cmd/fleetguardctl

smoke:
	./dist/fleetguard-agent -config examples/agent.json
	./dist/fleetguard-controller -config examples/controller.json
	./dist/fleetguardctl check-config -kind agent -config examples/agent.json
	./dist/fleetguardctl check-config -kind controller -config examples/controller.json
	./dist/fleetguardctl version
	./dist/fleetguardctl simulate

simulate: build
	./dist/fleetguardctl simulate

clean:
	rm -rf dist
