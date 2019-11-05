SHELL = /bin/bash
OASIS_GO ?= go

# The following flags enable additional behavior for deterministic builds.
#
# * -trimpath as of Go 1.13 will strip all host dependent filesystem paths
#   from binaries.
#
# * -ldflags=-buildid= will set the `.note.go.buildid` section to empty,
#   to work around https://github.com/golang/go/issues/33772.  Once we
#   migrate to a version of Go that has the fix, it can be removed.
GOFLAGS ?= -trimpath -ldflags=-buildid= -v

all: generate build

# Generate required files.
#
# Note: For now this still uses GOPATH because it is unknown if the protoc
# compiler plugin supports modules.
generate:
	@echo "Running go generate"
	@env -u GOPATH $(OASIS_GO) generate -v ./...

# Build all the things.
build: generate
	@echo "Building Oasis node"
	@env -u GOPATH $(OASIS_GO) build $(GOFLAGS) -o ./oasis-node/oasis-node ./oasis-node
	@echo "Building Oasis test harness"
	@env -u GOPATH $(OASIS_GO) build $(GOFLAGS) -o ./oasis-test-runner/oasis-test-runner ./oasis-test-runner
	@echo "Building Oasis local network runner"
	@env -u GOPATH $(OASIS_GO) build $(GOFLAGS) -o ./oasis-net-runner/oasis-net-runner ./oasis-net-runner

# Oasis node with coverage.
integrationrunner: oasis-node/integrationrunner/integrationrunner.test
oasis-node/integrationrunner/integrationrunner.test: generate
	env -u GOPATH $(OASIS_GO) test $(GOFLAGS) -c -covermode=atomic -coverpkg=./... -o $@ ./oasis-node/integrationrunner

# Run go fmt.
fmt:
	@env -u GOPATH $(OASIS_GO) fmt ./...

# Lint.
lint:
	@env -u GOPATH golangci-lint run

# Test.
test: generate
	@env -u GOPATH $(OASIS_GO) test -race -v ./...

# Urkel interoperability test helpers.
urkel-test-helpers: generate
	@env -u GOPATH $(OASIS_GO) build $(GOFLAGS) -o ./storage/mkvs/urkel/interop/urkel_test_helpers ./storage/mkvs/urkel/interop

# Clean.
clean:
	@env -u GOPATH $(OASIS_GO) clean

.PHONY: all generate build integrationrunner lint test clean
