SHELL = /bin/bash
OASIS_GO ?= go

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
	@env -u GOPATH $(OASIS_GO) build -v -o ./oasis-node/oasis-node ./oasis-node
	@echo "Building Oasis test harness"
	@env -u GOPATH $(OASIS_GO) build -v -o ./oasis-test-runner/oasis-test-runner ./oasis-test-runner
	@echo "Building Oasis local network runner"
	@env -u GOPATH $(OASIS_GO) build -v -o ./oasis-net-runner/oasis-net-runner ./oasis-net-runner

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
	@env -u GOPATH $(OASIS_GO) build -v -o ./storage/mkvs/urkel/interop/urkel_test_helpers ./storage/mkvs/urkel/interop

# Clean.
clean:
	@env -u GOPATH $(OASIS_GO) clean

.PHONY: all generate build lint test clean
