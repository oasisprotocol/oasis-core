SHELL = /bin/bash
EKIDEN_GO ?= go

all: generate build

# Generate required files.
#
# Note: For now this still uses GOPATH because it is unknown if the protoc
# compiler plugin supports modules.
generate:
	@echo "Running go generate"
	@env -u GOPATH $(EKIDEN_GO) generate -v ./...

# Build the Ekiden node.
build: generate
	@echo "Building Ekiden node"
	@env -u GOPATH $(EKIDEN_GO) build -v -o ./ekiden/ekiden ./ekiden

# Run go fmt.
fmt:
	@env -u GOPATH $(EKIDEN_GO) fmt ./...

# Lint.
lint:
	@env -u GOPATH golangci-lint run

# Test.
test: generate
	@env -u GOPATH $(EKIDEN_GO) test -race -v ./...

.PHONY: all generate build lint test
