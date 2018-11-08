SHELL = /bin/bash

all: generate build

# Generate required files.
#
# Note: For now this still uses GOPATH because it is unknown if the protoc
# compiler plugin supports modules.
generate:
	@echo "Running go generate"
	@env -u GOPATH go generate -v ./...

# Build the Ekiden node.
build: generate
	@echo "Building Ekiden node"
	@env -u GOPATH go build -v -o ./ekiden/ekiden ./ekiden

# Run go fmt.
fmt:
	@env -u GOPATH go fmt ./...

# Lint.
lint:
	@env -u GOPATH golangci-lint run

# Test.
test:
	@env -u GOPATH go test -race -v ./...

.PHONY: all generate build lint test
