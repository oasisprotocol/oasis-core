SHELL = /bin/bash

all: generate build

# Generate required files.
#
# Note: For now this still uses GOPATH because it is unknown if the protoc
# compiler plugin supports modules.
generate:
	@echo "Running go generate"
	go generate -v ./...

# Build the Ekiden node.
build: generate
	@echo "Building Ekiden node"
	@go build -v -o ./ekiden/ekiden ./ekiden

# Run go fmt.
fmt:
	go fmt ./...

# Lint.
lint:
	golangci-lint run

# Test.
test:
	go test -race -v ./...

.PHONY: all generate build lint test
