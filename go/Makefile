SHELL = /bin/bash

# GOPATH used in the Ekiden development Docker container.
DOCKER_GOPATH ?= /go
# Code directory used in the Ekiden development Docker container.
DOCKER_CODE_DIR ?= $(shell pwd)/..
# Ekiden under GOPATH.
DOCKER_OASISLABS_GOPATH ?= $(DOCKER_GOPATH)/src/github.com/oasislabs
DOCKER_EKIDEN_GOPATH ?= $(DOCKER_OASISLABS_GOPATH)/ekiden

all: prepare dep generate build

# Prepare environment (if we are in Ekiden Docker container).
prepare:
	@set -e; \
	if [[ "$$GOPATH" == $(DOCKER_GOPATH) && -d $(DOCKER_CODE_DIR) ]]; then \
		echo "Preparing Go environment"; \
		if [[ ! -d $(DOCKER_OASISLABS_GOPATH) ]]; then \
			mkdir -p $(DOCKER_OASISLABS_GOPATH); \
			ln -s -f $(DOCKER_CODE_DIR) $(DOCKER_EKIDEN_GOPATH); \
		fi; \
	fi;

# Ensure all dependencies are present.
dep:
	@echo "Ensuring package dependencies"
	@test -d $(DOCKER_EKIDEN_GOPATH) && cd $(DOCKER_EKIDEN_GOPATH)/go; \
	dep ensure -v

# Generate required files.
generate:
	@echo "Running go generate"
	@test -d $(DOCKER_EKIDEN_GOPATH) && cd $(DOCKER_EKIDEN_GOPATH)/go; \
	go generate ./...

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
	@test -d $(DOCKER_EKIDEN_GOPATH) && cd $(DOCKER_EKIDEN_GOPATH)/go; \
	go test -race -v ./...

.PHONY: all prepare dep generate build lint test
