#!/usr/bin/env gmake

include common.mk

# List of runtimes to build.
RUNTIMES := keymanager-runtime \
	tests/runtimes/simple-keyvalue \
	tests/runtimes/staking-arbitrary

# Set all target as the default target.
all: build
	@$(ECHO) "$(CYAN)*** Everything built successfully!$(OFF)"

# Build.
build-targets := build-tools build-runtimes build-rust build-go

build-tools:
	@$(ECHO) "$(MAGENTA)*** Building Rust tools...$(OFF)"
	@# Suppress "binary already exists" error by redirecting stderr and stdout to /dev/null.
	@cargo install --path tools >/dev/null 2>&1 || true

build-runtimes:
	@for e in $(RUNTIMES); do \
		$(ECHO) "$(MAGENTA)*** Building runtime: $$e...$(OFF)"; \
		(cd $$e && \
			cargo build --target x86_64-fortanix-unknown-sgx && \
			cargo build && \
			cargo elf2sgxs \
		) || exit 1; \
	done

build-rust:
	@$(ECHO) "$(MAGENTA)*** Building Rust libraries and runtime loader...$(OFF)"
	@cargo build

build-go go:
	@$(MAKE) -C go build

build: $(build-targets)

build-helpers-go:
	@$(MAKE) -C go build-helpers

build-helpers: build-helpers-go

build-go-generate:
	@$(MAKE) -C go generate

# Format code.
fmt-targets := fmt-rust fmt-go

fmt-rust:
	@$(ECHO) "$(CYAN)*** Running cargo fmt... $(OFF)"
	@cargo fmt

fmt-go:
	@$(MAKE) -C go fmt

fmt: $(fmt-targets)

# Test.
test-unit-targets := test-unit-rust test-unit-go
test-targets := test-unit test-e2e

test-unit-rust: build-helpers
	@$(ECHO) "$(CYAN)*** Running Rust unit tests...$(OFF)"
	@export OASIS_STORAGE_PROTOCOL_SERVER_BINARY=$(realpath go/$(GO_TEST_HELPER_URKEL_PATH)) && \
		cargo test

test-unit-go:
	@$(MAKE) -C go test

test-unit: $(test-unit-targets)

test-e2e:
	@$(ECHO) "$(CYAN)*** Running E2E tests...$(OFF)"
	@.buildkite/scripts/test_e2e.sh

test: $(test-targets)

# Clean.
clean-targets := clean-runtimes clean-rust clean-go

clean-runtimes:
	@$(ECHO) "$(CYAN)*** Cleaning up runtimes...$(OFF)"
	@for e in $(RUNTIMES); do \
		(cd $$e && cargo clean) || exit 1; \
	done

clean-rust:
	@$(ECHO) "$(CYAN)*** Cleaning up Rust...$(OFF)"
	@cargo clean

clean-go:
	@$(MAKE) -C go clean

clean: $(clean-targets)

# Prepare release.
release:
	@goreleaser $(GORELEASER_ARGS)

# Develop in a Docker container.
docker-shell:
	@docker run -t -i --rm \
	  --name oasis-core \
	  --security-opt apparmor:unconfined \
	  --security-opt seccomp=unconfined \
	  -v $(shell pwd):/code \
	  -w /code \
	  oasislabs/development:0.3.0 \
	  bash

# List of targets that are not actual files.
.PHONY: \
	$(build-targets) go build \
	build-helpers-go build-helpers build-go-generate \
	$(fmt-targets) fmt \
	$(test-unit-targets) $(test-targets) test \
	$(clean-targets) clean \
	release docker-shell \
	all
