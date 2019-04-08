#!/usr/bin/env gmake

# List of paths to runtimes that we should build.
RUNTIMES = keymanager-runtime \
	tests/runtimes/simple-keyvalue

# Key manager enclave path.
KM_ENCLAVE_PATH ?= target/x86_64-fortanix-unknown-sgx/debug/ekiden-keymanager-runtime.sgxs

# Check if we're running in an interactive terminal.
ISATTY := $(shell [ -t 0 ] && echo 1)

ifdef ISATTY
# Running in interactive terminal, OK to use colors!
MAGENTA = \e[35;1m
CYAN = \e[36;1m
OFF = \e[0m

# Built-in echo doesn't support '-e'.
ECHO = /bin/echo -e
else
# Don't use colors if not running interactively.
MAGENTA = ""
CYAN = ""
OFF = ""

# OK to use built-in echo.
ECHO = echo
endif


.PHONY: all tools runtimes rust go clean fmt test test-unit test-e2e

all: tools runtimes rust go
	@$(ECHO) "$(CYAN)*** Everything built successfully!$(OFF)"

tools:
	@$(ECHO) "$(CYAN)*** Building Rust tools...$(OFF)"
	@cargo install --force --path tools

runtimes:
	@$(ECHO) "$(CYAN)*** Building runtimes...$(OFF)"
	@for e in $(RUNTIMES); do \
		export KM_ENCLAVE_PATH=$$(pwd)/$(KM_ENCLAVE_PATH) && \
		\
		$(ECHO) "$(MAGENTA)*** Building runtime: $$e$(OFF)"; \
		(cd $$e && \
			cargo build --target x86_64-fortanix-unknown-sgx && \
			cargo build && \
			cargo elf2sgxs \
		) || exit 1; \
	done

rust:
	@$(ECHO) "$(CYAN)*** Building Rust libraries and runtime loader...$(OFF)"
	@export KM_ENCLAVE_PATH=$$(pwd)/$(KM_ENCLAVE_PATH) && \
		cargo build

go:
	@$(ECHO) "$(CYAN)*** Building Go node...$(OFF)"
	@$(MAKE) -C go

fmt:
	@cargo fmt
	@$(MAKE) -C go fmt

test: test-unit test-e2e

test-unit:
	@$(ECHO) "$(CYAN)*** Running Rust unit tests...$(OFF)"
	@export KM_ENCLAVE_PATH=$$(pwd)/$(KM_ENCLAVE_PATH) && \
		cargo test
	@$(ECHO) "$(CYAN)*** Running Go unit tests...$(OFF)"
	@$(MAKE) -C go test

test-e2e:
	@$(ECHO) "$(CYAN)*** Running E2E tests...$(OFF)"
	@.buildkite/scripts/test_e2e.sh
	@$(ECHO) "$(CYAN)*** Running E2E migration tests...$(OFF)"
	@.buildkite/scripts/test_migration.sh

clean:
	@$(ECHO) "$(CYAN)*** Cleaning up...$(OFF)"
	@cargo clean
