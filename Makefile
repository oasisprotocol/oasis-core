#!/usr/bin/env gmake

# List of paths to runtimes that we should build.
RUNTIMES = keymanager-runtime \
	tests/runtimes/simple-keyvalue

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


.PHONY: all tools runtimes rust go clean clean-runtimes clean-go fmt test test-unit test-e2e

all: tools runtimes rust go
	@$(ECHO) "$(CYAN)*** Everything built successfully!$(OFF)"

tools:
	@$(ECHO) "$(CYAN)*** Building Rust tools...$(OFF)"
	@# Suppress "binary already exists" error by redirecting stderr and stdout to /dev/null.
	@cargo install --path tools >/dev/null 2>&1 || true

runtimes:
	@$(ECHO) "$(CYAN)*** Building test runtimes...$(OFF)"
	@for e in $(RUNTIMES); do \
		$(ECHO) "$(MAGENTA)*** Building runtime: $$e$(OFF)"; \
		(cd $$e && \
			cargo build --target x86_64-fortanix-unknown-sgx && \
			cargo build && \
			cargo elf2sgxs \
		) || exit 1; \
	done

rust:
	@$(ECHO) "$(CYAN)*** Building Rust libraries and runtime loader...$(OFF)"
	@cargo build

go:
	@$(ECHO) "$(CYAN)*** Building Go binaries...$(OFF)"
	@$(MAKE) -C go

fmt:
	@cargo fmt
	@$(MAKE) -C go fmt

test: test-unit test-e2e

test-unit:
	@$(ECHO) "$(CYAN)*** Building storage interoperability test helpers...$(OFF)"
	@$(MAKE) -C go urkel-test-helpers
	@$(ECHO) "$(CYAN)*** Running Rust unit tests...$(OFF)"
	@export OASIS_STORAGE_PROTOCOL_SERVER_BINARY=$(realpath go/storage/mkvs/urkel/interop/urkel_test_helpers) && \
		cargo test
	@$(ECHO) "$(CYAN)*** Running Go unit tests...$(OFF)"
	@$(MAKE) -C go test

test-e2e:
	@$(ECHO) "$(CYAN)*** Running E2E tests...$(OFF)"
	@.buildkite/scripts/test_e2e.sh

clean-runtimes:
	@$(ECHO) "$(CYAN)*** Cleaning up runtimes...$(OFF)"
	@for e in $(RUNTIMES); do \
		(cd $$e && cargo clean) || exit 1; \
	done

clean-go:
	@$(ECHO) "$(CYAN)*** Cleaning up Go node...$(OFF)"
	@$(MAKE) -C go clean

clean: clean-go clean-runtimes
	@$(ECHO) "$(CYAN)*** Cleaning up...$(OFF)"
	@cargo clean

