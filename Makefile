#!/usr/bin/env gmake

# List of paths to enclaves that we should build.
ENCLAVES = tests/runtimes/test-db-encryption \
	tests/runtimes/test-logger \
	tests/runtimes/simple-keyvalue \
	key-manager/dummy/enclave

# Command that builds each enclave.
BUILD_ENCLAVE = cargo ekiden build-enclave --output-identity


# Make sure we're running inside the `cargo ekiden shell` container.
ifndef SGX_MODE
$(error ERROR: You need to run `make` from inside the `cargo ekiden shell` container to build Ekiden!)
endif


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


.PHONY: all tools enclaves rust go clean

all: tools enclaves rust go
	@$(ECHO) "$(CYAN)*** Everything built successfully!$(OFF)"

tools:
	@$(ECHO) "$(CYAN)*** Building Rust tools...$(OFF)"
	@cargo install --force --path tools

enclaves:
	@$(ECHO) "$(CYAN)*** Building enclaves...$(OFF)"
	@for e in $(ENCLAVES); do \
		$(ECHO) "$(MAGENTA)*** Building enclave: $$e$(OFF)"; \
		(cd $$e && $(BUILD_ENCLAVE)) || exit 1; \
	done

rust:
	@$(ECHO) "$(CYAN)*** Building Rust worker...$(OFF)"
	@cargo build

go:
	@$(ECHO) "$(CYAN)*** Building Go node...$(OFF)"
	@$(MAKE) -C go

clean:
	@$(ECHO) "$(CYAN)*** Cleaning up...$(OFF)"
	@cargo clean
	@-rm -f Cargo.lock
