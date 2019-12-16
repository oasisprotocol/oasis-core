include ../common.mk

# Check if Go's linkers flags are set in common.mk and add them as extra flags.
ifneq ($(GOLDFLAGS),)
	GO_EXTRA_FLAGS += -ldflags $(GOLDFLAGS)
endif

# Set all target as the default target.
all: build

# Build.
# List of Go binaries to build.
go-binaries := oasis-node oasis-test-runner oasis-net-runner
# List of test helpers to build.
test-helpers := urkel
# List of test vectors to generate.
test-vectors := staking

generate:
	@$(ECHO) "$(MAGENTA)*** Running go generate...$(OFF)"
	@$(GO) generate ./...

$(go-binaries):
	@$(ECHO) "$(MAGENTA)*** Building $@...$(OFF)"
	$(GO) build $(GOFLAGS) $(GO_EXTRA_FLAGS) -o ./$@/$@ ./$@

oasis-node: generate

build: $(go-binaries)

# Build test helpers.
# Urkel interoperability test helpers.
urkel: generate
	@$(ECHO) "$(MAGENTA)*** Building test helpers for $@...$(OFF)"
	@$(GO) build $(GOFLAGS) $(GO_EXTRA_FLAGS) -o ./$(GO_TEST_HELPER_URKEL_PATH) ./$(shell dirname $(GO_TEST_HELPER_URKEL_PATH))

build-helpers: $(test-helpers)

$(test-vectors):
	@$(ECHO) "$(MAGENTA)*** Generating test vectors for $@...$(OFF)"
	@$(GO) run ./$@/gen_vectors

staking: generate

gen-test-vectors: $(test-vectors)

# Format code.
fmt:
	@$(ECHO) "$(CYAN)*** Running go fmt...$(OFF)"
	@$(GO) fmt ./...

# Lint.
lint: generate
	@$(ECHO) "$(CYAN)*** Running Go linters...$(OFF)"
	@env -u GOPATH golangci-lint run

# Test.
test: generate
	@$(ECHO) "$(CYAN)*** Running Go unit tests...$(OFF)"
	@$(GO) test -timeout 5m -race -v ./...

# Test oasis-node with coverage.
integrationrunner: generate
	@$(ECHO) "$(CYAN)*** Testing oasis-node with coverate...$(OFF)"
	@$(GO) test $(GOFLAGS) -c -covermode=atomic -coverpkg=./... -o oasis-node/$@/$@.test ./oasis-node/$@

# Clean.
clean:
	@$(ECHO) "$(CYAN)*** Cleaning up Go...$(OFF)"
	@$(GO) clean

# List of targets that are not actual files.
.PHONY: \
	generate $(go-binaries) build \
	$(test-helpers) build-helpers $(test-vectors) gen-test-vectors \
	fmt lint test integrationrunner clean all
