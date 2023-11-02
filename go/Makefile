include ../common.mk

# Check if Go's linkers flags are set in common.mk and add them as extra flags.
ifneq ($(GOLDFLAGS),)
	GO_EXTRA_FLAGS += -ldflags $(GOLDFLAGS)
endif

# Initialize GO_TAGS variable to hold the build tags.
GO_TAGS :=

# Include jemalloc tag unless explicitly disabled (used by badgerdb).
ifneq ($(OASIS_BADGER_NO_JEMALLOC), 1)
	ifneq ($(GO_TAGS),)
		GO_TAGS := $(GO_TAGS),
	endif
	GO_TAGS := $(GO_TAGS)jemalloc
endif

# Include rocksdb tags unless explicitly disabled.
ifneq ($(OASIS_NO_ROCKSDB), 1)
	ifneq ($(GO_TAGS),)
		GO_TAGS := $(GO_TAGS),
	endif
	GO_TAGS := $(GO_TAGS)rocksdb,grocksdb_clean_link
endif

# If GO_TAGS is not empty, append it to GO_EXTRA_FLAGS.
ifneq ($(GO_TAGS),)
	GO_EXTRA_FLAGS += -tags "$(GO_TAGS)"
endif

# Set all target as the default target.
all: build

# Generate.
generate:
	@$(ECHO) "$(MAGENTA)*** Running go generate...$(OFF)"
	@$(GO) generate ./...
	@$(MAKE) fmt

# Build.
# List of Go binaries to build.
go-binaries := oasis-node oasis-test-runner oasis-net-runner oasis-remote-signer \
	extra/extract-metrics oasis-test-runner/scenario/pluginsigner/example_signer_plugin

$(go-binaries):
	@$(ECHO) "$(MAGENTA)*** Building $@...$(OFF)"
	@$(GO) build $(GOFLAGS) $(GO_EXTRA_FLAGS) -o ./$@/$(notdir $@) ./$@
ifeq ($(GO_BUILD_E2E_COVERAGE),1)
	@$(ECHO) "$(MAGENTA)*** Building $@ with E2E coverage...$(OFF)"
	@$(GO) test $(GOFLAGS) -c -tags e2ecoverage -covermode=atomic -coverpkg=./... -o ./$@/$(notdir $@).test ./$@
endif

build: $(go-binaries)

# Build test helpers.
# List of test helpers to build.
test-helpers := mkvs

# MKVS interoperability test helpers.
mkvs:
	@$(ECHO) "$(MAGENTA)*** Building test helpers for $@...$(OFF)"
	@$(GO) build $(GOFLAGS) $(GO_EXTRA_FLAGS) -o ./$(GO_TEST_HELPER_MKVS_PATH) ./$(shell dirname $(GO_TEST_HELPER_MKVS_PATH))

build-helpers: $(test-helpers)

# List of test vectors to generate.
test-vectors-targets := staking/gen_vectors \
	staking/gen_account_vectors \
	registry/gen_vectors \
	governance/gen_vectors

$(test-vectors-targets):
	@$(ECHO) "$(MAGENTA)*** Generating test vectors ($@)...$(OFF)"
	@$(GO) run ./$@

# Extended set of staking/gen_account_vectors test vectors.
staking/gen_account_vectors_extended:
	@$(ECHO) "$(MAGENTA)*** Generating test vectors ($@)...$(OFF)"
	@$(GO) run ./staking/gen_account_vectors -extended

# Format code.
fmt:
	@$(ECHO) "$(CYAN)*** Running Go formatters...$(OFF)"
	@gofumpt -w .
	@goimports -w -local github.com/oasisprotocol/oasis-core .

# Lint.
lint:
	@$(ECHO) "$(CYAN)*** Running Go linters...$(OFF)"
	@$(GOLANGCI_LINT) run --timeout 4m

lint-mod-tidy:
	@$(ECHO) "$(CYAN)*** Checking go mod tidy...$(OFF)"
	@$(ENSURE_GIT_CLEAN)
	@$(CHECK_GO_MOD_TIDY)

# Test.
test-targets := test-unit test-node

test-unit:
	@$(ECHO) "$(CYAN)*** Running Go unit tests...$(OFF)"
	@$(GO) test -timeout 5m -race -v $(GO_TEST_FLAGS) \
	  $$($(GO) list ./... | grep --invert-match github.com/oasisprotocol/oasis-core/go/oasis-node)

test-node:
	@$(ECHO) "$(CYAN)*** Running Go node tests...$(OFF)"
	@$(GO) test -timeout 5m -race -v $(GO_TEST_FLAGS) github.com/oasisprotocol/oasis-core/go/oasis-node/...

test: $(test-targets)

# Test without caching.
force-test:
	@$(ECHO) "$(CYAN)*** Running Go unit tests in force mode...$(OFF)"
	@$(MAKE) test GO_TEST_FLAGS=-count=1

# Clean.
clean:
	@$(ECHO) "$(CYAN)*** Cleaning up Go...$(OFF)"
	@$(GO) clean

# List of targets that are not actual files.
.PHONY: \
	generate $(go-binaries) $(go-plugins) build \
	$(test-helpers) build-helpers \
	$(test-vectors-targets) \
	fmt lint \
	$(test-targets) test force-test \
	clean all

.FORCE:
