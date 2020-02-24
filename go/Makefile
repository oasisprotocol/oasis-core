include ../common.mk

# Check if Go's linkers flags are set in common.mk and add them as extra flags.
ifneq ($(GOLDFLAGS),)
	GO_EXTRA_FLAGS += -ldflags $(GOLDFLAGS)
endif

# Set all target as the default target.
all: build

# Build.
# List of Go binaries to build.
go-binaries := oasis-node oasis-test-runner oasis-net-runner extra/stats
# List of test helpers to build.
test-helpers := urkel
# List of test vectors to generate.
test-vectors := staking

generate:
	@$(ECHO) "$(MAGENTA)*** Running go generate...$(OFF)"
	@$(GO) generate ./...

$(go-binaries):
	@$(ECHO) "$(MAGENTA)*** Building $@...$(OFF)"
	@$(GO) build $(GOFLAGS) $(GO_EXTRA_FLAGS) -o ./$@/$(notdir $@) ./$@

oasis-node:

build: $(go-binaries)

# Build test helpers.
# Urkel interoperability test helpers.
urkel:
	@$(ECHO) "$(MAGENTA)*** Building test helpers for $@...$(OFF)"
	@$(GO) build $(GOFLAGS) $(GO_EXTRA_FLAGS) -o ./$(GO_TEST_HELPER_URKEL_PATH) ./$(shell dirname $(GO_TEST_HELPER_URKEL_PATH))

build-helpers: $(test-helpers)

$(test-vectors):
	@$(ECHO) "$(MAGENTA)*** Generating test vectors for $@...$(OFF)"
	@$(GO) run ./$@/gen_vectors

staking:

gen-test-vectors: $(test-vectors)

# Format code.
fmt:
	@$(ECHO) "$(CYAN)*** Running go fmt...$(OFF)"
	@$(GO) fmt ./...

# Lint.
lint:
	@$(ECHO) "$(CYAN)*** Running Go linters...$(OFF)"
	@env -u GOPATH golangci-lint run --timeout 2m

# Test.
test:
	@$(ECHO) "$(CYAN)*** Running Go unit tests...$(OFF)"
	@$(GO) test -timeout 5m -race -v $(GO_TEST_FLAGS) ./...

# Test without caching.
force-test:
	@$(ECHO) "$(CYAN)*** Running Go unit tests in force mode...$(OFF)"
	@$(MAKE) test GO_TEST_FLAGS=-count=1

# Test oasis-node with coverage.
integrationrunner:
	@$(ECHO) "$(CYAN)*** Testing oasis-node with coverate...$(OFF)"
	@$(GO) test $(GOFLAGS) -c -covermode=atomic -coverpkg=./... -o oasis-node/$@/$@.test ./oasis-node/$@

# Fuzzing.
fuzz-targets := fuzz-consensus \
	fuzz-storage \
	fuzz-mkvs/Tree \
	fuzz-mkvs/Proof \
	fuzz-mkvs/Node

define canned-fuzz-run
@TARGETDIR=$(shell pwd)/$<; \
WORKDIR=/tmp/oasis-node-$@; \
if [ "$(FUZZ_NO_BUILD)" != "1" ]; then \
	mkdir -p "$$WORKDIR"; \
	pushd $$TARGETDIR >/dev/null; \
		$(ECHO) "$(CYAN)*** Building fuzzer for $@...$(OFF)"; \
		go-fuzz-build -o $$WORKDIR/fuzz.zip; \
	popd >/dev/null; \
fi; \
if [ "$(FUZZ_BUILD_ONLY)" != "1" ]; then \
	mkdir -p "$$WORKDIR"; \
	cd "$$WORKDIR"; \
	$(ECHO) "$(CYAN)*** Running fuzzer for $@...$(OFF)"; \
	if [ "$(@D)" == "." ]; then \
		go-fuzz -bin=$$WORKDIR/fuzz.zip -workdir=$$WORKDIR; \
	else \
		go-fuzz -bin=$$WORKDIR/fuzz.zip -workdir=$$WORKDIR -func Fuzz$(@F); \
	fi; \
fi;
endef

# Fuzz consensus transactions.
fuzz-consensus: consensus/tendermint/fuzz/
	$(canned-fuzz-run)
# Fuzz general storage interface.
fuzz-storage: storage/fuzz/ oasis-node
	@mkdir -p /tmp/oasis-node-fuzz-storage/identity
	@chmod 0700 /tmp/oasis-node-fuzz-storage/identity
	@oasis-node/oasis-node identity init --datadir /tmp/oasis-node-fuzz-storage/identity
	$(canned-fuzz-run)
# Fuzz MKVS data structures.
fuzz-mkvs/Tree: storage/mkvs/urkel/fuzz
	$(canned-fuzz-run)
fuzz-mkvs/Proof: storage/mkvs/urkel/fuzz
	$(canned-fuzz-run)
fuzz-mkvs/Node: storage/mkvs/urkel/fuzz
	$(canned-fuzz-run)

# Target that only builds all fuzzing infrastructure.
build-fuzz: FUZZ_BUILD_ONLY=1
build-fuzz: $(fuzz-targets)

# Clean.
clean:
	@$(ECHO) "$(CYAN)*** Cleaning up Go...$(OFF)"
	@$(GO) clean

# List of targets that are not actual files.
.PHONY: \
	generate $(go-binaries) build \
	$(test-helpers) build-helpers $(test-vectors) gen-test-vectors $(fuzz-targets) \
	fmt lint test integrationrunner clean all

.FORCE:
