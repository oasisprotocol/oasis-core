#!/usr/bin/env gmake

include common.mk

# List of runtimes to build.
RUNTIMES := keymanager-runtime \
	tests/runtimes/simple-keyvalue

# Set all target as the default target.
all: build
	@$(ECHO) "$(CYAN)*** Everything built successfully!$(OFF)"

# Build.
build-targets := build-tools build-runtimes build-rust build-go

build-tools:
	@$(ECHO) "$(MAGENTA)*** Building Rust tools...$(OFF)"
	@# Suppress "binary already exists" error by redirecting stderr and stdout to /dev/null.
	@CARGO_TARGET_DIR=target/default cargo install --path tools >/dev/null 2>&1 || true

# NOTE: We epxplictly set CARGO_TARGET_DIR as a workaround to avoid
#       recompilations in newer cargo nightly builds.
#       See https://github.com/oasislabs/oasis-core/pull/2673 for details.
build-runtimes:
	@CARGO_TARGET_ROOT=$(shell pwd)/target && for e in $(RUNTIMES); do \
		$(ECHO) "$(MAGENTA)*** Building runtime: $$e...$(OFF)"; \
		(cd $$e && \
			CARGO_TARGET_DIR=$${CARGO_TARGET_ROOT}/sgx cargo build --target x86_64-fortanix-unknown-sgx && \
			CARGO_TARGET_DIR=$${CARGO_TARGET_ROOT}/default cargo build && \
			CARGO_TARGET_DIR=$${CARGO_TARGET_ROOT}/sgx cargo elf2sgxs \
		) || exit 1; \
	done

build-rust:
	@$(ECHO) "$(MAGENTA)*** Building Rust libraries and runtime loader...$(OFF)"
	@CARGO_TARGET_DIR=target/default cargo build

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

# Lint code, commits and documentation.
lint-targets := lint-go lint-git lint-md lint-changelog

lint-go:
	@$(MAKE) -C go lint

lint-git: fetch-git
	@COMMIT_SHA=`git rev-parse $(OASIS_CORE_GIT_ORIGIN_REMOTE)/$(RELEASE_BRANCH)` && \
	echo "Running gitlint for commits from $(OASIS_CORE_GIT_ORIGIN_REMOTE)/$(RELEASE_BRANCH) ($${COMMIT_SHA:0:7})..."; \
	gitlint --commits $(OASIS_CORE_GIT_ORIGIN_REMOTE)/$(RELEASE_BRANCH)...HEAD

lint-md:
	@npx markdownlint-cli '**/*.md' --ignore .changelog/

# NOTE: Non-zero exit status is recorded but only set at the end so that all
# markdownlint or gitlint errors can be seen at once.
lint-changelog:
	@exit_status=0; \
	npx markdownlint-cli --config .changelog/.markdownlint.yml .changelog/ || exit_status=$$?; \
	for fragment in $(CHANGELOG_FRAGMENTS_NON_TRIVIAL); do \
		echo "Running gitlint on $$fragment..."; \
		gitlint --msg-filename $$fragment || exit_status=$$?; \
	done; \
	exit $$exit_status

lint: $(lint-targets)

# Test.
test-unit-targets := test-unit-rust test-unit-go
test-targets := test-unit test-e2e

test-unit-rust: build-helpers
	@$(ECHO) "$(CYAN)*** Running Rust unit tests...$(OFF)"
	@export OASIS_STORAGE_PROTOCOL_SERVER_BINARY=$(realpath go/$(GO_TEST_HELPER_URKEL_PATH)) && \
		CARGO_TARGET_DIR=target/default cargo test

test-unit-go:
	@$(MAKE) -C go test

test-unit: $(test-unit-targets)

test-e2e:
	@$(ECHO) "$(CYAN)*** Running E2E tests...$(OFF)"
	@.buildkite/scripts/test_e2e.sh

test: $(test-targets)

# Clean.
clean-targets := clean-runtimes clean-rust clean-go clean-version-files

clean-runtimes:
	@$(ECHO) "$(CYAN)*** Cleaning up runtimes...$(OFF)"
	@CARGO_TARGET_ROOT=$(shell pwd)/target && for e in $(RUNTIMES); do \
		(cd $$e && \
			CARGO_TARGET_DIR=$${CARGO_TARGET_ROOT}/default cargo clean && \
			CARGO_TARGET_DIR=$${CARGO_TARGET_ROOT}/sgx cargo clean) || exit 1; \
	done

clean-rust:
	@$(ECHO) "$(CYAN)*** Cleaning up Rust...$(OFF)"
	@CARGO_TARGET_DIR=target/default cargo clean

clean-go:
	@$(MAKE) -C go clean

clean-version-files:
	@$(ECHO) "$(CYAN)*** Cleaning Punch version files...$(OFF)"
	@rm --force $(_PUNCH_VERSION_FILE_PATH_PREFIX)*.py

clean: $(clean-targets)

# Fetch all the latest changes (including tags) from the canonical upstream git
# repository.
fetch-git:
	@$(ECHO_STDERR) "Fetching the latest changes (including tags) from $(OASIS_CORE_GIT_ORIGIN_REMOTE) remote..."
	@git fetch $(OASIS_CORE_GIT_ORIGIN_REMOTE) --tags

# Assemble Change log.
changelog: fetch-git
	@$(ENSURE_NEXT_VERSION)
	@$(ECHO_STDERR) "Generating Change Log for version $(NEXT_VERSION)..."
	towncrier build --version $(NEXT_VERSION)
	@$(ECHO_STDERR) "Next, review the staged changes, commit them and make a pull request."

# Tag the next release.
tag-next-release: fetch-git
	@$(ENSURE_NEXT_VERSION)
	@$(ECHO_STDERR) "Checking if we can tag version $(NEXT_VERSION) as the next release..."
	@$(ENSURE_VALID_RELEASE_BRANCH_NAME)
	@$(ENSURE_NO_CHANGELOG_FRAGMENTS)
	@$(ENSURE_NEXT_VERSION_IN_CHANGELOG)
	@$(ECHO_STDERR) "All checks have passed. Proceeding with tagging the $(OASIS_CORE_GIT_ORIGIN_REMOTE)/$(RELEASE_BRANCH)'s HEAD with tag 'v$(NEXT_VERSION)'."
	@$(CONFIRM_ACTION)
	@$(ECHO_STDERR) "If this appears to be stuck, you might need to touch your security key for GPG sign operation."
	@git tag --sign --message="Version $(NEXT_VERSION)" v$(NEXT_VERSION) $(OASIS_CORE_GIT_ORIGIN_REMOTE)/$(RELEASE_BRANCH)
	@git push $(OASIS_CORE_GIT_ORIGIN_REMOTE) v$(NEXT_VERSION)
	@$(ECHO_STDERR) "$(CYAN)Tag 'v$(NEXT_VERSION)' has been successfully pushed to $(OASIS_CORE_GIT_ORIGIN_REMOTE) remote.$(OFF)"

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
	$(lint-targets) lint \
	$(test-unit-targets) $(test-targets) test \
	$(clean-targets) clean \
	fetch-git changelog tag-next-release release docker-shell \
	all
