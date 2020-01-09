SHELL := /bin/bash

# Check if we're running in an interactive terminal.
ISATTY := $(shell [ -t 0 ] && echo 1)

ifdef ISATTY
	# Running in interactive terminal, OK to use colors!
	MAGENTA := \e[35;1m
	CYAN := \e[36;1m
	OFF := \e[0m

	# Built-in echo doesn't support '-e'.
	ECHO = /bin/echo -e
else
	# Don't use colors if not running interactively.
	MAGENTA := ""
	CYAN := ""
	OFF := ""

	# OK to use built-in echo.
	ECHO := echo
endif

# Try to determine Oasis Core's version from git.
LATEST_TAG := $(shell git describe --tags --match 'v*' --abbrev=0 2>/dev/null)
VERSION := $(subst v,,$(LATEST_TAG))
IS_TAG := $(shell git describe --tags --match 'v*' --exact-match 2>/dev/null && echo YES || echo NO)
ifeq ($(and $(LATEST_TAG),$(IS_TAG)),NO)
	# The current commit is not exactly a tag, append commit and dirty info to
	# the version.
	VERSION := $(VERSION)-git$(shell git describe --always --match '' --dirty=+dirty 2>/dev/null)
endif
export VERSION

# Try to compute the next version based on the current version using the Punch
# tool.
# NOTE: This is a little messy because Punch doesn't support the following at
# the moment:
#   - Passing current version as an CLI parameter.
#   - Outputting the new version to stdout without making modifications to any
#     files.
_PUNCH_VERSION_FILE := $(shell mktemp /tmp/oasis-core.XXXXX.py)
# NOTE: The "OUTPUT = $(eval OUTPUT := $$(shell some-comand))$(OUTPUT)" syntax
# defers simple variable expansion so that it is only computed the first time it
# is used. For more details, see:
# http://make.mad-scientist.net/deferred-simple-variable-expansion/.
NEXT_VERSION ?= $(eval NEXT_VERSION := $$(shell \
	echo "Fetching all tags from the default remote..." 1>&2 && \
	git fetch --tags && \
	python3 -c "print('year=\"{}\"\nminor={}'.format(*'$(LATEST_TAG)'.lstrip('v').split('.')))" > $(_PUNCH_VERSION_FILE) 2>/dev/null && \
	punch --config-file .punch_config.py --version-file $(_PUNCH_VERSION_FILE) --action custom_bump --quiet 2>/dev/null && \
	python3 -c "exec(open('$(_PUNCH_VERSION_FILE)').read()); print('{}.{}'.format(year, minor))" \
	))$(NEXT_VERSION)

# Go binary to use for all Go commands.
OASIS_GO ?= go

# Go command prefix to use in all Go commands.
GO := env -u GOPATH $(OASIS_GO)

# NOTE: The -trimpath flag strips all host dependent filesystem paths from
# binaries which is required for deterministic builds.
GOFLAGS ?= -trimpath -v

# Add Oasis Core's version as a linker string value definition.
ifneq ($(VERSION),)
	export GOLDFLAGS ?= "-X github.com/oasislabs/oasis-core/go/common/version.SoftwareVersion=$(VERSION)"
endif

# Go build command to use by default.
GO_BUILD_CMD := env -u GOPATH $(OASIS_GO) build $(GOFLAGS)

# Path to the Urkel interoperability test helpers binary in go/.
GO_TEST_HELPER_URKEL_PATH := storage/mkvs/urkel/interop/urkel-test-helpers

# Instruct GoReleaser to create a "snapshot" release by default.
GORELEASER_ARGS ?= release --snapshot --rm-dist
ifeq ($(GITHUB_ACTIONS), true)
	# Running inside GitHub Actions, create a real release.
	# TODO: Prepare Release notes from the automatically generated changelog
	# after https://github.com/oasislabs/oasis-core/issues/759 is implemented.
	RELEASE_NOTES := $(shell mktemp /tmp/oasis-core.XXXXX)
	_ := $(shell echo "We're are pleased to present you Oasis Core $(VERSION)!" > $(RELEASE_NOTES))
	GORELEASER_ARGS = release --release-notes $(RELEASE_NOTES)
endif
