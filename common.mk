SHELL := /bin/bash

# Check if we're running in an interactive terminal.
ISATTY := $(shell [ -t 0 ] && echo 1)

ifdef ISATTY
	# Running in interactive terminal, OK to use colors!
	MAGENTA := \e[35;1m
	CYAN := \e[36;1m
	RED := \e[0;31m
	OFF := \e[0m

	# Built-in echo doesn't support '-e'.
	ECHO = /bin/echo -e
else
	# Don't use colors if not running interactively.
	MAGENTA := ""
	CYAN := ""
	RED := ""
	OFF := ""

	# OK to use built-in echo.
	ECHO := echo
endif

# A version of echo that outputs to stderr instead of stdout.
ECHO_STDERR := $(ECHO) 1>&2

# Helper that asks the user to confirm the action.
define CONFIRM_ACTION =
	$(ECHO_STDERR) -n "Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]
endef

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

# Try to compute the next version based on the latest tag of the origin remote
# using the Punch tool.
# First, all tags from the origin remote are fetched. Next, the latest tag on
# the origin/master branch is determined. It represents Oasis Core's current
# version. Lastly, the Punch tool is used to bump the version according to the
# configurated versioning scheme in .punch_config.py.
#
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
	set -e; \
	echo "Fetching all tags from the origin remote..." 1>&2; \
	git fetch origin --tags; \
	LATEST_TAG_ORIGIN=`git describe --tags --match 'v*' --abbrev=0 origin/master` \
	python3 -c "import os; year, minor = os.environ['LATEST_TAG_ORIGIN'].lstrip('v').split('.'); \
		print(f'year=\"{year}\"\nminor={minor}')" > $(_PUNCH_VERSION_FILE); \
	punch --config-file .punch_config.py --version-file $(_PUNCH_VERSION_FILE) --action custom_bump --quiet; \
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

# If running inside GitHub Actions, create a real release.
ifeq ($(GITHUB_ACTIONS), true)

# Auxiliary variable that defines a new line for later substitution.
define newline


endef

# GitHub release' text in Markdown format.
define RELEASE_TEXT =
For a list of changes in this release, see the [Change Log].

*NOTE: If you are upgrading from an earlier release, please **carefully review**
the [Change Log] for **Removals and Breaking changes**.*

If you would like to become a node operator for the Oasis Network, see the
[Operator Docs](https://docs.oasis.dev/operators/overview.html).

[Change Log]: https://github.com/oasislabs/oasis-core/blob/v$(VERSION)/CHANGELOG.md

endef

# Temporary file with GitHub release's text.
_RELEASE_NOTES_FILE := $(shell mktemp /tmp/oasis-core.XXXXX)
_ := $(shell printf "$(subst ",\",$(subst $(newline),\n,$(RELEASE_TEXT)))" > $(_RELEASE_NOTES_FILE))
GORELEASER_ARGS = release --release-notes $(_RELEASE_NOTES_FILE)

endif

# Helper that ensures $(NEXT_VERSION) variable is not empty.
define ENSURE_NEXT_VERSION =
	if [[ -z "$(NEXT_VERSION)" ]]; then \
		$(ECHO_STDERR) "$(RED)Error: Could not compute project's next version.$(OFF)"; \
		exit 1; \
	fi
endef

# Helper that ensures the origin/master's HEAD doesn't contain any Change Log fragments.
define ENSURE_NO_CHANGELOG_FRAGMENTS =
	CHANGELOG_FRAGMENTS=`git ls-tree -r --name-only origin/master .changelog | \
	       grep --invert-match --extended-regexp '(README.md|template.md.j2)'`; \
	if [[ -n $${CHANGELOG_FRAGMENTS} ]]; then \
		$(ECHO_STDERR) "$(RED)Error: Found the following Change Log fragments on origin/master branch:"; \
		$(ECHO_STDERR) "$${CHANGELOG_FRAGMENTS}$(OFF)"; \
		exit 1; \
	fi
endef

# Helper that ensures the origin/master's HEAD contains a Change Log section for the next release.
define ENSURE_NEXT_VERSION_IN_CHANGELOG =
	if ! ( git show origin/master:CHANGELOG.md | \
		   grep --quiet '^## $(NEXT_VERSION) (.*)' ); then \
		$(ECHO_STDERR) "$(RED)Error: Could not locate Change Log section for release $(NEXT_VERSION).$(OFF)"; \
		exit 1; \
	fi
endef
