#!/bin/bash

set -euo pipefail

# Determine coverage file location.
covfile=$(mktemp coverage-e2e-XXXXXXXXXX.txt)

# Get the binary name from the first argument.
binary=$1
shift

# Run the specified binary with E2E coverage instrumentation.
exec $binary \
  -test.coverprofile "$covfile" \
  -test.run "^TestCoverageE2E$" \
  -- "$@"
