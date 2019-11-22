#!/bin/bash

set -euo pipefail

covfile=$(mktemp coverage-e2e-XXXXXXXXXX.txt)

printf "%s\n" "$*" >"$covfile.args"

exec ./go/oasis-node/integrationrunner/integrationrunner.test \
  -test.coverprofile "$covfile.uncommitted" \
  -integration.run \
  -- "$@"
