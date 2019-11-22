#!/bin/bash

set -euxo pipefail

mkdir -p /tmp/coverage-to-merge
buildkite-agent artifact download "coverage-*.txt*" /tmp/coverage-to-merge

has_problems=

for placeholder in /tmp/coverage-to-merge/coverage-e2e-*.txt; do
  rm "$placeholder"
  if [ -e "$placeholder.uncommitted.commit" ]; then
    mv "$placeholder.uncommitted" "$placeholder"
  else
    echo >&2 "invocation with args $(cat "$placeholder.args") did not commit coverage data"
    has_problems=1
  fi
done

gocovmerge /tmp/coverage-to-merge/coverage-*.txt >merged-coverage.txt

set +x
CODECOV_TOKEN=$(cat ~/.codecov/oasis_core_api_token)
export CODECOV_TOKEN
set -x
bash <(curl -s https://codecov.io/bash) -Z -f merged-coverage.txt

if [ "$has_problems" ]; then
  exit 1
fi
