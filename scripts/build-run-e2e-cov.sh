#!/bin/sh -e

make
make -C go GO_BUILD_E2E_COVERAGE=1

.buildkite/scripts/test_e2e.sh --test basic

type gocovmerge || go get github.com/wadey/gocovmerge
gocovmerge coverage-e2e-*.txt >merged-coverage.txt

go tool cover -html=merged-coverage.txt
