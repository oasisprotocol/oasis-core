#!/bin/sh -e

make
make -C go integrationrunner

.buildkite/scripts/test_e2e.sh --test basic

type gocovmerge || go get github.com/wadey/gocovmerge
gocovmerge coverage-e2e-*.txt >merged-coverage.txt

cd go/oasis-node/integrationrunner
go tool cover -html=../../../merged-coverage.txt
