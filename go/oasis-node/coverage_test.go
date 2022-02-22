//go:build e2ecoverage
// +build e2ecoverage

package main

import (
	"testing"

	cmnTesting "github.com/oasisprotocol/oasis-core/go/common/testing"
)

func TestCoverageE2E(t *testing.T) {
	cmnTesting.RunMain(t, main)
}
