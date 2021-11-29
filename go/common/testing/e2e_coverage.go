//go:build e2ecoverage
// +build e2ecoverage

package testing

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
)

// RunMain runs the specified main function inside unit tests. This is usually used in E2E coverage
// wrapper "tests" in order to generate coverage for a binary.
func RunMain(t *testing.T, mainFn func()) {
	// Trim (test-related) arguments and call the usual main.
	os.Args = common.TrimArgs(os.Args)
	mainFn()

	// Suppress coverage report on stdout.
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	require.NoError(t, err, "opening %s", os.DevNull)
	os.Stdout = f
}
