// Oasis post-upgrade test runner (for testing only).
package main

import (
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"

	"github.com/oasisprotocol/oasis-core/test-upgrade/scenario/e2e"
	"github.com/oasisprotocol/oasis-core/test-upgrade/scenario/e2e/runtime"
)

func main() {
	// Register all scenarios and scenario parameters.
	for _, register := range []func() error{
		e2e.RegisterScenarios,
		runtime.RegisterScenarios,
	} {
		if err := register(); err != nil {
			common.EarlyLogAndExit(err)
		}
	}

	cmd.Execute()
}
