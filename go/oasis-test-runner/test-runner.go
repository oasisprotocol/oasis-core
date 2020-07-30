// Oasis network integration test harness.
package main

import (
	"github.com/hashicorp/go-plugin"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e/runtime"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/pluginsigner"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/remotesigner"
)

func main() {
	// If we use go-plugin, we are supposed to clean clients up.
	defer plugin.CleanupClients()

	// The general idea is that it should be possible to reuse everything
	// except for the main() function  and specialized test cases to write
	// test drivers that need to exercise the Oasis network or things built
	// up on the Oasis network.
	//
	// Other implementations will likely want to override parts of cmd.rootCmd,
	// in particular the `Use`, `Short`, and `Version` fields.

	// Register all scenarios and scenario parameters.
	for _, register := range []func() error{
		e2e.RegisterScenarios,
		runtime.RegisterScenarios,
		pluginsigner.RegisterScenarios,
		remotesigner.RegisterScenarios,
	} {
		if err := register(); err != nil {
			common.EarlyLogAndExit(err)
		}
	}

	// Execute the command, now that everything has been initialized.
	cmd.Execute()
}
