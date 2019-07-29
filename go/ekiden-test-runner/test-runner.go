// Ekiden integration test harness.
package main

import (
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/cmd"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/scenario/e2e"
)

func main() {
	// The general idea is that it should be possible to reuse everything
	// except for the main() function  and specialized test cases to write
	// test drivers that need to exercise ekiden or things built up on
	// ekiden.
	//
	// Other implementations will likely want to override parts of rootCmd,
	// in particular the `Use`, `Short`, and `Version` fields.
	rootCmd := cmd.RootCmd()

	// Register the ekiden e2e test cases.
	rootCmd.Flags().AddFlagSet(e2e.Flags)
	_ = cmd.Register(e2e.Basic)

	// Execute the command, now that everything has been initialized.
	cmd.Execute()
}
