// Oasis network integration test harness.
package main

import (
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario/e2e"
)

func main() {
	// The general idea is that it should be possible to reuse everything
	// except for the main() function  and specialized test cases to write
	// test drivers that need to exercise the Oasis network or things built
	// up on the Oasis network.
	//
	// Other implementations will likely want to override parts of rootCmd,
	// in particular the `Use`, `Short`, and `Version` fields.
	rootCmd := cmd.RootCmd()

	// Register the e2e test cases.
	rootCmd.Flags().AddFlagSet(e2e.Flags)
	// Basic test.
	_ = cmd.Register(e2e.Basic)
	_ = cmd.Register(e2e.BasicEncryption)
	// Byzantine compute node.
	_ = cmd.Register(e2e.ByzantineComputeHonest)
	_ = cmd.Register(e2e.ByzantineComputeWrong)
	_ = cmd.Register(e2e.ByzantineComputeStraggler)
	// Byzantine merge node.
	_ = cmd.Register(e2e.ByzantineMergeHonest)
	_ = cmd.Register(e2e.ByzantineMergeWrong)
	_ = cmd.Register(e2e.ByzantineMergeStraggler)
	// Storage sync test.
	_ = cmd.Register(e2e.StorageSync)
	// Sentry test.
	_ = cmd.Register(e2e.Sentry)
	// Keymanager restart test.
	_ = cmd.Register(e2e.KeymanagerRestart)
	// Dump/restore test.
	_ = cmd.Register(e2e.DumpRestore)
	// Halt test.
	_ = cmd.Register(e2e.HaltRestore)
	// Registry CLI test.
	_ = cmd.Register(e2e.RegistryCLI)
	// Stake CLI test.
	_ = cmd.Register(e2e.StakeCLI)
	// Node shutdown test.
	_ = cmd.Register(e2e.NodeShutdown)
	// Gas fees test.
	_ = cmd.Register(e2e.GasFees)
	// Identity CLI test.
	_ = cmd.Register(e2e.IdentityCLI)
	// Runtime prune test.
	_ = cmd.Register(e2e.RuntimePrune)
	// Transaction source test.
	_ = cmd.Register(e2e.TxSourceTransferShort)
	_ = cmd.RegisterNondefault(e2e.TxSourceTransfer)

	// Execute the command, now that everything has been initialized.
	cmd.Execute()
}
