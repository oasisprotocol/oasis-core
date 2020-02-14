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
	// Byzantine executor node.
	_ = cmd.Register(e2e.ByzantineExecutorHonest)
	_ = cmd.Register(e2e.ByzantineExecutorWrong)
	_ = cmd.Register(e2e.ByzantineExecutorStraggler)
	// Byzantine merge node.
	_ = cmd.Register(e2e.ByzantineMergeHonest)
	_ = cmd.Register(e2e.ByzantineMergeWrong)
	_ = cmd.Register(e2e.ByzantineMergeStraggler)
	// Storage sync test.
	_ = cmd.Register(e2e.StorageSync)
	// Sentry test.
	_ = cmd.Register(e2e.Sentry)
	_ = cmd.Register(e2e.SentryEncryption)
	// Keymanager restart test.
	_ = cmd.Register(e2e.KeymanagerRestart)
	// Dump/restore test.
	_ = cmd.Register(e2e.DumpRestore)
	// Halt test.
	_ = cmd.Register(e2e.HaltRestore)
	// Multiple runtimes test.
	_ = cmd.Register(e2e.MultipleRuntimes)
	// Registry CLI test.
	_ = cmd.Register(e2e.RegistryCLI)
	// Stake CLI test.
	_ = cmd.Register(e2e.StakeCLI)
	// Node shutdown test.
	_ = cmd.Register(e2e.NodeShutdown)
	// Gas fees tests.
	_ = cmd.Register(e2e.GasFeesStaking)
	_ = cmd.Register(e2e.GasFeesRuntimes)
	// Identity CLI test.
	_ = cmd.Register(e2e.IdentityCLI)
	// Runtime prune test.
	_ = cmd.Register(e2e.RuntimePrune)
	// Runtime dynamic registration test.
	_ = cmd.Register(e2e.RuntimeDynamic)
	// Transaction source test.
	_ = cmd.Register(e2e.TxSourceTransferShort)
	_ = cmd.RegisterNondefault(e2e.TxSourceTransfer)
	// Node upgrade tests.
	_ = cmd.Register(e2e.NodeUpgrade)
	_ = cmd.Register(e2e.NodeUpgradeCancel)

	// Execute the command, now that everything has been initialized.
	cmd.Execute()
}
