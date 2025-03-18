package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
)

// Flag for consensus state reset.
const (
	PreserveValidatorRuntimeStorage uint8 = iota
	PreserveValidatorLocalStorage
	ForceValidatorReset
	PreserveComputeWorkerRuntimeStorage
	PreserveComputeWorkerLocalStorage
	ForceComputeWorkerReset
	PreserveClientRuntimeStorage
	PreserveClientLocalStorage
	ForceClientReset
	PreserveByzantineRuntimeStorage
	PreserveByzantineLocalStorage
	ForceByzantineReset
	PreserveSentryRuntimeStorage
	PreserveSentryLocalStorage
	ForceSentryReset
	PreserveKeymanagerRuntimeStorage
	PreserveKeymanagerLocalStorage
	ForceKeymanagerReset
)

// ResetConsensusState removes all consensus state, preserving runtime storage and node-local
// storage databases unless specified with flags otherwise.
func (sc *Scenario) ResetConsensusState(childEnv *env.Env, flags map[uint8]bool) error {
	if flags == nil {
		flags = map[uint8]bool{
			PreserveComputeWorkerRuntimeStorage: true,
			PreserveKeymanagerLocalStorage:      true,
		}
	}

	cli := cli.New(childEnv, sc.Net, sc.Logger)
	for _, val := range sc.Net.Validators() {
		if err := cli.UnsafeReset(
			val.DataDir(),
			flags[PreserveValidatorRuntimeStorage],
			flags[PreserveValidatorLocalStorage],
			flags[ForceValidatorReset],
		); err != nil {
			return err
		}
	}
	for _, cw := range sc.Net.ComputeWorkers() {
		if err := cli.UnsafeReset(cw.DataDir(),
			flags[PreserveComputeWorkerRuntimeStorage],
			flags[PreserveComputeWorkerLocalStorage],
			flags[ForceComputeWorkerReset],
		); err != nil {
			return err
		}
	}
	for _, cl := range sc.Net.Clients() {
		if err := cli.UnsafeReset(cl.DataDir(),
			flags[PreserveClientRuntimeStorage],
			flags[PreserveClientLocalStorage],
			flags[ForceClientReset],
		); err != nil {
			return err
		}
	}
	for _, bz := range sc.Net.Byzantine() {
		if err := cli.UnsafeReset(bz.DataDir(),
			flags[PreserveByzantineRuntimeStorage],
			flags[PreserveByzantineLocalStorage],
			flags[ForceByzantineReset],
		); err != nil {
			return err
		}
	}
	for _, se := range sc.Net.Sentries() {
		if err := cli.UnsafeReset(se.DataDir(),
			flags[PreserveSentryRuntimeStorage],
			flags[PreserveSentryLocalStorage],
			flags[ForceSentryReset],
		); err != nil {
			return err
		}
	}
	for _, kw := range sc.Net.Keymanagers() {
		if err := cli.UnsafeReset(kw.DataDir(),
			flags[PreserveKeymanagerRuntimeStorage],
			flags[PreserveKeymanagerLocalStorage],
			flags[ForceKeymanagerReset],
		); err != nil {
			return err
		}
	}

	return nil
}

// DumpRestoreNetwork first dumps the current network state and then attempts to restore it.
func (sc *Scenario) DumpRestoreNetwork(
	childEnv *env.Env,
	fixture *oasis.NetworkFixture,
	doDbDump bool,
	genesisMapFn func(*genesis.Document),
	resetFlags map[uint8]bool,
) error {
	// Stop any compute workers before taking a dump. Otherwise runtime state may progress after
	// taking the dump which would result in rollback which is not allowed.
	sc.Logger.Info("stopping compute nodes before dumping state")
	for _, n := range sc.Net.ComputeWorkers() {
		if err := n.StopGracefully(); err != nil {
			return fmt.Errorf("failed to stop node: %w", err)
		}
	}

	// Dump-restore network.
	sc.Logger.Info("dumping network state",
		"child", childEnv,
	)

	dumpPath := filepath.Join(childEnv.Dir(), "genesis_dump.json")
	args := []string{
		"genesis", "dump",
		"--height", "0",
		"--genesis.file", dumpPath,
		"--address", "unix:" + sc.Net.Validators()[0].SocketPath(),
	}

	if err := cli.RunSubCommand(childEnv, sc.Logger, "genesis-dump", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to dump state: %w", err)
	}

	// Stop the network.
	sc.Logger.Info("stopping the network")
	sc.Net.Stop()

	if doDbDump {
		if err := sc.dumpDatabase(childEnv, fixture, dumpPath); err != nil {
			return fmt.Errorf("scenario/e2e/dump_restore: failed to dump database: %w", err)
		}
	}

	if len(sc.Net.ComputeWorkers()) > 0 {
		// Dump storage.
		args = []string{
			"debug", "storage", "export",
			"--genesis.file", dumpPath,
			"--config", sc.Net.ComputeWorkers()[0].ConfigFile(),
			"--storage.export.dir", filepath.Join(childEnv.Dir(), "storage_dumps"),
			"--debug.dont_blame_oasis",
			"--debug.allow_test_keys",
		}
		if err := cli.RunSubCommand(childEnv, sc.Logger, "storage-dump", sc.Net.Config().NodeBinary, args); err != nil {
			return fmt.Errorf("scenario/e2e/dump_restore: failed to dump storage: %w", err)
		}
	}

	// Reset all the state back to the vanilla state.
	if err := sc.ResetConsensusState(childEnv, resetFlags); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to clean CometBFT storage: %w", err)
	}

	// Apply optional mapping function to the genesis document.
	if genesisMapFn != nil {
		// Load the existing export.
		genesis := genesisFile.NewProvider(dumpPath)
		doc, err := genesis.GetGenesisDocument()
		if err != nil {
			return fmt.Errorf("failed to get genesis document: %w", err)
		}

		genesisMapFn(doc)

		// Write back the updated document.
		buf, err := json.Marshal(doc)
		if err != nil {
			return fmt.Errorf("failed to marshal updated genesis document: %w", err)
		}
		if err = os.WriteFile(dumpPath, buf, 0o600); err != nil {
			return fmt.Errorf("failed to write updated genesis document: %w", err)
		}
	}

	// Start the network and the client again.
	sc.Logger.Info("starting the network again")

	fixture.Network.GenesisFile = dumpPath
	// Make sure to not overwrite entities.
	for i, entity := range fixture.Entities {
		if !entity.IsDebugTestEntity {
			fixture.Entities[i].Restore = true
		}
	}

	// If network is used, enable shorter per-node socket paths, because some e2e test datadir
	// exceed maximum unix socket path length.
	fixture.Network.UseShortGrpcSocketPaths = true

	var err error
	if sc.Net, err = fixture.Create(childEnv); err != nil {
		return err
	}

	return nil
}

func (sc *Scenario) dumpDatabase(childEnv *env.Env, _ *oasis.NetworkFixture, exportPath string) error {
	// Load the existing export.
	genesis := genesisFile.NewProvider(exportPath)
	exportedDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("failed to get genesis doc (export): %w", err)
	}

	sc.Logger.Info("dumping via debug dumpdb")

	// Dump the state with the debug command off one of the validators.
	dbDumpPath := filepath.Join(childEnv.Dir(), "debug_dump.json")
	args := []string{
		"debug", "dumpdb",
		"--config", sc.Net.Validators()[0].ConfigFile(),
		"-g", sc.Net.GenesisPath(),
		"--dump.version", fmt.Sprintf("%d", exportedDoc.Height),
		"--dump.output", dbDumpPath,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	if err = cli.RunSubCommand(childEnv, sc.Logger, "debug-dump", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("failed to dump database: %w", err)
	}

	// Load the dumped state.
	genesis = genesisFile.NewProvider(dbDumpPath)
	dbDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("failed to get genesis doc (dump): %w", err)
	}

	// Compare the two documents for approximate equality.  Note: Certain
	// fields will be different, so those are fixed up before the comparison.
	dbDoc.Beacon.Base = exportedDoc.Beacon.Base
	dbDoc.Time = exportedDoc.Time
	dbRaw, err := json.Marshal(dbDoc)
	if err != nil {
		return fmt.Errorf("failed to marshal fixed up dump: %w", err)
	}
	expRaw, err := json.Marshal(exportedDoc)
	if err != nil {
		return fmt.Errorf("failed to re-marshal export doc: %w", err)
	}
	if !bytes.Equal(expRaw, dbRaw) {
		return fmt.Errorf("dump does not match state export")
	}

	return nil
}

func (sc *Scenario) finishWithoutChild() error {
	var err error
	select {
	case err = <-sc.Net.Errors():
		return err
	default:
		return sc.Net.CheckLogWatchers()
	}
}
