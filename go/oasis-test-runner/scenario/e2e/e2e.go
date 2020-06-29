// Package e2e implements the Oasis e2e test scenarios.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"

	flag "github.com/spf13/pflag"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdNode "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/node"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

const (
	// cfgNodeBinary is the path to oasis-node executable.
	cfgNodeBinary = "node.binary"
)

// E2eParamsDummy is a dummy instance of E2E used to register global e2e flags.
var E2eParamsDummy *E2E = NewE2E("")

// E2E is a base scenario for oasis-node end-to-end tests.
type E2E struct {
	Net    *oasis.Network
	Flags  *env.ParameterFlagSet
	Logger *logging.Logger

	name string
}

// NewE2E creates a new base scenario for oasis-node end-to-end tests.
func NewE2E(name string) *E2E {
	// Empty scenario name is used for registering global parameters only.
	fullName := "e2e"
	if name != "" {
		fullName += "/" + name
	}

	sc := &E2E{
		name:   fullName,
		Logger: logging.GetLogger("scenario/" + fullName),
		Flags:  env.NewParameterFlagSet(fullName, flag.ContinueOnError),
	}
	sc.Flags.String(cfgNodeBinary, "oasis-node", "path to the node binary")

	return sc
}

// Implements scenario.Scenario.
func (sc *E2E) Clone() E2E {
	return E2E{
		Net:    sc.Net,
		Flags:  sc.Flags.Clone(),
		Logger: sc.Logger,
		name:   sc.name,
	}
}

// Implements scenario.Scenario.
func (sc *E2E) Name() string {
	return sc.name
}

// Implements scenario.Scenario.
func (sc *E2E) Parameters() *env.ParameterFlagSet {
	return sc.Flags
}

// Implements scenario.Scenario.
func (sc *E2E) PreInit(childEnv *env.Env) error {
	return nil
}

// Implements scenario.Scenario.
func (sc *E2E) Fixture() (*oasis.NetworkFixture, error) {
	nodeBinary, _ := sc.Flags.GetString(cfgNodeBinary)

	return &oasis.NetworkFixture{
		Network: oasis.NetworkCfg{
			NodeBinary: nodeBinary,
			Consensus: consensusGenesis.Genesis{
				Parameters: consensusGenesis.Parameters{
					GasCosts: transaction.Costs{
						consensusGenesis.GasOpTxByte: 1,
					},
				},
			},
		},
		Entities: []oasis.EntityCfg{
			{IsDebugTestEntity: true},
			{},
		},
		Validators: []oasis.ValidatorFixture{
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
		},
	}, nil
}

// Implements scenario.Scenario.
func (sc *E2E) Init(childEnv *env.Env, net *oasis.Network) error {
	sc.Net = net
	return nil
}

// ResetConsensusState removes all consensus state, preserving runtime storage and node-local
// storage databases.
func (sc *E2E) ResetConsensusState(childEnv *env.Env) error {
	doClean := func(dataDir string, cleanArgs []string) error {
		args := append([]string{
			"unsafe-reset",
			"--" + cmdCommon.CfgDataDir, dataDir,
		}, cleanArgs...)

		return cli.RunSubCommand(childEnv, sc.Logger, "unsafe-reset", sc.Net.Config().NodeBinary, args)
	}

	for _, val := range sc.Net.Validators() {
		if err := doClean(val.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, cw := range sc.Net.ComputeWorkers() {
		if err := doClean(cw.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, cl := range sc.Net.Clients() {
		if err := doClean(cl.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, bz := range sc.Net.Byzantine() {
		if err := doClean(bz.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, se := range sc.Net.Sentries() {
		if err := doClean(se.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, sw := range sc.Net.StorageWorkers() {
		if err := doClean(sw.DataDir(), []string{"--" + cmdNode.CfgPreserveMKVSDatabase}); err != nil {
			return err
		}
	}
	for _, kw := range sc.Net.Keymanagers() {
		if err := doClean(kw.DataDir(), []string{"--" + cmdNode.CfgPreserveLocalStorage}); err != nil {
			return err
		}
	}

	return nil
}

// DumpRestoreNetwork first dumps the current network state and then attempts to restore it.
func (sc *E2E) DumpRestoreNetwork(childEnv *env.Env, fixture *oasis.NetworkFixture, doDbDump bool) error {
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

	if len(sc.Net.StorageWorkers()) > 0 {
		// Dump storage.
		args = []string{
			"debug", "storage", "export",
			"--genesis.file", dumpPath,
			"--datadir", sc.Net.StorageWorkers()[0].DataDir(),
			"--storage.export.dir", filepath.Join(childEnv.Dir(), "storage_dumps"),
			"--debug.dont_blame_oasis",
			"--debug.allow_test_keys",
		}
		if err := cli.RunSubCommand(childEnv, sc.Logger, "storage-dump", sc.Net.Config().NodeBinary, args); err != nil {
			return fmt.Errorf("scenario/e2e/dump_restore: failed to dump storage: %w", err)
		}
	}

	// Reset all the state back to the vanilla state.
	if err := sc.ResetConsensusState(childEnv); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to clean tendemint storage: %w", err)
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

	var err error
	if sc.Net, err = fixture.Create(childEnv); err != nil {
		return err
	}

	// If network is used, enable shorter per-node socket paths, because some e2e test datadir
	// exceed maximum unix socket path length.
	sc.Net.Config().UseShortGrpcSocketPaths = true

	return nil
}

func (sc *E2E) dumpDatabase(childEnv *env.Env, fixture *oasis.NetworkFixture, exportPath string) error {
	// Load the existing export.
	eFp, err := genesisFile.NewFileProvider(exportPath)
	if err != nil {
		return fmt.Errorf("failed to instantiate file provider (export): %w", err)
	}
	exportedDoc, err := eFp.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("failed to get genesis doc (export): %w", err)
	}

	sc.Logger.Info("dumping via debug dumpdb")

	// Dump the state with the debug command off one of the validators.
	dbDumpPath := filepath.Join(childEnv.Dir(), "debug_dump.json")
	args := []string{
		"debug", "dumpdb",
		"--datadir", sc.Net.Validators()[0].DataDir(),
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
	fp, err := genesisFile.NewFileProvider(dbDumpPath)
	if err != nil {
		return fmt.Errorf("failed to instantiate file provider (db): %w", err)
	}
	dbDoc, err := fp.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("failed to get genesis doc (dump): %w", err)
	}

	// Compare the two documents for approximate equality.  Note: Certain
	// fields will be different, so those are fixed up before the comparison.
	dbDoc.EpochTime.Base = exportedDoc.EpochTime.Base
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

func (sc *E2E) finishWithoutChild() error {
	var err error
	select {
	case err = <-sc.Net.Errors():
		return err
	default:
		return sc.Net.CheckLogWatchers()
	}
}

// RegisterScenarios registers all end-to-end scenarios.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterScenarioParams(E2eParamsDummy.Name(), E2eParamsDummy.Parameters())

	// Register default scenarios which are executed, if no test names provided.
	for _, s := range []scenario.Scenario{
		// Registry CLI test.
		RegistryCLI,
		// Stake CLI test.
		StakeCLI,
		// Gas fees tests.
		GasFeesStaking,
		GasFeesStakingDumpRestore,
		// Identity CLI test.
		IdentityCLI,
		// Node upgrade tests.
		NodeUpgrade,
		NodeUpgradeCancel,
		// Debonding entries from genesis test.
		Debond,
		// Early query test.
		EarlyQuery,
	} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	return nil
}
