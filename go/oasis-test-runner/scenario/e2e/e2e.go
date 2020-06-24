// Package e2e implements the Oasis e2e test scenarios.
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"

	flag "github.com/spf13/pflag"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
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

var (
	// E2eParamsDummy is a dummy instance of e2eImpl used to register global e2e flags.
	E2eParamsDummy *e2eImpl = newE2eImpl("")
)

// e2eImpl is a base class for tests involving oasis-node.
type e2eImpl struct {
	net    *oasis.Network
	name   string
	logger *logging.Logger
	flags  *env.ParameterFlagSet
}

func newE2eImpl(name string) *e2eImpl {
	// Empty scenario name is used for registering global parameters only.
	fullName := "e2e"
	if name != "" {
		fullName += "/" + name
	}

	sc := &e2eImpl{
		name:   fullName,
		logger: logging.GetLogger("scenario/" + fullName),
		flags:  env.NewParameterFlagSet(fullName, flag.ContinueOnError),
	}
	sc.flags.String(cfgNodeBinary, "oasis-node", "path to the node binary")

	return sc
}

func (sc *e2eImpl) Clone() e2eImpl {
	return e2eImpl{
		net:    sc.net,
		name:   sc.name,
		logger: sc.logger,
		flags:  sc.flags.Clone(),
	}
}

func (sc *e2eImpl) Name() string {
	return sc.name
}

func (sc *e2eImpl) Parameters() *env.ParameterFlagSet {
	return sc.flags
}

func (sc *e2eImpl) PreInit(childEnv *env.Env) error {
	return nil
}

func (sc *e2eImpl) Fixture() (*oasis.NetworkFixture, error) {
	nodeBinary, _ := sc.flags.GetString(cfgNodeBinary)

	return &oasis.NetworkFixture{
		Network: oasis.NetworkCfg{
			NodeBinary:              nodeBinary,
			ConsensusGasCostsTxByte: 1,
		},
		Entities: []oasis.EntityCfg{
			oasis.EntityCfg{IsDebugTestEntity: true},
			oasis.EntityCfg{},
		},
		Validators: []oasis.ValidatorFixture{
			oasis.ValidatorFixture{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
			oasis.ValidatorFixture{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
			oasis.ValidatorFixture{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
		},
	}, nil
}

func (sc *e2eImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	sc.net = net
	return nil
}

func (sc *e2eImpl) cleanTendermintStorage(childEnv *env.Env) error {
	doClean := func(dataDir string, cleanArgs []string) error {
		args := append([]string{
			"unsafe-reset",
			"--" + cmdCommon.CfgDataDir, dataDir,
		}, cleanArgs...)

		return cli.RunSubCommand(childEnv, sc.logger, "unsafe-reset", sc.net.Config().NodeBinary, args)
	}

	for _, val := range sc.net.Validators() {
		if err := doClean(val.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, cw := range sc.net.ComputeWorkers() {
		if err := doClean(cw.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, cl := range sc.net.Clients() {
		if err := doClean(cl.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, bz := range sc.net.Byzantine() {
		if err := doClean(bz.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, se := range sc.net.Sentries() {
		if err := doClean(se.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, sw := range sc.net.StorageWorkers() {
		if err := doClean(sw.DataDir(), []string{"--" + cmdNode.CfgPreserveMKVSDatabase}); err != nil {
			return err
		}
	}
	for _, kw := range sc.net.Keymanagers() {
		if err := doClean(kw.DataDir(), []string{"--" + cmdNode.CfgPreserveLocalStorage}); err != nil {
			return err
		}
	}

	return nil
}

func (sc *e2eImpl) dumpRestoreNetwork(childEnv *env.Env, fixture *oasis.NetworkFixture, doDbDump bool) error {
	// Dump-restore network.
	sc.logger.Info("dumping network state",
		"child", childEnv,
	)

	dumpPath := filepath.Join(childEnv.Dir(), "genesis_dump.json")
	args := []string{
		"genesis", "dump",
		"--height", "0",
		"--genesis.file", dumpPath,
		"--address", "unix:" + sc.net.Validators()[0].SocketPath(),
	}

	if err := cli.RunSubCommand(childEnv, sc.logger, "genesis-dump", sc.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to dump state: %w", err)
	}

	// Stop the network.
	sc.logger.Info("stopping the network")
	sc.net.Stop()

	if doDbDump {
		if err := sc.dumpDatabase(childEnv, fixture, dumpPath); err != nil {
			return fmt.Errorf("scenario/e2e/dump_restore: failed to dump database: %w", err)
		}
	}

	if len(sc.net.StorageWorkers()) > 0 {
		// Dump storage.
		args = []string{
			"debug", "storage", "export",
			"--genesis.file", dumpPath,
			"--datadir", sc.net.StorageWorkers()[0].DataDir(),
			"--storage.export.dir", filepath.Join(childEnv.Dir(), "storage_dumps"),
			"--debug.dont_blame_oasis",
			"--debug.allow_test_keys",
		}
		if err := cli.RunSubCommand(childEnv, sc.logger, "storage-dump", sc.net.Config().NodeBinary, args); err != nil {
			return fmt.Errorf("scenario/e2e/dump_restore: failed to dump storage: %w", err)
		}
	}

	// Reset all the state back to the vanilla state.
	if err := sc.cleanTendermintStorage(childEnv); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to clean tendemint storage: %w", err)
	}

	// Start the network and the client again.
	sc.logger.Info("starting the network again")

	fixture.Network.GenesisFile = dumpPath
	// Make sure to not overwrite entities.
	for i, entity := range fixture.Entities {
		if !entity.IsDebugTestEntity {
			fixture.Entities[i].Restore = true
		}
	}

	var err error
	if sc.net, err = fixture.Create(childEnv); err != nil {
		return err
	}

	// If network is used, enable shorter per-node socket paths, because some e2e test datadir
	// exceed maximum unix socket path length.
	sc.net.Config().UseShortGrpcSocketPaths = true

	return nil
}

func (sc *e2eImpl) dumpDatabase(childEnv *env.Env, fixture *oasis.NetworkFixture, exportPath string) error {
	// Load the existing export.
	eFp, err := genesisFile.NewFileProvider(exportPath)
	if err != nil {
		return fmt.Errorf("failed to instantiate file provider (export): %w", err)
	}
	exportedDoc, err := eFp.GetGenesisDocument()
	if err != nil {
		return fmt.Errorf("failed to get genesis doc (export): %w", err)
	}

	sc.logger.Info("dumping via debug dumpdb")

	// Dump the state with the debug command off one of the validators.
	dbDumpPath := filepath.Join(childEnv.Dir(), "debug_dump.json")
	args := []string{
		"debug", "dumpdb",
		"--datadir", sc.net.Validators()[0].DataDir(),
		"-g", sc.net.GenesisPath(),
		"--dump.version", fmt.Sprintf("%d", exportedDoc.Height),
		"--dump.output", dbDumpPath,
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "debug-dump", sc.net.Config().NodeBinary, args); err != nil {
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

func (sc *e2eImpl) finishWithoutChild() error {
	var err error
	select {
	case err = <-sc.net.Errors():
		return err
	default:
		return sc.net.CheckLogWatchers()
	}
}

// RegisterScenarios registers all end-to-end scenarios.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterTestParams(E2eParamsDummy.Name(), E2eParamsDummy.Parameters())
	cmd.RegisterTestParams(RuntimeParamsDummy.Name(), RuntimeParamsDummy.Parameters())

	// Register default scenarios which are executed, if no test names provided.
	for _, s := range []scenario.Scenario{
		// Runtime test.
		Runtime,
		RuntimeEncryption,
		// Byzantine executor node.
		ByzantineExecutorHonest,
		ByzantineExecutorWrong,
		ByzantineExecutorStraggler,
		// Byzantine merge node.
		ByzantineMergeHonest,
		ByzantineMergeWrong,
		ByzantineMergeStraggler,
		// Storage sync test.
		StorageSync,
		// Sentry test.
		Sentry,
		SentryEncryption,
		// Keymanager restart test.
		KeymanagerRestart,
		// Keymanager replicate test.
		KeymanagerReplicate,
		// Dump/restore test.
		DumpRestore,
		// Halt test.
		HaltRestore,
		// Multiple runtimes test.
		MultipleRuntimes,
		// Registry CLI test.
		RegistryCLI,
		// Stake CLI test.
		StakeCLI,
		// Node shutdown test.
		NodeShutdown,
		// Gas fees tests.
		GasFeesStaking,
		GasFeesStakingDumpRestore,
		GasFeesRuntimes,
		// Identity CLI test.
		IdentityCLI,
		// Runtime prune test.
		RuntimePrune,
		// Runtime dynamic registration test.
		RuntimeDynamic,
		// Transaction source test.
		TxSourceMultiShort,
		// Node upgrade tests.
		NodeUpgrade,
		NodeUpgradeCancel,
		// Debonding entries from genesis test.
		Debond,
		// Late start test.
		LateStart,
		// KeymanagerUpgrade test.
		KeymanagerUpgrade,
		// Early query test.
		EarlyQuery,
	} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	// Register non-default scenarios which are executed on-demand only.
	for _, s := range []scenario.Scenario{
		// Transaction source test. Non-default, because it runs for ~6 hours.
		TxSourceMulti,
	} {
		if err := cmd.RegisterNondefault(s); err != nil {
			return err
		}
	}

	return nil
}
