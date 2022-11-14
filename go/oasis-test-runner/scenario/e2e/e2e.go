// Package e2e implements the Oasis e2e test scenarios.
package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	goHash "hash"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	flag "github.com/spf13/pflag"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
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
var E2eParamsDummy = NewE2E("")

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

// Clone implements scenario.Scenario.
func (sc *E2E) Clone() E2E {
	return E2E{
		Net:    sc.Net,
		Flags:  sc.Flags.Clone(),
		Logger: sc.Logger,
		name:   sc.name,
	}
}

// Name implements scenario.Scenario.
func (sc *E2E) Name() string {
	return sc.name
}

// Parameters implements scenario.Scenario.
func (sc *E2E) Parameters() *env.ParameterFlagSet {
	return sc.Flags
}

// PreInit implements scenario.Scenario.
func (sc *E2E) PreInit(childEnv *env.Env) error {
	return nil
}

// Fixture implements scenario.Scenario.
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
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true, SupplementarySanityInterval: 1}},
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
		},
		Seeds: []oasis.SeedFixture{{}},
	}, nil
}

// Init implements scenario.Scenario.
func (sc *E2E) Init(childEnv *env.Env, net *oasis.Network) error {
	sc.Net = net
	return nil
}

// GetExportedGenesisFiles gathers exported genesis files and ensures
// all exported genesis files match.
func (sc *E2E) GetExportedGenesisFiles(skipCompute bool) ([]string, error) {
	dumpGlob := "genesis-*.json"

	// Gather all nodes.
	var nodes []interface {
		ExportsPath() string
	}
	for _, v := range sc.Net.Validators() {
		nodes = append(nodes, v)
	}
	if !skipCompute {
		for _, n := range sc.Net.ComputeWorkers() {
			nodes = append(nodes, n)
		}
	}
	for _, n := range sc.Net.Keymanagers() {
		nodes = append(nodes, n)
	}

	// Gather all genesis files.
	var files []string
	for _, node := range nodes {
		dumpGlobPath := filepath.Join(node.ExportsPath(), dumpGlob)
		globMatch, err := filepath.Glob(dumpGlobPath)
		if err != nil {
			return nil, fmt.Errorf("glob failed: %s: %w", dumpGlobPath, err)
		}
		if len(globMatch) == 0 {
			return nil, fmt.Errorf("genesis file not found in: %s", dumpGlobPath)
		}
		if len(globMatch) > 1 {
			return nil, fmt.Errorf("more than one genesis file found in: %s", dumpGlobPath)
		}
		files = append(files, globMatch[0])
	}

	// Assert all exported files match.
	var firstHash goHash.Hash
	for _, file := range files {
		// Compute hash.
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %s: %w", file, err)
		}
		defer f.Close()
		hnew := sha256.New()
		if _, err := io.Copy(hnew, f); err != nil {
			return nil, fmt.Errorf("sha256 failed on: %s: %w", file, err)
		}
		if firstHash == nil {
			firstHash = hnew
		}

		// Compare hash with first hash.
		if !bytes.Equal(firstHash.Sum(nil), hnew.Sum(nil)) {
			return nil, fmt.Errorf("exported genesis files do not match %s, %s", files[0], file)
		}
	}

	return files, nil
}

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
func (sc *E2E) ResetConsensusState(childEnv *env.Env, flags map[uint8]bool) error {
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
func (sc *E2E) DumpRestoreNetwork(
	childEnv *env.Env,
	fixture *oasis.NetworkFixture,
	doDbDump bool,
	genesisMapFn func(*genesis.Document),
	resetFlags map[uint8]bool,
) error {
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
			"--datadir", sc.Net.ComputeWorkers()[0].DataDir(),
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
		return fmt.Errorf("scenario/e2e/dump_restore: failed to clean tendermint storage: %w", err)
	}

	// Apply optional mapping function to the genesis document.
	if genesisMapFn != nil {
		// Load the existing export.
		fp, err := genesisFile.NewFileProvider(dumpPath)
		if err != nil {
			return fmt.Errorf("failed to instantiate genesis document file provider: %w", err)
		}
		doc, err := fp.GetGenesisDocument()
		if err != nil {
			return fmt.Errorf("failed to get genesis document: %w", err)
		}

		genesisMapFn(doc)

		// Write back the updated document.
		buf, err := json.Marshal(doc)
		if err != nil {
			return fmt.Errorf("failed to marshal updated genesis document: %w", err)
		}
		if err = ioutil.WriteFile(dumpPath, buf, 0o600); err != nil {
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
		// Genesis file test.
		GenesisFile,
		// Node upgrade tests.
		NodeUpgradeDummy,
		NodeUpgradeMaxAllowances,
		NodeUpgradeV62,
		NodeUpgradeEmpty,
		NodeUpgradeCancel,
		// Debonding entries from genesis test.
		Debond,
		// Early query test.
		EarlyQuery,
		EarlyQueryInitHeight,
		// Consensus state sync.
		ConsensusStateSync,
		// Multiple seeds test.
		MultipleSeeds,
		// Seed API test.
		SeedAPI,
		// ValidatorEquivocation test.
		ValidatorEquivocation,
		// Byzantine VRF beacon tests.
		ByzantineVRFBeaconHonest,
		ByzantineVRFBeaconEarly,
		ByzantineVRFBeaconMissing,
		// Minimum transact balance test.
		MinTransactBalance,
	} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	return nil
}
