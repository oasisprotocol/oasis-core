// Package dumpdb implements the dumpdb sub-command.
package dumpdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci"
	cmtAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	beaconApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon"
	governanceApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance"
	keymanagerApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager"
	registryApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	roothashApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash"
	schedulerApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler"
	stakingApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	vaultApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault"
	cmtCommon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

const (
	cfgDumpOutput     = "dump.output"
	cfgDumpReadOnlyDB = "dump.read_only_db"
	cfgDumpVersion    = "dump.version"
)

var (
	dumpDBCmd = &cobra.Command{
		Use:   "dumpdb",
		Short: "dump the on-disk consensus DB to a JSON document",
		Run:   doDumpDB,
	}

	dumpDBFlags = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("cmd/debug/dumpdb")
)

func doDumpDB(cmd *cobra.Command, _ []string) {
	var ok bool
	defer func() {
		if !ok {
			os.Exit(1)
		}
	}()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory must be set")
		return
	}

	// Load the old genesis document, required for filling in parameters
	// that are not persisted to ABCI state.
	fp := genesisFile.NewProvider(flags.GenesisFile())
	oldDoc, err := fp.GetGenesisDocument()
	if err != nil {
		logger.Error("failed to get existing genesis document",
			"err", err,
		)
		return
	}

	// Initialize the ABCI state storage for access.
	//
	// Note: While it would be great to always use read-only DB access,
	// badger will refuse to open a DB that isn't closed properly in
	// read-only mode because it needs to truncate the value log.
	//
	// Hope you have backups if you ever run into this.
	ctx := context.Background()
	ldb, _, stateRoot, err := abci.InitStateStorage(
		&abci.ApplicationConfig{
			DataDir:             filepath.Join(dataDir, cmtCommon.StateDir),
			StorageBackend:      config.GlobalConfig.Storage.Backend,
			MemoryOnlyStorage:   false,
			ReadOnlyStorage:     viper.GetBool(cfgDumpReadOnlyDB),
			DisableCheckpointer: true,
			ChainContext:        oldDoc.ChainContext(),
		},
	)
	if err != nil {
		logger.Error("failed to initialize ABCI storage backend",
			"err", err,
		)
	}
	defer ldb.Cleanup()

	latestVersion := int64(stateRoot.Version)
	dumpVersion := viper.GetInt64(cfgDumpVersion)
	if dumpVersion == 0 {
		dumpVersion = latestVersion
	}
	if dumpVersion <= 0 || dumpVersion > latestVersion {
		logger.Error("dump requested for version that does not exist",
			"dump_version", dumpVersion,
			"latest_version", latestVersion,
		)
		return
	}

	// Generate the dump by querying all of the relevant backends, and
	// extracting the immutable parameters from the current genesis
	// document.
	//
	// WARNING: The state is not guaranteed to be usable as a genesis
	// document without manual intervention, and only the state that
	// would be exported by the normal dump process will be present
	// in the dump.
	qs := &dumpQueryState{
		ldb:    ldb,
		height: dumpVersion,
	}
	doc := &genesis.Document{
		Height:    qs.BlockHeight(),
		Time:      time.Now(), // XXX: Make this deterministic?
		ChainID:   oldDoc.ChainID,
		ExtraData: oldDoc.ExtraData,
	}

	// BUG(?): EpochTime.Base in a exported dump will be set to the
	// current epoch, this uses the original genesis doc.  I'm not
	// sure if there is a right answer here.

	// Registry
	registrySt, err := dumpRegistry(ctx, qs)
	if err != nil {
		logger.Error("failed to dump registry state",
			"err", err,
		)
	}
	doc.Registry = *registrySt

	// RootHash
	rootHashSt, err := dumpRootHash(ctx, qs)
	if err != nil {
		logger.Error("failed to dump root hash state",
			"err", err,
		)
		return
	}
	doc.RootHash = *rootHashSt

	// Staking
	stakingSt, err := dumpStaking(ctx, qs)
	if err != nil {
		logger.Error("failed to dump staking state",
			"err", err,
		)
		return
	}
	// Add static values to the staking genesis state.
	stakingSt.TokenSymbol = oldDoc.Staking.TokenSymbol
	stakingSt.TokenValueExponent = oldDoc.Staking.TokenValueExponent
	doc.Staking = *stakingSt

	// KeyManager
	keyManagerSt, err := dumpKeyManager(ctx, qs)
	if err != nil {
		logger.Error("failed to dump key manager state",
			"err", err,
		)
		return
	}
	doc.KeyManager = *keyManagerSt

	// Scheduler
	schedulerSt, err := dumpScheduler(ctx, qs)
	if err != nil {
		logger.Error("failed to dump scheduler state",
			"err", err,
		)
		return
	}
	doc.Scheduler = *schedulerSt

	// Governance
	governanceSt, err := dumpGovernance(ctx, qs)
	if err != nil {
		logger.Error("failed to dump governance state",
			"err", err,
		)
		return
	}
	doc.Governance = *governanceSt

	// Beacon
	beaconSt, err := dumpBeacon(ctx, qs)
	if err != nil {
		logger.Error("failed to dump beacon state",
			"err", err,
		)
		return
	}
	doc.Beacon = *beaconSt

	// Consensus
	consensusSt, err := dumpConsensus(ctx, qs)
	if err != nil {
		logger.Error("failed to dump consensus state",
			"err", err,
		)
		return
	}
	doc.Consensus = *consensusSt

	// Vault
	vaultSt, err := dumpVault(ctx, qs)
	if err != nil {
		logger.Error("failed to dump vault state",
			"err", err,
		)
		return
	}
	doc.Vault = vaultSt

	logger.Info("writing state dump",
		"output", viper.GetString(cfgDumpOutput),
	)

	// Write out the document.
	w, shouldClose, err := cmdCommon.GetOutputWriter(cmd, cfgDumpOutput)
	if err != nil {
		logger.Error("failed to get output writer for state dump",
			"err", err,
		)
		return
	}
	if shouldClose {
		defer w.Close()
	}
	prettyDoc, err := cmdCommon.PrettyJSONMarshal(doc)
	if err != nil {
		logger.Error("failed to marshal state dump into JSON",
			"err", err,
		)
		return
	}
	if _, err := w.Write(prettyDoc); err != nil {
		logger.Error("failed to write state dump file",
			"err", err,
		)
		return
	}

	ok = true
}

func dumpRegistry(ctx context.Context, qs *dumpQueryState) (*registry.Genesis, error) {
	qf := registryApp.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create registry query: %w", err)
	}
	st, err := q.Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump registry state: %w", err)
	}
	return st, nil
}

func dumpRootHash(ctx context.Context, qs *dumpQueryState) (*roothash.Genesis, error) {
	qf := roothashApp.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create root hash query: %w", err)
	}
	st, err := q.Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump root hash state: %w", err)
	}
	return st, nil
}

func dumpStaking(ctx context.Context, qs *dumpQueryState) (*staking.Genesis, error) {
	qf := stakingApp.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create staking query: %w", err)
	}
	st, err := q.Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump staking state: %w", err)
	}
	return st, nil
}

func dumpKeyManager(ctx context.Context, qs *dumpQueryState) (*keymanager.Genesis, error) {
	qf := keymanagerApp.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create key manager query: %w", err)
	}
	secrets, err := q.Secrets().Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump key manager state: %w", err)
	}
	churp, err := q.Churp().Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump key manager state: %w", err)
	}
	return &keymanager.Genesis{
		Genesis: *secrets,
		Churp:   churp,
	}, nil
}

func dumpScheduler(ctx context.Context, qs *dumpQueryState) (*scheduler.Genesis, error) {
	qf := schedulerApp.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create scheduler query: %w", err)
	}
	st, err := q.Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump scheduler state: %w", err)
	}
	return st, nil
}

func dumpGovernance(ctx context.Context, qs *dumpQueryState) (*governance.Genesis, error) {
	qf := governanceApp.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create governance query: %w", err)
	}
	st, err := q.Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump governance state: %w", err)
	}
	return st, nil
}

func dumpBeacon(ctx context.Context, qs *dumpQueryState) (*beacon.Genesis, error) {
	qf := beaconApp.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create beacon query: %w", err)
	}
	st, err := q.Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump beacon state: %w", err)
	}
	return st, nil
}

func dumpConsensus(ctx context.Context, qs *dumpQueryState) (*consensus.Genesis, error) {
	qf := abci.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create consensus query: %w", err)
	}
	params, err := q.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to get consensus params: %w", err)
	}
	return &consensus.Genesis{
		Backend:    cmtAPI.BackendName,
		Parameters: *params,
	}, nil
}

func dumpVault(ctx context.Context, qs *dumpQueryState) (*vault.Genesis, error) {
	qf := vaultApp.NewQueryFactory(qs)
	q, err := qf.QueryAt(ctx, qs.BlockHeight())
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to create vault query: %w", err)
	}
	st, err := q.Genesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("dumpdb: failed to dump vault state: %w", err)
	}
	return st, nil
}

type dumpQueryState struct {
	ldb    storage.LocalBackend
	height int64
}

func (qs *dumpQueryState) Storage() storage.LocalBackend {
	return qs.ldb
}

func (qs *dumpQueryState) Checkpointer() checkpoint.Checkpointer {
	return nil
}

func (qs *dumpQueryState) BlockHeight() int64 {
	return qs.height
}

func (qs *dumpQueryState) GetEpoch(context.Context, int64) (beacon.EpochTime, error) {
	// This is only required because certain registry backend queries
	// need the epoch to filter out expired nodes.  It is not
	// implemented because acquiring a full state dump does not
	// involve any of the relevant queries.
	return beacon.EpochTime(0), fmt.Errorf("dumpdb/dumpQueryState: GetEpoch not supported")
}

func (qs *dumpQueryState) LastRetainedVersion() (int64, error) {
	// This is not required in the dump process.
	return 0, fmt.Errorf("dumpdb/dumpQueryState: LastRetainedEpoch not supported")
}

// Register registers the dumpdb sub-commands.
func Register(parentCmd *cobra.Command) {
	dumpDBCmd.Flags().AddFlagSet(flags.GenesisFileFlags)
	dumpDBCmd.Flags().AddFlagSet(dumpDBFlags)
	parentCmd.AddCommand(dumpDBCmd)
}

func init() {
	dumpDBFlags.String(cfgDumpOutput, "dump.json", "path to dumped ABCI state")
	dumpDBFlags.Bool(cfgDumpReadOnlyDB, false, "read-only DB access")
	dumpDBFlags.Int64(cfgDumpVersion, 0, "ABCI state version to dump (0 = most recent)")
	_ = viper.BindPFlags(dumpDBFlags)
}
