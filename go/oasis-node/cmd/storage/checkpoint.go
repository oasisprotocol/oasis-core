package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	cmtCfg "github.com/cometbft/cometbft/config"
	cmtProtoState "github.com/cometbft/cometbft/proto/tendermint/state"
	cmtProto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmtState "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cometbft/cometbft/version"
	"github.com/cosmos/gogoproto/proto"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const (
	consensusSubdir = "consensus"
	runtimesSubdir  = "runtimes"

	consensusMetaFilename = "bootstrap.cbor"
)

type bootstrapMeta struct {
	State  []byte `json:"state"`
	Commit []byte `json:"commit"`
}

func newCheckpointCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "checkpoint",
		Short: "create and restore storage checkpoints",
		PersistentPreRunE: func(_ *cobra.Command, args []string) error {
			if err := cmdCommon.Init(); err != nil {
				cmdCommon.EarlyLogAndExit(err)
			}
			running, err := cmdCommon.IsNodeRunning()
			if err != nil {
				return fmt.Errorf("failed to ensure the node is not running: %w", err)
			}
			if running {
				return fmt.Errorf("checkpoint operations can only be done when the node is not running")
			}
			return nil
		},
	}

	cmd.AddCommand(newCreateCmd())
	cmd.AddCommand(newImportCmd())

	return cmd
}

func newCreateCmd() *cobra.Command {
	var (
		height    uint64
		runtimeID string
		round     uint64
		outDir    string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Args:  cobra.NoArgs,
		Short: "create storage checkpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			dataDir := cmdCommon.DataDir()

			// Consensus checkpoint:
			createConsensusCp := func(outputDir string) error {
				ndb, close, err := openConsensusNodeDB(dataDir)
				if err != nil {
					return fmt.Errorf("failed to open consensus state DB: %w", err)
				}
				defer close()

				return createCheckpoints(ctx, ndb, common.Namespace{}, height, outputDir)
			}
			if height != 0 { // TODO handle zero value vs not set correctly.
				consensusOutDir := filepath.Join(outDir, consensusSubdir)
				if err := createConsensusCp(consensusOutDir); err != nil {
					return fmt.Errorf("failed to create consensus checkpoint (height: %d): %w", height, err)
				}
				if err := createCometBFTBootstrapMeta(ctx, dataDir, height, consensusOutDir); err != nil {
					return fmt.Errorf("failed to write bootstrap metadata: %w", err)
				}
			}

			// Runtime Checkpoints:
			createRuntimeCps := func(ns common.Namespace, outputDir string) error {
				ndb, err := openRuntimeStateDB(dataDir, ns)
				if err != nil {
					return fmt.Errorf("failed to open runtime state DB: %w", err)
				}
				defer ndb.Close()

				return createCheckpoints(ctx, ndb, ns, round, outputDir)
			}
			if runtimeID != "" {
				var ns common.Namespace
				if err := ns.UnmarshalHex(runtimeID); err != nil {
					return fmt.Errorf("malformed source runtime ID: %q: %w", runtimeID, err)
				}
				rtOutDir := filepath.Join(outDir, runtimesSubdir, ns.Hex())
				if err := createRuntimeCps(ns, rtOutDir); err != nil {
					return fmt.Errorf("failed to create runtime checkpoints (runtime: %s, round: %d): %w", runtimeID, round, err)
				}
			}

			return nil
		},
	}

	cmd.Flags().Uint64Var(&height, "height", 0, "consensus height")
	cmd.Flags().StringVar(&runtimeID, "runtime", "", "hex encoded runtime ID")
	cmd.Flags().Uint64Var(&round, "round", 0, "round for which checkpoints will be created")
	cmd.Flags().StringVar(&outDir, "output-dir", "", "output directory")

	return cmd
}

func newImportCmd() *cobra.Command {
	var inputDir string

	cmd := &cobra.Command{
		Use:   "import",
		Args:  cobra.NoArgs,
		Short: "import storage checkpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			dataDir := cmdCommon.DataDir()

			// Consensus checkpoint:
			restoreConsensusCp := func(inputDir string) error {
				ndb, close, err := openConsensusNodeDB(dataDir)
				if err != nil {
					return fmt.Errorf("failed to open consensus state DB: %w", err)
				}
				defer close()

				return restoreCheckpoints(ctx, ndb, common.Namespace{}, inputDir)
			}
			consensusInputDir := filepath.Join(inputDir, consensusSubdir)
			_, err := os.ReadDir(consensusInputDir)
			switch {
			case err == nil:
				if err := restoreConsensusCp(consensusInputDir); err != nil {
					return fmt.Errorf("failed to restore consensus cp (input dir: %s): %w", consensusInputDir, err)
				}

				meta, err := readCometBFTBootstrapMeta(consensusInputDir)
				if err != nil {
					return fmt.Errorf("failed to read bootstrap metadata: %w", err)
				}
				if err := bootstrapTrustedState(dataDir, meta); err != nil {
					return fmt.Errorf("failed to bootstrap CometBFT trusted state: %w", err)
				}
			case os.IsNotExist(err):
				// No consensus checkpoints to restore
			default:
				return fmt.Errorf("failed to stat: %w", err)
			}

			// Runtime checkpoints:
			restoreRuntimeCp := func(inputDir string, ns common.Namespace) error {
				ndb, err := openRuntimeStateDB(dataDir, ns)
				if err != nil {
					return err
				}
				defer ndb.Close()

				return restoreCheckpoints(ctx, ndb, ns, inputDir)
			}
			runtimeInputDir := filepath.Join(inputDir, runtimesSubdir)
			entries, err := os.ReadDir(runtimeInputDir)
			switch {
			case err == nil:
				for _, entry := range entries {
					var ns common.Namespace
					if err := ns.UnmarshalHex(entry.Name()); err != nil {
						return fmt.Errorf("malformed source runtime ID: %q: %w", entry.Name(), err)
					}
					rtCpsDir := filepath.Join(runtimeInputDir, entry.Name())

					if err := restoreRuntimeCp(rtCpsDir, ns); err != nil {
						return fmt.Errorf("failed to import checkpoints (checkpoint dir: %s): %w", rtCpsDir, err)
					}
				}
			case os.IsNotExist(err):
				// No runtime checkpoints to restore
			default:
				return fmt.Errorf("failed to stat: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&inputDir, "input-dir", "", "directory with checkpoints to import")

	return cmd
}

func createCheckpoints(ctx context.Context, ndb api.NodeDB, ns common.Namespace, version uint64, outputDir string) error {
	if err := ensureEmptyDir(outputDir); err != nil {
		return err
	}

	latest, ok := ndb.GetLatestVersion()
	if !ok {
		return fmt.Errorf("empty state DB")
	}
	earliest := ndb.GetEarliestVersion()
	if version < earliest || version > latest {
		return fmt.Errorf("version not finalized (finalized range: %d-%d)", earliest, latest)
	}

	roots, err := ndb.GetRootsForVersion(version)
	if err != nil {
		return fmt.Errorf("failed to get finalized roots %w", err)
	}
	if len(roots) == 0 {
		// Empty roots are implicit in NodeDB and therefore not returned by GetRootsForVersion.
		// If at this height state DB has an empty state, create a checkpoint for the empty state root,
		// so that importing it will still finalize this version (making NodeDB non-empty).
		//
		// In case of state DB with with multiple empty roots (e.g. state and IO root both empty)
		// this will create only one empty checkpoint (duplicate hash), which is safe as we only need
		// it to finalize version with implicitly empty state and IO root.
		stateRoot := node.Root{
			Namespace: ns,
			Version:   version,
			Type:      node.RootTypeState,
		}
		stateRoot.Hash.Empty()
		roots = []node.Root{stateRoot}
	}

	creator, err := checkpoint.NewFileCreator(outputDir, ndb)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint file creator: %w", err)
	}

	for _, root := range roots {
		_, err := creator.CreateCheckpoint(ctx, root, 8*1024*1024, 8) // 8MiB chunks
		if err != nil {
			return fmt.Errorf("failed to create checkpoint (rootType: %s): %w", root.Type, err)
		}
	}

	return nil
}

func restoreCheckpoints(ctx context.Context, ndb api.NodeDB, ns common.Namespace, inputDir string) error {
	isEmpty, err := isEmptyDir(inputDir)
	if err != nil {
		return fmt.Errorf("aborting checkpoint restoration: failed to inspect input directory: %w", err)
	}
	if isEmpty {
		return fmt.Errorf("aborting checkpoint restoration: input directory is empty: %s", inputDir)
	}
	if _, ok := ndb.GetLatestVersion(); ok {
		return fmt.Errorf("aborting checkpoint restoration: state db not empty")
	}

	provider, err := checkpoint.NewFileCreator(inputDir, nil) // ndb = nil since we will only restore checkpoints.
	if err != nil {
		return fmt.Errorf("failed to create checkpoint file creator: %w", err)
	}
	cps, err := provider.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1, Namespace: ns})
	if err != nil {
		return fmt.Errorf("failed to read checkpoints: %w", err)
	}

	var roots []node.Root
	for _, cp := range cps {
		if err := importCp(ctx, ndb, provider, cp); err != nil {
			return fmt.Errorf("failed to import checkpoint (root hash: %s): %w", cp.Root.Hash, err)
		}
		roots = append(roots, cp.Root)
	}
	if err := ndb.Finalize(roots); err != nil {
		return fmt.Errorf("failed to finalize: %w", err)
	}

	return nil
}

func importCp(ctx context.Context, ndb api.NodeDB, provider checkpoint.Creator, cp *checkpoint.Metadata) error {
	if err := ndb.StartMultipartInsert(cp.Root.Version); err != nil {
		return fmt.Errorf("failed to start multipart insert: %w", err)
	}
	defer func() {
		if err := ndb.AbortMultipartInsert(); err != nil {
			logger.Error("failed to abort multi-part insert", "err", err)
		}
	}()

	for idx := range cp.Chunks {
		chunk, err := cp.GetChunkMetadata(uint64(idx))
		if err != nil {
			return fmt.Errorf("failed to get chunk metadata: %w", err)
		}
		var buf bytes.Buffer
		if err := provider.GetCheckpointChunk(ctx, chunk, &buf); err != nil {
			return fmt.Errorf("failed to read checkpoint chunk (idx: %d): %w", idx, err)
		}
		if err := checkpoint.RestoreChunk(ctx, ndb, chunk, &buf); err != nil {
			return fmt.Errorf("failed to restore chunk: %w", err)
		}
	}
	return nil
}

func createCometBFTBootstrapMeta(ctx context.Context, dataDir string, height uint64, outputDir string) error {
	stateStore, err := openConsensusStatestore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open cometbft state store: %w", err)
	}
	defer stateStore.Close()

	blockStore, err := openConsensusBlockstore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open consensus blockstore: %w", err)
	}
	defer blockStore.Close()

	state, err := state(height, stateStore, blockStore)
	if err != nil {
		return fmt.Errorf("failed to load consensus state at height %d: %w", height, err)
	}
	statePB, err := state.ToProto()
	if err != nil {
		return fmt.Errorf("failed to convert consensus state to proto: %w", err)
	}
	stateBytes, err := proto.Marshal(statePB)
	if err != nil {
		return fmt.Errorf("failed to marshal consensus state: %w", err)
	}

	commit, err := commit(blockStore, height)
	if err != nil {
		return fmt.Errorf("failed to load consensus commit at height %d: %w", height, err)
	}
	commitBytes, err := proto.Marshal(commit.ToProto())
	if err != nil {
		return fmt.Errorf("failed to marshal consensus commit: %w", err)
	}

	meta := bootstrapMeta{
		State:  stateBytes,
		Commit: commitBytes,
	}
	if err := os.WriteFile(filepath.Join(outputDir, consensusMetaFilename), cbor.Marshal(meta), 0o600); err != nil {
		return fmt.Errorf("failed to write bootstrap metadata: %w", err)
	}

	return nil
}

func readCometBFTBootstrapMeta(inputDir string) (bootstrapMeta, error) {
	data, err := os.ReadFile(filepath.Join(inputDir, consensusMetaFilename))
	if err != nil {
		return bootstrapMeta{}, err
	}

	var meta bootstrapMeta
	if err := cbor.Unmarshal(data, &meta); err != nil {
		return bootstrapMeta{}, fmt.Errorf("failed to decode bootstrap metadata: %w", err)
	}

	return meta, nil
}

// bootstrapTrustedState synchronizes the cometbft databases after the state sync
// has been performed offline.
//
// It is expected that the block store and state store are empty at the time the
// function is called.
//
// Adapted from https://github.com/oasisprotocol/cometbft/blob/08e22df73d354512fc27bd0c5731b3dcf1f8fef7/node/node.go#L198.
func bootstrapTrustedState(dataDir string, meta bootstrapMeta) error {
	stateDB, err := openConsensusStateDB(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open cometbft state store: %w", err)
	}
	defer stateDB.Close()

	blockStore, err := openConsensusBlockstore(dataDir)
	if err != nil {
		return fmt.Errorf("failed to open consensus blockstore: %w", err)
	}
	defer blockStore.Close()

	if !blockStore.IsEmpty() {
		return fmt.Errorf("blockstore not empty, trying to initialize non empty state")
	}

	stateStore := cmtState.NewBootstrapStore(stateDB, cmtState.StoreOptions{
		DiscardABCIResponses: cmtCfg.DefaultConfig().Storage.DiscardABCIResponses,
	})
	defer stateStore.Close()

	state, err := stateStore.Load()
	if err != nil {
		return err
	}

	if !state.IsEmpty() {
		return fmt.Errorf("state not empty, trying to initialize non empty state")
	}

	var statePB cmtProtoState.State
	if err := proto.Unmarshal(meta.State, &statePB); err != nil {
		return fmt.Errorf("failed to unmarshal consensus state: %w", err)
	}
	metaState, err := cmtState.FromProto(&statePB)
	if err != nil {
		return fmt.Errorf("failed to parse consensus state: %w", err)
	}

	var commitPB cmtProto.Commit
	if err := proto.Unmarshal(meta.Commit, &commitPB); err != nil {
		return fmt.Errorf("failed to unmarshal consensus commit: %w", err)
	}
	commit, err := cmttypes.CommitFromProto(&commitPB)
	if err != nil {
		return fmt.Errorf("failed to parse consensus commit: %w", err)
	}

	if err = stateStore.Bootstrap(*metaState); err != nil {
		return err
	}

	err = blockStore.SaveSeenCommit(metaState.LastBlockHeight, commit)
	if err != nil {
		return err
	}

	// Once the stores are bootstrapped, we need to set the height at which the node has finished
	// statesyncing. This will allow the blocksync reactor to fetch blocks at a proper height.
	// In case this operation fails, it is equivalent to a failure in online state sync where the operator
	// needs to manually delete the state and blockstores and rerun the bootstrapping process.
	err = stateStore.SetOfflineStateSyncHeight(metaState.LastBlockHeight)
	if err != nil {
		return fmt.Errorf("failed to set synced height: %w", err)
	}

	return nil
}

// commit is adapted and simplified and mimics StateProvider behaviour used in the upstream BootstrapState.
func commit(blockStore *store.BlockStore, height uint64) (*cmttypes.Commit, error) {
	commit := blockStore.LoadBlockCommit(int64(height))
	if commit == nil {
		return nil, fmt.Errorf("commit not found at height %d", height)
	}
	return commit, nil
}

// state is adapted and mimics StateProvider behaviour used in the upstream BootstrapState.
func state(height uint64, stateStore cmtState.Store, blockStore *store.BlockStore) (cmtState.State, error) {
	// The snapshot height maps onto the state heights as follows:
	//
	// height: last block, i.e. the snapshotted height
	// height+1: current block, i.e. the first block we'll process after the snapshot
	// height+2: next block, i.e. the second block after the snapshot
	//
	// We need to fetch the NextValidators from height+2 because if the application changed
	// the validator set at the snapshot height then this only takes effect at height+2.
	h := int64(height)
	lastMeta := blockStore.LoadBlockMeta(h)
	if lastMeta == nil {
		return cmtState.State{}, fmt.Errorf("block meta not found at height %d", h)
	}
	currentMeta := blockStore.LoadBlockMeta(h + 1)
	if currentMeta == nil {
		return cmtState.State{}, fmt.Errorf("block meta not found at height %d", h+1)
	}
	nextMeta := blockStore.LoadBlockMeta(h + 2)
	if nextMeta == nil {
		return cmtState.State{}, fmt.Errorf("block meta not found at height %d", h+2)
	}

	lastVals, err := stateStore.LoadValidators(h)
	if err != nil {
		return cmtState.State{}, err
	}
	currentVals, err := stateStore.LoadValidators(h + 1)
	if err != nil {
		return cmtState.State{}, err
	}
	nextVals, err := stateStore.LoadValidators(h + 2)
	if err != nil {
		return cmtState.State{}, err
	}

	consensusParams, err := stateStore.LoadConsensusParams(h + 1)
	if err != nil {
		return cmtState.State{}, err
	}

	storeState, err := stateStore.Load()
	if err != nil {
		return cmtState.State{}, err
	}
	if storeState.IsEmpty() {
		return cmtState.State{}, fmt.Errorf("state store is empty")
	}

	state := cmtState.State{
		ChainID: storeState.ChainID,
		Version: cmtProtoState.Version{
			Consensus: currentMeta.Header.Version,
			Software:  version.TMCoreSemVer,
		},
		InitialHeight: storeState.InitialHeight,
	}
	if state.InitialHeight == 0 {
		state.InitialHeight = 1
	}

	state.LastBlockHeight = lastMeta.Header.Height
	state.LastBlockTime = lastMeta.Header.Time
	state.LastBlockID = lastMeta.BlockID
	state.AppHash = currentMeta.Header.AppHash
	state.LastResultsHash = currentMeta.Header.LastResultsHash
	state.LastValidators = lastVals
	state.Validators = currentVals
	state.NextValidators = nextVals
	state.LastHeightValidatorsChanged = nextMeta.Header.Height
	state.ConsensusParams = consensusParams
	state.LastHeightConsensusParamsChanged = currentMeta.Header.Height

	return state, nil
}

func isEmptyDir(dir string) (bool, error) {
	// Over-engineering?
	f, err := os.Open(dir)
	if err != nil {
		return false, fmt.Errorf("failed to open directory %q: %w", dir, err)
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if errors.Is(err, io.EOF) {
		return true, nil // empty
	}
	if err == nil {
		return false, nil
	}
	return false, fmt.Errorf("failed to read directory %q: %w", dir, err)
}

func ensureEmptyDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	isEmpty, err := isEmptyDir(dir)
	if err != nil {
		return err
	}
	if !isEmpty {
		return fmt.Errorf("output directory is not empty: %s", dir)
	}

	return nil
}
