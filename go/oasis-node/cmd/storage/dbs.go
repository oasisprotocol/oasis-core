package storage

import (
	"fmt"
	"path/filepath"

	cometbftDB "github.com/cometbft/cometbft-db"
	cmtCfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci"
	cmtCommon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	cmtDB "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage"
)

func openConsensusNodeDB(dataDir string) (api.NodeDB, func(), error) {
	ldb, ndb, _, err := abci.InitStateStorage(
		&abci.ApplicationConfig{
			DataDir:             filepath.Join(dataDir, cmtCommon.StateDir),
			StorageBackend:      config.GlobalConfig.Storage.Backend,
			MemoryOnlyStorage:   false,
			ReadOnlyStorage:     false,
			DisableCheckpointer: true,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize ABCI storage backend: %w", err)
	}

	// Close and Cleanup both only close NodeDB. Still closing both explicitly,
	// to prevent resource leaks if things change in the future.
	close := func() {
		ndb.Close()
		ldb.Cleanup()
	}

	return ndb, close, nil
}

func openConsensusBlockstore(dataDir string) (*store.BlockStore, error) {
	cmtConfig := cmtCfg.DefaultConfig()
	cmtConfig.SetRoot(filepath.Join(dataDir, cmtCommon.StateDir))

	dbProvider, err := cmtDB.Provider()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain db provider: %w", err)
	}

	blockstoreDB, err := cmtDB.OpenBlockstoreDB(dbProvider, cmtConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to open blockstore: %w", err)
	}
	blockstore := store.NewBlockStore(blockstoreDB)

	return blockstore, nil
}

func openConsensusStateDB(dataDir string) (cometbftDB.DB, error) {
	cmtConfig := cmtCfg.DefaultConfig()
	cmtConfig.SetRoot(filepath.Join(dataDir, cmtCommon.StateDir))

	dbProvider, err := cmtDB.Provider()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain db provider: %w", err)
	}
	return cmtDB.OpenStateDB(dbProvider, cmtConfig)
}

func openConsensusStatestore(dataDir string) (state.Store, error) {
	stateDB, err := openConsensusStateDB(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open state db: %w", err)
	}
	return cmtDB.OpenStateStore(stateDB), nil
}

func openRuntimeStateDB(dataDir string, runtimeID common.Namespace) (api.NodeDB, error) {
	rtDir := runtimeConfig.GetRuntimeStateDir(dataDir, runtimeID)
	backend, err := storage.NewLocalBackend(rtDir, runtimeID)
	if err != nil {
		return nil, fmt.Errorf("failed to open storage backend (runtimeID: %s): %w", runtimeID, err)
	}
	return backend.NodeDB(), err
}

func openRuntimeLightHistory(dataDir string, rt common.Namespace) (history.History, error) {
	rtDir := runtimeConfig.GetRuntimeStateDir(dataDir, rt)
	history, err := history.New(rt, rtDir, history.NewNonePrunerFactory(), true)
	if err != nil {
		return nil, fmt.Errorf("failed to open new light history: %w", err)
	}
	return history, nil
}
