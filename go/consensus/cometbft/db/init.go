// Package db implements several CometBFT DB backends.
package db

import (
	"fmt"

	dbm "github.com/cometbft/cometbft-db"
	cmtconfig "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/node"
	cmtnode "github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/state"

	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db/badger"
)

// BackendName returns the currently configured CometBFT database backend.
func BackendName() string {
	return badger.BackendName
}

// Provider returns the currently configured CometBFT DBProvider.
func Provider() (node.DBProvider, error) {
	return badger.DBProvider, nil
}

// New constructs a new CometBFT DB with the configured backend.
func New(fn string, noSuffix bool) (dbm.DB, error) {
	return badger.New(fn, noSuffix)
}

// OpenBlockstoreDB opens a CometBFT managed blockstore DB.
//
// This function is a hack as CometBFT does not expose a way to access the underlying databases.
func OpenBlockstoreDB(provider cmtnode.DBProvider, cfg *cmtconfig.Config) (dbm.DB, error) {
	// NOTE: DBContext uses a full CometBFT config but the only thing that is actually used
	// is the data dir field.
	db, err := provider(&cmtnode.DBContext{ID: "blockstore", Config: cfg})
	if err != nil {
		return nil, fmt.Errorf("failed to open blockstore: %w", err)
	}

	return db, nil
}

// OpenStateDB opens a CometBFT managed state DB.
//
// This function is a hack as CometBFT does not expose a way to access the underlying databases.
func OpenStateDB(provider cmtnode.DBProvider, cfg *cmtconfig.Config) (dbm.DB, error) {
	// NOTE: DBContext uses a full CometBFT config but the only thing that is actually used
	// is the data dir field.
	db, err := provider(&cmtnode.DBContext{ID: "state", Config: cfg})
	if err != nil {
		return nil, fmt.Errorf("failed to open state db: %w", err)
	}

	return db, nil
}

// OpenStateStore constructs a new state store using default options.
func OpenStateStore(stateDB dbm.DB) state.Store {
	return state.NewStore(stateDB, state.StoreOptions{})
}
