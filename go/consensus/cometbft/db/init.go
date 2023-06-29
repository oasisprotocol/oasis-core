// Package db implements several CometBFT DB backends.
package db

import (
	dbm "github.com/cometbft/cometbft-db"
	"github.com/cometbft/cometbft/node"

	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db/badger"
)

// GetBackendName returns the currently configured CometBFT database backend.
func GetBackendName() string {
	return badger.BackendName
}

// GetProvider returns the currently configured CometBFT DBProvider.
func GetProvider() (node.DBProvider, error) {
	return badger.DBProvider, nil
}

// New constructs a new CometBFT DB with the configured backend.
func New(fn string, noSuffix bool) (dbm.DB, error) {
	return badger.New(fn, noSuffix)
}
