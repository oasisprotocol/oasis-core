// Package inspector contains utility functions for inspecting Tendermint state.
package inspector

import (
	"github.com/tendermint/iavl"
	dbm "github.com/tendermint/tm-db"

	"github.com/oasislabs/ekiden/go/tendermint/db"
)

// MuxState is an open ABCI mux state database.
type MuxState struct {
	db   dbm.DB
	tree *iavl.ImmutableTree
}

// Close closes the underlying database
func (s *MuxState) Close() {
	s.db.Close()
}

// Tree returns the immutable tree representing ABCI mux state.
func (s *MuxState) Tree() *iavl.ImmutableTree {
	return s.tree
}

// OpenMuxState opens the ABCI mux state for inspection.
func OpenMuxState(filename string) (*MuxState, error) {
	db, err := db.New(filename, true)
	if err != nil {
		return nil, err
	}

	tree := iavl.NewMutableTree(db, 128)
	_, err = tree.Load()
	if err != nil {
		db.Close()
		return nil, err
	}

	return &MuxState{db: db, tree: tree.ImmutableTree}, nil
}
