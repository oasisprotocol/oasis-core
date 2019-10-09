package api

import dbm "github.com/tendermint/tm-db"

// SizeableDB is a tendermint database abstraction DB that supports
// reporting it's database size for metrics purposes.
type SizeableDB interface {
	dbm.DB

	// Size returns the database size.
	Size() (int64, error)
}
