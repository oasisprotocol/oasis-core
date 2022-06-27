package db

import (
	"sync"

	dbm "github.com/tendermint/tm-db"
)

// Closer manages closing of multiple Tendermint Core databases.
type Closer struct {
	l   sync.Mutex
	dbs []dbm.DB
}

// Close closes all the managed databases.
func (c *Closer) Close() {
	c.l.Lock()
	defer c.l.Unlock()

	for _, db := range c.dbs {
		_ = db.Close()
	}
}

// NewCloser creates a new empty database closer.
func NewCloser() *Closer {
	return &Closer{}
}

type dbWithCloser struct {
	dbm.DB
}

func (d *dbWithCloser) Close() error {
	// Do nothing unless explicitly closed via the closer.
	return nil
}

// WithCloser wraps a Tendermint Core database instance so that it can only be closed by the given
// closer instance. Direct attempts to close the returned database instance will be ignored.
func WithCloser(db dbm.DB, closer *Closer) dbm.DB {
	closer.l.Lock()
	defer closer.l.Unlock()

	closer.dbs = append(closer.dbs, db)

	return &dbWithCloser{db}
}
