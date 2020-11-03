// Package api defines the transaction pool interfaces.
package api

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
)

var (
	ErrCallAlreadyExists = fmt.Errorf("call already exists in pool")
	ErrFull              = fmt.Errorf("pool is full")
	ErrCallTooLarge      = p2pError.Permanent(fmt.Errorf("call too large"))
)

// Config is a transaction pool configuration.
type Config struct {
	MaxPoolSize       uint64
	MaxBatchSize      uint64
	MaxBatchSizeBytes uint64
}

// TxPool is the transaction pool interface.
type TxPool interface {
	// Name is the transaction pool implementation name.
	Name() string

	// Add adds a single transaction into the transaction pool.
	Add(tx []byte) error

	// AddBatch adds a transaction batch into the transaction pool.
	AddBatch(batch [][]byte) error

	// GetBatch gets a transaction batch from the transaction pool.
	GetBatch(force bool) [][]byte

	// RemoveBatch removes a batch from the transaction pool.
	RemoveBatch(batch [][]byte) error

	// IsQueued returns whether a transaction is in the queue already.
	IsQueued(txHash hash.Hash) bool

	// Size returns the number of transactions in the transaction pool.
	Size() uint64

	// UpdateConfig updates the transaction pool config.
	UpdateConfig(Config) error

	// IsQueue returns true if pool maintains FIFO order of transactions.
	IsQueue() bool

	// Clear clears the transaction pool.
	Clear()
}
