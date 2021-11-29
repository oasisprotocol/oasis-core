// Package api defines the transaction pool interfaces.
package api

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
)

var (
	ErrCallAlreadyExists = fmt.Errorf("call already exists in pool")
	ErrFull              = fmt.Errorf("pool is full")
	ErrCallTooLarge      = p2pError.Permanent(fmt.Errorf("call too large"))
)

// Config is a transaction pool configuration.
type Config struct {
	MaxPoolSize uint64

	WeightLimits map[transaction.Weight]uint64
}

// TxPool is the transaction pool interface.
type TxPool interface {
	// Name is the transaction pool implementation name.
	Name() string

	// Add adds a single transaction into the transaction pool.
	Add(tx *transaction.CheckedTransaction) error

	// GetBatch gets a transaction batch from the transaction pool.
	GetBatch(force bool) []*transaction.CheckedTransaction

	// GetKnownBatch gets a set of known transactions from the transaction pool.
	//
	// For any missing transactions nil will be returned in their place and the map of missing
	// transactions will be populated accoordingly.
	GetKnownBatch(batch []hash.Hash) ([]*transaction.CheckedTransaction, map[hash.Hash]int)

	// RemoveBatch removes a batch from the transaction pool.
	RemoveBatch(batch []hash.Hash) error

	// IsQueued returns whether a transaction is in the queue already.
	IsQueued(txHash hash.Hash) bool

	// Size returns the number of transactions in the transaction pool.
	Size() uint64

	// UpdateConfig updates the transaction pool config.
	UpdateConfig(Config) error

	// Clear clears the transaction pool.
	Clear()
}
