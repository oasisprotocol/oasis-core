package api

import (
	"time"

	"github.com/cometbft/cometbft/abci/types"
)

// BlockInfo contains information about a block which is always present in block context.
type BlockInfo struct {
	Time                 time.Time
	ProposerAddress      []byte
	LastCommitInfo       types.CommitInfo
	ValidatorMisbehavior []types.Misbehavior

	GasAccountant GasAccountant
}

// BlockContextKey is an interface for a block context key.
type BlockContextKey interface {
	// NewDefault returns a new default value for the given key.
	NewDefault() interface{}
}

// BlockContext can be used to store arbitrary key/value pairs for state that
// is needed while processing a block.
//
// When a block is committed, this context is automatically reset.
type BlockContext struct {
	BlockInfo

	storage map[BlockContextKey]interface{}
}

// Get returns the value stored under the given key (if any). If no value
// currently exists, the NewDefault method is called on the key to produce a
// default value and that value is stored.
func (bc *BlockContext) Get(key BlockContextKey) interface{} {
	v, ok := bc.storage[key]
	if !ok {
		v = key.NewDefault()
		bc.storage[key] = v
	}
	return v
}

// Set overwrites the value stored under the given key.
func (bc *BlockContext) Set(key BlockContextKey, value interface{}) {
	bc.storage[key] = value
}

// NewBlockContext creates a new block context.
func NewBlockContext(blockInfo BlockInfo) *BlockContext {
	return &BlockContext{
		BlockInfo: blockInfo,
		storage:   make(map[BlockContextKey]interface{}),
	}
}
