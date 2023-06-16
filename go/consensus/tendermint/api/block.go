package api

import (
	"github.com/cometbft/cometbft/abci/types"
)

// blockProposerKey is the block context key for storing the block proposer address.
type blockProposerKey struct{}

// NewDefault returns a new default value for the given key.
func (bpk blockProposerKey) NewDefault() interface{} {
	// This should never be called as a block proposer must always be created by the application
	// multiplexer.
	panic("no proposer address in block context")
}

// SetBlockProposer sets the block proposer address.
func SetBlockProposer(ctx *Context, proposer []byte) {
	ctx.BlockContext().Set(blockProposerKey{}, proposer)
}

// GetBlockProposer returns the block proposer address.
func GetBlockProposer(ctx *Context) []byte {
	return ctx.BlockContext().Get(blockProposerKey{}).([]byte)
}

// lastCommitInfoKey is the block context key for storing the last commit info.
type lastCommitInfoKey struct{}

// NewDefault returns a new default value for the given key.
func (bpk lastCommitInfoKey) NewDefault() interface{} {
	// This should never be called as it must always be created by the application multiplexer.
	panic("no last commit info in block context")
}

// SetLastCommitInfo sets the last commit info.
func SetLastCommitInfo(ctx *Context, lastCommitInfo types.CommitInfo) {
	ctx.BlockContext().Set(lastCommitInfoKey{}, lastCommitInfo)
}

// GetLastCommitInfo returns the last commit info.
func GetLastCommitInfo(ctx *Context) types.CommitInfo {
	return ctx.BlockContext().Get(lastCommitInfoKey{}).(types.CommitInfo)
}

// validatorMisbehaviorKey is the block context key for storing the validator misbehavior info.
type validatorMisbehaviorKey struct{}

// NewDefault returns a new default value for the given key.
func (bpk validatorMisbehaviorKey) NewDefault() interface{} {
	// This should never be called as it must always be created by the application multiplexer.
	panic("no validator misbehavior info in block context")
}

// SetValidatorMisbehavior sets the validator misbehavior info.
func SetValidatorMisbehavior(ctx *Context, misbehavior []types.Misbehavior) {
	ctx.BlockContext().Set(validatorMisbehaviorKey{}, misbehavior)
}

// GetValidatorMisbehavior returns the validator misbehavior info.
func GetValidatorMisbehavior(ctx *Context) []types.Misbehavior {
	return ctx.BlockContext().Get(validatorMisbehaviorKey{}).([]types.Misbehavior)
}
