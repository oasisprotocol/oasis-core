package api

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
