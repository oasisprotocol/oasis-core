package abci

import (
	"time"

	tmcmn "github.com/tendermint/tendermint/libs/common"

	"github.com/oasislabs/ekiden/go/tendermint/api"
)

// ContextType is a context type.
type ContextType uint

const (
	// ContextCheckTx is CheckTx context.
	ContextCheckTx ContextType = iota
	// ContextDeliverTx is DeliverTx context.
	ContextDeliverTx
	// ContextBeginBlock is BeginBlock context.
	ContextBeginBlock
)

// OnCommitHook is a function used as a on commit hook.
type OnCommitHook func(*ApplicationState)

// Context is the context of processing a transaction/block.
type Context struct {
	outputType  ContextType
	data        interface{}
	tags        []tmcmn.KVPair
	currentTime time.Time

	onCommitHooks map[string]OnCommitHook
}

// NewContext creates a new Context of the given type.
func NewContext(outputType ContextType, now int64) *Context {
	return &Context{
		outputType:    outputType,
		currentTime:   time.Unix(now, 0),
		onCommitHooks: make(map[string]OnCommitHook),
	}
}

// Type returns the type of this output.
func (c *Context) Type() ContextType {
	return c.outputType
}

// Data returns the data to be serialized with this output.
func (c *Context) Data() interface{} {
	return c.data
}

// Tags returns the tags to be passed with this output.
func (c *Context) Tags() []tmcmn.KVPair {
	return c.tags
}

// IsCheckOnly returns true if this output is part of a CheckTx.
func (c *Context) IsCheckOnly() bool {
	return c.outputType == ContextCheckTx
}

// EmitData emits data to be serialized as transaction output.
func (c *Context) EmitData(data interface{}) {
	c.data = data
}

// EmitTag emits a key-value tag for the current transaction/block.
func (c *Context) EmitTag(key []byte, value []byte) {
	c.tags = append(c.tags, tmcmn.KVPair{key, value})
}

// GetTag returns a specific tag's value if it exists.
func (c *Context) GetTag(key []byte) []byte {
	return api.GetTag(c.tags, key)
}

// Now returns the current tendermint time.
func (c *Context) Now() time.Time {
	return c.currentTime
}

// RegisterOnCommitHook registers a new on commit hook.
func (c *Context) RegisterOnCommitHook(id string, hook OnCommitHook) {
	c.onCommitHooks[id] = hook
}

func (c *Context) fireOnCommitHooks(state *ApplicationState) {
	for _, hook := range c.onCommitHooks {
		hook(state)
	}
}
