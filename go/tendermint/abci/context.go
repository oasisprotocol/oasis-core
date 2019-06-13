package abci

import (
	"sort"
	"time"

	tmcmn "github.com/tendermint/tendermint/libs/common"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

// ContextType is a context type.
type ContextType uint

const (
	// ContextInitChain is InitChain context.
	ContextInitChain ContextType = iota
	// ContextCheckTx is CheckTx context.
	ContextCheckTx
	// ContextDeliverTx is DeliverTx context.
	ContextDeliverTx
	// ContextBeginBlock is BeginBlock context.
	ContextBeginBlock
	// ContextEndBlock is EndBlock context.
	ContextEndBlock
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

	timerLogger *logging.Logger
}

// NewContext creates a new Context of the given type.
func NewContext(outputType ContextType, now time.Time) *Context {
	return &Context{
		outputType:    outputType,
		currentTime:   now,
		onCommitHooks: make(map[string]OnCommitHook),
		timerLogger:   logging.GetLogger("tendermint/context/timer"),
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

// IsInitChain returns true if this output is part of a InitChain.
func (c *Context) IsInitChain() bool {
	return c.outputType == ContextInitChain
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
	c.tags = append(c.tags, tmcmn.KVPair{Key: key, Value: value})
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
	hookOrder := make([]string, 0, len(c.onCommitHooks))
	for id := range c.onCommitHooks {
		hookOrder = append(hookOrder, id)
	}
	sort.Strings(hookOrder)

	for _, id := range hookOrder {
		c.onCommitHooks[id](state)
	}
}
