package abci

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
)

// maxSubcallDepth is the maximum subcall depth.
const maxSubcallDepth = 8

// ExecuteMessage implements api.MessageSubscriber.
func (mux *abciMux) ExecuteMessage(ctx *api.Context, kind, msg interface{}) (interface{}, error) {
	switch kind {
	case api.MessageExecuteSubcall:
		// Subcall execution request.
		info, ok := msg.(*api.SubcallInfo)
		if !ok {
			return nil, fmt.Errorf("invalid subcall info")
		}
		return struct{}{}, mux.executeSubcall(ctx, info)
	default:
		return nil, nil
	}
}

// executeSubcall executes a subcall.
func (mux *abciMux) executeSubcall(ctx *api.Context, info *api.SubcallInfo) error {
	if ctx.CallDepth() > maxSubcallDepth {
		return fmt.Errorf("call depth exceeded")
	}

	ctx = ctx.WithCallerAddress(info.Caller)
	defer ctx.Close()
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	// Lookup method handler.
	app, err := mux.resolveAppForMethod(ctx, info.Method)
	if err != nil {
		return err
	}

	tx := &transaction.Transaction{
		Method: info.Method,
		Body:   info.Body,
	}
	if err = app.ExecuteTx(ctx, tx); err != nil {
		return err
	}

	ctx.Commit()

	return nil
}
