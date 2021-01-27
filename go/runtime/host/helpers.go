package host

import (
	"context"
	"errors"
	"fmt"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

var (
	ErrInvalidArgument = errors.New("runtime: invalid argument")
	ErrInternal        = errors.New("runtime: internal error")
	ErrCheckTxFailed   = errors.New("runtime: check tx failed")
)

// RichRuntime provides higher-level functions for talking with a runtime.
type RichRuntime interface {
	Runtime

	// CheckTx requests the runtime to check a given transaction.
	CheckTx(ctx context.Context, rb *block.Block, lb *consensus.LightBlock, tx []byte) error
}

type richRuntime struct {
	Runtime
}

// Implements RichRuntime.
func (r *richRuntime) CheckTx(ctx context.Context, rb *block.Block, lb *consensus.LightBlock, tx []byte) error {
	if rb == nil || lb == nil {
		return ErrInvalidArgument
	}

	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeCheckTxBatchRequest: &protocol.RuntimeCheckTxBatchRequest{
			ConsensusBlock: *lb,
			Inputs:         transaction.RawBatch{tx},
			Block:          *rb,
		},
	})
	switch {
	case err != nil:
		return fmt.Errorf("%w: %s", ErrInternal, err)
	case resp.RuntimeCheckTxBatchResponse == nil:
		return fmt.Errorf("%w: malformed runtime response", ErrInternal)
	case len(resp.RuntimeCheckTxBatchResponse.Results) != 1:
		return fmt.Errorf("%w: malformed runtime response: incorrect number of results", ErrInternal)
	}

	// Interpret CheckTx result.
	result := resp.RuntimeCheckTxBatchResponse.Results[0]
	if !result.IsSuccess() {
		return fmt.Errorf("%w: %s", ErrCheckTxFailed, result.Error)
	}

	return nil
}

// NewRichRuntime creates a new higher-level wrapper for a given runtime. It provides additional
// convenience functions for talking with a runtime.
func NewRichRuntime(rt Runtime) RichRuntime {
	return &richRuntime{Runtime: rt}
}
