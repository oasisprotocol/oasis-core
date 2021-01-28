package host

import (
	"context"
	"errors"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

var (
	// ErrInvalidArgument is the error returned when any of the passed method arguments is invalid.
	ErrInvalidArgument = errors.New("runtime: invalid argument")
	// ErrCheckTxFailed is the error returned when a transaction is rejected by the runtime.
	ErrCheckTxFailed = errors.New("runtime: check tx failed")
	// ErrInternal is the error returned when an unspecified internal error occurs.
	ErrInternal = errors.New("runtime: internal error")
)

// RichRuntime provides higher-level functions for talking with a runtime.
type RichRuntime interface {
	Runtime

	// CheckTx requests the runtime to check a given transaction.
	CheckTx(ctx context.Context, rb *block.Block, lb *consensus.LightBlock, tx []byte) error

	// Query requests the runtime to answer a runtime-specific query.
	Query(ctx context.Context, rb *block.Block, method string, args cbor.RawMessage) (cbor.RawMessage, error)
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

// Implements RichRuntime.
func (r *richRuntime) Query(ctx context.Context, rb *block.Block, method string, args cbor.RawMessage) (cbor.RawMessage, error) {
	if rb == nil {
		return nil, ErrInvalidArgument
	}

	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeQueryRequest: &protocol.RuntimeQueryRequest{
			Method: method,
			Header: rb.Header,
			Args:   args,
		},
	})
	switch {
	case err != nil:
		return nil, err
	case resp.RuntimeQueryResponse == nil:
		return nil, fmt.Errorf("%w: malformed runtime response", ErrInternal)
	}
	return resp.RuntimeQueryResponse.Data, nil
}

// NewRichRuntime creates a new higher-level wrapper for a given runtime. It provides additional
// convenience functions for talking with a runtime.
func NewRichRuntime(rt Runtime) RichRuntime {
	return &richRuntime{Runtime: rt}
}
