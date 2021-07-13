package host

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

var (
	// ErrInvalidArgument is the error returned when any of the passed method arguments is invalid.
	ErrInvalidArgument = fmt.Errorf("runtime: invalid argument")
	// ErrCheckTxFailed is the error returned when a transaction is rejected by the runtime.
	ErrCheckTxFailed = fmt.Errorf("runtime: check tx failed")
	// ErrInternal is the error returned when an unspecified internal error occurs.
	ErrInternal = fmt.Errorf("runtime: internal error")
)

// RichRuntime provides higher-level functions for talking with a runtime.
type RichRuntime interface {
	Runtime

	// CheckTx requests the runtime to check a given transaction.
	CheckTx(
		ctx context.Context,
		rb *block.Block,
		lb *consensus.LightBlock,
		epoch beacon.EpochTime,
		batch transaction.RawBatch,
	) ([]protocol.CheckTxResult, error)

	// Query requests the runtime to answer a runtime-specific query.
	Query(
		ctx context.Context,
		rb *block.Block,
		lb *consensus.LightBlock,
		epoch beacon.EpochTime,
		method string,
		args cbor.RawMessage,
	) (cbor.RawMessage, error)

	// QueryBatchLimits requests the runtime to answer the batch limits query.
	QueryBatchLimits(
		ctx context.Context,
		rb *block.Block,
		lb *consensus.LightBlock,
		epoch beacon.EpochTime,
	) (map[transaction.Weight]uint64, error)
}

type richRuntime struct {
	Runtime
}

// Implements RichRuntime.
func (r *richRuntime) CheckTx(
	ctx context.Context,
	rb *block.Block,
	lb *consensus.LightBlock,
	epoch beacon.EpochTime,
	batch transaction.RawBatch,
) ([]protocol.CheckTxResult, error) {
	if rb == nil || lb == nil {
		return nil, ErrInvalidArgument
	}

	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeCheckTxBatchRequest: &protocol.RuntimeCheckTxBatchRequest{
			ConsensusBlock: *lb,
			Inputs:         batch,
			Block:          *rb,
			Epoch:          epoch,
		},
	})
	switch {
	case err != nil:
		return nil, errors.WithContext(ErrInternal, err.Error())
	case resp.RuntimeCheckTxBatchResponse == nil:
		return nil, errors.WithContext(ErrInternal, "malformed runtime response")
	case len(resp.RuntimeCheckTxBatchResponse.Results) != len(batch):
		return nil, errors.WithContext(ErrInternal, "malformed runtime response: incorrect number of results")
	}
	return resp.RuntimeCheckTxBatchResponse.Results, nil
}

// Implements RichRuntime.
func (r *richRuntime) Query(
	ctx context.Context,
	rb *block.Block,
	lb *consensus.LightBlock,
	epoch beacon.EpochTime,
	method string,
	args cbor.RawMessage,
) (cbor.RawMessage, error) {
	if rb == nil {
		return nil, ErrInvalidArgument
	}

	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeQueryRequest: &protocol.RuntimeQueryRequest{
			ConsensusBlock: *lb,
			Header:         rb.Header,
			Epoch:          epoch,
			Method:         method,
			Args:           args,
		},
	})
	switch {
	case err != nil:
		return nil, err
	case resp.RuntimeQueryResponse == nil:
		return nil, errors.WithContext(ErrInternal, "malformed runtime response")
	}
	return resp.RuntimeQueryResponse.Data, nil
}

// Implements RichRuntime.
func (r *richRuntime) QueryBatchLimits(
	ctx context.Context,
	rb *block.Block,
	lb *consensus.LightBlock,
	epoch beacon.EpochTime,
) (map[transaction.Weight]uint64, error) {
	resp, err := r.Query(ctx, rb, lb, epoch, protocol.MethodQueryBatchWeightLimits, nil)
	if err != nil {
		return nil, err
	}

	var weightLimits map[transaction.Weight]uint64
	if err = cbor.Unmarshal(resp, &weightLimits); err != nil {
		return nil, errors.WithContext(ErrInternal, fmt.Sprintf("malformed runtime response: %v", err))
	}
	return weightLimits, nil
}

// NewRichRuntime creates a new higher-level wrapper for a given runtime. It provides additional
// convenience functions for talking with a runtime.
func NewRichRuntime(rt Runtime) RichRuntime {
	return &richRuntime{Runtime: rt}
}
