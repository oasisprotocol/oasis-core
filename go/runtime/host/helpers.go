package host

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
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
		maxMessages uint32,
		batch transaction.RawBatch,
	) ([]protocol.CheckTxResult, error)

	// Query requests the runtime to answer a runtime-specific query.
	Query(
		ctx context.Context,
		rb *block.Block,
		lb *consensus.LightBlock,
		epoch beacon.EpochTime,
		maxMessages uint32,
		method string,
		args []byte,
	) ([]byte, error)

	// LocalRPC requests the runtime to handle a local RPC call.
	LocalRPC(
		ctx context.Context,
		method string,
		args any,
		rsp any,
	) error

	// ConsensusSync requests the runtime to sync its light client up to the given consensus height.
	ConsensusSync(ctx context.Context, height uint64) error
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
	maxMessages uint32,
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
			MaxMessages:    maxMessages,
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
	maxMessages uint32,
	method string,
	args []byte,
) ([]byte, error) {
	if rb == nil {
		return nil, ErrInvalidArgument
	}

	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeQueryRequest: &protocol.RuntimeQueryRequest{
			ConsensusBlock: *lb,
			Header:         rb.Header,
			Epoch:          epoch,
			MaxMessages:    maxMessages,
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
func (r *richRuntime) LocalRPC(
	ctx context.Context,
	method string,
	args any,
	rsp any,
) error {
	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeLocalRPCCallRequest: &protocol.RuntimeLocalRPCCallRequest{
			Request: cbor.Marshal(&enclaverpc.Request{
				Method: method,
				Args:   args,
			}),
		},
	})
	switch {
	case err != nil:
		return err
	case resp.RuntimeLocalRPCCallResponse == nil:
		return errors.WithContext(ErrInternal, "malformed runtime response")
	default:
	}

	var msg enclaverpc.Message
	if err = cbor.Unmarshal(resp.RuntimeLocalRPCCallResponse.Response, &msg); err != nil {
		return fmt.Errorf("malformed message envelope: %w", err)
	}

	switch {
	case msg.Response == nil:
		return fmt.Errorf("message is not a response: '%+v'", msg)
	case msg.Response.Body.Success != nil:
	case msg.Response.Body.Error != nil:
		return fmt.Errorf("rpc failure: '%s'", *msg.Response.Body.Error)
	default:
		return fmt.Errorf("unknown rpc response status: '%+v'", msg)
	}

	if rsp != nil {
		if err = cbor.Unmarshal(msg.Response.Body.Success, rsp); err != nil {
			return fmt.Errorf("failed to extract rpc response payload: %w", err)
		}
	}

	return nil
}

// Implements RichRuntime.
func (r *richRuntime) ConsensusSync(ctx context.Context, height uint64) error {
	resp, err := r.Call(ctx, &protocol.Body{
		RuntimeConsensusSyncRequest: &protocol.RuntimeConsensusSyncRequest{
			Height: height,
		},
	})
	switch {
	case err != nil:
		return err
	case resp.RuntimeConsensusSyncResponse == nil:
		return errors.WithContext(ErrInternal, "malformed runtime response")
	}
	return nil
}

// NewRichRuntime creates a new higher-level wrapper for a given runtime. It provides additional
// convenience functions for talking with a runtime.
func NewRichRuntime(rt Runtime) RichRuntime {
	return &richRuntime{Runtime: rt}
}
