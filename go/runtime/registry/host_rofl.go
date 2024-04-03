package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	cmnSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	rofl "github.com/oasisprotocol/oasis-core/go/runtime/rofl/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// ronlEnclaveRPCTimeout is the maximum amount of time EnclaveRPC handling can take.
	ronlEnclaveRPCTimeout = 2 * time.Second
	// roflAttachRuntimeTimeout is the maximum amount of time runtime attachment can take.
	roflAttachRuntimeTimeout = 2 * time.Second
	// roflNotifyTimeout is the maximum amount of time runtime notification handling can take.
	roflNotifyTimeout = 2 * time.Second
	// roflLocalStorageKeyPrefix is the implicit local storage prefix for all ROFL keys.
	roflLocalStorageKeyPrefix = "rofl."
)

// roflHostHandler is a host handler extended for use by ROFL components.
type roflHostHandler struct {
	parent *runtimeHostHandler
	cr     host.CompositeRuntime

	client        runtimeClient.RuntimeClient
	eventNotifier *roflEventNotifier

	logger *logging.Logger
}

func newSubHandlerROFL(parent *runtimeHostHandler, cr host.CompositeRuntime) (host.RuntimeHandler, error) {
	client, err := parent.env.GetRuntimeRegistry().Client()
	if err != nil {
		return nil, err
	}

	logger := logging.GetLogger("runtime/registry/host").
		With("runtime_id", parent.runtime.ID()).
		With("component", bundle.ComponentROFL)

	return &roflHostHandler{
		parent:        parent,
		cr:            cr,
		client:        client,
		eventNotifier: newROFLEventNotifier(parent.runtime, client, logger),
		logger:        logger,
	}, nil
}

// Implements host.RuntimeHandler.
func (rh *roflHostHandler) NewSubHandler(host.CompositeRuntime, *bundle.Component) (host.RuntimeHandler, error) {
	return nil, fmt.Errorf("cannot create sub-component for leaf handler")
}

// Implements host.RuntimeHandler.
func (rh *roflHostHandler) AttachRuntime(rt host.Runtime) error {
	return rh.eventNotifier.AttachRuntime(rt)
}

// Implements protocol.Handler.
func (rh *roflHostHandler) Handle(ctx context.Context, rq *protocol.Body) (*protocol.Body, error) {
	var (
		rsp protocol.Body
		err error
	)
	switch {
	case rq.HostRPCCallRequest != nil:
		// RPC.
		return rh.handleHostRPCCall(ctx, rq)
	case rq.HostLocalStorageGetRequest != nil:
		// Local storage get.
		rq.HostLocalStorageGetRequest.Key = append([]byte(roflLocalStorageKeyPrefix), rq.HostLocalStorageGetRequest.Key...)
		return rh.parent.Handle(ctx, rq)
	case rq.HostLocalStorageSetRequest != nil:
		// Local storage set.
		rq.HostLocalStorageSetRequest.Key = append([]byte(roflLocalStorageKeyPrefix), rq.HostLocalStorageSetRequest.Key...)
		return rh.parent.Handle(ctx, rq)
	case rq.HostSubmitTxRequest != nil:
		// Transaction submission.
		rsp.HostSubmitTxResponse, err = rh.handleHostSubmitTx(ctx, rq.HostSubmitTxRequest)
	case rq.HostRegisterNotifyRequest != nil:
		// Subscription to host notifications.
		rsp.HostRegisterNotifyResponse, err = rh.handleHostRegisterNotify(ctx, rq.HostRegisterNotifyRequest)
	default:
		// All other requests handled by parent.
		return rh.parent.Handle(ctx, rq)
	}

	// For locally handled methods.
	if err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (rh *roflHostHandler) handleHostRPCCall(
	ctx context.Context,
	rq *protocol.Body,
) (*protocol.Body, error) {
	switch rq.HostRPCCallRequest.Endpoint {
	case rofl.EnclaveRPCEndpointRONL:
		// Route EnclaveRPC request to RONL component.
		compRt, ok := rh.cr.Component(bundle.ComponentID_RONL)
		if !ok {
			return nil, fmt.Errorf("endpoint not supported")
		}
		if rq.HostRPCCallRequest.Kind != enclaverpc.KindNoiseSession {
			return nil, fmt.Errorf("only secure noise sessions are allowed")
		}

		callCtx, cancel := context.WithTimeout(ctx, ronlEnclaveRPCTimeout)
		defer cancel()

		rspRaw, err := compRt.Call(callCtx, &protocol.Body{
			RuntimeRPCCallRequest: &protocol.RuntimeRPCCallRequest{
				Request: rq.HostRPCCallRequest.Request,
				Kind:    rq.HostRPCCallRequest.Kind,
			},
		})
		if err != nil {
			rh.logger.Warn("failed to route EnclaveRPC call to RONL",
				"err", err,
				"kind", rq.HostRPCCallRequest.Kind,
			)
			return nil, err
		}

		rsp := rspRaw.RuntimeRPCCallResponse
		if rsp == nil {
			rh.logger.Warn("malformed response from runtime",
				"response", rspRaw,
			)
			return nil, fmt.Errorf("malformed response from RONL")
		}

		return &protocol.Body{
			HostRPCCallResponse: &protocol.HostRPCCallResponse{
				Response: rsp.Response,
			},
		}, nil
	default:
		// All other EnclaveRPC endpoints handled by parent.
		return rh.parent.Handle(ctx, rq)
	}
}

func (rh *roflHostHandler) handleHostSubmitTx(
	ctx context.Context,
	rq *protocol.HostSubmitTxRequest,
) (*protocol.HostSubmitTxResponse, error) {
	submitRq := &runtimeClient.SubmitTxRequest{
		RuntimeID: rq.RuntimeID,
		Data:      rq.Data,
	}

	switch rq.Wait {
	case true:
		// We need to wait for transaction inclusion.
		rsp, err := rh.client.SubmitTxMeta(ctx, submitRq)
		switch {
		case err != nil:
			return nil, err
		case rsp.CheckTxError != nil:
			return nil, errors.WithContext(runtimeClient.ErrCheckTxFailed, rsp.CheckTxError.String())
		default:
		}

		var proof *syncer.Proof
		// TODO: Add support for inclusion proofs.

		return &protocol.HostSubmitTxResponse{
			Output:     rsp.Output,
			Round:      rsp.Round,
			BatchOrder: rsp.BatchOrder,
			Proof:      proof,
		}, nil
	default:
		// Just submit and forget.
		err := rh.client.SubmitTxNoWait(ctx, submitRq)
		if err != nil {
			return nil, err
		}
		return &protocol.HostSubmitTxResponse{}, nil
	}
}

func (rh *roflHostHandler) handleHostRegisterNotify(
	ctx context.Context,
	rq *protocol.HostRegisterNotifyRequest,
) (*protocol.Empty, error) {
	// Subscribe to event notifications.
	if err := rh.eventNotifier.RegisterNotify(ctx, rq); err != nil {
		return nil, err
	}

	return &protocol.Empty{}, nil
}

type roflAttachRuntimeCmd struct {
	rt host.Runtime
	ch chan<- error
}

type roflEventNotifierCmd struct {
	// registerNotify is the command to register for notifications.
	registerNotify *protocol.HostRegisterNotifyRequest
	// attachRuntime is the command to attach a runtime host.
	attachRuntime *roflAttachRuntimeCmd
}

type roflEventNotifier struct {
	startOne cmnSync.One

	runtime Runtime
	client  runtimeClient.RuntimeClient
	cmdCh   chan *roflEventNotifierCmd

	logger *logging.Logger
}

func newROFLEventNotifier(runtime Runtime, client runtimeClient.RuntimeClient, logger *logging.Logger) *roflEventNotifier {
	return &roflEventNotifier{
		startOne: cmnSync.NewOne(),
		runtime:  runtime,
		client:   client,
		cmdCh:    make(chan *roflEventNotifierCmd),
		logger:   logger,
	}
}

func (en *roflEventNotifier) start() {
	en.startOne.TryStart(en.run)
}

func (en *roflEventNotifier) RegisterNotify(ctx context.Context, rq *protocol.HostRegisterNotifyRequest) error {
	en.start() // Ensure event notifier is running.

	select {
	case <-ctx.Done():
		return ctx.Err()
	case en.cmdCh <- &roflEventNotifierCmd{registerNotify: rq}:
	}
	return nil
}

func (en *roflEventNotifier) AttachRuntime(rt host.Runtime) error {
	en.start() // Ensure event notifier is running.

	ch := make(chan error, 1)
	en.cmdCh <- &roflEventNotifierCmd{attachRuntime: &roflAttachRuntimeCmd{rt, ch}}

	select {
	case <-time.After(roflAttachRuntimeTimeout):
		return fmt.Errorf("timeout while attaching runtime")
	case err := <-ch:
		return err
	}
}

func (en *roflEventNotifier) run(ctx context.Context) {
	var (
		rt    host.Runtime
		blkCh <-chan *roothash.AnnotatedBlock

		notifyBlocks bool
		notifyTags   [][]byte
	)

	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-en.cmdCh:
			// Process a command.
			switch {
			case cmd.registerNotify != nil:
				// Update configuration.
				notifyBlocks = cmd.registerNotify.RuntimeBlock

				if re := cmd.registerNotify.RuntimeEvent; re != nil {
					notifyTags = re.Tags
				} else {
					notifyTags = nil
				}
			case cmd.attachRuntime != nil:
				// Attach runtime.
				var err error
				switch {
				case rt != nil:
					// Already attached.
					err = fmt.Errorf("runtime already attached")
				default:
					// Attach runtime and subscribe to blocks.
					rt = cmd.attachRuntime.rt

					// Subscribe to runtime blocks.
					var blkSub pubsub.ClosableSubscription
					blkCh, blkSub, err = en.client.WatchBlocks(ctx, en.runtime.ID())
					if err != nil {
						err = fmt.Errorf("failed to subscribe to runtime blocks: %w", err)
						break
					}
					defer blkSub.Close()
				}

				cmd.attachRuntime.ch <- err
				close(cmd.attachRuntime.ch)
			default:
				panic("runtime/rofl: unsupported command for event notifier")
			}
		case blk := <-blkCh:
			// New runtime block has been produced.
			if notifyBlocks {
				en.notifyBlock(ctx, rt, blk)
			}

			en.notifyTags(ctx, rt, blk, notifyTags)
		}
	}
}

func (en *roflEventNotifier) notifyBlock(ctx context.Context, rt host.Runtime, blk *roothash.AnnotatedBlock) {
	ctx, cancel := context.WithTimeout(ctx, roflNotifyTimeout)
	defer cancel()

	_, err := rt.Call(ctx, &protocol.Body{
		RuntimeNotifyRequest: &protocol.RuntimeNotifyRequest{
			RuntimeBlock: blk,
		},
	})
	if err != nil {
		en.logger.Warn("failed to deliver block notification to runtime",
			"err", err,
			"round", blk.Block.Header.Round,
		)
	}
}

func (en *roflEventNotifier) notifyTags(
	ctx context.Context,
	rt host.Runtime,
	blk *roothash.AnnotatedBlock,
	notifyTags [][]byte,
) {
	if len(notifyTags) == 0 {
		return
	}

	tree := transaction.NewTree(en.runtime.Storage(), blk.Block.Header.StorageRootIO())
	defer tree.Close()

	tags, err := tree.GetTagMultiple(ctx, notifyTags)
	if err != nil {
		en.logger.Warn("failed to fetch tags for block",
			"err", err,
			"round", blk.Block.Header.Round,
		)
		return
	}

	if len(tags) == 0 {
		return
	}

	tagKeys := make([][]byte, 0, len(tags))
	for _, tag := range tags {
		tagKeys = append(tagKeys, tag.Key)
	}

	ctx, cancel := context.WithTimeout(ctx, roflNotifyTimeout)
	defer cancel()

	_, err = rt.Call(ctx, &protocol.Body{
		RuntimeNotifyRequest: &protocol.RuntimeNotifyRequest{
			RuntimeEvent: &protocol.RuntimeNotifyEvent{
				Block: blk,
				Tags:  tagKeys,
			},
		},
	})
	if err != nil {
		en.logger.Warn("failed to deliver event notification to runtime",
			"err", err,
			"round", blk.Block.Header.Round,
		)
	}
}
