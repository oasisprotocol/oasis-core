package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	rofl "github.com/oasisprotocol/oasis-core/go/runtime/rofl/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// ronlEnclaveRPCTimeout is the maximum amount of time EnclaveRPC handling can take.
	ronlEnclaveRPCTimeout = 2 * time.Second
	// roflSubmitTxTimeout is the maximum amount of time that the host will wait for transaction
	// inclusion into a block.
	roflSubmitTxTimeout = 1 * time.Minute
	// roflLocalStorageKeySeparator is the local storage key separator after component ID.
	roflLocalStorageKeySeparator = ":"
)

// roflHostHandler is a host handler extended for use by ROFL components.
type roflHostHandler struct {
	parent *runtimeHostHandler

	id    component.ID
	comp  *bundle.ExplodedComponent
	comps map[component.ID]host.Runtime

	client       runtimeClient.RuntimeClient
	roflNotifier *ROFLNotifier

	logger *logging.Logger
}

func newSubHandlerROFL(comp *bundle.ExplodedComponent, parent *runtimeHostHandler, roflNotifier *ROFLNotifier) (*roflHostHandler, error) {
	client, err := parent.env.GetRuntimeRegistry().Client()
	if err != nil {
		return nil, err
	}

	logger := logging.GetLogger("runtime/registry/host").
		With("runtime_id", parent.runtime.ID()).
		With("component_id", comp.ID())

	return &roflHostHandler{
		parent:       parent,
		id:           comp.ID(),
		comp:         comp,
		comps:        make(map[component.ID]host.Runtime),
		client:       client,
		roflNotifier: roflNotifier,
		logger:       logger,
	}, nil
}

// Implements host.RuntimeHandler.
func (rh *roflHostHandler) NewSubHandler(*bundle.ExplodedComponent) (host.RuntimeHandler, error) {
	return nil, fmt.Errorf("cannot create sub-component for leaf handler")
}

// Implements host.RuntimeHandler.
func (rh *roflHostHandler) AttachRuntime(id component.ID, rt host.Runtime) error {
	rh.comps[id] = rt
	if id != rh.id {
		return nil
	}
	return nil
}

// getLocalStorageKey returns a properly namespaced version of the local storage key.
func (rh *roflHostHandler) getLocalStorageKey(key []byte) []byte {
	result, _ := rh.id.MarshalText()
	result = append(result, roflLocalStorageKeySeparator...)
	result = append(result, key...)
	return result
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
		rq.HostLocalStorageGetRequest.Key = rh.getLocalStorageKey(rq.HostLocalStorageGetRequest.Key)
		return rh.parent.Handle(ctx, rq)
	case rq.HostLocalStorageSetRequest != nil:
		// Local storage set.
		rq.HostLocalStorageSetRequest.Key = rh.getLocalStorageKey(rq.HostLocalStorageSetRequest.Key)
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
		ronl, ok := rh.comps[component.ID_RONL]
		if !ok {
			return nil, fmt.Errorf("endpoint not supported")
		}
		if rq.HostRPCCallRequest.Kind != enclaverpc.KindNoiseSession {
			return nil, fmt.Errorf("only secure noise sessions are allowed")
		}

		callCtx, cancel := context.WithTimeout(ctx, ronlEnclaveRPCTimeout)
		defer cancel()

		rspRaw, err := ronl.Call(callCtx, &protocol.Body{
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
	case rofl.LocalRPCEndpointBundleManager, rofl.LocalRPCEndpointVolumeManager, rofl.LocalRPCEndpointLogManager,
		rofl.LocalRPCEndpointAttestation:
		// Route management requests to handler.
		if rq.HostRPCCallRequest.Kind != enclaverpc.KindLocalQuery {
			return nil, fmt.Errorf("endpoint not supported")
		}

		var rpcRq enclaverpc.Request
		if err := cbor.Unmarshal(rq.HostRPCCallRequest.Request, &rpcRq); err != nil {
			return nil, fmt.Errorf("malformed request: %w", err)
		}

		var (
			rsp any
			err error
		)
		switch rq.HostRPCCallRequest.Endpoint {
		case rofl.LocalRPCEndpointBundleManager:
			rsp, err = rh.handleBundleManagement(&rpcRq)
		case rofl.LocalRPCEndpointVolumeManager:
			rsp, err = rh.handleVolumeManagement(&rpcRq)
		case rofl.LocalRPCEndpointLogManager:
			rsp, err = rh.handleLogManagement(ctx, &rpcRq)
		case rofl.LocalRPCEndpointAttestation:
			rsp, err = rh.handleAttestation(&rpcRq)
		default:
			return nil, fmt.Errorf("endpoint not supported")
		}

		if err != nil {
			return nil, err
		}

		return &protocol.Body{
			HostRPCCallResponse: &protocol.HostRPCCallResponse{
				Response: cbor.Marshal(rsp),
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

	submitTxCtx, cancel := context.WithTimeout(ctx, roflSubmitTxTimeout)
	defer cancel()

	switch rq.Wait {
	case true:
		// We need to wait for transaction inclusion.
		rsp, err := rh.client.SubmitTxMeta(submitTxCtx, submitRq)
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
		err := rh.client.SubmitTxNoWait(submitTxCtx, submitRq)
		if err != nil {
			return nil, err
		}
		return &protocol.HostSubmitTxResponse{}, nil
	}
}

func (rh *roflHostHandler) handleHostRegisterNotify(
	_ context.Context,
	rq *protocol.HostRegisterNotifyRequest,
) (*protocol.Empty, error) {
	// Subscribe to event notifications.
	nfs := &rofl.Notifications{
		Blocks: rq.RuntimeBlock,
	}
	if rq.RuntimeEvent != nil {
		nfs.Events = rq.RuntimeEvent.Tags
	}
	rh.roflNotifier.register(rh.id, nfs)

	return &protocol.Empty{}, nil
}

// handleAttestation handles attestation local RPCs.
func (rh *roflHostHandler) handleAttestation(rq *enclaverpc.Request) (any, error) {
	switch rq.Method {
	case rofl.MethodAttestLabels:
		// Attest component labels.
		var args rofl.AttestLabelsRequest
		if err := cbor.Unmarshal(rq.Args, &args); err != nil {
			return nil, err
		}
		return rh.handleAttestLabels(&args)
	default:
		return nil, fmt.Errorf("method not supported")
	}
}

func (rh *roflHostHandler) handleAttestLabels(args *rofl.AttestLabelsRequest) (*rofl.AttestLabelsResponse, error) {
	if len(args.Labels) == 0 {
		return nil, fmt.Errorf("no labels specified")
	}
	if len(args.Labels) > rofl.MaxAttestLabels {
		return nil, fmt.Errorf("too many labels specified (max: %d)", rofl.MaxAttestLabels)
	}

	labels := make(map[string]string, len(args.Labels))
	for _, key := range args.Labels {
		// NOTE: We do not discriminate between a zero value and label not being set.
		labels[key] = rh.comp.Labels[key]
	}

	identity, err := rh.parent.env.GetNodeIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve label attestation key")
	}

	ri, ok := rh.comps[rh.id]
	if !ok {
		return nil, fmt.Errorf("failed to retrieve component")
	}
	teeCap, err := ri.GetCapabilityTEE()
	if err != nil || teeCap == nil {
		return nil, fmt.Errorf("failed to retrieve component RAK")
	}

	la := rofl.LabelAttestation{
		Labels: labels,
		RAK:    teeCap.RAK,
	}

	encLa, signature, err := rofl.AttestLabels(identity.NodeSigner, la)
	if err != nil {
		return nil, fmt.Errorf("failed to sign label attestation")
	}

	return &rofl.AttestLabelsResponse{
		Attestation: encLa,
		NodeID:      identity.NodeSigner.Public(),
		Signature:   *signature,
	}, nil
}
