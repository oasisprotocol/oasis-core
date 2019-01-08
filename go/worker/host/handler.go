package host

import (
	"context"
	"errors"

	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/enclaverpc"
	"github.com/oasislabs/ekiden/go/worker/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/ias"
)

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("RPC endpoint not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	storage storage.Backend
	ias     *ias.IAS

	keyManager *enclaverpc.Client
}

func (h *hostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	// IAS.
	if body.HostIasGetSpidRequest != nil {
		spid, err := h.ias.GetSPID(ctx)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostIasGetSpidResponse: &protocol.HostIasGetSpidResponse{SPID: spid}}, nil
	}
	if body.HostIasGetQuoteTypeRequest != nil {
		qt, err := h.ias.GetQuoteSignatureType(ctx)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostIasGetQuoteTypeResponse: &protocol.HostIasGetQuoteTypeResponse{QuoteType: uint32(*qt)}}, nil
	}
	if body.HostIasReportRequest != nil {
		// TODO: What about PSE manifest?
		avr, signature, certs, err := h.ias.VerifyEvidence(ctx, body.HostIasReportRequest.Quote, []byte(""))
		if err != nil {
			return nil, err
		}
		// We need to be sure to represent nil bytes as empty byte slices instead of nil as
		// those are encoded differently in CBOR and the other side expects them to be
		// serialized as byte arrays.
		if len(signature) == 0 {
			signature = []byte("")
		}
		if len(certs) == 0 {
			certs = []byte("")
		}
		return &protocol.Body{HostIasReportResponse: &protocol.HostIasReportResponse{
			AVR:          avr,
			Signature:    signature,
			Certificates: certs,
		}}, nil
	}
	if body.HostIasSigRlRequest != nil {
		sigRL, err := h.ias.GetSigRL(ctx, body.HostIasSigRlRequest.GID)
		if err != nil {
			return nil, err
		}
		// We need to be sure to represent nil bytes as empty byte slices instead of nil as
		// those are encoded differently in CBOR and the other side expects them to be
		// serialized as byte arrays.
		if len(sigRL) == 0 {
			sigRL = []byte("")
		}
		return &protocol.Body{HostIasSigRlResponse: &protocol.HostIasSigRlResponse{
			SigRL: sigRL,
		}}, nil
	}
	// RPC.
	if body.HostRPCCallRequest != nil {
		switch body.HostRPCCallRequest.Endpoint {
		case protocol.EndpointKeyManager:
			// Check if key manager is available.
			if h.keyManager == nil {
				return nil, errEndpointNotSupported
			}

			// Call into the remote key manager.
			res, err := h.keyManager.CallEnclave(ctx, body.HostRPCCallRequest.Request)
			if err != nil {
				return nil, err
			}
			return &protocol.Body{HostRPCCallResponse: &protocol.HostRPCCallResponse{
				Response: res,
			}}, nil
		default:
			return nil, errEndpointNotSupported
		}
	}
	// Storage.
	if body.HostStorageGetRequest != nil {
		value, err := h.storage.Get(ctx, body.HostStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostStorageGetResponse: &protocol.HostStorageGetResponse{Value: value}}, nil
	}
	if body.HostStorageGetBatchRequest != nil {
		values, err := h.storage.GetBatch(ctx, body.HostStorageGetBatchRequest.Keys)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostStorageGetBatchResponse: &protocol.HostStorageGetBatchResponse{Values: values}}, nil
	}
	if body.HostStorageInsertRequest != nil {
		err := h.storage.Insert(
			ctx,
			body.HostStorageInsertRequest.Value,
			body.HostStorageInsertRequest.Expiry,
		)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostStorageInsertResponse: &protocol.Empty{}}, nil
	}
	if body.HostStorageInsertBatchRequest != nil {
		err := h.storage.InsertBatch(ctx, body.HostStorageInsertBatchRequest.Values)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostStorageInsertBatchResponse: &protocol.Empty{}}, nil
	}

	return nil, errMethodNotSupported
}

func newHostHandler(storage storage.Backend, ias *ias.IAS, keyManager *enclaverpc.Client) protocol.Handler {
	return &hostHandler{storage, ias, keyManager}
}
