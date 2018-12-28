package worker

import (
	"context"
	"errors"

	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/ias"
	"github.com/oasislabs/ekiden/go/worker/protocol"
)

var (
	errMethodNotSupported = errors.New("method not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	storage storage.Backend
	ias     *ias.IAS
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
		return &protocol.Body{HostIasSigRlResponse: &protocol.HostIasSigRlResponse{
			SigRL: sigRL,
		}}, nil
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

func newHostHandler(storage storage.Backend, ias *ias.IAS) protocol.Handler {
	return &hostHandler{storage, ias}
}
