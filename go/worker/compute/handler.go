package compute

import (
	"context"
	"errors"

	"github.com/opentracing/opentracing-go"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/client"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

var (
	errMethodNotSupported   = errors.New("method not supported")
	errEndpointNotSupported = errors.New("RPC endpoint not supported")

	_ protocol.Handler = (*hostHandler)(nil)
)

type hostHandler struct {
	runtimeID signature.PublicKey

	storage      storage.Backend
	keyManager   *keymanager.Client
	localStorage *host.LocalStorage
}

func (h *hostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	// RPC.
	if body.HostRPCCallRequest != nil {
		switch body.HostRPCCallRequest.Endpoint {
		case protocol.EndpointKeyManager:
			// Call into the remote key manager.
			res, err := h.keyManager.CallRemote(ctx, h.runtimeID, body.HostRPCCallRequest.Request)
			if err != nil {
				return nil, err
			}
			return &protocol.Body{HostRPCCallResponse: &protocol.HostRPCCallResponse{
				Response: cbor.FixSliceForSerde(res),
			}}, nil
		default:
			return nil, errEndpointNotSupported
		}
	}
	// Storage.
	if body.HostStorageSyncGetSubtreeRequest != nil {
		rq := body.HostStorageSyncGetSubtreeRequest
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.GetSubtree(root_hash, node_path, node_depth, max_depth)",
			opentracing.Tag{Key: "root_hash", Value: rq.Root.Hash},
			opentracing.Tag{Key: "node_path", Value: rq.NodePath},
			opentracing.Tag{Key: "node_bit_depth", Value: rq.NodeBitDepth},
			opentracing.Tag{Key: "max_depth", Value: rq.MaxDepth},
		)
		defer span.Finish()

		nodeID := storage.NodeID{
			Path:     rq.NodePath,
			BitDepth: rq.NodeBitDepth,
		}

		subtree, err := h.storage.GetSubtree(sctx, rq.Root, nodeID, rq.MaxDepth)
		if err != nil {
			return nil, err
		}

		serialized, err := subtree.MarshalBinary()
		if err != nil {
			return nil, err
		}

		return &protocol.Body{HostStorageSyncSerializedResponse: &protocol.HostStorageSyncSerializedResponse{Serialized: serialized}}, nil
	}
	if body.HostStorageSyncGetPathRequest != nil {
		rq := body.HostStorageSyncGetPathRequest
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.GetPath(root_hash, key, start_depth)",
			opentracing.Tag{Key: "root_hash", Value: rq.Root.Hash},
			opentracing.Tag{Key: "key", Value: rq.Key},
			opentracing.Tag{Key: "start_bit_depth", Value: rq.StartBitDepth},
		)
		defer span.Finish()

		subtree, err := h.storage.GetPath(sctx, rq.Root, rq.Key, rq.StartBitDepth)
		if err != nil {
			return nil, err
		}

		serialized, err := subtree.MarshalBinary()
		if err != nil {
			return nil, err
		}

		return &protocol.Body{HostStorageSyncSerializedResponse: &protocol.HostStorageSyncSerializedResponse{Serialized: serialized}}, nil
	}
	if body.HostStorageSyncGetNodeRequest != nil {
		rq := body.HostStorageSyncGetNodeRequest
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.GetNode(root_hash, node_path, node_depth)",
			opentracing.Tag{Key: "root_hash", Value: rq.Root.Hash},
			opentracing.Tag{Key: "node_path", Value: rq.NodePath},
			opentracing.Tag{Key: "node_depth", Value: rq.NodeBitDepth},
		)
		defer span.Finish()

		nodeID := storage.NodeID{
			Path:     rq.NodePath,
			BitDepth: rq.NodeBitDepth,
		}

		node, err := h.storage.GetNode(sctx, rq.Root, nodeID)
		if err != nil {
			return nil, err
		}

		serialized, err := node.MarshalBinary()
		if err != nil {
			return nil, err
		}

		return &protocol.Body{HostStorageSyncSerializedResponse: &protocol.HostStorageSyncSerializedResponse{Serialized: serialized}}, nil
	}
	// Local storage.
	if body.HostLocalStorageGetRequest != nil {
		value, err := h.localStorage.Get(h.runtimeID, body.HostLocalStorageGetRequest.Key)
		if err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageGetResponse: &protocol.HostLocalStorageGetResponse{Value: value}}, nil
	}
	if body.HostLocalStorageSetRequest != nil {
		if err := h.localStorage.Set(h.runtimeID, body.HostLocalStorageSetRequest.Key, body.HostLocalStorageSetRequest.Value); err != nil {
			return nil, err
		}
		return &protocol.Body{HostLocalStorageSetResponse: &protocol.Empty{}}, nil
	}

	return nil, errMethodNotSupported
}

func newHostHandler(runtimeID signature.PublicKey, storage storage.Backend, keyManager *keymanager.Client, localStorage *host.LocalStorage) protocol.Handler {
	return &hostHandler{runtimeID, storage, keyManager, localStorage}
}
