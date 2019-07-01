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
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.GetSubtree(root_hash, node_path, node_depth, max_depth)",
			opentracing.Tag{Key: "root_hash", Value: body.HostStorageSyncGetSubtreeRequest.RootHash},
			opentracing.Tag{Key: "node_path", Value: body.HostStorageSyncGetSubtreeRequest.NodePath},
			opentracing.Tag{Key: "node_depth", Value: body.HostStorageSyncGetSubtreeRequest.NodeDepth},
			opentracing.Tag{Key: "max_depth", Value: body.HostStorageSyncGetSubtreeRequest.MaxDepth},
		)
		defer span.Finish()

		nodeID := storage.NodeID{
			Path:  body.HostStorageSyncGetSubtreeRequest.NodePath,
			Depth: body.HostStorageSyncGetSubtreeRequest.NodeDepth,
		}

		subtree, err := h.storage.GetSubtree(sctx, body.HostStorageSyncGetSubtreeRequest.RootHash, nodeID, body.HostStorageSyncGetSubtreeRequest.MaxDepth)
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
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.GetPath(root_hash, key, start_depth)",
			opentracing.Tag{Key: "root_hash", Value: body.HostStorageSyncGetPathRequest.RootHash},
			opentracing.Tag{Key: "key", Value: body.HostStorageSyncGetPathRequest.Key},
			opentracing.Tag{Key: "start_depth", Value: body.HostStorageSyncGetPathRequest.StartDepth},
		)
		defer span.Finish()

		subtree, err := h.storage.GetPath(sctx, body.HostStorageSyncGetPathRequest.RootHash, body.HostStorageSyncGetPathRequest.Key, body.HostStorageSyncGetPathRequest.StartDepth)
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
		span, sctx := opentracing.StartSpanFromContext(ctx, "storage.GetNode(root_hash, node_path, node_depth)",
			opentracing.Tag{Key: "root_hash", Value: body.HostStorageSyncGetNodeRequest.RootHash},
			opentracing.Tag{Key: "node_path", Value: body.HostStorageSyncGetNodeRequest.NodePath},
			opentracing.Tag{Key: "node_depth", Value: body.HostStorageSyncGetNodeRequest.NodeDepth},
		)
		defer span.Finish()

		nodeID := storage.NodeID{
			Path:  body.HostStorageSyncGetNodeRequest.NodePath,
			Depth: body.HostStorageSyncGetNodeRequest.NodeDepth,
		}

		node, err := h.storage.GetNode(sctx, body.HostStorageSyncGetNodeRequest.RootHash, nodeID)
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
