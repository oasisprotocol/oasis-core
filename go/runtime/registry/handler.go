package registry

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusResults "github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/results"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// Ensure that the runtime host handler implements the Handler interface.
var _ protocol.Handler = (*runtimeHostHandler)(nil)

// RuntimeHostHandlerEnvironment is the host environment interface.
type RuntimeHostHandlerEnvironment interface {
	// GetKeyManagerClient returns the key manager client for this runtime.
	GetKeyManagerClient() (runtimeKeymanager.Client, error)

	// GetTxPool returns the transaction pool for this runtime.
	GetTxPool() (txpool.TransactionPool, error)

	// GetNodeIdentity returns the identity of a node running this runtime.
	GetNodeIdentity() (*identity.Identity, error)

	// GetLightClient returns the consensus light client.
	GetLightClient() (consensus.LightClient, error)

	// GetRuntimeRegistry returns the runtime registry.
	GetRuntimeRegistry() Registry
}

// RuntimeHostHandlerFactory is an interface that can be used to create new runtime handlers and
// notifiers when provisioning hosted runtimes.
type RuntimeHostHandlerFactory interface {
	// NewRuntimeHostHandler creates a new runtime host handler.
	NewRuntimeHostHandler() host.RuntimeHandler
}

// RuntimeHostHandler is a runtime host handler suitable for compute runtimes. It provides the
// required set of methods for interacting with the outside world.
type runtimeHostHandler struct {
	env       RuntimeHostHandlerEnvironment
	runtime   Runtime
	consensus consensus.Backend
}

// NewRuntimeHostHandler returns a protocol handler that provides the required host methods for the
// runtime to interact with the outside world.
//
// The passed identity may be nil.
func NewRuntimeHostHandler(
	env RuntimeHostHandlerEnvironment,
	runtime Runtime,
	consensus consensus.Backend,
) host.RuntimeHandler {
	return &runtimeHostHandler{
		env:       env,
		runtime:   runtime,
		consensus: consensus,
	}
}

// Implements protocol.Handler.
func (h *runtimeHostHandler) Handle(ctx context.Context, rq *protocol.Body) (*protocol.Body, error) {
	var (
		rsp protocol.Body
		err error
	)

	switch {
	case rq.HostRPCCallRequest != nil:
		// RPC.
		rsp.HostRPCCallResponse, err = h.handleHostRPCCall(ctx, rq.HostRPCCallRequest)
	case rq.HostSubmitPeerFeedbackRequest != nil:
		// Peer feedback.
		rsp.HostSubmitPeerFeedbackResponse, err = h.handleHostSubmitPeerFeedback(rq.HostSubmitPeerFeedbackRequest)
	case rq.HostStorageSyncRequest != nil:
		// Storage sync.
		rsp.HostStorageSyncResponse, err = h.handleHostStorageSync(ctx, rq.HostStorageSyncRequest)
	case rq.HostLocalStorageGetRequest != nil:
		// Local storage get.
		rsp.HostLocalStorageGetResponse, err = h.handleHostLocalStorageGet(rq.HostLocalStorageGetRequest)
	case rq.HostLocalStorageSetRequest != nil:
		// Local storage set.
		rsp.HostLocalStorageSetResponse, err = h.handleHostLocalStorageSet(rq.HostLocalStorageSetRequest)
	case rq.HostFetchConsensusBlockRequest != nil:
		// Consensus light client.
		rsp.HostFetchConsensusBlockResponse, err = h.handleHostFetchConsensusBlock(ctx, rq.HostFetchConsensusBlockRequest)
	case rq.HostFetchConsensusEventsRequest != nil:
		// Consensus events.
		rsp.HostFetchConsensusEventsResponse, err = h.handleHostFetchConsensusEvents(ctx, rq.HostFetchConsensusEventsRequest)
	case rq.HostFetchGenesisHeightRequest != nil:
		// Consensus genesis height.
		rsp.HostFetchGenesisHeightResponse, err = h.handleHostFetchGenesisHeight(ctx)
	case rq.HostFetchTxBatchRequest != nil:
		// Transaction pool.
		rsp.HostFetchTxBatchResponse, err = h.handleHostFetchTxBatch(rq.HostFetchTxBatchRequest)
	case rq.HostFetchBlockMetadataTxRequest != nil:
		// Block metadata.
		rsp.HostFetchBlockMetadataTxResponse, err = h.handleHostFetchBlockMetadataTx(ctx, rq.HostFetchBlockMetadataTxRequest)
	case rq.HostProveFreshnessRequest != nil:
		// Prove freshness.
		rsp.HostProveFreshnessResponse, err = h.handleHostProveFreshness(ctx, rq.HostProveFreshnessRequest)
	case rq.HostIdentityRequest != nil:
		// Host identity.
		rsp.HostIdentityResponse, err = h.handleHostIdentity()
	default:
		err = fmt.Errorf("method not supported")
	}

	if err != nil {
		return nil, err
	}
	return &rsp, nil
}

// Implements host.RuntimeHandler.
func (h *runtimeHostHandler) NewSubHandler(id component.ID) (host.RuntimeHandler, error) {
	switch id.Kind {
	case component.ROFL:
		return newSubHandlerROFL(id, h)
	default:
		return nil, fmt.Errorf("cannot create sub-handler for component '%s'", id.Kind)
	}
}

// Implements host.RuntimeHandler.
func (h *runtimeHostHandler) AttachRuntime(component.ID, host.Runtime) error {
	return nil
}

func (h *runtimeHostHandler) handleHostRPCCall(
	ctx context.Context,
	rq *protocol.HostRPCCallRequest,
) (*protocol.HostRPCCallResponse, error) {
	switch rq.Endpoint {
	case runtimeKeymanager.EnclaveRPCEndpoint:
		// Call into the remote key manager.
		kmCli, err := h.env.GetKeyManagerClient()
		if err != nil {
			return nil, err
		}

		if rq.RequestID == 0 {
			var (
				res  []byte
				node signature.PublicKey
			)

			res, node, err = kmCli.CallEnclaveDeprecated(ctx, rq.Request, rq.Nodes, rq.Kind, rq.PeerFeedback) //nolint:staticcheck // Suppress SA1019 deprecation warning
			if err != nil {
				return nil, err
			}

			return &protocol.HostRPCCallResponse{
				Response: res,
				Node:     node,
			}, nil
		}

		res, err := kmCli.CallEnclave(ctx, rq.RequestID, rq.Request, rq.Nodes, rq.Kind)
		if err != nil {
			return nil, err
		}

		return &protocol.HostRPCCallResponse{
			Response: res.Data,
			Node:     res.Node,
		}, nil
	default:
		return nil, fmt.Errorf("endpoint not supported")
	}
}

func (h *runtimeHostHandler) handleHostSubmitPeerFeedback(
	rq *protocol.HostSubmitPeerFeedbackRequest,
) (*protocol.Empty, error) {
	switch rq.Endpoint {
	case runtimeKeymanager.EnclaveRPCEndpoint:
		kmCli, err := h.env.GetKeyManagerClient()
		if err != nil {
			return nil, err
		}

		kmCli.SubmitPeerFeedback(rq.RequestID, rq.PeerFeedback)

		return &protocol.Empty{}, nil
	default:
		return nil, fmt.Errorf("endpoint not supported")
	}
}

func (h *runtimeHostHandler) handleHostStorageSync(
	ctx context.Context,
	rq *protocol.HostStorageSyncRequest,
) (*protocol.HostStorageSyncResponse, error) {
	var rs syncer.ReadSyncer
	switch rq.Endpoint {
	case protocol.HostStorageEndpointRuntime:
		// Runtime storage.
		rs = h.runtime.Storage()
		if rs == nil {
			// May be unsupported for unmanaged runtimes like the key manager.
			return nil, fmt.Errorf("endpoint not supported")
		}
	case protocol.HostStorageEndpointConsensus:
		// Consensus state storage.
		rs = h.consensus.State()
	default:
		return nil, fmt.Errorf("endpoint not supported")
	}

	var rsp *storage.ProofResponse
	var err error
	switch {
	case rq.SyncGet != nil:
		rsp, err = rs.SyncGet(ctx, rq.SyncGet)
	case rq.SyncGetPrefixes != nil:
		rsp, err = rs.SyncGetPrefixes(ctx, rq.SyncGetPrefixes)
	case rq.SyncIterate != nil:
		rsp, err = rs.SyncIterate(ctx, rq.SyncIterate)
	default:
		return nil, fmt.Errorf("method not supported")
	}
	if err != nil {
		return nil, err
	}

	return &protocol.HostStorageSyncResponse{ProofResponse: rsp}, nil
}

func (h *runtimeHostHandler) handleHostLocalStorageGet(
	rq *protocol.HostLocalStorageGetRequest,
) (*protocol.HostLocalStorageGetResponse, error) {
	value, err := h.runtime.LocalStorage().Get(rq.Key)
	if err != nil {
		return nil, err
	}
	return &protocol.HostLocalStorageGetResponse{Value: value}, nil
}

func (h *runtimeHostHandler) handleHostLocalStorageSet(
	rq *protocol.HostLocalStorageSetRequest,
) (*protocol.Empty, error) {
	if err := h.runtime.LocalStorage().Set(rq.Key, rq.Value); err != nil {
		return nil, err
	}
	return &protocol.Empty{}, nil
}

func (h *runtimeHostHandler) handleHostFetchConsensusBlock(
	ctx context.Context,
	rq *protocol.HostFetchConsensusBlockRequest,
) (*protocol.HostFetchConsensusBlockResponse, error) {
	// Invoke the light client. If a local full node is available the light
	// client will internally query the local node first.
	lc, err := h.env.GetLightClient()
	if err != nil {
		return nil, err
	}
	blk, _, err := lc.GetLightBlock(ctx, int64(rq.Height))
	if err != nil {
		return nil, fmt.Errorf("light block fetch failure: %w", err)
	}

	return &protocol.HostFetchConsensusBlockResponse{Block: *blk}, nil
}

func (h *runtimeHostHandler) handleHostFetchConsensusEvents(
	ctx context.Context,
	rq *protocol.HostFetchConsensusEventsRequest,
) (*protocol.HostFetchConsensusEventsResponse, error) {
	var evs []*consensusResults.Event
	switch rq.Kind {
	case protocol.EventKindStaking:
		sevs, err := h.consensus.Staking().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(sevs))
		for _, sev := range sevs {
			evs = append(evs, &consensusResults.Event{Staking: sev})
		}
	case protocol.EventKindRegistry:
		revs, err := h.consensus.Registry().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(revs))
		for _, rev := range revs {
			evs = append(evs, &consensusResults.Event{Registry: rev})
		}
	case protocol.EventKindRootHash:
		revs, err := h.consensus.RootHash().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(revs))
		for _, rev := range revs {
			evs = append(evs, &consensusResults.Event{RootHash: rev})
		}
	case protocol.EventKindGovernance:
		gevs, err := h.consensus.Governance().GetEvents(ctx, int64(rq.Height))
		if err != nil {
			return nil, err
		}
		evs = make([]*consensusResults.Event, 0, len(gevs))
		for _, gev := range gevs {
			evs = append(evs, &consensusResults.Event{Governance: gev})
		}
	default:
		return nil, fmt.Errorf("method not supported")
	}
	return &protocol.HostFetchConsensusEventsResponse{Events: evs}, nil
}

func (h *runtimeHostHandler) handleHostFetchGenesisHeight(
	ctx context.Context,
) (*protocol.HostFetchGenesisHeightResponse, error) {
	doc, err := h.consensus.GetGenesisDocument(ctx)
	if err != nil {
		return nil, err
	}
	return &protocol.HostFetchGenesisHeightResponse{Height: uint64(doc.Height)}, nil
}

func (h *runtimeHostHandler) handleHostFetchTxBatch(
	rq *protocol.HostFetchTxBatchRequest,
) (*protocol.HostFetchTxBatchResponse, error) {
	txPool, err := h.env.GetTxPool()
	if err != nil {
		return nil, err
	}

	batch := txPool.GetSchedulingExtra(rq.Offset, rq.Limit)
	raw := make([][]byte, 0, len(batch))
	for _, tx := range batch {
		raw = append(raw, tx.Raw())
	}

	return &protocol.HostFetchTxBatchResponse{Batch: raw}, nil
}

func (h *runtimeHostHandler) handleHostFetchBlockMetadataTx(
	ctx context.Context,
	rq *protocol.HostFetchBlockMetadataTxRequest,
) (*protocol.HostFetchBlockMetadataTxResponse, error) {
	tps, err := h.consensus.GetTransactionsWithProofs(ctx, int64(rq.Height))
	if err != nil {
		return nil, err
	}

	// The block metadata transaction should be located at the end of the block.
	for i := len(tps.Transactions) - 1; i >= 0; i-- {
		rawTx := tps.Transactions[i]

		var sigTx transaction.SignedTransaction
		if err = cbor.Unmarshal(rawTx, &sigTx); err != nil {
			continue
		}

		// Signature already verified by the validators, skipping.

		var tx transaction.Transaction
		if err = cbor.Unmarshal(sigTx.Blob, &tx); err != nil {
			continue
		}

		if tx.Method != consensus.MethodMeta {
			continue
		}

		return &protocol.HostFetchBlockMetadataTxResponse{
			SignedTx: &sigTx,
			Proof: &transaction.Proof{
				Height:   int64(rq.Height),
				RawProof: tps.Proofs[i],
			},
		}, nil
	}

	return nil, fmt.Errorf("block metadata transaction not found")
}

func (h *runtimeHostHandler) handleHostProveFreshness(
	ctx context.Context,
	rq *protocol.HostProveFreshnessRequest,
) (*protocol.HostProveFreshnessResponse, error) {
	identity, err := h.env.GetNodeIdentity()
	if err != nil {
		return nil, err
	}
	tx := registry.NewProveFreshnessTx(0, nil, rq.Blob)
	sigTx, proof, err := consensus.SignAndSubmitTxWithProof(ctx, h.consensus, identity.NodeSigner, tx)
	if err != nil {
		return nil, err
	}

	return &protocol.HostProveFreshnessResponse{
		SignedTx: sigTx,
		Proof:    proof,
	}, nil
}

func (h *runtimeHostHandler) handleHostIdentity() (*protocol.HostIdentityResponse, error) {
	identity, err := h.env.GetNodeIdentity()
	if err != nil {
		return nil, err
	}

	return &protocol.HostIdentityResponse{
		NodeID: identity.NodeSigner.Public(),
	}, nil
}
