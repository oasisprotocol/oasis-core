package byzantine

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var _ storage.Backend = (*honestNodeStorage)(nil)

type honestNodeStorage struct {
	nodeID signature.PublicKey
	client storage.Backend
	initCh chan struct{}
}

func dialOptionForNode(ourCerts []tls.Certificate, node *node.Node) (grpc.DialOption, error) {
	tlsKeys := make(map[signature.PublicKey]bool)
	for _, addr := range node.TLS.Addresses {
		tlsKeys[addr.PubKey] = true
	}

	creds, err := cmnGrpc.NewClientCreds(&cmnGrpc.ClientOptions{
		CommonName:    identity.CommonName,
		ServerPubKeys: tlsKeys,
		Certificates:  ourCerts,
	})
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(creds), nil
}

func dialNode(node *node.Node, opts grpc.DialOption) (*grpc.ClientConn, error) {
	manualResolver := manual.NewBuilderWithScheme("oasis-core-resolver")

	conn, err := cmnGrpc.Dial("oasis-core-resolver:///", opts,
		grpc.WithBalancerName(roundrobin.Name), // nolint: staticcheck
		grpc.WithResolvers(manualResolver),
	)
	if err != nil {
		return nil, fmt.Errorf("failed dialing node: %w", err)
	}
	var resolverState resolver.State
	for _, addr := range node.TLS.Addresses {
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.UpdateState(resolverState)

	return conn, nil
}

func newHonestNodeStorage(id *identity.Identity, node *node.Node) (*honestNodeStorage, error) {
	opts, err := dialOptionForNode([]tls.Certificate{*id.GetTLSCertificate()}, node)
	if err != nil {
		return nil, fmt.Errorf("storage client DialOptionForNode: %w", err)
	}
	conn, err := dialNode(node, opts)
	if err != nil {
		return nil, fmt.Errorf("storage client DialNode: %w", err)
	}

	initCh := make(chan struct{})
	close(initCh)

	return &honestNodeStorage{
		nodeID: node.ID,
		client: storage.NewStorageClient(conn),
		initCh: initCh,
	}, nil
}

func (hns *honestNodeStorage) SyncGet(ctx context.Context, request *syncer.GetRequest) (*syncer.ProofResponse, error) {
	return hns.client.SyncGet(ctx, request)
}

func (hns *honestNodeStorage) SyncGetPrefixes(ctx context.Context, request *syncer.GetPrefixesRequest) (*syncer.ProofResponse, error) {
	return hns.client.SyncGetPrefixes(ctx, request)
}

func (hns *honestNodeStorage) SyncIterate(ctx context.Context, request *syncer.IterateRequest) (*syncer.ProofResponse, error) {
	return hns.client.SyncIterate(ctx, request)
}

func (hns *honestNodeStorage) Apply(ctx context.Context, request *storage.ApplyRequest) ([]*storage.Receipt, error) {
	return hns.client.Apply(ctx, request)
}

func (hns *honestNodeStorage) ApplyBatch(ctx context.Context, request *storage.ApplyBatchRequest) ([]*storage.Receipt, error) {
	return hns.client.ApplyBatch(ctx, request)
}

func (hns *honestNodeStorage) GetDiff(ctx context.Context, request *storage.GetDiffRequest) (storage.WriteLogIterator, error) {
	return hns.client.GetDiff(ctx, request)
}

func (hns *honestNodeStorage) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	return hns.client.GetCheckpoints(ctx, request)
}

func (hns *honestNodeStorage) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	return hns.client.GetCheckpointChunk(ctx, chunk, w)
}

func (hns *honestNodeStorage) Cleanup() {
}

func (hns *honestNodeStorage) Initialized() <-chan struct{} {
	return hns.initCh
}

func storageConnectToCommittee(ht *honestTendermint, height int64, committee *scheduler.Committee, role scheduler.Role, id *identity.Identity) ([]*honestNodeStorage, error) {
	var hnss []*honestNodeStorage
	if err := schedulerForRoleInCommittee(ht, height, committee, role, func(n *node.Node) error {
		hns, err := newHonestNodeStorage(id, n)
		if err != nil {
			return fmt.Errorf("new honest node storage %s: %w", n.ID, err)
		}

		hnss = append(hnss, hns)

		return nil
	}); err != nil {
		return nil, err
	}

	return hnss, nil
}

func storageBroadcastCleanup(hnss []*honestNodeStorage) {
	for _, hns := range hnss {
		hns.Cleanup()
	}
}

func storageBroadcastApplyBatch(
	ctx context.Context,
	hnss []*honestNodeStorage,
	ns common.Namespace,
	dstRound uint64,
	ops []storage.ApplyOp,
) ([]*storage.Receipt, error) {
	var receipts []*storage.Receipt
	for _, hns := range hnss {
		r, err := hns.ApplyBatch(ctx, &storage.ApplyBatchRequest{Namespace: ns, DstRound: dstRound, Ops: ops})
		if err != nil {
			return receipts, fmt.Errorf("honest node storage ApplyBatch %s: %w", hns.nodeID, err)
		}

		receipts = append(receipts, r...)
	}

	return receipts, nil
}
