package byzantine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/grpc/resolver/manual"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/node"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/checkpoint"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/syncer"
)

var _ storage.Backend = (*honestNodeStorage)(nil)

type honestNodeStorage struct {
	nodeID            signature.PublicKey
	client            storage.Backend
	resolverCleanupCb func()
	initCh            chan struct{}
}

func dialOptionForNode(ourCerts []tls.Certificate, node *node.Node) (grpc.DialOption, error) {
	certPool := x509.NewCertPool()
	for _, addr := range node.Committee.Addresses {
		nodeCert, err := addr.ParseCertificate()
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse node's address certificate")
		}
		certPool.AddCert(nodeCert)
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: ourCerts,
		RootCAs:      certPool,
		ServerName:   identity.CommonName,
	})
	return grpc.WithTransportCredentials(creds), nil
}

func dialNode(node *node.Node, opts grpc.DialOption) (*grpc.ClientConn, func(), error) {
	manualResolver, address, cleanupCb := manual.NewManualResolver()

	conn, err := cmnGrpc.Dial(address, opts, grpc.WithBalancerName(roundrobin.Name)) //nolint: staticcheck
	if err != nil {
		cleanupCb()
		return nil, nil, errors.Wrap(err, "failed dialing node")
	}
	var resolverState resolver.State
	for _, addr := range node.Committee.Addresses {
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.UpdateState(resolverState)

	return conn, cleanupCb, nil
}

func newHonestNodeStorage(id *identity.Identity, node *node.Node) (*honestNodeStorage, error) {
	opts, err := dialOptionForNode([]tls.Certificate{*id.TLSCertificate}, node)
	if err != nil {
		return nil, errors.Wrap(err, "storage client DialOptionForNode")
	}
	conn, resolverCleanupCb, err := dialNode(node, opts)
	if err != nil {
		return nil, errors.Wrap(err, "storage client DialNode")
	}

	initCh := make(chan struct{})
	close(initCh)

	return &honestNodeStorage{
		nodeID:            node.ID,
		client:            storage.NewStorageClient(conn),
		resolverCleanupCb: resolverCleanupCb,
		initCh:            initCh,
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

func (hns *honestNodeStorage) Merge(ctx context.Context, request *storage.MergeRequest) ([]*storage.Receipt, error) {
	return hns.client.Merge(ctx, request)
}

func (hns *honestNodeStorage) MergeBatch(ctx context.Context, request *storage.MergeBatchRequest) ([]*storage.Receipt, error) {
	return hns.client.MergeBatch(ctx, request)
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
	hns.resolverCleanupCb()
}

func (hns *honestNodeStorage) Initialized() <-chan struct{} {
	return hns.initCh
}

func storageConnectToCommittee(ht *honestTendermint, height int64, committee *scheduler.Committee, role scheduler.Role, id *identity.Identity) ([]*honestNodeStorage, error) {
	var hnss []*honestNodeStorage
	if err := schedulerForRoleInCommittee(ht, height, committee, role, func(n *node.Node) error {
		hns, err := newHonestNodeStorage(id, n)
		if err != nil {
			return errors.Wrapf(err, "new honest node storage %s", n.ID)
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
			return receipts, errors.Wrapf(err, "honest node storage ApplyBatch %s", hns.nodeID)
		}

		receipts = append(receipts, r...)
	}

	return receipts, nil
}

func storageBroadcastMergeBatch(
	ctx context.Context,
	hnss []*honestNodeStorage,
	ns common.Namespace,
	round uint64,
	ops []storage.MergeOp,
) ([]*storage.Receipt, error) {
	var receipts []*storage.Receipt
	for _, hns := range hnss {
		r, err := hns.MergeBatch(ctx, &storage.MergeBatchRequest{Namespace: ns, Round: round, Ops: ops})
		if err != nil {
			return receipts, errors.Wrapf(err, "honest node storage MergeBatch %s", hns.nodeID)
		}

		receipts = append(receipts, r...)
	}

	return receipts, nil
}
