package byzantine

import (
	"context"
	"crypto/tls"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/node"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	storageclient "github.com/oasislabs/oasis-core/go/storage/client"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/syncer"
)

var _ storage.Backend = (*honestNodeStorage)(nil)

type honestNodeStorage struct {
	nodeID            signature.PublicKey
	client            storage.Backend
	resolverCleanupCb func()
	initCh            chan struct{}
}

func newHonestNodeStorage(id *identity.Identity, node *node.Node) (*honestNodeStorage, error) {
	opts, err := storageclient.DialOptionForNode([]tls.Certificate{*id.TLSCertificate}, node)
	if err != nil {
		return nil, errors.Wrap(err, "storage client DialOptionForNode")
	}
	conn, resolverCleanupCb, err := storageclient.DialNode(node, opts)
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

func (hns *honestNodeStorage) GetCheckpoint(ctx context.Context, request *storage.GetCheckpointRequest) (storage.WriteLogIterator, error) {
	return hns.client.GetCheckpoint(ctx, request)
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
