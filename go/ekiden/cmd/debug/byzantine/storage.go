package byzantine

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/node"
	storagegrpc "github.com/oasislabs/ekiden/go/grpc/storage"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	storageclient "github.com/oasislabs/ekiden/go/storage/client"
	urkelnode "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

var _ storage.Backend = (*honestNodeStorage)(nil)

type honestNodeStorage struct {
	nodeID            signature.PublicKey
	client            storagegrpc.StorageClient
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
		client:            storagegrpc.NewStorageClient(conn),
		resolverCleanupCb: resolverCleanupCb,
		initCh:            initCh,
	}, nil
}

func (hns *honestNodeStorage) GetSubtree(ctx context.Context, root urkelnode.Root, id urkelnode.ID, maxDepth urkelnode.Depth) (*syncer.Subtree, error) {
	panic("not implemented")
}

func (hns *honestNodeStorage) GetPath(ctx context.Context, root urkelnode.Root, id urkelnode.ID, key urkelnode.Key) (*syncer.Subtree, error) {
	idPathBinary, err := id.Path.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("id Path MarshalBinary failed: %+v", err))
	}
	keyBinary, err := key.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("key MarshalBinary failed: %+v", err))
	}
	resp, err := hns.client.GetPath(ctx, &storagegrpc.GetPathRequest{
		Root: root.MarshalCBOR(),
		Id: &storagegrpc.NodeID{
			BitDepth: uint32(id.BitDepth),
			Path:     idPathBinary,
		},
		Key: keyBinary,
	})
	if err != nil {
		return nil, errors.Wrap(err, "client GetPath")
	}
	var subtree storage.Subtree
	if err = subtree.UnmarshalBinary(resp.GetSubtree()); err != nil {
		return nil, errors.Wrap(err, "subtree UnmarshalBinary")
	}

	return &subtree, nil
}

func (hns *honestNodeStorage) GetNode(ctx context.Context, root urkelnode.Root, id urkelnode.ID) (urkelnode.Node, error) {
	panic("not implemented")
}

func (hns *honestNodeStorage) Apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog storage.WriteLog,
) ([]*storage.Receipt, error) {
	panic("not implemented")
}

func (hns *honestNodeStorage) ApplyBatch(
	ctx context.Context,
	ns common.Namespace,
	dstRound uint64,
	ops []storage.ApplyOp,
) ([]*storage.Receipt, error) {
	namespaceBinary, err := ns.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("namespace MarshalBinary failed: %+v", err))
	}
	var pOps []*storagegrpc.ApplyOp
	for _, op := range ops {
		srcRootRaw, err1 := op.SrcRoot.MarshalBinary()
		if err1 != nil {
			panic(fmt.Sprintf("apply operation source root MarshalBinary failed: %+v", err1))
		}
		dstRootRaw, err1 := op.DstRoot.MarshalBinary()
		if err1 != nil {
			panic(fmt.Sprintf("apply operation destination root MarshalBinary failed: %+v", err1))
		}
		var pLogs []*storagegrpc.LogEntry
		for _, log := range op.WriteLog {
			pLogs = append(pLogs, &storagegrpc.LogEntry{
				Key:   log.Key,
				Value: log.Value,
			})
		}
		pOps = append(pOps, &storagegrpc.ApplyOp{
			SrcRound: op.SrcRound,
			SrcRoot:  srcRootRaw,
			DstRoot:  dstRootRaw,
			Log:      pLogs,
		})
	}
	resp, err := hns.client.ApplyBatch(ctx, &storagegrpc.ApplyBatchRequest{
		Namespace: namespaceBinary,
		DstRound:  dstRound,
		Ops:       pOps,
	})
	if err != nil {
		return nil, errors.Wrap(err, "client ApplyBatch")
	}
	var receipts []*storage.Receipt
	if err = cbor.Unmarshal(resp.GetReceipts(), &receipts); err != nil {
		panic(fmt.Sprintf("CBOR unmarshal receipts failed: %+v", err))
	}

	return receipts, nil
}

func (hns *honestNodeStorage) Merge(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	base hash.Hash,
	others []hash.Hash,
) ([]*storage.Receipt, error) {
	panic("not implemented")
}

func (hns *honestNodeStorage) MergeBatch(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	ops []storage.MergeOp,
) ([]*storage.Receipt, error) {
	panic("not implemented")
}

func (hns *honestNodeStorage) GetDiff(context.Context, storage.Root, storage.Root) (storage.WriteLogIterator, error) {
	panic("not implemented")
}

func (hns *honestNodeStorage) GetCheckpoint(context.Context, storage.Root) (storage.WriteLogIterator, error) {
	panic("not implemented")
}

func (hns *honestNodeStorage) Cleanup() {
	hns.resolverCleanupCb()
}

func (hns *honestNodeStorage) Initialized() <-chan struct{} {
	return hns.initCh
}

func storageConnectToCommittee(svc service.TendermintService, height int64, committee *scheduler.Committee, role scheduler.Role, id *identity.Identity) ([]*honestNodeStorage, error) {
	var hnss []*honestNodeStorage
	if err := schedulerForRoleInCommittee(svc, height, committee, role, func(n *node.Node) error {
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
		r, err := hns.ApplyBatch(ctx, ns, dstRound, ops)
		if err != nil {
			return receipts, errors.Wrapf(err, "honest node storage ApplyBatch %s", hns.nodeID)
		}

		receipts = append(receipts, r...)
	}

	return receipts, nil
}
