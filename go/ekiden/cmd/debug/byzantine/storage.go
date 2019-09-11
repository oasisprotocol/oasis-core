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

func (hns *honestNodeStorage) SyncGet(ctx context.Context, request *syncer.GetRequest) (*syncer.ProofResponse, error) {
	rsp, err := hns.client.SyncGet(ctx, &storagegrpc.ReadSyncerRequest{
		Request: cbor.Marshal(request),
	})
	if err != nil {
		return nil, errors.Wrap(err, "client SyncGet")
	}

	var rs syncer.ProofResponse
	if err := cbor.Unmarshal(rsp.Response, &rs); err != nil {
		return nil, errors.Wrap(err, "response Unmarshal")
	}
	return &rs, nil
}

func (hns *honestNodeStorage) SyncGetPrefixes(ctx context.Context, request *syncer.GetPrefixesRequest) (*syncer.ProofResponse, error) {
	rsp, err := hns.client.SyncGetPrefixes(ctx, &storagegrpc.ReadSyncerRequest{
		Request: cbor.Marshal(request),
	})
	if err != nil {
		return nil, errors.Wrap(err, "client SyncGet")
	}

	var rs syncer.ProofResponse
	if err := cbor.Unmarshal(rsp.Response, &rs); err != nil {
		return nil, errors.Wrap(err, "response Unmarshal")
	}
	return &rs, nil
}

func (hns *honestNodeStorage) SyncIterate(ctx context.Context, request *syncer.IterateRequest) (*syncer.ProofResponse, error) {
	rsp, err := hns.client.SyncIterate(ctx, &storagegrpc.ReadSyncerRequest{
		Request: cbor.Marshal(request),
	})
	if err != nil {
		return nil, errors.Wrap(err, "client SyncGet")
	}

	var rs syncer.ProofResponse
	if err := cbor.Unmarshal(rsp.Response, &rs); err != nil {
		return nil, errors.Wrap(err, "response Unmarshal")
	}
	return &rs, nil
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
	namespaceBinary, err := ns.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("namespace MarshalBinary failed: %+v", err))
	}
	var pOps []*storagegrpc.MergeOp
	for _, op := range ops {
		baseRaw, err1 := op.Base.MarshalBinary()
		if err1 != nil {
			panic(fmt.Sprintf("merge operation base MarshalBinary failed: %+v", err1))
		}
		var pOthers [][]byte
		for _, other := range op.Others {
			otherRaw, err2 := other.MarshalBinary()
			if err2 != nil {
				panic(fmt.Sprintf("other MarshalBinary failed: %+v", err2))
			}
			pOthers = append(pOthers, otherRaw)
		}
		pOps = append(pOps, &storagegrpc.MergeOp{
			Base:   baseRaw,
			Others: pOthers,
		})
	}
	resp, err := hns.client.MergeBatch(ctx, &storagegrpc.MergeBatchRequest{
		Namespace: namespaceBinary,
		Round:     round,
		Ops:       pOps,
	})
	if err != nil {
		return nil, errors.Wrap(err, "client MergeBatch")
	}
	var receipts []*storage.Receipt
	if err = cbor.Unmarshal(resp.GetReceipts(), &receipts); err != nil {
		panic(fmt.Sprintf("CBOR unmarshal receipts failed: %+v", err))
	}

	return receipts, nil
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

func storageBroadcastMergeBatch(
	ctx context.Context,
	hnss []*honestNodeStorage,
	ns common.Namespace,
	round uint64,
	ops []storage.MergeOp,
) ([]*storage.Receipt, error) {
	var receipts []*storage.Receipt
	for _, hns := range hnss {
		r, err := hns.MergeBatch(ctx, ns, round, ops)
		if err != nil {
			return receipts, errors.Wrapf(err, "honest node storage MergeBatch %s", hns.nodeID)
		}

		receipts = append(receipts, r...)
	}

	return receipts, nil
}
