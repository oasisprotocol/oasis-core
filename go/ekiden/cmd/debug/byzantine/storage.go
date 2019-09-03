package byzantine

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/node"
	storagegrpc "github.com/oasislabs/ekiden/go/grpc/storage"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	storageclient "github.com/oasislabs/ekiden/go/storage/client"
	urkelnode "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

var _ storage.Backend = (*honestNodeStorage)(nil)

type honestNodeStorage struct {
	client            storagegrpc.StorageClient
	resolverCleanupCb func()
	initCh            chan struct{}
}

func newHonestNodeStorage(id *identity.Identity, node *node.Node) (*honestNodeStorage, error) { // nolint: deadcode, unused
	opts, err := storageclient.DialOptionForNode([]tls.Certificate{*id.TLSCertificate}, node)
	if err != nil {
		return nil, errors.Wrap(err, "storageclient DialOptionForNode")
	}
	conn, resolverCleanupCb, err := storageclient.DialNode(node, opts)
	if err != nil {
		return nil, errors.Wrap(err, "storageclient DialNode")
	}

	initCh := make(chan struct{})
	close(initCh)

	return &honestNodeStorage{
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
	panic("not implemented")
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
