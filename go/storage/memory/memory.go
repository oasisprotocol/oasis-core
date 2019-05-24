// Package memory implements the memory backed storage backend.
package memory

import (
	"context"
	"encoding/hex"
	"sync"

	"github.com/opentracing/opentracing-go"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/storage/api"
)

// BackendName is the name of this implementation.
const BackendName = "memory"

var (
	_ api.Backend          = (*memoryBackend)(nil)
	_ api.SweepableBackend = (*memoryBackend)(nil)
)

type memoryEntry struct {
	value      []byte
	expiration epochtime.EpochTime
}

type memoryBackend struct {
	sync.RWMutex

	logger  *logging.Logger
	store   map[api.Key]*memoryEntry
	sweeper *api.Sweeper
	nodedb  nodedb.NodeDB

	signingKey *signature.PrivateKey
}

func (b *memoryBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return nil, api.ErrIncoherentTime
	}

	b.RLock()
	defer b.RUnlock()

	ent, ok := b.store[key]
	if !ok {
		return nil, api.ErrKeyNotFound
	}
	if ent.expiration < epoch {
		return nil, api.ErrKeyExpired
	}

	return append([]byte{}, ent.value...), nil
}

func (b *memoryBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	var values [][]byte
	for _, key := range keys {
		value, err := b.Get(ctx, key)
		if err != nil {
			switch err {
			case nil, api.ErrKeyNotFound, api.ErrKeyExpired:
				break
			default:
				return nil, err
			}
		}

		values = append(values, value)
	}

	return values, nil
}

func (b *memoryBackend) GetReceipt(ctx context.Context, keys []api.Key) (*api.SignedReceipt, error) {
	if b.signingKey == nil {
		return nil, api.ErrCantProve
	}

	if _, err := b.GetBatch(ctx, keys); err != nil {
		return nil, err
	}

	receipt := api.Receipt{
		Keys: keys,
	}
	signed, err := signature.SignSigned(*b.signingKey, api.ReceiptSignatureContext, &receipt)
	if err != nil {
		return nil, err
	}

	return &api.SignedReceipt{
		Signed: *signed,
	}, nil
}

func (b *memoryBackend) Insert(ctx context.Context, value []byte, expiration uint64, opts api.InsertOptions) error {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return api.ErrIncoherentTime
	}

	key := api.HashStorageKey(value)
	ent := &memoryEntry{
		value:      append([]byte{}, value...),
		expiration: epoch + epochtime.EpochTime(expiration),
	}

	b.logger.Debug("Insert",
		"key", key,
		"value", hex.EncodeToString(value),
		"expiration", ent.expiration,
	)

	span, _ := opentracing.StartSpanFromContext(ctx, "storage-memory-lock-set",
		opentracing.Tag{Key: "ekiden.storage_key", Value: key},
	)

	b.Lock()
	defer b.Unlock()

	// XXX: This will unconditionally overwrite the expiration time
	// of existing entries.  Should it do something better?  (eg: Use
	// the longer of the two.)
	b.store[key] = ent

	span.Finish()

	return nil
}

func (b *memoryBackend) InsertBatch(ctx context.Context, values []api.Value, opts api.InsertOptions) error {
	// No atomicity for in-memory backend, we just repeatedly insert.
	for _, value := range values {
		if err := b.Insert(ctx, value.Data, value.Expiration, opts); err != nil {
			return err
		}
	}

	return nil
}

func (b *memoryBackend) GetKeys(ctx context.Context) (<-chan *api.KeyInfo, error) {
	kiChan := make(chan *api.KeyInfo)

	go func() {
		b.RLock()
		defer b.RUnlock()
		defer close(kiChan)

		for k, ent := range b.store {
			ki := api.KeyInfo{
				Key:        k,
				Expiration: ent.expiration,
			}
			select {
			case kiChan <- &ki:
			case <-ctx.Done():
				break
			}
		}
	}()

	return kiChan, nil
}

func (b *memoryBackend) apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*hash.Hash, error) {
	var r hash.Hash

	// Check if we already have the expected new root in our local DB.
	if urkel.HasRoot(b.nodedb, expectedNewRoot) {
		// We do, don't apply anything.
		r = expectedNewRoot
	} else {
		// We don't, apply operations.
		tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}

		for _, entry := range log {
			if len(entry.Value) == 0 {
				err = tree.Remove(ctx, entry.Key)
			} else {
				err = tree.Insert(ctx, entry.Key, entry.Value)
			}
			if err != nil {
				return nil, err
			}
		}

		_, r, err = tree.Commit(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &r, nil
}

func (b *memoryBackend) signReceipt(ctx context.Context, roots []hash.Hash) (*api.MKVSReceipt, error) {
	receipt := api.MKVSReceiptBody{
		Version: 1,
		Roots:   roots,
	}
	signed, err := signature.SignSigned(*b.signingKey, api.MKVSReceiptSignatureContext, &receipt)
	if err != nil {
		return nil, err
	}

	return &api.MKVSReceipt{
		Signed: *signed,
	}, nil
}

func (b *memoryBackend) ApplyBatch(ctx context.Context, ops []api.ApplyOp) (*api.MKVSReceipt, error) {
	var roots []hash.Hash
	for _, op := range ops {
		root, err := b.apply(ctx, op.Root, op.ExpectedNewRoot, op.WriteLog)
		if err != nil {
			return nil, err
		}
		roots = append(roots, *root)
	}

	return b.signReceipt(ctx, roots)
}

func (b *memoryBackend) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*api.MKVSReceipt, error) {
	r, err := b.apply(ctx, root, expectedNewRoot, log)
	if err != nil {
		return nil, err
	}

	return b.signReceipt(ctx, []hash.Hash{*r})
}

func (b *memoryBackend) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *memoryBackend) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetPath(ctx, root, key, startDepth)
}

func (b *memoryBackend) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetNode(ctx, root, id)
}

func (b *memoryBackend) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	tree, err := urkel.NewWithRoot(ctx, nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetValue(ctx, root, id)
}

func (b *memoryBackend) PurgeExpired(epoch epochtime.EpochTime) {
	b.Lock()
	defer b.Unlock()

	for key, ent := range b.store {
		if ent.expiration < epoch {
			b.logger.Debug("Expire",
				"key", key,
			)
			delete(b.store, key)
		}
	}
}

func (b *memoryBackend) Cleanup() {
	b.sweeper.Close()
	b.nodedb.Close()
}

func (b *memoryBackend) Initialized() <-chan struct{} {
	return b.sweeper.Initialized()
}

// New constructs a new memory backed storage Backend instance.
func New(timeSource epochtime.Backend, signingKey *signature.PrivateKey) api.Backend {
	ndb, _ := nodedb.NewMemoryNodeDB()

	b := &memoryBackend{
		logger:     logging.GetLogger("storage/memory"),
		store:      make(map[api.Key]*memoryEntry),
		signingKey: signingKey,
		nodedb:     ndb,
	}
	b.sweeper = api.NewSweeper(b, timeSource)

	return b
}
