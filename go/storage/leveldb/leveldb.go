// Package leveldb implements the LevelDB backed storage backend.
package leveldb

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "leveldb"

	// DBFile is the default backing store filename.
	DBFile = "storage.leveldb.db"

	// MKVSDBFile is the default MKVS backing store filename.
	MKVSDBFile = "mkvs_storage.leveldb.db"
)

var (
	_ api.Backend = (*leveldbBackend)(nil)

	keyVersion = []byte("version")
	dbVersion  = []byte{0x00}

	prefixValues = []byte("values/")

	leveldbSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ekiden_storage_leveldb_size",
			Help: "Total size of the leveldb table(s) (MiB)",
		},
	)
	leveldbCollectors = []prometheus.Collector{
		leveldbSize,
	}

	metricsOnce sync.Once
)

type leveldbBackend struct {
	logger *logging.Logger
	db     *leveldb.DB
	nodedb nodedb.NodeDB

	signingKey *signature.PrivateKey

	closeOnce sync.Once
}

func (b *leveldbBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	v, err := b.GetBatch(ctx, []api.Key{key})
	if err != nil {
		return nil, err
	}

	if v[0] == nil {
		return nil, api.ErrKeyNotFound
	}

	return v[0], nil
}

func (b *leveldbBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	// While expiration isn't enforced at all, there won't be meaningful
	// concurrent writes to the underlying database, so there is no need
	// to work off a snapshot.

	var values [][]byte
	for _, key := range keys {
		value, err := b.db.Get(append(prefixValues, key[:]...), nil)
		switch err {
		case nil:
		case leveldb.ErrNotFound:
			value = nil
		default:
			return nil, err
		}

		values = append(values, value)
	}

	return values, nil
}

func (b *leveldbBackend) GetReceipt(ctx context.Context, keys []api.Key) (*api.SignedReceipt, error) {
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

func (b *leveldbBackend) Insert(ctx context.Context, value []byte, expiration uint64, opts api.InsertOptions) error {
	return b.InsertBatch(ctx, []api.Value{api.Value{Data: value, Expiration: expiration}}, opts)
}

func (b *leveldbBackend) InsertBatch(ctx context.Context, values []api.Value, opts api.InsertOptions) error {
	b.logger.Debug("InsertBatch",
		"values", values,
	)

	batch := new(leveldb.Batch)
	for _, value := range values {
		hash := api.HashStorageKey(value.Data)
		key := append(prefixValues, hash[:]...)

		batch.Put(key, value.Data)
	}

	wrErr := b.db.Write(batch, &opt.WriteOptions{Sync: true})
	if wrErr == nil {
		b.updateMetrics()
	}

	return wrErr
}

func (b *leveldbBackend) GetKeys(ctx context.Context) (<-chan *api.KeyInfo, error) {
	kiChan := make(chan *api.KeyInfo)

	go func() {
		defer close(kiChan)

		snap, err := b.db.GetSnapshot()
		if err != nil {
			b.logger.Error("GetKeys b.db.GetSnapshot", "err", err)
			return
		}
		defer snap.Release()

		ro := opt.ReadOptions{
			DontFillCache: true,
		}
		iter := snap.NewIterator(util.BytesPrefix(prefixValues), &ro)
		defer iter.Release()

		for iter.Next() {
			// TODO: Fetch actual expiration.
			ki := api.KeyInfo{
				Expiration: epochtime.EpochInvalid,
			}
			copy(ki.Key[:], iter.Key()[len(prefixValues):])
			select {
			case kiChan <- &ki:
			case <-ctx.Done():
				return
			}
		}
		if err := iter.Error(); err != nil {
			b.logger.Error("GetKeys iter.Error", "err", err)
			return
		}
	}()

	return kiChan, nil
}

func (b *leveldbBackend) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*api.MKVSReceipt, error) {
	var r hash.Hash

	// Check if we already have the expected new root in our local DB.
	if urkel.HasRoot(b.nodedb, expectedNewRoot) {
		// We do, don't apply anything.
		r = expectedNewRoot
	} else {
		// We don't, apply operations.
		tree, err := urkel.NewWithRoot(nil, b.nodedb, root)
		if err != nil {
			return nil, err
		}

		for _, entry := range log {
			if len(entry.Value) == 0 {
				err = tree.Remove(entry.Key)
			} else {
				err = tree.Insert(entry.Key, entry.Value)
			}
			if err != nil {
				return nil, err
			}
		}

		_, r, err = tree.Commit()
		if err != nil {
			return nil, err
		}
	}

	receipt := api.MKVSReceiptBody{
		Version: 1,
		Root:    r,
	}
	signed, err := signature.SignSigned(*b.signingKey, api.MKVSReceiptSignatureContext, &receipt)
	if err != nil {
		return nil, err
	}

	return &api.MKVSReceipt{
		Signed: *signed,
	}, nil
}

func (b *leveldbBackend) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	// TODO: Don't create a new root every time (issue #1580).
	tree, err := urkel.NewWithRoot(nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *leveldbBackend) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	// TODO: Don't create a new root every time (issue #1580).
	tree, err := urkel.NewWithRoot(nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetPath(ctx, root, key, startDepth)
}

func (b *leveldbBackend) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	// TODO: Don't create a new root every time (issue #1580).
	tree, err := urkel.NewWithRoot(nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetNode(ctx, root, id)
}

func (b *leveldbBackend) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	// TODO: Don't create a new root every time (issue #1580).
	tree, err := urkel.NewWithRoot(nil, b.nodedb, root)
	if err != nil {
		return nil, err
	}

	return tree.GetValue(ctx, root, id)
}

func (b *leveldbBackend) Cleanup() {
	b.closeOnce.Do(func() {
		b.nodedb.Close()
		_ = b.db.Close()
	})
}

func (b *leveldbBackend) Initialized() <-chan struct{} {
	initCh := make(chan struct{})
	close(initCh)
	return initCh
}

func (b *leveldbBackend) updateMetrics() {
	var stats leveldb.DBStats
	if err := b.db.Stats(&stats); err != nil {
		b.logger.Error("Stats",
			"err", err,
		)
		return
	}

	var total int64
	for _, v := range stats.LevelSizes {
		total += v
	}
	leveldbSize.Set(float64(total) / 1024768.0)
}

func checkVersion(db *leveldb.DB) error {
	ver, err := db.Get(keyVersion, nil)
	switch err {
	case leveldb.ErrNotFound:
		return db.Put(keyVersion, dbVersion, nil)
	case nil:
		break
	default:
		return err
	}

	if !bytes.Equal(ver, dbVersion) {
		return fmt.Errorf("storage/leveldb: incompatible LevelDB store version: '%v'", hex.EncodeToString(ver))
	}

	return nil
}

// New constructs a new LevelDB backed storage Backend instance, using
// the provided path for the database.
func New(dbDir string, mkvsDBDir string, timeSource epochtime.Backend, signingKey *signature.PrivateKey) (api.Backend, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(leveldbCollectors...)
	})

	db, err := leveldb.OpenFile(dbDir, nil)
	if err != nil {
		return nil, err
	}

	if err = checkVersion(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	ndb, err := nodedb.NewLevelDBNodeDB(mkvsDBDir)
	if err != nil {
		return nil, err
	}

	b := &leveldbBackend{
		logger:     logging.GetLogger("storage/leveldb"),
		db:         db,
		nodedb:     ndb,
		signingKey: signingKey,
	}
	b.updateMetrics()

	return b, nil
}
