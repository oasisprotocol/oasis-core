package badger

import (
	"container/list"
	"context"
	"fmt"

	"github.com/dgraph-io/badger/v2"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const maxLRUEntries = 3000000

type lruElement struct {
	hash *hash.Hash
	elem *list.Element
}

type checkerCommon struct {
	ctx context.Context
	txn *badger.Txn
	ndb api.NodeDB

	lru    *list.List
	hashes map[hash.Hash]*list.Element
}

func (cc *checkerCommon) checkNodes(root node.Root) error {
	err := api.Visit(cc.ctx, cc.ndb, root, func(ctx context.Context, n node.Node) bool {
		// We just need to walk through the tree, nothing to do except trying to
		// minimize tree traversal in case multiple roots share some subtrees.
		h := n.GetHash()
		el, ok := cc.hashes[h]
		if ok {
			cc.lru.MoveToFront(el)
			return false
		}
		item := &lruElement{
			hash: &h,
		}
		el = cc.lru.PushFront(item)
		item.elem = el
		cc.hashes[h] = el
		if len(cc.hashes) > maxLRUEntries {
			el = cc.lru.Back()
			cc.lru.Remove(el)
			item = el.Value.(*lruElement)
			delete(cc.hashes, *item.hash)
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("error walking tree at root %v: %w", root, err)
	}
	return nil
}

func checkSanityInternal(ctx context.Context, db *badgerNodeDB, display DisplayHelper) error {
	txn := db.db.NewTransactionAt(maxTimestamp, false)
	defer txn.Discard()

	// Determine last version in the db.
	firstVersion, lastVersion, err := func() (uint64, uint64, error) {
		itOpts := badger.DefaultIteratorOptions
		itOpts.Prefix = rootsMetadataKeyFmt.Encode()
		itOpts.Reverse = true

		itR := txn.NewIterator(itOpts)
		defer itR.Close()

		itR.Seek([]byte{rootsMetadataKeyFmt.Prefix(), 0xff})
		if !itR.Valid() {
			return 0, 0, fmt.Errorf("no roots stored")
		}

		var last uint64
		if !rootsMetadataKeyFmt.Decode(itR.Item().Key(), &last) {
			return 0, 0, fmt.Errorf("last roots metadata key not decodable")
		}

		itOpts.Reverse = false
		itF := txn.NewIterator(itOpts)
		defer itF.Close()

		itF.Rewind()
		if !itF.Valid() {
			return 0, 0, fmt.Errorf("no roots stored")
		}

		var first uint64
		if !rootsMetadataKeyFmt.Decode(itF.Item().Key(), &first) {
			return 0, 0, fmt.Errorf("first roots metadata key not decodable")
		}
		return first, last, nil
	}()
	if err != nil {
		return fmt.Errorf("mkvs/badger/check: %w", err)
	}
	totalVersions := lastVersion - firstVersion + 1

	itOpts := badger.DefaultIteratorOptions
	itOpts.Prefix = rootsMetadataKeyFmt.Encode()
	it := txn.NewIterator(itOpts)
	defer it.Close()

	display.DisplayStepBegin("checking per-version storage trees")
	var version, doneVersions uint64
	common := &checkerCommon{
		ctx: ctx,
		txn: txn,
		ndb: db,

		lru:    list.New(),
		hashes: map[hash.Hash]*list.Element{},
	}

	for it.Rewind(); it.Valid(); it.Next() {
		rootsMeta := &rootsMetadata{}
		if !rootsMetadataKeyFmt.Decode(it.Item().Key(), &version) {
			return fmt.Errorf("mkvs/badger/check: undecodable roots metadata key (%v) at item version %d", it.Item().Key(), it.Item().Version())
		}
		err = it.Item().Value(func(val []byte) error {
			return cbor.Unmarshal(val, &rootsMeta)
		})
		if err != nil {
			return fmt.Errorf("mkvs/badger/check: error reading roots metadata for version %d: %w", version, err)
		}

		for rootHash := range rootsMeta.Roots {
			root := node.Root{
				Namespace: db.namespace,
				Version:   version,
				Type:      rootHash.Type(),
				Hash:      rootHash.Hash(),
			}
			if err = common.checkNodes(root); err != nil {
				return fmt.Errorf("mkvs/badger/check: error traversing tree nodes for root %v: %w", root, err)
			}
		}

		doneVersions++
		display.DisplayProgress("versions checked", doneVersions, totalVersions)
	}

	return nil
}

// CheckSanity checks the sanity of the node database by traversing all stored trees.
func CheckSanity(ctx context.Context, cfg *api.Config, display DisplayHelper) error {
	db := &badgerNodeDB{
		logger:           logging.GetLogger("mkvs/db/badger/migrate"),
		namespace:        cfg.Namespace,
		discardWriteLogs: cfg.DiscardWriteLogs,
	}
	roCfg := *cfg
	roCfg.ReadOnly = true
	opts := commonConfigToBadgerOptions(&roCfg, db)

	var err error
	if db.db, err = badger.OpenManaged(opts); err != nil {
		return fmt.Errorf("mkvs/badger/check: failed to open database: %w", err)
	}
	defer db.Close()

	// Make sure that we can discard any deleted/invalid metadata.
	db.db.SetDiscardTs(tsMetadata)

	return checkSanityInternal(ctx, db, display)
}
