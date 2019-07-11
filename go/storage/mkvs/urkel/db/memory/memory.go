// Package memory provides a memory-backed node database.
package memory

import (
	"container/list"
	"context"
	"sync"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

var _ api.NodeDB = (*memoryNodeDB)(nil)

type doubleHash [2 * hash.Size]byte

type writeLogDigest []logEntryDigest

type logEntryDigest struct {
	key  []byte
	leaf *node.LeafNode
}

type lifetime struct {
	endRound   uint64
	startRound uint64
}

type rootInfo struct {
	// next is the hash of the following root.
	next *hash.Hash

	// gcIndexUpdates are the updates to the gcIndex that need to be applied
	// in case this root is finalized.
	gcIndexUpdates map[lifetime]map[hash.Hash]bool
	// addedNodes are the nodes that have been added by this root so that we
	// can remove them if this root turns out to be not finalized.
	addedNodes []hash.Hash
}

type round struct {
	number uint64

	roots     map[hash.Hash]*rootInfo
	writeLogs map[doubleHash]writeLogDigest
}

type namespace struct {
	roundList          *list.List
	rounds             map[uint64]*list.Element
	lastFinalizedRound *uint64

	nodes map[hash.Hash][]byte

	gcIndex map[lifetime]map[hash.Hash]bool
}

func (ns *namespace) getPreviousRound(rnd uint64) (uint64, error) {
	var prev *list.Element
	r := ns.rounds[rnd]
	if r == nil {
		// Round does not exist so it must be the last one.
		prev = ns.roundList.Back()
	} else {
		prev = r.Prev()
	}

	if prev == nil {
		return 0, nil
	}

	num := prev.Value.(*round).number
	if num >= rnd {
		return 0, api.ErrRoundWentBackwards
	}
	return num, nil
}

type memoryNodeDB struct {
	api.CheckpointableDB

	sync.RWMutex

	namespaces map[common.Namespace]*namespace
}

func (h doubleHash) fromRoots(startRoot node.Root, endRoot node.Root) {
	copy(h[:hash.Size], startRoot.Hash[:])
	copy(h[hash.Size:], endRoot.Hash[:])
}

// New creates a new in-memory node database.
func New() (api.NodeDB, error) {
	db := &memoryNodeDB{
		namespaces: make(map[common.Namespace]*namespace),
	}
	db.CheckpointableDB = api.NewCheckpointableDB(db)
	return db, nil
}

func (d *memoryNodeDB) getNamespaceLocked(ns common.Namespace) *namespace {
	n := d.namespaces[ns]
	if n == nil {
		n = &namespace{
			roundList: list.New(),
			rounds:    make(map[uint64]*list.Element),
			nodes:     make(map[hash.Hash][]byte),
			gcIndex:   make(map[lifetime]map[hash.Hash]bool),
		}
		d.namespaces[ns] = n
	}
	return n
}

func (d *memoryNodeDB) GetNode(root node.Root, ptr *node.Pointer) (node.Node, error) {
	if ptr == nil || !ptr.IsClean() {
		panic("urkel: attempted to get invalid pointer from node database")
	}

	d.RLock()
	defer d.RUnlock()

	raw, err := d.getLocked(root, ptr.Hash)
	if err != nil {
		return nil, err
	}

	return node.UnmarshalBinary(raw)
}

func (d *memoryNodeDB) GetWriteLog(ctx context.Context, startRoot node.Root, endRoot node.Root) (api.WriteLogIterator, error) {
	if !endRoot.Follows(&startRoot) {
		return nil, api.ErrRootMustFollowOld
	}

	d.RLock()
	defer d.RUnlock()

	var key doubleHash
	key.fromRoots(startRoot, endRoot)

	ns := d.getNamespaceLocked(endRoot.Namespace)
	re := ns.rounds[endRoot.Round]
	if re == nil {
		return nil, api.ErrWriteLogNotFound
	}

	round := re.Value.(*round)
	log, ok := round.writeLogs[key]
	if !ok {
		return nil, api.ErrWriteLogNotFound
	}

	writeLog := make(writelog.WriteLog, len(log))
	for idx, entry := range log {
		writeLog[idx] = writelog.LogEntry{
			Key:   entry.key,
			Value: entry.leaf.Value.Value,
		}
	}

	return api.NewStaticWriteLogIterator(writeLog), nil
}

func (d *memoryNodeDB) HasRoot(root node.Root) bool {
	// An empty root is always implicitly present.
	if root.Hash.IsEmpty() {
		return true
	}

	d.RLock()
	defer d.RUnlock()

	ns := d.getNamespaceLocked(root.Namespace)
	r := ns.rounds[root.Round]
	if r == nil {
		return false
	}

	return r.Value.(*round).roots[root.Hash] != nil
}

func (d *memoryNodeDB) Finalize(ctx context.Context, namespace common.Namespace, rnd uint64, roots []hash.Hash) error {
	d.Lock()
	defer d.Unlock()

	ns := d.getNamespaceLocked(namespace)

	// Make sure that the previous round has been finalized.
	if rnd > 0 && (ns.lastFinalizedRound == nil || *ns.lastFinalizedRound < (rnd-1)) {
		return api.ErrNotFinalized
	}
	// Make sure that this round has not yet been finalized.
	if ns.lastFinalizedRound != nil && rnd <= *ns.lastFinalizedRound {
		return api.ErrAlreadyFinalized
	}

	re := ns.rounds[rnd]
	if re == nil {
		return api.ErrRoundNotFound
	}
	r := re.Value.(*round)

	// Determine a set of finalized roots. Finalization is transitive, so if
	// a parent root is finalized the child should be consider finalized too.
	finalizedRoots := make(map[hash.Hash]bool)
	for _, rootHash := range roots {
		finalizedRoots[rootHash] = true
	}

	for updated := true; updated; {
		updated = false

		for rootHash, ri := range r.roots {
			// If next root hash is among the finalized roots, add this root as well.
			if !finalizedRoots[rootHash] && ri.next != nil && finalizedRoots[*ri.next] {
				finalizedRoots[rootHash] = true
				updated = true
			}
		}
	}

	// Go through all roots and either commit GC updates or prune them based on
	// whether they are included in the finalized roots or not.
	for rootHash, ri := range r.roots {
		if finalizedRoots[rootHash] {
			// Commit garbage collection index updates for any finalized roots.
			for lt, pnodes := range ri.gcIndexUpdates {
				nodes := ns.gcIndex[lt]
				if nodes == nil {
					nodes = make(map[hash.Hash]bool)
					ns.gcIndex[lt] = nodes
				}

				for h := range pnodes {
					nodes[h] = true
				}
			}
		} else {
			// Remove any non-finalized roots. It is safe to remove these nodes
			// as they can never be resurrected due to the round being part of the
			// node hash.
			for _, h := range ri.addedNodes {
				delete(ns.nodes, h)
			}
			delete(r.roots, rootHash)
		}

		ri.gcIndexUpdates = nil
		ri.addedNodes = nil
	}

	ns.lastFinalizedRound = &rnd

	return nil
}

func (d *memoryNodeDB) Prune(ctx context.Context, namespace common.Namespace, rnd uint64) (int, error) {
	var pruned int
	ns := d.getNamespaceLocked(namespace)

	re := ns.rounds[rnd]
	if re == nil {
		return 0, api.ErrRoundNotFound
	}
	r := re.Value.(*round)

	// Make sure that the round that we try to prune has been finalized.
	if ns.lastFinalizedRound == nil || *ns.lastFinalizedRound < rnd {
		return 0, api.ErrNotFinalized
	}

	pruneHashes := make(map[hash.Hash]bool)

	// Check for any lone roots as those should be pruned since no further round
	// will reference them.
	for rootHash, ri := range r.roots {
		if ri.next != nil {
			continue
		}

		// Traverse the root and prune all items created in this round.
		root := node.Root{Namespace: namespace, Round: rnd, Hash: rootHash}
		err := api.Visit(ctx, d, root, func(ctx context.Context, n node.Node) bool {
			if n.GetCreatedRound() == rnd {
				pruneHashes[n.GetHash()] = true
			}
			return true
		})
		if err != nil {
			return 0, err
		}
	}

	prevRound, err := ns.getPreviousRound(rnd)
	if err != nil {
		return 0, err
	}

	// XXX: This is suboptimal as we don't have a proper range scan.
	for lt, nodes := range ns.gcIndex {
		if lt.endRound != rnd {
			continue
		}

		delete(ns.gcIndex, lt)

		if lt.startRound > prevRound || lt.startRound == lt.endRound {
			// Either start round is after the previous round or the node starts and
			// terminates in the same round. Prune the node(s).
			for h := range nodes {
				pruneHashes[h] = true
			}
		} else {
			// Since the current round is being pruned, the lifetime ends at the
			// previous round.
			lt.endRound = prevRound
			ns.gcIndex[lt] = nodes
		}
	}

	for h := range pruneHashes {
		delete(ns.nodes, h)
		pruned++
	}

	// Prune round.
	ns.roundList.Remove(re)

	return pruned, nil
}

func (d *memoryNodeDB) Close() {
}

func (d *memoryNodeDB) getLocked(root node.Root, id hash.Hash) ([]byte, error) {
	item := d.getNamespaceLocked(root.Namespace).nodes[id]
	if item == nil {
		return nil, api.ErrNodeNotFound
	}

	return item, nil
}

type memoryBatch struct {
	api.BaseBatch

	db *memoryNodeDB

	namespace common.Namespace
	round     uint64
	oldRoot   node.Root

	ops          []func(newRoot node.Root, ns *namespace)
	removedNodes []node.Node
	addedNodes   []hash.Hash
}

func (d *memoryNodeDB) NewBatch(namespace common.Namespace, round uint64, oldRoot node.Root) api.Batch {
	return &memoryBatch{
		db:        d,
		namespace: namespace,
		round:     round,
		oldRoot:   oldRoot,
	}
}

func (b *memoryBatch) MaybeStartSubtree(subtree api.Subtree, depth node.Depth, subtreeRoot *node.Pointer) api.Subtree {
	if subtree == nil {
		return &memorySubtree{batch: b}
	}
	return subtree
}

func (b *memoryBatch) PutWriteLog(writeLog writelog.WriteLog, annotations writelog.WriteLogAnnotations) error {
	b.ops = append(b.ops, func(newRoot node.Root, ns *namespace) {
		digest := make(writeLogDigest, len(writeLog))
		for idx, entry := range writeLog {
			if annotations[idx].InsertedNode != nil {
				nd := annotations[idx].InsertedNode.Node
				if nd == nil {
					raw, err := b.db.getLocked(newRoot, annotations[idx].InsertedNode.Hash)
					if err != nil {
						panic(err)
					}

					nd, err = node.UnmarshalBinary(raw)
					if err != nil {
						panic(err)
					}
				}
				digest[idx] = logEntryDigest{
					key:  entry.Key,
					leaf: nd.(*node.LeafNode),
				}
			} else {
				digest[idx] = logEntryDigest{
					key:  entry.Key,
					leaf: nil,
				}
			}
		}

		var key doubleHash
		key.fromRoots(b.oldRoot, newRoot)

		round := ns.rounds[newRoot.Round].Value.(*round)
		round.writeLogs[key] = digest
	})
	return nil
}

func (b *memoryBatch) RemoveNodes(nodes []node.Node) error {
	b.removedNodes = nodes
	return nil
}

func (b *memoryBatch) Commit(root node.Root) error {
	if !root.Follows(&b.oldRoot) {
		return api.ErrRootMustFollowOld
	}

	b.db.Lock()
	defer b.db.Unlock()

	ns := b.db.getNamespaceLocked(root.Namespace)
	prevRound, err := ns.getPreviousRound(root.Round)
	if err != nil {
		return err
	}

	// Check old root.
	var oldRootInfo *rootInfo
	if !b.oldRoot.Hash.IsEmpty() {
		if prevRound != b.oldRoot.Round && b.oldRoot.Round != root.Round {
			return api.ErrPreviousRoundMismatch
		}

		oldRoundElem := ns.rounds[b.oldRoot.Round]
		if oldRoundElem == nil {
			return api.ErrRoundNotFound
		}
		oldRound := oldRoundElem.Value.(*round)
		oldRootInfo = oldRound.roots[b.oldRoot.Hash]
		if oldRootInfo == nil {
			return api.ErrRootNotFound
		}
	}

	// Create new root.
	var r *round
	re := ns.rounds[root.Round]
	if re == nil {
		last := ns.roundList.Back()
		if last != nil && last.Value.(*round).number >= root.Round {
			return api.ErrRoundWentBackwards
		}

		r = &round{
			number:    root.Round,
			roots:     make(map[hash.Hash]*rootInfo),
			writeLogs: make(map[doubleHash]writeLogDigest),
		}
		ns.rounds[root.Round] = ns.roundList.PushBack(r)
	} else {
		r = re.Value.(*round)
	}

	ri := &rootInfo{
		gcIndexUpdates: make(map[lifetime]map[hash.Hash]bool),
	}
	r.roots[root.Hash] = ri

	// Mark the old root as having a successor.
	if oldRootInfo != nil {
		oldRootInfo.next = &root.Hash
	}

	// Apply operations.
	for _, op := range b.ops {
		op(root, ns)
	}
	ri.addedNodes = b.addedNodes

	// Mark removed nodes for garbage collection. Updates against the GC index
	// are only applied in case this root is finalized.
	for _, n := range b.removedNodes {
		// Node lives from the round it was created in up to the previous round.
		//
		// NOTE: The node will never be resurrected as the round number is part
		//       of the node hash.
		lt := lifetime{endRound: prevRound, startRound: n.GetCreatedRound()}
		if b.oldRoot.Round == root.Round {
			// If the previous root is in the same round, the node needs to end
			// in the same round instead.
			lt.endRound = root.Round
		}

		nodes := ri.gcIndexUpdates[lt]
		if nodes == nil {
			nodes = make(map[hash.Hash]bool)
			ri.gcIndexUpdates[lt] = nodes
		}
		nodes[n.GetHash()] = true
	}

	b.Reset()

	return b.BaseBatch.Commit(root)
}

func (b *memoryBatch) Reset() {
	b.ops = nil
	b.removedNodes = nil
	b.addedNodes = nil
}

type memorySubtree struct {
	batch *memoryBatch
}

func (s *memorySubtree) PutNode(depth node.Depth, ptr *node.Pointer) error {
	data, err := ptr.Node.MarshalBinary()
	if err != nil {
		return err
	}

	s.batch.ops = append(s.batch.ops, func(newRoot node.Root, ns *namespace) {
		h := ptr.Node.GetHash()
		ns.nodes[h] = data
		s.batch.addedNodes = append(s.batch.addedNodes, h)
	})
	return nil
}

func (s *memorySubtree) VisitCleanNode(depth node.Depth, ptr *node.Pointer) error {
	return nil
}

func (s *memorySubtree) Commit() error {
	return nil
}
