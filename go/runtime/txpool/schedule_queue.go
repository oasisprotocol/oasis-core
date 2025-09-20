package txpool

import (
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/google/btree"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

// blockTransaction is a transaction within a block.
type blockTransaction struct {
	raw      *MainQueueTransaction
	block    *transactionBlock
	position int
}

// transactionBlock is a collection of transactions.
//
// Although it can contain transactions from any source, it is most useful
// when the transactions come from the same sender and are ordered by their
// sequence number in ascending order.
type transactionBlock struct {
	txs []*blockTransaction
}

// newTransactionBlock creates a new transaction block.
func newTransactionBlock(raws ...*MainQueueTransaction) *transactionBlock {
	blk := &transactionBlock{
		txs: make([]*blockTransaction, 0, len(raws)),
	}

	for i, raw := range raws {
		tx := &blockTransaction{
			raw:      raw,
			block:    blk,
			position: i,
		}
		blk.txs = append(blk.txs, tx)
	}

	return blk
}

// empty returns true if the block contains no transactions.
func (b *transactionBlock) empty() bool {
	return len(b.txs) == 0
}

// size returns the number of transactions in the block.
func (b *transactionBlock) size() int {
	return len(b.txs)
}

// first returns the first transaction in the block.
func (b *transactionBlock) first() (*blockTransaction, bool) {
	if len(b.txs) == 0 {
		return nil, false
	}
	return b.txs[0], true
}

// last returns the last transaction in the block.
func (b *transactionBlock) last() (*blockTransaction, bool) {
	if len(b.txs) == 0 {
		return nil, false
	}
	return b.txs[len(b.txs)-1], true
}

// pop removes and returns the last transaction in the block.
func (b *transactionBlock) pop() (*blockTransaction, bool) {
	if len(b.txs) == 0 {
		return nil, false
	}

	pos := len(b.txs) - 1
	last := b.txs[pos]
	b.txs = b.txs[:pos]

	return last, true
}

// clear removes all transactions from the block.
func (b *transactionBlock) clear() {
	b.txs = nil
}

// split divides the block into two at the given position.
func (b *transactionBlock) split(pos int) (*transactionBlock, *transactionBlock) {
	pos = min(pos, len(b.txs))

	leftTxs := b.txs[:pos]
	rightTxs := b.txs[pos:]

	left := &transactionBlock{
		txs: leftTxs,
	}
	for i, tx := range leftTxs {
		tx.block = left
		tx.position = i
	}

	right := &transactionBlock{
		txs: slices.Clone(rightTxs),
	}
	for i, tx := range rightTxs {
		tx.block = right
		tx.position = i
	}

	b.clear()

	return left, right
}

// merge moves all transactions from the given block to the current block.
func (b *transactionBlock) merge(blk *transactionBlock) {
	for _, tx := range blk.txs {
		tx.block = b
		tx.position = len(b.txs)
		b.txs = append(b.txs, tx)
	}

	blk.clear()
}

// partition splits the block into smaller adjacent blocks to prioritize
// earlier blocks.
func (b *transactionBlock) partition() []*transactionBlock {
	// Split to pieces.
	blks := make([]*transactionBlock, 0, len(b.txs))
	for _, tx := range b.txs {
		blk := newTransactionBlock(tx.raw)
		blks = append(blks, blk)
	}

	// Merge from right to left.
	for i := len(blks) - 2; i >= 0; i-- {
		left := blks[i]

		for i+1 < len(blks) {
			right := blks[i+1]

			if left.priority() > right.priority() {
				break
			}

			left.merge(right)

			for j := i + 2; j < len(blks); j++ {
				blks[j-1] = blks[j]
			}
			blks = blks[:len(blks)-1]
		}
	}

	return blks
}

// priority computes the average priority of all transactions in the block.
func (b *transactionBlock) priority() uint64 {
	if len(b.txs) == 0 {
		return 0
	}

	// Prevent overflow by summing quotients first, then handling remainders.
	var quotients uint64
	for _, tx := range b.txs {
		quotients += tx.raw.priority / uint64(len(b.txs))
	}
	var reminders uint64
	for _, tx := range b.txs {
		reminders += tx.raw.priority % uint64(len(b.txs))
	}
	average := quotients + reminders/uint64(len(b.txs))

	return average
}

// firstSeen computes the average first-seen timestamp of all transactions
// in the block.
func (b *transactionBlock) firstSeen() time.Time {
	if len(b.txs) == 0 {
		return time.Unix(0, 0)
	}

	var total int64
	for _, tx := range b.txs {
		total += tx.raw.firstSeen.UnixNano()
	}
	average := total / int64(len(b.txs))

	return time.Unix(0, average)
}

// transactionBlockLess is a comparison function for ordering transaction
// blocks by priority.
func transactionBlockLess(b1, b2 *transactionBlock) bool {
	switch {
	case b1 == b2:
		return false
	case b1 == nil:
		return false // nil is last (descending order).
	case b2 == nil:
		return true // nil is last (descending order).
	}

	// We are iterating over the queue in descending order, so we want higher
	// priority blocks to be later in the queue.
	p1 := b1.priority()
	p2 := b2.priority()
	if p1 != p2 {
		return p1 < p2
	}

	// If blocks have the same priority, sort by average seen time
	// (earlier transactions are later in the queue as we are iterating
	// over the queue in descending order).
	t1 := b1.firstSeen()
	t2 := b2.firstSeen()
	return t1.After(t2)
}

// scheduleQueue prioritizes transactions by highest priority, while ensuring
// that transactions from the same sender are returned in ascending sequence
// number order and only when all preceding transactions are present.
type scheduleQueue struct {
	mu sync.Mutex

	capacity int
	limit    int

	txs         map[hash.Hash]*blockTransaction
	txsBySender map[string]map[uint64]*blockTransaction

	blocks *btree.BTreeG[*transactionBlock]
}

// newScheduleQueue creates a new schedule queue with the given capacity
// and maximum transaction limit per sender.
func newScheduleQueue(capacity int, limit int) *scheduleQueue {
	return &scheduleQueue{
		capacity:    capacity,
		limit:       limit,
		txs:         make(map[hash.Hash]*blockTransaction),
		txsBySender: make(map[string]map[uint64]*blockTransaction),
		blocks:      btree.NewG(2, transactionBlockLess),
	}
}

// size returns the number of transactions in the queue.
func (q *scheduleQueue) size() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.txs)
}

// clear removes all transactions from the queue.
func (q *scheduleQueue) clear() {
	q.mu.Lock()
	defer q.mu.Unlock()

	clear(q.txs)
	clear(q.txsBySender)
	q.blocks.Clear(true)
}

// get returns a transaction by its hash from the queue.
func (q *scheduleQueue) get(h hash.Hash) (*MainQueueTransaction, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	tx, ok := q.txs[h]
	if !ok {
		return nil, false
	}
	return tx.raw, true
}

// all returns all transactions currently in the queue.
func (q *scheduleQueue) all() []*MainQueueTransaction {
	q.mu.Lock()
	defer q.mu.Unlock()

	txs := make([]*MainQueueTransaction, 0, len(q.txs))
	for _, tx := range q.txs {
		txs = append(txs, tx.raw)
	}
	return txs
}

// add inserts a new transaction into the queue.
func (q *scheduleQueue) add(raw *MainQueueTransaction) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	senderTxs, ok := q.txsBySender[raw.sender]
	if !ok {
		senderTxs = make(map[uint64]*blockTransaction)
		q.txsBySender[raw.sender] = senderTxs
	}

	// Remove expired transactions.
	for _, tx := range senderTxs {
		if tx.raw.senderSeq >= raw.senderStateSeq {
			continue
		}
		q.removeLocked(tx, senderTxs)
	}

	// Reject duplicate transaction.
	if _, ok := q.txs[raw.hash]; ok {
		return fmt.Errorf("duplicate transaction: %s", raw.hash)
	}

	// Bump existing transaction.
	if tx, ok := senderTxs[raw.senderSeq]; ok {
		if raw.priority < tx.raw.priority {
			return fmt.Errorf("replacement transaction has lower priority: %s", raw.hash)
		}
		q.removeLocked(tx, senderTxs)
	}

	// Make space for the new transaction.
	switch {
	case len(senderTxs) >= q.limit:
		// If the sender has reached the limit, remove one of his transactions.
		var last *blockTransaction
		for _, tx := range senderTxs {
			if last == nil || last.raw.senderSeq < tx.raw.senderSeq {
				last = tx
			}
		}
		if last == nil || last.raw.senderSeq <= raw.senderSeq {
			// Reject if the limit is 0 or if the new transaction has
			// the highest sequence number among the sender's transactions
			// in the queue.
			return fmt.Errorf("sender queue is full")
		}
		q.removeLocked(last, senderTxs)
	case len(q.txs) >= q.capacity:
		// If the queue is full, remove the last transaction from a block
		// with the lowest priority.
		tx, ok := func() (*blockTransaction, bool) {
			blk, ok := q.blocks.Min()
			if !ok {
				return nil, false
			}
			if blk.priority() >= raw.priority {
				return nil, false
			}
			return blk.last()
		}()
		if !ok {
			// Reject if the capacity is 0 or if the new transaction has
			// lower priority than the lowest priority block.
			if len(senderTxs) == 0 {
				delete(q.txsBySender, raw.sender)
			}
			return fmt.Errorf("schedule queue is full")
		}
		q.removeLocked(tx, q.txsBySender[tx.raw.sender])
	default:
		// Space is already available.
	}

	// Create a new block with the given transaction.
	blk := newTransactionBlock(raw)
	tx, _ := blk.first()

	q.txs[tx.raw.hash] = tx
	senderTxs[tx.raw.senderSeq] = tx

	q.blocks.ReplaceOrInsert(tx.block)

	// Merge block with adjacent blocks.
	q.tryMergeLocked(tx.block, senderTxs)

	return nil
}

// remove deletes the specified transactions from the queue.
func (q *scheduleQueue) remove(txHashes []hash.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, h := range txHashes {
		tx, ok := q.txs[h]
		if !ok {
			continue
		}
		q.removeLocked(tx, q.txsBySender[tx.raw.sender])
	}
}

// removeLocked deletes the specified transaction from the queue.
func (q *scheduleQueue) removeLocked(tx *blockTransaction, senderTxs map[uint64]*blockTransaction) {
	delete(q.txs, tx.raw.hash)
	delete(senderTxs, tx.raw.senderSeq)
	q.blocks.Delete(tx.block)

	left, right := tx.block.split(tx.position + 1)
	_, _ = left.pop()

	// After removal, we may be able to split the left and the right block
	// into smaller blocks to prioritize earlier blocks.
	for _, blk := range left.partition() {
		q.blocks.ReplaceOrInsert(blk)
	}
	for _, blk := range right.partition() {
		q.blocks.ReplaceOrInsert(blk)
	}
}

// tryMergeLocked attempts to merge the given block with adjacent blocks
// to increase priority of the blocks with lower sequence numbers.
func (q *scheduleQueue) tryMergeLocked(blk *transactionBlock, senderTxs map[uint64]*blockTransaction) {
	for {
		var ok1, ok2 bool
		blk, ok1 = q.tryMergeLeftLocked(blk, senderTxs)
		blk, ok2 = q.tryMergeRightLocked(blk, senderTxs)
		if !ok1 && !ok2 {
			return
		}
	}
}

// tryMergeLeftLocked attempts to merge the given block with the adjacent
// left block containing transactions with lower sequence numbers.
//
// A merge is performed only if the following conditions are met:
//   - The last transaction in the left block is the predecessor of the first
//     transaction in the right block.
//   - Merging the right block into the left doesn't decrease the priority
//     of the left block.
func (q *scheduleQueue) tryMergeLeftLocked(right *transactionBlock, senderTxs map[uint64]*blockTransaction) (*transactionBlock, bool) {
	tx, ok := right.first()
	if !ok {
		return right, false
	}
	if tx.raw.senderSeq == 0 {
		return right, false
	}

	tx, ok = senderTxs[tx.raw.senderSeq-1]
	if !ok {
		return right, false
	}
	left := tx.block

	if left.priority() > right.priority() {
		return right, false
	}

	q.blocks.Delete(left)
	q.blocks.Delete(right)
	left.merge(right)
	q.blocks.ReplaceOrInsert(left)

	return left, true
}

// tryMergeRightLocked attempts to merge the given block with the adjacent
// right block containing transactions with higher sequence numbers.
//
// A merge is performed only if the following conditions are met:
//   - The last transaction in the left block is the predecessor of the first
//     transaction in the right block.
//   - Merging the right block into the left doesn't decrease the priority
//     of the left block.
func (q *scheduleQueue) tryMergeRightLocked(left *transactionBlock, senderTxs map[uint64]*blockTransaction) (*transactionBlock, bool) {
	tx, ok := left.last()
	if !ok {
		return left, false
	}
	if tx.raw.senderSeq == math.MaxUint64 {
		return left, false
	}
	tx, ok = senderTxs[tx.raw.senderSeq+1]
	if !ok {
		return left, false
	}
	right := tx.block

	if left.priority() > right.priority() {
		return left, false
	}

	q.blocks.Delete(left)
	q.blocks.Delete(right)
	left.merge(right)
	q.blocks.ReplaceOrInsert(left)

	return left, true
}

// getPrioritizedBatch returns a batch of transactions ordered by priority,
// starting after the given offset, up to the specified limit.
func (q *scheduleQueue) getPrioritizedBatch(offset *hash.Hash, limit int) []*MainQueueTransaction {
	return q.getBatch(offset, limit, true)
}

// getPrioritizedBatchAll returns a batch of transactions ordered by priority,
// starting after the given offset, up to the specified limit.
//
// This method takes into account all transactions and does not enforce
// sequence number order.
func (q *scheduleQueue) getPrioritizedBatchAll(offset *hash.Hash, limit int) []*MainQueueTransaction {
	return q.getBatch(offset, limit, false)
}

func (q *scheduleQueue) getBatch(offset *hash.Hash, limit int, enforceOrder bool) []*MainQueueTransaction {
	q.mu.Lock()
	defer q.mu.Unlock()

	var (
		lastTx  *blockTransaction
		lastBlk *transactionBlock
	)
	if offset != nil {
		tx, ok := q.txs[*offset]
		if !ok {
			// Offset does not exist so no items will be matched anyway.
			return nil
		}
		lastTx = tx
		lastBlk = tx.block
	}

	batch := make([]*MainQueueTransaction, 0, limit)

	q.blocks.DescendLessOrEqual(lastBlk, func(blk *transactionBlock) bool {
		// Skip a block if it has a gap relative to its predecessor.
		if enforceOrder && !q.shouldQueueLocked(blk) {
			return true
		}

		// Ignore transactions before the offset.
		txs := blk.txs
		if blk == lastBlk {
			txs = txs[lastTx.position+1:]
		}

		// Trim block if it exceeds the remaining limit.
		if available := limit - len(batch); available < len(txs) {
			txs = txs[:available]
		}

		for _, tx := range txs {
			batch = append(batch, tx.raw)
		}

		return len(batch) < limit
	})

	return batch
}

// shouldQueueLocked returns true if the given block should be queued.
//
// A block is queued only if all transactions between it and the sender’s
// transaction with the lowest sequence number are present.
func (q *scheduleQueue) shouldQueueLocked(blk *transactionBlock) bool {
	first, ok := blk.first()
	if !ok {
		return false
	}

	var lower uint64
	lowest := uint64(math.MaxUint64)
	for _, tx := range q.txsBySender[first.raw.sender] {
		lowest = min(lowest, tx.raw.senderSeq)
		if tx.raw.senderSeq < first.raw.senderSeq {
			lower++
		}
	}

	return lowest+lower == first.raw.senderSeq
}
