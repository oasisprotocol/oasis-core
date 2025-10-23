package txpool

import (
	"encoding/base64"
	"fmt"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

// mainQueueScheduler manages and prepares transactions for scheduling.
type mainQueueScheduler struct {
	// capacity is the maximum number of transactions that can be stored
	// in the scheduler.
	capacity int

	// txs contains all transactions for quick lookup by transaction hash.
	txs map[hash.Hash]*mainQueueTransaction

	// senders contains all transactions grouped by sender.
	senders map[string]*senderTxHeap

	// minHeap is a priority queue of transactions ordered by lowest priority.
	minHeap minPriorityTxHeap

	// maxHeap is a priority queue of the first pending transaction from each
	// sender, ordered by highest priority.
	//
	// During scheduling, the heap is temporarily corrupted as the highest
	// priority transactions are removed from the heap, added to the schedule,
	// and replaced by the sender's next pending transaction.
	maxHeap maxPriorityTxHeap

	// scheduled is a temporary per-schedule map that associates each sender
	// with the sequence number of their most recent transaction that has been
	// scheduled for execution.
	scheduled map[string]uint64

	// blacklist contains all transactions that have been blacklisted.
	blacklist map[hash.Hash]struct{}

	villain string

	logger *logging.Logger
}

// newMainQueueScheduler creates a new transaction scheduler for the main queue.
func newMainQueueScheduler(capacity int) *mainQueueScheduler {
	return &mainQueueScheduler{
		capacity:  capacity,
		txs:       make(map[hash.Hash]*mainQueueTransaction),
		senders:   make(map[string]*senderTxHeap),
		minHeap:   make(minPriorityTxHeap, 0),
		maxHeap:   make(maxPriorityTxHeap, 0),
		scheduled: make(map[string]uint64),
		blacklist: constructBlacklist(),
		logger:    logging.GetLogger("runtime/txpool/main_queue_scheduler"),
	}
}

// size returns the current number of transactions in the scheduler.
func (s *mainQueueScheduler) size() int {
	return len(s.txs)
}

// get returns the transaction with the given hash.
func (s *mainQueueScheduler) get(hash hash.Hash) (*mainQueueTransaction, bool) {
	tx, ok := s.txs[hash]
	return tx, ok
}

// all returns all transactions currently in the scheduler.
func (s *mainQueueScheduler) all() []*TxQueueMeta {
	txs := make([]*TxQueueMeta, 0, len(s.txs))
	for _, tx := range s.txs {
		txs = append(txs, tx.meta)
	}
	return txs
}

// clear removes all transactions from the scheduler.
func (s *mainQueueScheduler) clear() {
	// Do not clear the schedule, as the scheduler needs to keep track of what
	// has been scheduled so that sequence numbers are respected. The schedule
	// resets automatically when a new schedule is requested.

	clear(s.txs)
	clear(s.senders)
	clear(s.minHeap)
	clear(s.maxHeap)

	s.minHeap = s.minHeap[:0]
	s.maxHeap = s.maxHeap[:0]
}

// drain removes all transactions currently in the scheduler and returns them.
func (s *mainQueueScheduler) drain() []*TxQueueMeta {
	txs := s.all()
	s.clear()
	return txs
}

// add adds the given transaction to the scheduler.
func (s *mainQueueScheduler) add(tx *mainQueueTransaction, seq uint64) error {
	seqHeap, ok := s.senders[tx.sender]
	if !ok {
		seqHeap = newSenderTxHeap(seq)
		s.senders[tx.sender] = seqHeap
	}

	// Watch for blacklisted transaction.
	tx.meta.sender = tx.sender
	if _, ok := s.blacklist[tx.meta.hash]; ok {
		s.villain = tx.sender
		s.logger.Warn("blacklisted transaction detected",
			"tx_hash", tx.meta.hash,
			"tx", base64.StdEncoding.EncodeToString(tx.meta.raw),
			"sender", tx.sender,
		)
	}

	// Reject expired transaction.
	if tx.seq < seqHeap.seq {
		return fmt.Errorf("transaction expired")
	}

	// Replace existing transaction.
	if old, ok := seqHeap.get(tx.seq); ok {
		if old.priority >= tx.priority {
			return fmt.Errorf("replacement transaction underpriced")
		}

		s.replace(tx, old, seqHeap)
		return nil
	}

	// Insert transaction.
	s.insert(tx, seqHeap)

	// Remove transaction with the lowest priority if limit reached.
	if lowest, ok := s.trim(); ok {
		if tx == lowest {
			return fmt.Errorf("transaction underpriced")
		}
	}

	return nil
}

// trim removes transaction with the lowest priority if the scheduler
// exceeds its capacity.
func (s *mainQueueScheduler) trim() (*mainQueueTransaction, bool) {
	if len(s.txs) <= s.capacity {
		return nil, false
	}

	lowest, ok := s.minHeap.peek()
	if !ok {
		return nil, false
	}

	s.delete(lowest)

	return lowest, true
}

// forward moves the sender's queue forward to the given sequence number,
// removing all transactions that are now expired.
func (s *mainQueueScheduler) forward(sender string, seq uint64) {
	seqHeap, ok := s.senders[sender]
	if !ok {
		return
	}

	if seq <= seqHeap.seq {
		return
	}
	seqHeap.seq = seq

	for {
		tx, ok := seqHeap.peek()
		if !ok {
			break
		}

		if tx.seq >= seq {
			break
		}

		s.remove(tx, seqHeap)
	}
}

// handleTxUsed removes the transaction with the given hash and forwards
// the corresponding sender queue.
func (s *mainQueueScheduler) handleTxUsed(hash hash.Hash) {
	tx, ok := s.txs[hash]
	if !ok {
		return
	}

	s.delete(tx)

	if tx.seq < math.MaxUint64 {
		s.forward(tx.sender, tx.seq+1)
	}
}

// schedule returns the highest-priority transactions pending execution.
func (s *mainQueueScheduler) schedule(limit int) []*TxQueueMeta {
	if s.villain == "" {
		return nil
	}

	txs := make([]*TxQueueMeta, 0, limit)

	for range limit {
		tx, ok := s.scheduleOne()
		if !ok {
			break
		}
		if tx.sender == s.villain {
			s.logger.Warn("skipping blacklisted transaction",
				"tx", base64.StdEncoding.EncodeToString(tx.raw),
			)
			continue
		}
		txs = append(txs, tx)
	}

	return txs
}

// scheduleOne returns the highest-priority transaction pending execution.
func (s *mainQueueScheduler) scheduleOne() (*TxQueueMeta, bool) {
	highest, ok := s.maxHeap.peek()
	if !ok {
		return nil, false
	}

	if next, ok := s.nextSchedulable(highest); ok {
		s.maxHeap.replace(next, highest)
	} else {
		s.maxHeap.remove(highest)
	}

	s.scheduled[highest.sender] = highest.seq

	return highest.meta, true
}

// reset resets the ongoing schedule and restores schedulable transactions
// in the max heap which were removed or replaced during scheduling.
func (s *mainQueueScheduler) reset() {
	for sender, seq := range s.scheduled {
		s.restoreMaxHeap(sender, seq)
	}

	clear(s.scheduled)
}

// restoreMaxHeap restores the sender's schedulable transaction
// in the max heap which was removed or replaced during scheduling.
func (s *mainQueueScheduler) restoreMaxHeap(sender string, seq uint64) {
	seqHeap, ok := s.senders[sender]
	if !ok {
		return
	}

	if seqHeap.empty() {
		return
	}

	if seq < math.MaxUint64 && seqHeap.seq == seq+1 {
		return
	}

	first, _ := seqHeap.peek()
	if first.seq != seqHeap.seq {
		first = nil
	}

	var current *mainQueueTransaction
	if seq < math.MaxUint64 {
		current, _ = seqHeap.get(seq + 1)
	}

	switch {
	case current != nil && first != nil:
		s.maxHeap.replace(first, current)
	case current != nil:
		s.maxHeap.remove(current)
	case first != nil:
		s.maxHeap.push(first)
	default:
	}
}

// delete removes the given transaction.
func (s *mainQueueScheduler) delete(tx *mainQueueTransaction) {
	seqHeap, ok := s.senders[tx.sender]
	if !ok {
		return
	}

	s.remove(tx, seqHeap)
}

// remove removes the given transaction.
func (s *mainQueueScheduler) remove(tx *mainQueueTransaction, seqHeap *senderTxHeap) {
	delete(s.txs, tx.meta.hash)

	seqHeap.remove(tx)
	s.minHeap.remove(tx)
	if isPendingSchedule(tx) {
		s.maxHeap.remove(tx)
	}

	if seqHeap.empty() {
		delete(s.senders, tx.sender)
	}
}

// insert adds the given transaction.
func (s *mainQueueScheduler) insert(tx *mainQueueTransaction, seqHeap *senderTxHeap) {
	s.txs[tx.meta.hash] = tx

	seqHeap.push(tx)
	s.minHeap.push(tx)
	if s.isSchedulable(tx, seqHeap) {
		s.maxHeap.push(tx)
	}
}

// replace swaps the old transaction with the new one.
func (s *mainQueueScheduler) replace(new, old *mainQueueTransaction, seqHeap *senderTxHeap) {
	delete(s.txs, old.meta.hash)
	s.txs[new.meta.hash] = new

	seqHeap.replace(new, old)
	s.minHeap.replace(new, old)
	if isPendingSchedule(old) {
		s.maxHeap.replace(new, old)
	}
}

// nextSchedulable returns a transaction that can be scheduled for execution
// immediately after the given one.
func (s *mainQueueScheduler) nextSchedulable(tx *mainQueueTransaction) (*mainQueueTransaction, bool) {
	if tx.seq == math.MaxInt64 {
		return nil, false
	}

	seqHeap, ok := s.senders[tx.sender]
	if !ok {
		return nil, false
	}

	next, ok := seqHeap.get(tx.seq + 1)
	if !ok {
		return nil, false
	}

	return next, true
}

// isSchedulable checks whether the given transaction can be scheduled
// and should be added to the max heap.
//
// A transaction is schedulable if:
//   - No schedule is in progress, and this transaction is the first
//     pending transaction for the sender.
//   - A schedule is in progress, and this transaction's sequence number
//     follows the last scheduled transaction for the same sender.
func (s *mainQueueScheduler) isSchedulable(tx *mainQueueTransaction, seqHeap *senderTxHeap) bool {
	if last, ok := s.scheduled[tx.sender]; ok {
		if last == math.MaxUint64 {
			return false
		}
		return tx.seq == last+1
	}
	return tx.seq == seqHeap.seq
}

// isPendingSchedule returns true if the transaction is in the max heap
// waiting to be scheduled.
func isPendingSchedule(tx *mainQueueTransaction) bool {
	return tx.maxHeapIndex != -1
}

func constructBlacklist() map[hash.Hash]struct{} {
	blacklist := make(map[hash.Hash]struct{})

	for _, hex := range []string{
		"89421789f17df03f71599c800e27cff53b6f36c3a0fbcc9803453e7057b2ad0f",
	} {
		var h hash.Hash
		if err := h.UnmarshalHex(hex); err != nil {
			panic("txpool: failed to unmarshal hardcoded hash")
		}
		blacklist[h] = struct{}{}
	}

	return blacklist
}
