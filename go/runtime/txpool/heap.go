package txpool

import (
	"container/heap"
)

// senderTxHeap is a heap of sender's transactions ordered by sequence number.
type senderTxHeap struct {
	// txs provides quick lookup of the sender’s transactions by nonce.
	txs map[uint64]*mainQueueTransaction

	// seqHeap is a min-heap of transactions ordered by sequence number.
	seqHeap seqNumTxHeap

	// seq is the latest confirmed sequence number for the sender.
	seq uint64
}

// newSenderTxHeap creates a new sender heap.
func newSenderTxHeap(seq uint64) *senderTxHeap {
	return &senderTxHeap{
		txs:     make(map[uint64]*mainQueueTransaction),
		seqHeap: make([]*mainQueueTransaction, 0, 1),
		seq:     seq,
	}
}

// empty returns true if the heap has no transactions.
func (h *senderTxHeap) empty() bool {
	return len(h.seqHeap) == 0
}

// get returns a transaction by its sequence number.
func (h *senderTxHeap) get(seq uint64) (*mainQueueTransaction, bool) {
	tx, ok := h.txs[seq]
	return tx, ok
}

// peek returns the transaction with the lowest sequence number.
func (h *senderTxHeap) peek() (*mainQueueTransaction, bool) {
	return h.seqHeap.peek()
}

// push adds the given transaction to the heap.
func (h *senderTxHeap) push(tx *mainQueueTransaction) {
	h.seqHeap.push(tx)
	h.txs[tx.seq] = tx
}

// remove removes the given transaction from the heap.
func (h *senderTxHeap) remove(tx *mainQueueTransaction) {
	h.seqHeap.remove(tx)
	delete(h.txs, tx.seq)
}

// replace swaps the old transaction with the new one.
func (h *senderTxHeap) replace(new, old *mainQueueTransaction) {
	h.seqHeap.replace(new, old)
	delete(h.txs, old.seq)
	h.txs[new.seq] = new
}

// minPriorityTxHeap is a heap of transactions ordered by ascending priority.
type minPriorityTxHeap []*mainQueueTransaction

func (h minPriorityTxHeap) Len() int {
	return len(h)
}

func (h minPriorityTxHeap) Less(i, j int) bool {
	return h[i].priority < h[j].priority
}

func (h minPriorityTxHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].minHeapIndex = i
	h[j].minHeapIndex = j
}

func (h *minPriorityTxHeap) Push(x any) {
	n := len(*h)
	item := x.(*mainQueueTransaction)
	item.minHeapIndex = n
	*h = append(*h, item)
}

func (h *minPriorityTxHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.minHeapIndex = -1
	*h = old[0 : n-1]
	return item
}

// peek returns the transaction with the lowest priority.
func (h *minPriorityTxHeap) peek() (*mainQueueTransaction, bool) {
	if len(*h) == 0 {
		return nil, false
	}
	return (*h)[0], true
}

// push adds the given transaction to the heap.
func (h *minPriorityTxHeap) push(tx *mainQueueTransaction) {
	heap.Push(h, tx)
}

// remove removes the given transaction from the heap.
func (h *minPriorityTxHeap) remove(tx *mainQueueTransaction) {
	heap.Remove(h, tx.minHeapIndex)
}

// replace swaps the old transaction with the new one.
func (h *minPriorityTxHeap) replace(new, old *mainQueueTransaction) {
	new.minHeapIndex = old.minHeapIndex
	old.minHeapIndex = -1
	(*h)[new.minHeapIndex] = new
	heap.Fix(h, new.minHeapIndex)
}

// maxPriorityTxHeap is a heap of transactions ordered by descending priority.
type maxPriorityTxHeap []*mainQueueTransaction

func (h maxPriorityTxHeap) Len() int {
	return len(h)
}

func (h maxPriorityTxHeap) Less(i, j int) bool {
	return h[i].priority > h[j].priority
}

func (h maxPriorityTxHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].maxHeapIndex = i
	h[j].maxHeapIndex = j
}

func (h *maxPriorityTxHeap) Push(x any) {
	n := len(*h)
	item := x.(*mainQueueTransaction)
	item.maxHeapIndex = n
	*h = append(*h, item)
}

func (h *maxPriorityTxHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.maxHeapIndex = -1
	*h = old[0 : n-1]
	return item
}

// peek returns the transaction with the highest priority.
func (h *maxPriorityTxHeap) peek() (*mainQueueTransaction, bool) {
	if len(*h) == 0 {
		return nil, false
	}
	return (*h)[0], true
}

// push adds the given transaction to the heap.
func (h *maxPriorityTxHeap) push(tx *mainQueueTransaction) {
	heap.Push(h, tx)
}

// remove removes the given transaction from the heap.
func (h *maxPriorityTxHeap) remove(tx *mainQueueTransaction) {
	heap.Remove(h, tx.maxHeapIndex)
}

// replace swaps the old transaction with the new one.
func (h *maxPriorityTxHeap) replace(new, old *mainQueueTransaction) {
	new.maxHeapIndex = old.maxHeapIndex
	old.maxHeapIndex = -1
	(*h)[new.maxHeapIndex] = new
	heap.Fix(h, new.maxHeapIndex)
}

// seqNumTxHeap is a heap of transactions ordered by ascending sequence numbers.
type seqNumTxHeap []*mainQueueTransaction

func (h seqNumTxHeap) Len() int {
	return len(h)
}

func (h seqNumTxHeap) Less(i, j int) bool {
	return h[i].seq < h[j].seq
}

func (h seqNumTxHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].seqHeapIndex = i
	h[j].seqHeapIndex = j
}

func (h *seqNumTxHeap) Push(x any) {
	n := len(*h)
	item := x.(*mainQueueTransaction)
	item.seqHeapIndex = n
	*h = append(*h, item)
}

func (h *seqNumTxHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.seqHeapIndex = -1
	*h = old[0 : n-1]
	return item
}

// peek returns the transaction with the lowest sequence number.
func (h *seqNumTxHeap) peek() (*mainQueueTransaction, bool) {
	if len(*h) == 0 {
		return nil, false
	}
	return (*h)[0], true
}

// push adds the given transaction to the heap.
func (h *seqNumTxHeap) push(tx *mainQueueTransaction) {
	heap.Push(h, tx)
}

// remove removes the given transaction from the heap.
func (h *seqNumTxHeap) remove(tx *mainQueueTransaction) {
	heap.Remove(h, tx.seqHeapIndex)
}

// replace swaps the old transaction with the new one.
func (h *seqNumTxHeap) replace(new, old *mainQueueTransaction) {
	new.seqHeapIndex = old.seqHeapIndex
	old.seqHeapIndex = -1
	(*h)[new.seqHeapIndex] = new
	heap.Fix(h, new.seqHeapIndex)
}
