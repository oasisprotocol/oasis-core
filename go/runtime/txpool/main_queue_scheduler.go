package txpool

import (
	"fmt"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

// blockedTransactions is a list of hex-encoded transaction hashes that
// should be rejected by the scheduler.
//
// Currently, all these transactions originate from the Sapphire mainnet and
// contain future nonces. They are stuck in the pool due to issues with future
// nonces, and can only be removed by submitting a replacement transaction
// with the same nonce. Since these transactions are quite old and executing
// them now could cause harmful side effects, we explicitly block them.
var blockedTransactions = []string{
	"0018054c83022953b7d3182acf49261a2ec98589b17de44f9be125afd3999ba6",
	"1265a6a9b91a6d71f30e0b28a49c4c18b7d5f7af8013e1f93124601580a61110",
	"1644b671d1aa41708215bff40bc3bf17961d011e87195097064d643f6c3a7568",
	"164f2510298fd984bb65cb431caffae5f2a1ae6a95378a2efb0e27db1097c414",
	"166c28e9b3bea98f98b48f735fa00d9228a187d4753e92bd29ae378d0c03068f",
	"1695c98a495dc129020f1acac318b9328aab9dd22f02f712176979a194ffd1e7",
	"200b1286ba663e665d586b8d1712bc13cbbbb1038f97b3c84a9a7a75895ef664",
	"23ba2f9aa27110de0c3f460e522edbc7355a615977ec57beafc8be137417fab3",
	"26d5894a8c6ce6ba5b30db69d89c18b7f8b46c70ea0d417e8555019aa8578131",
	"26f9653237087ee1ec2b35c72426fa802799156bfb2ea9483ba19d062ec1658d",
	"292cb4ca9229a1352e3d78427dd62c8a243f78a89fb84a33084456285fdd3e41",
	"2aba9ebce1dde2b3b76f004c1f6afebf4cf7c4a160a29bfdfe30c1bda50aab3f",
	"2e43a3e9b23f3a5624609da1efc31cc47b253458413a114cbfd31080b9eb5a74",
	"2e7e40f5c30884e14a59b3ae35d2c0c73a97c2623f2526c4b17be22f7ac873b7",
	"30ffb8eecd6156729c0f5b5d24be16a19b852b9374c9302c312ca78251cd063b",
	"32968713cefad5d81a011ccd9b21de37c61c84c28b84030528ba92573171374f",
	"359dd5e7b7edc09c032107724eb90d506c43931e0855af0f6f6520f2e3d6c5c3",
	"35b5479dd028a4a194739508a2921abd7b9869c338e622e1cbdbd1f7d5608d86",
	"3fe55788c3f1ece46417afd0aed8ae6cefbd0b975872f8ce3d9e71ab2a13af42",
	"42cfe6961ad418cd4525fa708f136a47e2e398d15bb2ba45ddccf420c4dac6ad",
	"4a56de20966375ae47bb15da2ac7118ddc9157f3d5fbfd08fb1d37d71317b77f",
	"4fcab3bd3f38d7012afa068190d83f09072a04eb95d279aaa0b74d35d33108fa",
	"52b0b2c0429202c4bd318640626c673f8706f73ef448e510b50440ae60c02a63",
	"580432caee0feb5d953ee12bfe701a0daa2d17076315e7f4791a10ffab7e59fe",
	"6206c44c793a1986a58636b9aa8a6a7b885be31101dc0aabfb6f446df1bcac6e",
	"6504d520a681006d9d67594f17a7cd67add0ada0b6c82df7d4b51d49a56852fb",
	"682db797051fddcf96e0d9647491f2f93e072bf6cef8458723b90146888fbc29",
	"6b41cbd8452cb915342955d4c627219f48626e8936dfab579044c077d0fd3a0f",
	"6b784588f915c96cd2a838940bad917c4b8fe290908cd0ef754a0258bd1bf1f6",
	"6dc366f0e83701f5740969be20dee9d2318d23d3e048227df9d91fb0fd00b06a",
	"6e96481f0ae7c98d968bb24d3ec018276144036203eb7f0a968dc374ac627678",
	"6f40c176b77c154328662f1f580fad0627ac17605c05a9b84ce8a34a2d3d9e1e",
	"76c32b51298b3621d548c44a99a7162e930dad349d0bc6a545b91d9d186fc05e",
	"7c11d286377eef68ddcaff4be5113a23098071e5d76a933b306eff3fd60ae2b1",
	"7de270a9f5a8df3e6c1b17eed550fa6156bef0c91c11594d5428983c1fba4156",
	"7e2ffb2c83ee946cd1191a470382369e4029151bf72ca6e0e71faa3e37ee26bd",
	"7f93a07a2a61abf71805a41174275ca3965a35a4aa60ddf9e0f082c89c228308",
	"80e5d664d358ed7864ebf9b6a84920e9af2616082d51418461d9e5f491c6156b",
	"83223f096c781dbbd445046090ebb4a1d6351602181ee7a60725544ad409482b",
	"849942afea1bce67d74ade12e1f07d28908ed8acc6ef3ddf7425b7972d3e8d7e",
	"84ece1f39aee0d2c9f969fae8902d90b914faa53bf1202d500899d91f9747c7e",
	"8e6ee4b22e35e6be4e79fd8805f9ed0efd13cf1ad6db6c3d692e155aa4d2859f",
	"90498fce55084666d703c8f247173c26073ea2d40e8ea9cd50031c68406d47aa",
	"933501a50f2ca2f3486455e0b66c66507cda5abb0208caceea2a7422ede671c3",
	"955556c7b259833ac80e7703769db9941d1d7193530c6f8972acb2941a3fe60b",
	"969bf93ef08f80e0f845b1e0604a7d4cefb3a17efbc1ae2f4b628fc6a544951c",
	"9bc5d9368f479569d24007ccc436d2c33939d606da6ef3e23a130b90f1ebd2f1",
	"a177b2e6427211346cd91d5ffb9ebd8646e57688a7c6a10aacf9e28e5a8dcbad",
	"a2657db29b79dea2e4b19f9e20ad28c4acfabb8a2fc88ea738220345188cb5e8",
	"a2e993aa6cc8f37281e7291ab04d98481d16cadcabee4dbb89c4a3a42861e130",
	"a6954d63f1985b5f2d55ac18f7b61c66bfcc0defbb6bc519a198cdcce1012665",
	"a7119e9339156fefdc2fe313a85fbba504e476c35c0c0d17a8e834fdd7322e9f",
	"a722f63b52faaae2dfd938d38474a69a1fed8b497fd6ce52c3abfa247157d8b4",
	"abf54e4ae0943cc2acfe6f9f54623e289aa1abb3c4a3aac12ce050084ee261fc",
	"ae33013feb656eddbbde354e079fe8b320259899483d105ee4122a2d407ce1aa",
	"ae7e9e4bcbe19fb977aef9fff28077123db530396100ea251cc1c266348d5185",
	"af199f1fe3e2e80b41bb76da5d8639d9272886a49ed4361e575c26965a84c42a",
	"b0bab2874c24f2d973127746b46ac8b30cfa8940c6c2a67145e05f38fe759219",
	"b499a529c83d1fe76cf5ec311786d29362c6fdf62b7a8c524664bb0cf42839d3",
	"b62d9a7d449b74fcebe9c7b2c1d29a22a54fb1f5338cc4b5a560bc7e36e11aa3",
	"bc687be6a9fcd0c168c1886b459f472603f2818d9799402364f4163552bde688",
	"bca5827809c179ef7b88610ef1d987fa66c37e6746acd44f83065b542ec7a7af",
	"c42d9de09256fa925be1a6bc3df4a832e0182c1830a4fe7dfbe90bdb910b75f7",
	"ca71e59e1fcfd434e1663fe6cc3da14a122f97e740fcb3685060cdd68e783b9e",
	"db312365028f92b466938b0400f1e4a810f94723df8ac85cb013c4c3ede9a041",
	"dbbac55fa1d2710060907a1d9f9fe68512b812909d3d65b60c3a3b1870220465",
	"dcd9e360c1d58501a10cdf99a66eb1173cbef46875cdf0ef81350a74523bd02b",
	"ded92b1176711d81ed8802b28d24898cc85e4561d7ba83035ee68746a207d844",
	"e282276f72864b0af60d9fd1b6d3e9f0e28cc3b5dec9edbadc2f661994a10612",
	"e3bc012dfe334ebedb68ee627f15378723e05c42aeb04014feabac1d6088c454",
	"e662d1b5c69f1babc99398a145d56f8c7860c9523f6fab3e4ecd41687923279b",
	"ebc040b30f129273cd1e4ab9048cfe09ad04df6f1bc43d40708078cf09d6a5e5",
	"f24a7e88ed42fb373aa4b2a2612496b6ffb5f62dcb7761eeaf8dfdcba80bb7d1",
	"f29624e65cbfffcb616406a4d765341f6a4db65e8802f747dc519eb11d23f39a",
	"ff05b170a13e2be0e2868c6af0e66c8e9e632b86b766e3c20f8ae10dc8d124d7",
}

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

	// blocked contains all transactions that should be blocked by the scheduler.
	blocked map[hash.Hash]struct{}
}

// newMainQueueScheduler creates a new transaction scheduler for the main queue.
func newMainQueueScheduler(capacity int) *mainQueueScheduler {
	blocked := make(map[hash.Hash]struct{})
	for _, hex := range blockedTransactions {
		var h hash.Hash
		if err := h.UnmarshalHex(hex); err != nil {
			panic(fmt.Sprintf("malformed transaction hash: %s", hex))
		}
		blocked[h] = struct{}{}
	}

	return &mainQueueScheduler{
		capacity:  capacity,
		txs:       make(map[hash.Hash]*mainQueueTransaction),
		senders:   make(map[string]*senderTxHeap),
		minHeap:   make(minPriorityTxHeap, 0),
		maxHeap:   make(maxPriorityTxHeap, 0),
		scheduled: make(map[string]uint64),
		blocked:   blocked,
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

	// Reject expired transaction.
	if tx.seq < seqHeap.seq {
		return fmt.Errorf("transaction expired")
	}

	// Reject blocked transaction.
	if _, ok := s.blocked[tx.meta.hash]; ok {
		return fmt.Errorf("transaction blocked")
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
	txs := make([]*TxQueueMeta, 0, limit)

	for range limit {
		tx, ok := s.scheduleOne()
		if !ok {
			break
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
