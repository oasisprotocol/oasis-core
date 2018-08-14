// Test that a given scheduler will eventually schedule all transactions.  This is a very basic
// test using a small amount of canned/generated data, and should be expanded to use larger
// amount of randomly generated data or real data from actual transactions.

package alg

import (
	"flag"
	"math/rand"
	"testing"
)

var tssSeed = flag.Int64("tss-seed", 1,
	"tss-seed <num> where <num is the seed for transaction slices source")

var tssNumTrans = flag.Int("tss-num-trans", 20000,
	"tss-num-trans <num> where <num> specifies the number of transactions to generate")

var tssNumWallets = flag.Int("tss-num-wallets", 10000,
	"tss-num-wallets <num> where <num> is the number of read-set/write-set locations (e.g., wallets)")

type TransactionSliceSource struct {
	rng      *rand.Rand
	nwallets int
	ntrans   int

	transPerBatch  int
	readsPerTrans  int
	writesPerTrans int
	nextTid        int
	retiredTid     []bool
}

func NewTransactionSliceSource(r *rand.Rand, nw int, nt int) *TransactionSliceSource {
	return &TransactionSliceSource{
		rng:      r,
		nwallets: nw,
		ntrans:   nt,

		transPerBatch:  100,
		readsPerTrans:  3,
		writesPerTrans: 3,
		nextTid:        0,
		retiredTid:     make([]bool, nt),
	}
}

func (tss *TransactionSliceSource) GetTransactions() []*Transaction {
	thisBatch := tss.transPerBatch
	if tss.ntrans < thisBatch {
		thisBatch = tss.ntrans
	}
	tss.ntrans -= thisBatch
	ts := make([]*Transaction, thisBatch)
	var loc Location
	for ix := 0; ix < thisBatch; ix++ {
		ts[ix] = NewTransaction()
		for count := 0; count < tss.readsPerTrans; count++ {
			for {
				loc = TestLocation(tss.rng.Intn(tss.nwallets))
				if !ts[ix].ReadSet.Contains(loc) {
					break
				}
			}
			ts[ix].ReadSet.Add(loc)
		}
		for count := 0; count < tss.writesPerTrans; count++ {
			for {
				loc = TestLocation(tss.rng.Intn(tss.nwallets))
				if !ts[ix].WriteSet.Contains(loc) {
					break
				}
			}
			ts[ix].WriteSet.Add(loc)
		}
		ts[ix].CreationSeqno = uint(tss.nextTid)
		tss.nextTid++
	}
	return ts
}

func (tss *TransactionSliceSource) RetireTransactions(t *testing.T, sgs []*Subgraph) {
	for _, sg := range sgs {
		for _, txn := range sg.Transactions {
			if tss.retiredTid[txn.CreationSeqno] {
				t.Errorf("Transaction %d retired twice?", txn.CreationSeqno)
			}
			tss.retiredTid[txn.CreationSeqno] = true
		}
	}
}

func (tss *TransactionSliceSource) HasUnretired() bool {
	for ix := 0; ix < tss.nextTid; ix++ {
		if !tss.retiredTid[ix] {
			return true
		}
	}
	return false
}

func VerifySchedulerRunsAllTransactions(t *testing.T, sn string, s Scheduler) {
	tss := NewTransactionSliceSource(rand.New(rand.NewSource(*tssSeed)), *tssNumWallets,
		*tssNumTrans)

	for {
		ts := tss.GetTransactions()
		if len(ts) == 0 {
			break
		}
		sgs := s.AddTransactions(ts)
		tss.RetireTransactions(t, sgs)
	}
	for {
		sgs := s.FlushSchedule()
		if len(sgs) == 0 {
			break
		}
		tss.RetireTransactions(t, sgs)
	}
	if tss.HasUnretired() {
		t.Errorf("Scheduler %s did not schedule all transactions.", sn)
	}
}

func TestAllTransactionsGetScheduled(t *testing.T) {
	VerifySchedulerRunsAllTransactions(t, "greedy subgraph", NewGreedySubgraphs(10, ExecutionTime(10)))
}
