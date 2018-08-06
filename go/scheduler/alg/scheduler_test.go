// Test that a given scheduler will eventually schedule all transactions.  This is a very basic
// test using a small amount of canned/generated data, and should be expanded to use larger
// amount of randomly generated data or real data from actual transactions.

package alg

import (
	"flag"
	"math/rand"
	"testing"
)

var tss_seed = flag.Int64("tss-seed", 1,
	"tss-seed <num> where <num is the seed for transaction slices source")

var tss_num_trans = flag.Int("tss-num-trans", 20000,
	"tss-num-trans <num> where <num> specifies the number of transactions to generate")

var tss_num_wallets = flag.Int("tss-num-wallets", 10000,
	"tss-num-wallets <num> where <num> is the number of read-set/write-set locations (e.g., wallets)")

type TransactionSliceSource struct {
	rng      *rand.Rand
	nwallets int
	ntrans   int

	trans_per_batch  int
	reads_per_trans  int
	writes_per_trans int
	next_tid         int
	retired_tid      []bool
}

func NewTransactionSliceSource(r *rand.Rand, nw int, nt int) *TransactionSliceSource {
	return &TransactionSliceSource{
		rng:      r,
		nwallets: nw,
		ntrans:   nt,

		trans_per_batch:  100,
		reads_per_trans:  3,
		writes_per_trans: 3,
		next_tid:         0,
		retired_tid:      make([]bool, nt),
	}
}

func (tss *TransactionSliceSource) GetTransactions() []*Transaction {
	this_batch := tss.trans_per_batch
	if tss.ntrans < this_batch {
		this_batch = tss.ntrans
	}
	tss.ntrans -= this_batch
	ts := make([]*Transaction, this_batch)
	var loc Location
	for ix := 0; ix < this_batch; ix++ {
		ts[ix] = NewTransaction()
		for count := 0; count < tss.reads_per_trans; count++ {
			for {
				loc = TestLocation(tss.rng.Intn(tss.nwallets))
				if !ts[ix].ReadSet.Contains(loc) {
					break
				}
			}
			ts[ix].ReadSet.Add(loc)
		}
		for count := 0; count < tss.writes_per_trans; count++ {
			for {
				loc = TestLocation(tss.rng.Intn(tss.nwallets))
				if !ts[ix].WriteSet.Contains(loc) {
					break
				}
			}
			ts[ix].WriteSet.Add(loc)
		}
		ts[ix].CreationSeqno = uint(tss.next_tid)
		tss.next_tid++
	}
	return ts
}

func (tss *TransactionSliceSource) RetireTransactions(t *testing.T, sgs []*Subgraph) {
	for _, sg := range sgs {
		for _, txn := range sg.Transactions {
			if tss.retired_tid[txn.CreationSeqno] {
				t.Errorf("Transaction %d retired twice?", txn.CreationSeqno)
			}
			tss.retired_tid[txn.CreationSeqno] = true
		}
	}
}

func (tss *TransactionSliceSource) HasUnretired() bool {
	for ix := 0; ix < tss.next_tid; ix++ {
		if !tss.retired_tid[ix] {
			return true
		}
	}
	return false
}

func VerifySchedulerRunsAllTransactions(t *testing.T, sn string, s Scheduler) {
	tss := NewTransactionSliceSource(rand.New(rand.NewSource(*tss_seed)), *tss_num_wallets,
		*tss_num_trans)

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
