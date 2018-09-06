package simulator

// Adversary transaction generator filter.

// The configuration parameters control how the adversary submit spammy transactions to try to
// affect the system throughput -- essentially, can an adversary easily mount a
// denial-of-service attack.  For DOS-resilience, we want to primarily measure the amount of
// resources that the adversary needs versus the amount of additional resources that they
// system has to expend to maintain the same (or only mildly degraded) level of service
// (throughput, in this case).  Some of the attack vectors are easily blocked, e.g., raw number
// of transactions; others, e.g., transactions that accesses certain transactions that cause
// casacading access conflicts, may require complex analysis.
//
// - Percentage affected: the number of spammy versus real transactions.  This can be a real
//   number representing the probability of injecting a spam transaction, delaying Get() from
//   the underlying true TransactionSource.
//
// - Spam transaction batch size:  how many spammy transactions should be injected each time we
//   decide to mount an attack?
//
// - Number of addresses in each spammy transaction: how many read/write or write/write
//   conflict can the adversary create?
//
//   The address(es) to use for spammy transactions is another potential design parameter.  For
//   now, we can just spread this out among the highest-probability [m, ..., n)
//   contracts/accounts.  Note that m = 0 normally, but in case of logical sharding, m is a
//   negative number.  If logical sharding is by sender address, the adversary is assumed to be
//   able to create enough accounts so that the

import (
	"fmt"
	"math"
	"math/rand"
	"sort"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
	"github.com/oasislabs/ekiden/go/scheduler/alg/randgen"
)

// adversaryConfig wraps the configuration parameters for how an adversary that is mounting a
// DOS attack might behave.

// AdversarialTransactionSource is a a filter that wraps a legitimate (statistical)
// TransactionSource that will inject in denial-of-service transactions, i.e., transactions
// with read-set and write-set locations chosen to maximize the load / likelihood of
// causing a batch of transactions to revert.
type AdversarialTransactionSource struct {
	r             *rand.Rand
	injectionProb float64
	targetFract   float64
	readFrac      float64
	targets       *alg.LocationRangeSet

	batchSize int
	ts        TransactionSource
	spamSeqno uint

	numTargets int64
	step       int
}

func countTargets(targets *alg.LocationRangeSet) uint64 {
	var total uint64
	if targets.IsEmpty() {
		return total
	}
	next := targets.MinLoc().(alg.TestLocation)
	pred := func(lr *alg.LocationRange) bool {
		lb := lr.LowerBound.(alg.TestLocation)
		ub := lr.UpperBound.(alg.TestLocation)
		if next < lb {
			next = lb
		}
		if next > ub {
			return false
		}
		total += uint64(ub - next + 1)
		return false
	}
	targets.Find(pred)
	return total
}

type choiceSort []int64

func (a choiceSort) Len() int           { return len(a) }
func (a choiceSort) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a choiceSort) Less(i, j int) bool { return a[i] < a[j] }

// mapTargets: given a slice of random values `choice` all in half open interval [0,
// `countTargets(targets)`), return a slice of the `TestLocation` associated with that value.
func mapTargets(targets *alg.LocationRangeSet, choice []int64) []alg.Location { // nolint: gocyclo
	if targets.IsEmpty() || len(choice) == 0 {
		return nil
	}
	sort.Sort(choiceSort(choice))
	result := make([]alg.Location, 0, len(choice))
	curChoice := choice[0]

	// choice: sorted list of [0, numTarget)
	// target ranges: [lb1, ub1], [lb2, ub2), ...
	//
	// we want choice 0 to map to lb1, ub1-lb1 to map to ub1,
	// ub1-lb1+1 to map to lb2, etc.
	//
	// offset is lb1 when processing the range [lb1, ub1], so choice in [0, ub1-lb1]
	// will map to [lb1, ub1].
	//
	// offset is lb2-(ub1-lb1+1) when processing the range [lb2, ub2], so a choice of
	// ub1-lb1+1 maps to lb2, etc.
	//
	// and offset is lb3-(ub1-lb1+1 + ub2-ub2+1) when processing the range [lb3, ub3].
	//
	// The update to offset is to compute the size of the range (count), then set offset =
	// lb2 - count.
	//
	// next is used to allow for overlapping ranges, e.g., when ub1 > lb2
	// we just pretend that lb2 = ub1+1.
	//
	next := int64(targets.MinLoc().(alg.TestLocation))
	sumCount := int64(0)

	pred := func(lr *alg.LocationRange) bool {
		lb := int64(lr.LowerBound.(alg.TestLocation))
		ub := int64(lr.UpperBound.(alg.TestLocation))
		// invar: lb <= ub
		if next > ub {
			// complete overlap, skip this range
			return false
		}
		// next <= ub
		if next > lb {
			lb = next
		}
		offset := lb - sumCount

		// There is a possibility of arthmetic overflow, e.g., if next = math.MinInt64
		// and ub >= -1.  We check for it and panic.
		if ub > 0 && next < 0 {
			if ub > math.MaxInt64+next {
				panic(fmt.Sprintf("RangeSet range [%d,%d] too big, next=%d, arithmetic underflow", lb, ub, next))
			}
		} else if ub < 0 && next > 0 {
			panic(fmt.Sprintf("Invariance violation: next <= ub, but next = %d, ub = %d", next, ub))
		}
		// Count is the number of entries in the current range that hasn't been handled
		// by the previous range (due to overlap).
		count := ub - next
		if count+1 < count {
			panic(fmt.Sprintf("RangeSet range [%d,%d] too big, next=%d, arithmetic overflow", lb, ub, next))
		}
		count = count + 1
		for curChoice+offset <= ub {
			result = append(result, alg.TestLocation(curChoice+offset))
			if len(result) == len(choice) {
				return true
			}
			curChoice = choice[len(result)]
		}
		sumCount += count
		next = ub + 1
		return false
	}
	targets.Find(pred)
	for _, loc := range result {
		if !targets.Contains(loc) {
			panic(fmt.Sprintf("location %d not in target\n", loc))
		}
	}
	return result
}

// NewAdversarialTransactionSource constructs and returns an AdversarialTransactionSource.
func NewAdversarialTransactionSource(
	rngSeed int64,
	inj float64,
	tFrac float64,
	rFrac float64,
	targets *alg.LocationRangeSet,
	batchSize int,
	ts TransactionSource,
	spamSeqno uint,
) (*AdversarialTransactionSource, error) {
	if inj < 0.0 {
		return nil, fmt.Errorf("NewAdversarialTransactionSource: Injection probability must be at least 0.0, got %g", inj)
	}
	if inj >= 1.0 {
		// Too close to 1 is pretty bogus, since all transactions are spam.
		return nil, fmt.Errorf("NewAdversarialTransactionSource: Injection probability must be less than 1.0, got %g", inj)
	}
	if rFrac < 0.0 || rFrac > 1.0 {
		return nil, fmt.Errorf("NewAdversarialTransactionSource: read fraction must be in [0.0,1.0], got %g", rFrac)
	}
	if targets == nil {
		return nil, fmt.Errorf("NewAdversarialTransactionSource: targets cannot be nil")
	}
	if targets.IsEmpty() {
		return nil, fmt.Errorf("NewAdversarialTransactionSource: targets cannot be empty")
	}
	// We allow 0 to mean be a pass-through.
	if batchSize < 0 {
		return nil, fmt.Errorf("NewAdversarialTransactionSource: batchSize must be at least 0")
	}

	rng := rand.New(rand.NewSource(rngSeed))
	nTargets := countTargets(targets)
	if int64(nTargets) < 0 {
		return nil, fmt.Errorf("NewAdversarialTransactionSource: number of targets cause overflow?!?")
	}
	iNTargets := int64(nTargets)
	return &AdversarialTransactionSource{
		r:             rng,
		injectionProb: inj,
		targetFract:   tFrac,
		readFrac:      rFrac,
		targets:       targets,
		batchSize:     batchSize,
		ts:            ts,

		numTargets: iNTargets,
		spamSeqno:  spamSeqno,
	}, nil
}

// Get the next Transaction from this source.  The result may be from the underlying wrapped
// TransactionSource, or it may be a bogus DOS transaction injected into the request stream.
func (ats *AdversarialTransactionSource) Get(tid uint) (*alg.Transaction, error) {
	var txn *alg.Transaction
	var err error
	if ats.step > 0 {
		ats.step--
		txn, err = ats.generateSpam()
	} else if ats.batchSize > 0 && ats.r.Float64() < ats.injectionProb {
		ats.step = ats.batchSize - 1
		txn, err = ats.generateSpam()
	} else {
		txn, err = ats.ts.Get(tid)
	}
	return txn, err
}

// Close cleans up this TransactionSource and invokes Close on the wrapped TransactionSource.
func (ats *AdversarialTransactionSource) Close() error {
	return ats.ts.Close()
}

func (ats *AdversarialTransactionSource) generateSpam() (*alg.Transaction, error) {
	// We pick targetFract of the targets to put into the read/write sets.  Additional
	// tweaks of the spamming algorithm could be:
	//
	//  - Pick from some _leverage_ subset so that there will always be some K of them
	//    chosen, e.g., these are high-load addresses that will be used to cause the actual
	//    victim addresses to become overloaded.  We do not want to cause a noticeable load
	//    spike on these addresses, since presumably these are well monitored.
	//
	//  - Pick from some _victim_ subset so that the victim transactions are always going
	//    to have conflicts (via the leverage set) and as a result have transactions in the
	//    same batch as the DOS transaction to be reverted.  There may be a separate
	//    _camouflage_ set of non-victims that are handled mostly the same way as victims
	//    to disguise who are the targetted victims.
	numAddresses := int64(ats.targetFract * float64(ats.numTargets))
	conflicts := randgen.PickNFromM(numAddresses, ats.numTargets, ats.r)
	conflictLocs := mapTargets(ats.targets, conflicts)
	ats.r.Shuffle(len(conflictLocs), func(i, j int) { conflictLocs[i], conflictLocs[j] = conflictLocs[j], conflictLocs[i] })
	trans := alg.NewTransaction()
	split := int64(ats.readFrac * float64(len(conflictLocs)))
	trans.ReadSet.AddSlice(conflictLocs[:split])
	trans.WriteSet.AddSlice(conflictLocs[split:])
	trans.TimeCost = 1
	trans.CreationSeqno = ats.spamSeqno
	ats.spamSeqno++
	return trans, nil
}
