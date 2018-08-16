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
	"flag"
	"fmt"
	"math/rand"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

// adversaryConfig wraps the configuration parameters for how an adversary that is mounting a
// DOS attack might behave.

type adversaryConfig struct {
	seed            int64
 	injectionProb   float64
 	spamBatchSize   int
 	targetAddresses string
}

var adversaryConfigFromFlags adversaryConfig

func init() {
	flag.Int64Var(&adversaryConfigFromFlags.seed, "adversary-seed", 0, "seed for rng used to randomize adversary actions")
	flag.Float64Var(&adversaryConfigFromFlags.injectionProb, "injection-prob", 0.01, "probability of deciding to inject (possibly many) DOS transactions")
	flag.IntVar(&adversaryConfigFromFlags.spamBatchSize, "dos-batch-size", 100, "number of DOS transactions to inject, once decision to spam is made")
	flag.StringVar(&adversaryConfigFromFlags.targetAddresses, "target-addresses", "0-16", "comma-separated list of integers or start-end integer ranges")
}

// AdversarialTransactionSource is a a filter that wraps a legitimate (statistical)
// TransactionSource that will inject in denial-of-service transactions, i.e., transactions
// with read-set and write-set locations chosen to maximize the load / likelihood of
// causing a batch of transactions to revert.
type AdversarialTransactionSource struct {
	r *rand.Rand
	injectionProb float64
	targets *alg.LocationRangeSet

	step int
	batchSize int
	numTargets uint64
	ts TransactionSource
}

func countTargets(targets *alg.LocationRangeSet) uint64 {
	var total uint64
	if targets.IsEmpty() {
		return total
	}
	next := targets.MinLoc().(alg.TestLocation)
	pred := func (lr *alg.LocationRange) bool {
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

// mapTargets:  given a random value `choice` in half open interval [0, `countTargets(targets)`),
// return the `TestLocation` associated with that value.
func mapTargets(targets *alg.LocationRangeSet, choice uint64) *alg.TestLocation {
	if targets.IsEmpty() {
		return nil
	}
	next := targets.MinLoc().(alg.TestLocation)
	var result alg.TestLocation
	pred := func (lr *alg.LocationRange) bool {
		lb := lr.LowerBound.(alg.TestLocation)
		ub := lr.UpperBound.(alg.TestLocation)
		// invar: lb <= ub
		if next < lb {
			next = lb
		}
		if next > ub {
			return false
		}
		// invar: lb <= next <= ub

		// Count is the number of entries in the current range that hasn't been handled
		// by the previous range (due to overlap).
		count := ub - next + 1
		// There is a possibility of arthmetic overflow, e.g., if next = math.MinInt64
		// and ub >= -1.  We check for it and panic.
		if count < 0 {
			panic(fmt.Sprintf("RangeSet range [%d,%d] too big, next=%d, arithmetic underflow", lb, ub, next))
		}
		if choice <= uint64(count) {
			result = alg.TestLocation((uint64(next) + choice))
			return true
		}
		// post: choice > count, so no underflow in subtraction
		choice -= uint64(count)
		return false
	}
	targets.Find(pred)
	return &result
}

// NewAdversarialTransactionSource constructs and returns an AdversarialTransactionSource.
func NewAdversarialTransactionSource(
	rngSeed int64,
	inj float64,
	targets *alg.LocationRangeSet,
	batchSize int,
	ts TransactionSource) (*AdversarialTransactionSource, error) {
	if inj < 0.0 {
		return nil, fmt.Errorf("NewAdversarialTransactionSource: Injection probability must be at least 0.0, got %f", inj)
	}
	if inj > 1.0 {
		return nil, fmt.Errorf("NewAdversarialTransactionSource: Injection probability must be at most 1.0, got %f", inj)
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

	return &AdversarialTransactionSource{
		r: rng,
		injectionProb: inj,
		targets: targets,
		batchSize: batchSize,
		numTargets: nTargets,
		ts: ts}, nil
}

// Get the next Transaction from this source.  The result may be from the underlying wrapped
// TransactionSource, or it may be a bogus DOS transaction injected into the request stream.
func (ats *AdversarialTransactionSource) Get(tid uint) (*alg.Transaction, error) {
	if ats.step != 0 {
		ats.step--
		return ats.generateSpam()
	}
	if ats.batchSize > 0 && ats.r.Float64() < ats.injectionProb {
		ats.step = ats.batchSize - 1
		return ats.generateSpam()
	}
	return ats.ts.Get(tid)
}

// Close cleans up this TransactionSource and invokes Close on the wrapped TransactionSource.
func (ats *AdversarialTransactionSource) Close() error {
	return ats.ts.Close()
}

func (ats *AdversarialTransactionSource) generateSpam() (*alg.Transaction, error) {
	return nil, nil
}

