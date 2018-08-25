package simulator

import (
	"errors"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
	"github.com/oasislabs/ekiden/go/scheduler/alg/randgen"
)

// RandomDistributionTransactionSource is a pseudo-randomly generated transaction source.  The
// rg generator is responsible for generating integers which is used as TestLocation values.
// Because of duplicate removal, if the number of read (or write) Location values to be put
// into the set becomes too large (much greater than sqrt of the number of possible Location
// values), then the sampling could take a long time.
type RandomDistributionTransactionSource struct {
	numTrans, numReads, numWrites int
	rg                            randgen.Rng
}

// NewRandomDistributionTransactionSource constructs and returns a
// RandomDistributionTransactionSource that will generate nt transactions before quitting, with
// each transaction containing nr TestLocation values in the read set, and nw TestLocation
// values in the write set.
func NewRandomDistributionTransactionSource(nt, nr, nw int, rg randgen.Rng) *RandomDistributionTransactionSource {
	if nt < 0 || nr < 0 || nw < 0 {
		panic("Invariance violation: number of transactions, read/write locations per transaction must be non-negative")
	}
	return &RandomDistributionTransactionSource{numTrans: nt, numReads: nr, numWrites: nw, rg: rg}
}

// Get generates a new transaction with the given sequence number, and read-set / write-set
// contents as dictated by the random number generator.
func (rdt *RandomDistributionTransactionSource) Get(seqno int) (*alg.Transaction, error) {
	if rdt.numTrans == 0 {
		return nil, errors.New("All requested transactions generated")
	}
	rdt.numTrans--
	t := alg.NewTransaction()
	rdt.sample(t.ReadSet, rdt.numReads)
	rdt.sample(t.WriteSet, rdt.numWrites)
	t.TimeCost = 1
	t.CreationSeqno = seqno
	return t, nil
}

func (rdt *RandomDistributionTransactionSource) sample(set *alg.LocationSet, count int) {
	var loc alg.TestLocation
	for n := 0; n < count; n++ {
		for {
			loc = alg.TestLocation(rdt.rg.Generate())
			if !set.Contains(loc) {
				break
			}
		}
		set.Add(loc)
	}
}

// Close does cleanup.  For RandomDistributionTransactionSource, there is none needed.
func (rdt *RandomDistributionTransactionSource) Close() error {
	return nil
}
