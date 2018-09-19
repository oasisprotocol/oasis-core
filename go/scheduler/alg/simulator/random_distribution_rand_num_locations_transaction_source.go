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
type RandomDistributionRandNumLocationsTransactionSource struct {
	numTrans int
	rg       randgen.Rng
	rLocRng  randgen.Rng
	wLocRng  randgen.Rng
}

// NewRandomDistributionRandNumLocationsTransactionSource constructs and returns a
// RandomDistributionRandNumLocationsTransactionSource that will generate nt transactions
// before quitting, with each transaction containing a random number of TestLocation values in
// the read set specified by nrRng, and a (random) number of TestLocation values in the write
// set specified by nwRng.  NB: nrRng or nwRng can be Fixed Rng instances.
func NewRandomDistributionRandNumLocationsTransactionSource(nt int, nrRng, nwRng, rg randgen.Rng) *RandomDistributionRandNumLocationsTransactionSource {
	if nt < 0 {
		panic("Invariance violation: number of transactions must be non-negative")
	}
	return &RandomDistributionRandNumLocationsTransactionSource{numTrans: nt, rLocRng: nrRng, wLocRng: nwRng, rg: rg}
}

// Get generates a new transaction with the given sequence number, and read-set / write-set
// contents as dictated by the random number generators.
func (rdt *RandomDistributionRandNumLocationsTransactionSource) Get(seqno int) (*alg.Transaction, error) {
	if rdt.numTrans == 0 {
		return nil, errors.New("All requested transactions generated")
	}
	rdt.numTrans--
	t := alg.NewTransaction()
	rdt.sample(t.ReadSet, rdt.rLocRng.Generate())
	rdt.sample(t.WriteSet, rdt.wLocRng.Generate())
	t.TimeCost = 1
	t.CreationSeqno = seqno
	return t, nil
}

// sample does rejection sampling to ensure that the `count` TestLocation values are distinct.
// Since the number of locations should be high, the probability that this will have to
// resample a lot should be very low.
func (rdt *RandomDistributionRandNumLocationsTransactionSource) sample(set *alg.LocationSet, count int) {
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

// Close does cleanup.  For RandomDistributionRandNumLocationsTransactionSource, there is none
// needed.
func (rdt *RandomDistributionRandNumLocationsTransactionSource) Close() error {
	return nil
}
