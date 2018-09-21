package simulator

import (
	"errors"
	"math/rand"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
	"github.com/oasislabs/ekiden/go/scheduler/alg/randgen"
)

// CryptoKitties is a pseudo-randomly generated transaction source intended to represent the
// cryptokitties contract.  A zipf distribution is used to model the cryptokitties contract
// parties: the dam kitten's owner (Alice), and the sire kitten's owner (Bob).  It is actually
// a 3-party transaction where Alice pays a siring fee to Bob and a birthing fee to the
// cryptokitties contract (K).  Later the cryptokitties contract pays the another party, the
// birther (Carol) who invokes the giveBirth method on the cryptokitties contract and drives
// the simulation forward.  Presumably the distribution for C is largely load-balanced across
// all auto-birthers.
//
// What this means is that there are two kinds of transactions: breeding, and birthing.  the
// breeding contract is a 3-party contract where one party is fixed, the cryptokitties account;
// the birthing contract is a 2-party contract between the auto-birther and cryptokitties.
//
// We use the address 0 as the cryptokitties address.  A, B, and C are randomly chosen so that
// the A ≠ B.  The number of breeding and birthing transactions should equal, but we just
// choose with probability 0.5 whether a transaction will be a breeding or birthing
// transaction.
//
// It is likely that the sire kitty distribution is over a smaller set, since to be a sire a
// kitty has to be listed to auction its siring.  We do not enforce anything here; the Rng can
// take this into account if needed.

// CryptoKittiesTransactionSource generates numTrans transactions.  About half will be 3 party
// transactions, and half will be 2 party transactions.  All will include the address 0 (K).
// The Rng for generating locations for A, B, and C may be an arbitrary distribution and should
// output in the range [1, num-addresses].
type CryptoKittiesTransactionSource struct {
	numTrans        int
	breedOrBirthRng *rand.Rand
	aliceRng        randgen.Rng
	bobRng          randgen.Rng
	carolRng        randgen.Rng
}

func NewCryptoKittiesTransactionSource(nt int, bbRng *rand.Rand, aRng, bRng, cRng randgen.Rng) *CryptoKittiesTransactionSource {
	if nt < 0 {
		panic("Invariance violation: number of transactions must be non-negative")
	}
	return &CryptoKittiesTransactionSource{numTrans: nt, breedOrBirthRng: bbRng, aliceRng: aRng, bobRng: bRng, carolRng: cRng}
}

func (ck *CryptoKittiesTransactionSource) Get(seqno int) (*alg.Transaction, error) {
	if ck.numTrans == 0 {
		return nil, errors.New("All requested transactions generated")
	}
	ck.numTrans--
	t := alg.NewTransaction()
	t.WriteSet.Add(alg.TestLocation(0))
	// t.ReadSet is empty: the kitty's genome is write-once at creation time, and other
	// than pregger cooldown for A's kitty, a kitty's state is const.  We assume that A
	// would not try to breed her kitty unless cooldown is done, since such a transaction
	// would revert, nor would she try to breed her with two sires simultaneously (and let
	// the blockchain figure out which wins) and so there is no point in modeling that.
	if (ck.breedOrBirthRng.Int() & 1) == 0 {
		// breeding
		addNewLocation(t.WriteSet, ck.aliceRng)
		addNewLocation(t.WriteSet, ck.bobRng)
	} else {
		// birthing
		addNewLocation(t.WriteSet, ck.carolRng)
	}
	t.TimeCost = 1
	t.CreationSeqno = seqno
	return t, nil
}

func addNewLocation(ls *alg.LocationSet, rng randgen.Rng) {
	for {
		loc := alg.TestLocation(rng.Generate())
		if !ls.Contains(loc) {
			ls.Add(loc)
			return
		}
	}
}

func (ck *CryptoKittiesTransactionSource) Close() error {
	return nil
}
