package simulator

import (
	"errors"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
	"github.com/oasislabs/ekiden/go/scheduler/alg/random_distribution"
)

type RandomDistributionTransactionSource struct {
	num_trans, num_reads, num_writes uint
	rg                               random_distribution.DiscreteGenerator
}

func NewRandomDistributionTransactionSource(nt, nr, nw uint, rg random_distribution.DiscreteGenerator) *RandomDistributionTransactionSource {
	return &RandomDistributionTransactionSource{num_trans: nt, num_reads: nr, num_writes: nw, rg: rg}
}

func (rdt *RandomDistributionTransactionSource) Get(seqno uint) (*alg.Transaction, error) {
	if rdt.num_trans == 0 {
		return nil, errors.New("All requested transactions generated")
	}
	rdt.num_trans--
	t := alg.NewTransaction()
	var n uint
	var loc alg.TestLocation
	for n = 0; n < rdt.num_reads; n++ {
		for {
			loc = alg.TestLocation(rdt.rg.Generate())
			if !t.ReadSet.Contains(loc) {
				break
			}
		}
		t.ReadSet.Add(loc)
	}
	for n = 0; n < rdt.num_writes; n++ {
		for {
			loc = alg.TestLocation(rdt.rg.Generate())
			if !t.WriteSet.Contains(loc) {
				break
			}
		}
		t.WriteSet.Add(loc)
	}
	t.TimeCost = 1
	t.CreationSeqno = seqno
	return t, nil
}

func (rdt *RandomDistributionTransactionSource) Close() {}
