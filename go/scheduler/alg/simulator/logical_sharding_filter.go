package simulator

import (
	"math/rand"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

type LogicalShardingFilter struct {
	shard_top_n  int
	shard_factor int
	ts           TransactionSource
	r            *rand.Rand
	top_map      []int64
}

func NewLogicalShardingFilter(seed int64, shard_n, shard_f int, ts TransactionSource) *LogicalShardingFilter {
	return &LogicalShardingFilter{shard_top_n: shard_n, shard_factor: shard_f, ts: ts, r: rand.New(rand.NewSource(seed))}
}

func (lsf *LogicalShardingFilter) Get(seqno uint) (*alg.Transaction, error) {
	lsf.top_map = make([]int64, lsf.shard_top_n) // zeros means no value
	t, e := lsf.ts.Get(seqno)
	if e == nil {
		// iterate over t's read-set and write-set, replace all elements 0 <= e <
		// lsf.shard_top_n with a random negative value (memoized)
		lsf.UpdateSet(t.ReadSet)
		lsf.UpdateSet(t.WriteSet)
	}
	return t, e
}

func (lsf *LogicalShardingFilter) UpdateSet(ls *alg.LocationSet) {
	repl := alg.NewLocationSet()
	for loc := range ls.Locations {
		tloc := loc.(alg.TestLocation)
		iloc := int64(tloc)
		if 0 <= iloc && iloc < int64(lsf.shard_top_n) {
			loc := int(iloc)
			if lsf.top_map[loc] == 0 {
				shard := int64(lsf.r.Intn(lsf.shard_factor))
				shard_base := int64(loc * lsf.shard_factor)
				lsf.top_map[loc] = -(1 + shard_base + shard)
			}
			repl.Add(alg.TestLocation(lsf.top_map[loc]))
		}
	}
	*ls = *repl
}

func (lsf *LogicalShardingFilter) Close() {
	lsf.ts.Close()
}
