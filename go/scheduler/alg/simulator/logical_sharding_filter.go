package simulator

import (
	"math/rand"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

// LogicalShardingFilter implements the TransactionSource interface and wraps an underlying
// TransactionSource.  It assumes that the underlying transaction source is non-uniform and
// further that the high-probability addresses are the low shardTopN values, i.e., in the half
// interval [0, ..., shardTopN).  Each of these addresses are "logically sharded" into
// shardFactor distinct (negative) addresses.
type LogicalShardingFilter struct {
	shardTopN   int
	shardFactor int
	ts          TransactionSource
	r           *rand.Rand
	topMap      []int64
}

// NewLogicalShardingFilter is a factory function that constructs a LogicalShardingFilter that
// operates according to the seed, shardN, and shardF, on the wrapped TransactionSource ts.
func NewLogicalShardingFilter(seed int64, shardN, shardF int, ts TransactionSource) *LogicalShardingFilter {
	return &LogicalShardingFilter{shardTopN: shardN, shardFactor: shardF, ts: ts, r: rand.New(rand.NewSource(seed))}
}

// Get obtains a transaction from the wrapped TransactionSource, and if non-nil, replaces the
// shardTopN locations with randomly selected negative addresses.  Each of the shardTopN
// address is randomly mapped to one of shardFactor addresses, and this mapping is consistent:
// if the address occurs in both the read and write sets, then they will both be mapped to the
// same random location.
func (lsf *LogicalShardingFilter) Get(seqno uint) (*alg.Transaction, error) {
	lsf.topMap = make([]int64, lsf.shardTopN) // zeros means no value
	t, e := lsf.ts.Get(seqno)
	if e == nil {
		// iterate over t's read-set and write-set, replace all elements 0 <= e <
		// lsf.shardTopN with a random negative value (memoized)
		lsf.updateSet(t.ReadSet)
		lsf.updateSet(t.WriteSet)
	}
	return t, e
}

// updateSet -- consistently update the LocationSet by logging random choices in topMap.
func (lsf *LogicalShardingFilter) updateSet(ls *alg.LocationSet) {
	repl := alg.NewLocationSet()
	ls.MemberIteratorCallbackWithEarlyExit(func(loc alg.Location) bool {
		tloc := loc.(alg.TestLocation)
		iloc := int64(tloc)
		if 0 <= iloc && iloc < int64(lsf.shardTopN) {
			loc := int(iloc)
			if lsf.topMap[loc] == 0 {
				shard := int64(lsf.r.Intn(lsf.shardFactor))
				shardBase := int64(loc * lsf.shardFactor)
				lsf.topMap[loc] = -(1 + shardBase + shard)
			}
			repl.Add(alg.TestLocation(lsf.topMap[loc]))
		}
		return false
	})
	*ls = *repl
}

// Close cleans up by closing the wrapped TransactionSource.
func (lsf *LogicalShardingFilter) Close() error {
	return lsf.ts.Close()
}
