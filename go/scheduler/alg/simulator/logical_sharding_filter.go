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
func (lsf *LogicalShardingFilter) Get(tid int) (*alg.Transaction, error) {
	// topMap is fresh/new for every transaction, so that we get a new random choice each
	// time for the top N addresses.
	lsf.topMap = make([]int64, lsf.shardTopN) // zeros means no value chosen yet
	t, e := lsf.ts.Get(tid)
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
	ls.Find(func(loc alg.Location) bool {
		tloc := loc.(alg.TestLocation)
		i64loc := int64(tloc)
		if 0 <= i64loc && i64loc < int64(lsf.shardTopN) {
			iloc := int(i64loc) // array indices are ints.
			if lsf.topMap[iloc] == 0 {
				shard := int64(lsf.r.Intn(lsf.shardFactor))
				if !(0 <= shard && shard < int64(lsf.shardFactor)) {
					panic("Intn range error")
				}
				shardBase := i64loc * int64(lsf.shardFactor)
				newIndex := -(1 + shardBase + shard)
				if !(-int64(lsf.shardFactor*lsf.shardTopN) <= newIndex && newIndex < 0) {
					panic("newIndex out of range")
				}
				lsf.topMap[iloc] = newIndex
			}
			repl.Add(alg.TestLocation(lsf.topMap[iloc]))
		} else {
			repl.Add(tloc)
		}
		return false
	})
	*ls = *repl
}

// Close cleans up by closing the wrapped TransactionSource.
func (lsf *LogicalShardingFilter) Close() error {
	return lsf.ts.Close()
}
