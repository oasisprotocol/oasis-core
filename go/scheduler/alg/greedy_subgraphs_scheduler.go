package alg

import (
	"sort"

	"github.com/oasislabs/ekiden/go/common/logging"
)

// GreedySubgraphsScheduler takes transactions from the queue of transactions and (greedily)
// assigns them to new subgraphs (batches of transactions) if there are no read/write or
// write/write conflicts with any existing subgraphs, and if there are conflicts with exactly
// one subgraph, adds it to that subgraph.  Otherwise, place the transaction in a `defer` list,
// to be placed in a later schedule.
//
// Future tweaks of the algorithm: if there are two or more conflicting subgraphs, and the
// subgraphs are sufficiently small, merge those subgraphs together to allow the transaction
// under consideration to be scheduled, rather than deferred.
type GreedySubgraphsScheduler struct {
	maxPending int
	maxTime    ExecutionTime
	inQueue    []*Transaction
	logger     *logging.Logger
}

// NewGreedySubgraphsScheduler constructs a new greedy subgraph scheduler object.  Only
// maxPending and maxTime are exposed in the ctor interface to control when the scheduler might
// emit a schedule and the maximum subgraph / commutative batch size used to generate the
// schedule.  NB: the scheduler is unaware of the number of compute committees available, and
// there is usually many small batches.
func NewGreedySubgraphsScheduler(maxP int, maxT ExecutionTime) *GreedySubgraphsScheduler {
	return &GreedySubgraphsScheduler{
		maxPending: maxP,
		maxTime:    maxT,
		inQueue:    nil,
		logger:     logging.GetLogger("GreedySubgraphsScheduler"),
	}
}

// AddTransactions add a slice of transactions to the queue.  See the Scheduler interface.
func (gs *GreedySubgraphsScheduler) AddTransactions(t []*Transaction) []*Subgraph {
	gs.inQueue = append(gs.inQueue, t...)
	if len(gs.inQueue) < gs.maxPending && len(t) != 0 {
		return nil
	}
	return gs.Schedule()
}

// FlushSchedule tells the scheduler to perform scheduling.  See the Scheduler interface.
func (gs *GreedySubgraphsScheduler) FlushSchedule() []*Subgraph {
	return gs.Schedule()
}

// NumDeferred returns the number of transactions that are queued for scheduling.
func (gs *GreedySubgraphsScheduler) NumDeferred() int {
	return len(gs.inQueue)
}

// Schedule actually performs scheduling and returns a slice containing mutually commutative
// subgraphs.
//
// nolint: gocyclo
func (gs *GreedySubgraphsScheduler) Schedule() []*Subgraph {
	deferred := make([]*Transaction, 0)
	readMap := make(map[Location][]int)
	writeMap := make(map[Location]int)
	// outGraphs[0] will forever be nil
	outGraphs := make([]*Subgraph, 1)

TransactionLoop:
	for _, t := range gs.inQueue {
		candidate := 0
		gs.logger.Debug("New write-set: %s", t.WriteSet.String())
		// Check for read/write and write/write conflicts that might be created by this
		// transaction's write-set.
		if t.WriteSet.Find(func(loc Location) bool {
			// Check for write/write conflicts.
			if sgix := writeMap[loc]; sgix != 0 {
				if candidate != 0 && candidate != sgix {
					gs.logger.Debug("-- deferring.  This will introduce write/write conflict w/ active")
					deferred = append(deferred, t)
					return true
				}
				if outGraphs[sgix].EstExecutionTime()+t.TimeCost > gs.maxTime {
					gs.logger.Debug("-- deferring.  Subgraph would be too full.")
					deferred = append(deferred, t)
					return true
				}
				gs.logger.Debug("-- found candidate: %d", sgix)
				candidate = sgix
			}
			// Check for read/write conflicts.  If there is a candidate for this
			// location, i.e., a subgraph contains a transaction that also writes to
			// the location, then the only reads from that location will be from
			// that subgraph, and we can skip it.  Otherwise, no other scheduled
			// transaction writes to the location, and if exactly one subgraph reads
			// from it, we want to put this one in the subgraph from it, we will put
			// it in there.  If there are more than one, we defer (or TODO consider
			// merging the the read subgraphs into one).
			if candidate != 0 {
				rlist := readMap[loc]
				if len(rlist) == 1 {
					candidate = rlist[0]
				} else if len(rlist) > 1 {
					// TODO:  consider merging subgraphs in rlist
					//
					// readMap and writeMap for all locations in resultant
					// subgraph will have to be updated.
					gs.logger.Debug("-- deferring.  Written loc is read from multiple subgraphs.")
					deferred = append(deferred, t)
					return true
				}
			}
			return false
		}) {
			continue TransactionLoop
		}
		// Check for read/write conflicts where a scheduled
		// transaction is writing to a location read by the
		// transaction under consideration.
		if t.ReadSet.Find(func(loc Location) bool {
			if sgix := writeMap[loc]; sgix != 0 {
				if candidate != 0 && candidate != sgix {
					// TODO: consider merging these two subgraphs
					gs.logger.Debug("-- deferring.  Written loc and read loc creates need to be added to two subgraphs.")
					deferred = append(deferred, t)
					return true
				}
				// post: candidate == 0 || candidate == sgix.
				candidate = sgix
			}
			return false
		}) {
			continue TransactionLoop
		}
		if candidate != 0 {
			gs.logger.Debug("-- adding to existing subgraph")
		} else {
			gs.logger.Debug("-- creating new subgraph")
			candidate = len(outGraphs)
			outGraphs = append(outGraphs, NewSubgraph())
		}
		outGraphs[candidate].AddTransaction(t)
		t.ReadSet.Find(func(loc Location) bool {
			readMap[loc] = append(readMap[loc], candidate)
			return false
		})
		t.WriteSet.Find(func(loc Location) bool {
			writeMap[loc] = candidate
			return false
		})
	}
	gs.inQueue = deferred

	// If there were subgraphs that were merged, then some of the entries in outGraphs will
	// be nil.  The first one is always nil.  TODO: when merging is implemented, do nil
	// filtration.
	outGraphs = outGraphs[1:]
	// sort result in estimated execution time order, highest first
	sort.Sort(subgraphOrder(outGraphs))
	return outGraphs
}
