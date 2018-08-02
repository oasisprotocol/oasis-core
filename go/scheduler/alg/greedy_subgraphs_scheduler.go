package alg

import (
	"sort"

	"github.com/oasislabs/ekiden/go/common/logging"
)

type GreedySubgraphsScheduler struct {
	max_pending int
	max_time    ExecutionTime
	in_queue    []*Transaction
	logger      *logging.Logger
}

func NewGreedySubgraphs(max_p int, max_t ExecutionTime) *GreedySubgraphsScheduler {
	return &GreedySubgraphsScheduler{
		max_pending: max_p,
		max_time:    max_t,
		in_queue:    nil,
		logger:      logging.GetLogger("GreedySubgraphsScheduler"),
	}
}

func (gs *GreedySubgraphsScheduler) AddTransactions(t []*Transaction) []*Subgraph {
	gs.in_queue = append(gs.in_queue, t...)
	if len(gs.in_queue) < gs.max_pending {
		return nil
	}
	return gs.Schedule()
}

func (gs *GreedySubgraphsScheduler) FlushSchedule() []*Subgraph {
	return gs.Schedule()
}

// For sorting subgraphs, highest cost first.
type SubgraphOrder []*Subgraph

func (a SubgraphOrder) Len() int           { return len(a) }
func (a SubgraphOrder) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SubgraphOrder) Less(i, j int) bool { return a[i].EstExecutionTime() > a[j].EstExecutionTime() }

func (gs *GreedySubgraphsScheduler) Schedule() []*Subgraph {
	deferred := make([]*Transaction, 0)
	read_map := make(map[Location][]int)
	write_map := make(map[Location]int)
	// out_graphs[0] will forever be nil
	out_graphs := make([]*Subgraph, 1)

TransactionLoop:
	for _, t := range gs.in_queue {
		candidate := 0
		gs.logger.Debug("New write-set: %s", t.WriteSet.ToString())
		// Check for read/write and write/write conflicts that might be created by this
		// transaction's write-set.
		for loc := range t.WriteSet.Locations {
			// Check for write/write conflicts.
			if sgix := write_map[loc]; sgix != 0 {
				if candidate != 0 && candidate != sgix {
					gs.logger.Debug("-- deferring.  This will introduce write/write conflict w/ active")
					deferred = append(deferred, t)
					continue TransactionLoop
				}
				if out_graphs[sgix].EstExecutionTime()+t.TimeCost > gs.max_time {
					gs.logger.Debug("-- deferring.  Subgraph would be too full.")
					deferred = append(deferred, t)
					continue TransactionLoop
				} else {
					gs.logger.Debug("-- found candidate: %d", sgix)
					candidate = sgix
				}
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
				rlist := read_map[loc]
				if len(rlist) == 1 {
					candidate = rlist[0]
				} else if len(rlist) > 1 {
					// TODO:  consider merging subgraphs in rlist
					//
					// read_map and write_map for all locations in resultant
					// subgraph will have to be updated.
					gs.logger.Debug("-- deferring.  Written loc is read from multiple subgraphs.")
					deferred = append(deferred, t)
					continue TransactionLoop
				}
			}
		}
		// Check for read/write conflicts where a scheduled
		// transaction is writing to a location read by the
		// transaction under consideration.
		for loc := range t.ReadSet.Locations {
			if sgix := write_map[loc]; sgix != 0 {
				if candidate != 0 && candidate != sgix {
					// TODO: consider merging these two subgraphs
					gs.logger.Debug("-- deferring.  Written loc and read loc creates need to be added to two subgraphs.")
					deferred = append(deferred, t)
					continue TransactionLoop
				}
				// post: candidate == 0 || candidate == sgix.
				candidate = sgix
			}
		}
		if candidate != 0 {
			gs.logger.Debug("-- adding to existing subgraph")
		} else {
			gs.logger.Debug("-- creating new subgraph")
			candidate = len(out_graphs)
			out_graphs = append(out_graphs, NewSubgraph())
		}
		out_graphs[candidate].AddTransaction(t)
		for loc := range t.ReadSet.Locations {
			read_map[loc] = append(read_map[loc], candidate)
		}
		for loc := range t.WriteSet.Locations {
			write_map[loc] = candidate
		}
	}
	gs.in_queue = deferred

	// If there were subgraphs that were merged, then some of the entries in out_graph will be nil.  The first one is always nil.
	// TODO: when merging is implemented, do nil filtration.
	out_graphs = out_graphs[1:]
	// sort result in estimated execution time order, highest first
	sort.Sort(SubgraphOrder(out_graphs))
	return out_graphs
}
