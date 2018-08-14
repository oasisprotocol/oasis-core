package alg

import (
	"bufio"
	"fmt"
)

const defaultTransactionCapacity = 10

// Subgraph maintains properties of a vertex-disjoint subgraph in the bipartite graph induced
// by transactions and their read-/write-sets, where transaction vertices have edges to each
// memory location to their read-set and write-set.
type Subgraph struct {
	ReadSet, WriteSet *LocationSet
	Transactions      []*Transaction
	timeCost          ExecutionTime
}

// AddTransaction adds the `t` Transaction to the receiver.
func (sg *Subgraph) AddTransaction(t *Transaction) {
	sg.ReadSet.Merge(t.ReadSet)
	sg.WriteSet.Merge(t.WriteSet)
	sg.Transactions = append(sg.Transactions, t)
	sg.timeCost += t.TimeCost
}

// EstExecutionTime returns the (estimated) execution time for the transactions within the
// subgraph.  Since a batch is run sequentially, this is just the sum of the time cost of all
// the transactions in the subgraph.
func (sg *Subgraph) EstExecutionTime() ExecutionTime {
	return sg.timeCost
}

// ConflictsWith is the boolean predicate that indicates if the transaction |t| has read-write
// or write-write conflicts with any of the transactions currently in the receiver subgraph.
// I.e., |t| cannot be added to a different subgraph in the current schedule, since it would
// cause the schedule to no longer be composed of commutative batches.
//
// TODO: Need better understanding of conflict type.  Maybe return an enum instead?
// Consider removing this method.  This is unused by GreedySubgraphsScheduler.
func (sg *Subgraph) ConflictsWith(t *Transaction) bool {
	// Read-Write conflict
	if t.ReadSet.Overlaps(sg.WriteSet) {
		return true
	}
	// Read-Write conflict
	if t.WriteSet.Overlaps(sg.ReadSet) {
		return true
	}
	// Write-Write conflict
	if t.WriteSet.Overlaps(sg.WriteSet) {
		return true
	}
	return false
}

// Merge adds all elements from `other` into the receiver subgraph.  We may want to merge two
// (or more) subgraphs if they are small, and if a new transaction writes to their read sets.
// Note that a new transaction cannot write into one subgraph's write set and another
// subgraph's read set simultaneously, since a schedule that contains those two subgraphs is
// not well-formed: the two subgraphs, even ignoring the new transaction, would not commute.
func (sg *Subgraph) Merge(other *Subgraph) {
	sg.ReadSet.Merge(other.ReadSet)
	sg.WriteSet.Merge(other.WriteSet)
	sg.Transactions = append(sg.Transactions, other.Transactions...)
	sg.timeCost += other.timeCost
}

// Write the receiver subgraph to the `bufio.Writer` pointed to by `bw`.  Unlike
// `Subgraph.Write` or `LocationSet.Write`, this is not in a canonical form and we do not
// supply a corresponding `Read` function.  It is the responsibility of the caller to check
// `bw.Flush()` for errors.
func (sg *Subgraph) Write(bw *bufio.Writer) {
	_, _ = fmt.Fprintf(bw, "Subgraph estimated total cost %d\n", uint64(sg.timeCost))
	_, _ = fmt.Fprintf(bw, "Transactions\n")
	j := 0
	sep := " "
	eltsMask := 0x3
	for _, t := range sg.Transactions {
		t.Write(bw)
		_, _ = bw.WriteString(sep)
		j = j + 1
		if (j & eltsMask) == 0 {
			sep = "\n"
		} else {
			sep = " "
		}
	}
	if j == 1 || (j&eltsMask) != 1 {
		_, _ = bw.WriteRune('\n')
	}
	_, _ = fmt.Fprintf(bw, "Read Set\n")
	sg.ReadSet.Write(bw)
	_, _ = fmt.Fprintf(bw, "\nWrite Set\n")
	sg.WriteSet.Write(bw)
	_, _ = bw.WriteRune('\n')
}

// NewSubgraph constructs and returns a new Subgraph object.
func NewSubgraph() *Subgraph {
	return &Subgraph{
		ReadSet:      NewLocationSet(),
		WriteSet:     NewLocationSet(),
		Transactions: make([]*Transaction, 0, defaultTransactionCapacity),
	}
}
