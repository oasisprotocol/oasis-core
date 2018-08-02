package alg

import (
	"bufio"
	"fmt"
)

const DEFAULT_TRANSACTION_CAPACITY = 10

type Subgraph struct {
	ReadSet, WriteSet *LocationSet
	Transactions      []*Transaction
	time_cost         ExecutionTime
}

func (sg *Subgraph) AddTransaction(t *Transaction) {
	sg.ReadSet.Merge(t.ReadSet)
	sg.WriteSet.Merge(t.WriteSet)
	sg.Transactions = append(sg.Transactions, t)
	sg.time_cost += t.TimeCost
}

// For scheduling we want the (estimated) execution time if all
// transactions within the subgraph were run sequentially.
func (sg *Subgraph) EstExecutionTime() ExecutionTime {
	return sg.time_cost
}

// Need better understanding of conflict type.
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

// We may want to merge two (or more) subgraphs if they are small, and
// if a new transaction writes to their read sets.
func (sg *Subgraph) Merge(other *Subgraph) {
	sg.ReadSet.Merge(other.ReadSet)
	sg.WriteSet.Merge(other.WriteSet)
	sg.Transactions = append(sg.Transactions, other.Transactions...)
	sg.time_cost += other.time_cost
}

func (sg *Subgraph) Write(bw *bufio.Writer) {
	fmt.Fprintf(bw, "Transactions\n")
	j := 0
	sep := " "
	elts_mask := 0x3
	for _, t := range sg.Transactions {
		t.Write(bw)
		bw.WriteString(sep)
		j = j + 1
		if (j & elts_mask) == 0 {
			sep = "\n"
		} else {
			sep = " "
		}
	}
	if j == 1 || (j&elts_mask) != 1 {
		bw.WriteRune('\n')
	}
	fmt.Fprintf(bw, "Read Set\n")
	sg.ReadSet.Write(bw)
	fmt.Fprintf(bw, "\nWrite Set\n")
	sg.WriteSet.Write(bw)
	bw.WriteRune('\n')
}

func NewSubgraph() *Subgraph {
	return &Subgraph{
		ReadSet:      NewLocationSet(),
		WriteSet:     NewLocationSet(),
		Transactions: make([]*Transaction, 0, DEFAULT_TRANSACTION_CAPACITY),
	}
}
