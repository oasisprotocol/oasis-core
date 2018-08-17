/*

Package alg provides the infrastructure for building and evaluating scheduling algorithms for
horizontal scaling of Oasis/Ethereum transactions.  At least one scheduling algorithm the
"greedy subgraph" algorithm, is implemented.  The interface is also designed to be directly
usable in the scheduler.

For experimentation/evaluation purposes, we define memory locations as int64 (TestLocation
type).  For actual use, this will be a full Ethereum global address, which is a tuple
consisting of the contract address, a 160-bit unsigned integer, and the address within the
storage address space for the contract, a 256-bit unsigned integer.

*/
package alg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
)

// ExecutionTime models the (estimated) cost of a transaction; depending on whether we want to
// use gas cost, wall clock time (in what units?), CPU cyles, etc, this may have to be changed
// to be a wider integral type.
type ExecutionTime uint32

// Transaction is the abstraction for atomic units that get scheduled.  It contains the
// information needed to determine whether a transaction will have read/write or write/write
// conflicts with another Transaction.  That is, it has the transaction's read-set and
// write-set of memory locations accessed by the transaction.  This information is determined
// by _pre-execution_ at a single (untrusted) compute server, and must be validated when the
// transaction is executed by members of a compute committee.
//
// The grammar for a Transaction's string representation:
//
// transaction : LPAREN LOCSET COMMA LOCSET COMMA INTEGER COMMA INTEGER RPAREN
//             ;
//
// where the first LOCSET is the read-set, and the second LOCSET is the write-set, and the last
// two INTEGERs are the estimated execution cost (unit unspecified) and a tranaction ID or
// sequence number.  (Optional non-newline white-space can occur between tokens.)
type Transaction struct {
	// Id TransactionIdType ?
	ReadSet, WriteSet *LocationSet
	TimeCost          ExecutionTime
	CreationSeqno     uint // to keep track of delay
}

// NewTransaction is a factory that constructs and returns a Transaction object.
func NewTransaction() *Transaction {
	return &Transaction{
		ReadSet:       NewLocationSet(),
		WriteSet:      NewLocationSet(),
		TimeCost:      0,
		CreationSeqno: 0,
	}
}

// Write the receiver transaction using the above grammar to the `bufio.Writer` argument.
// Caller should check error on bw.Flush().
func (t Transaction) Write(bw *bufio.Writer) {
	_, _ = bw.WriteString("(")
	t.ReadSet.Write(bw)
	_, _ = bw.WriteString(", ")
	t.WriteSet.Write(bw)
	_, _ = bw.WriteString(", ")
	_, _ = fmt.Fprintf(bw, "%d", t.TimeCost)
	_, _ = bw.WriteString(", ")
	_, _ = fmt.Fprintf(bw, "%d", t.CreationSeqno)
	_, _ = bw.WriteString(")")
}

// Read a transaction from `r`. The `lc` argument is used for its Location.Read interface
// method, since `Transaction`s (and `LocationSet`s) are oblivious to the actual type that
// implements the `Location` interface.  The string representation does not have to be in
// canonical (sorted read-/write-sets) format, but should use the production rule in the
// grammar above (and in LocationSet).
func (t *Transaction) Read(lc Location, r *bufio.Reader) error {
	var err error
	if err = expectRune('(', r); err != nil {
		return err
	}
	var s *LocationSet
	if s, err = ReadNewLocationSet(lc, r); err != nil {
		return err
	}
	t.ReadSet = s
	if err = expectRune(',', r); err != nil {
		return err
	}
	if s, err = ReadNewLocationSet(lc, r); err != nil {
		return err
	}
	t.WriteSet = s
	converted, err := fmt.Fscanf(r, ", %d, %d)", &t.TimeCost, &t.CreationSeqno)
	if err != nil {
		return err
	}
	if converted != 2 {
		return errors.New("Invalid execution time/cost or seqno")
	}
	return nil
}

// ToString converts the receiver transaction into a string.  The format should satisfy the
// grammar above.
func (t *Transaction) String() string {
	outputBuffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(outputBuffer)
	t.Write(bufw)
	if err := bufw.Flush(); err != nil {
		panic("Transaction.ToString conversion failed")
	}
	return outputBuffer.String()
}

// ReadNewTransaction reads in, from the bufioReader, a string representation of a Transaction
// using the location interface's Read for the memory locations accessed by the transaction.
// The Transaction is returned if there are no errors.
func ReadNewTransaction(l Location, r *bufio.Reader) (*Transaction, error) {
	t := NewTransaction()
	if err := t.Read(l, r); err != nil {
		return nil, err
	}
	return t, nil
}
