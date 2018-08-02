/*

Package scheduler.alg provides the infrastructure for building and evaluating scheduling
algorithms for horizontal scaling of Ethereum transactions.  At least one scheduling algorithm
the "greedy subgraph" algorithm, is implemented.  The interface is also designed to be directly
usable in the scheduler

The transaction abstraction for scheduling are the Transaction, which contains the information
needed to determine whether a transaction will have read/write or write/write conflicts with
another.  That is, it has the transaction's read-set and write-set of memory locations accessed
by the transaction.  This information is determined by _pre-execution_ at a single (untrusted)
compute server, and must be validated when the transaction is executed by members of a compute
committee.

For evaluation purposes, we define memory locations as int64.  For actual use, this will be a
full Ethereum global address, which is a tuple consisting of the contract address, a 160-bit
unsigned integer, and the address within the storage address space for the contract, a 256-bit
unsigned integer.

*/
package alg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
)

type ExecutionTime uint32 // estimated execution time

type Transaction struct {
	// Id TransactionIdType ?
	ReadSet, WriteSet *LocationSet
	TimeCost          ExecutionTime
	CreationSeqno     uint // to keep track of delay
}

func NewTransaction() *Transaction {
	return &Transaction{
		ReadSet:       NewLocationSet(),
		WriteSet:      NewLocationSet(),
		TimeCost:      0,
		CreationSeqno: 0,
	}
}

func (t Transaction) Write(w *bufio.Writer) {
	w.WriteString("(")
	t.ReadSet.Write(w)
	w.WriteString(", ")
	t.WriteSet.Write(w)
	w.WriteString(", ")
	w.WriteString(fmt.Sprintf("%d", t.TimeCost))
	w.WriteString(", ")
	w.WriteString(fmt.Sprintf("%d", t.CreationSeqno))
	w.WriteString(")")
}

func (t *Transaction) Read(lc Location, r *bufio.Reader) error {
	var err error
	if err = expect_rune('(', r); err != nil {
		return err
	}
	var s *LocationSet
	if s, err = ReadNewLocationSet(lc, r); err != nil {
		return err
	}
	t.ReadSet = s
	if err = expect_rune(',', r); err != nil {
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

func (t *Transaction) ToString() string {
	output_buffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(output_buffer)
	t.Write(bufw)
	if err := bufw.Flush(); err != nil {
		panic("Transaction.ToString conversion failed")
	}
	return output_buffer.String()
}

func ReadNewTransaction(l Location, r *bufio.Reader) (*Transaction, error) {
	t := NewTransaction()
	if err := t.Read(l, r); err != nil {
		return nil, err
	}
	return t, nil
}
