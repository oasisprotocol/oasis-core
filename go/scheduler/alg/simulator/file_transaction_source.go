package simulator

import (
	"bufio"
	"fmt"
	"os"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

// FileTransactionSource implements the TransactionSource interface and reads transactions from
// a file (perhaps logged via LoggingTransactionSource).  Along with control over seeding
// random number generators, this allows deterministic tests.
type FileTransactionSource struct {
	iof *os.File
	in  *bufio.Reader
}

// NewFileTransactionSource is a factory for FileTransactionSources where the data is read from
// the filename supplied in the fn formal parameter.
//
// nolint: gosec
//
// File inclusion is the intention.
func NewFileTransactionSource(fn string) *FileTransactionSource {
	// Handle "-" case to mean stdin.  This means files named "-" would have to be referred
	// to via "./-" which is awkward.  We could instead _only_ have the empty string ""
	// mean standard input, but that is different from the usual Unix convention.
	if fn == "" || fn == "-" {
		return &FileTransactionSource{iof: nil, in: bufio.NewReader(os.Stdin)}
	}
	f, err := os.Open(fn)
	if err != nil {
		panic(fmt.Sprintf("Could not open %s", fn))
	}
	return &FileTransactionSource{iof: f, in: bufio.NewReader(f)}
}

// Get reads the next transaction from the data file.  It will stop at *any* errors, e.g.,
// badly formatted transactions, and not just EOF.
func (ft *FileTransactionSource) Get(_ uint) (*alg.Transaction, error) {
	return alg.ReadNewTransaction(alg.TestLocation(0), ft.in)
}

// Close will close the underlying file and release the bufio buffers.
func (ft *FileTransactionSource) Close() error {
	if ft.iof != nil {
		if err := ft.iof.Close(); err != nil {
			return err
		}
	}
	ft.in = nil // No Close() because no "ownership" transfer(?) of *io.File
	return nil
}
