package simulator

import (
	"bufio"
	"fmt"
	"os"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

type FileTransactionSource struct {
	iof *os.File
	in  *bufio.Reader
}

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

// This will stop at *any* errors, e.g., badly formatted transactions, and not just EOF.
func (ft *FileTransactionSource) Get(_ uint) (*alg.Transaction, error) {
	return alg.ReadNewTransaction(alg.TestLocation(0), ft.in)
}

func (ft *FileTransactionSource) Close() {
	if ft.iof != nil {
		ft.iof.Close()
	}
	ft.in = nil // No Close() because no "ownership" transfer(?) of *io.File
}
