package simulator

import (
	"bufio"
	"fmt"
	"os"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

type LoggingTransactionSource struct {
	os *os.File
	bw *bufio.Writer
	ts TransactionSource
}

func NewLoggingTransactionSource(fn string, ts TransactionSource) *LoggingTransactionSource {
	os, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		panic(fmt.Sprintf("Could not open file %s for logging transactions", fn))
	}
	return &LoggingTransactionSource{os: os, bw: bufio.NewWriter(os), ts: ts}
}

func (lts *LoggingTransactionSource) Get(seqno uint) (*alg.Transaction, error) {
	t, e := lts.ts.Get(seqno)
	if e == nil {
		t.Write(lts.bw)
		lts.bw.WriteRune('\n')
	}
	return t, e
}

func (lts *LoggingTransactionSource) Close() {
	lts.ts.Close()
	if lts.bw.Flush() != nil {
		panic(fmt.Sprintf("Write to transaction output log %s failed", lts.os.Name()))
	}
	lts.os.Close()
}
