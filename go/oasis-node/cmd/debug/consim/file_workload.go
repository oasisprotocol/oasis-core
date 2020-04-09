package consim

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
)

const (
	cfgFileTxs       = "consim.workload.file.txs"
	fileWorkloadName = "file"
)

var fileTxsFlag = flag.NewFlagSet("", flag.ContinueOnError)

type fileWorkload struct {
	ch  chan []BlockTx
	dec *json.Decoder

	f *os.File
}

func (w *fileWorkload) Init(doc *genesis.Document) error {
	return nil
}

func (w *fileWorkload) Start(doc *genesis.Document, cancelCh <-chan struct{}, errCh chan<- error) (<-chan []BlockTx, error) {
	if _, err := w.dec.Token(); err != nil {
		return nil, fmt.Errorf("consim/workload/file: failed to find opening delimiter: %w", err)
	}
	w.ch = make(chan []BlockTx)

	go func() {
		defer close(w.ch)
		for w.dec.More() {
			var txVec []BlockTx
			if err := w.dec.Decode(&txVec); err != nil {
				errCh <- fmt.Errorf("consim/workload/file: failed to decode block tx: %w", err)
				return
			}
			select {
			case <-cancelCh:
				return
			case w.ch <- txVec:
			}
		}
	}()

	return w.ch, nil
}

func (w *fileWorkload) Finalize(*genesis.Document) error {
	if _, err := w.dec.Token(); err != nil {
		return fmt.Errorf("consim/workload/file: failed to find closing delimiter: %w", err)
	}

	return nil
}

func (w *fileWorkload) Cleanup() {
	_ = w.f.Close()
}

func newFileWorkload(rng *rand.Rand) (Workload, error) {
	f, err := os.Open(viper.GetString(cfgFileTxs))
	if err != nil {
		return nil, fmt.Errorf("consim/workload/file: failed to open transaction file: %w", err)
	}

	return &fileWorkload{
		dec: json.NewDecoder(bufio.NewReader(f)),
		f:   f,
	}, nil
}

func init() {
	fileTxsFlag.String(cfgFileTxs, "transactions.json", "path to transactions document")
	_ = viper.BindPFlags(fileTxsFlag)
}
