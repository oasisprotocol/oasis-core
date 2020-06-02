package consim

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/spf13/viper"

	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

// Tx is a single transaction, and the expected Check/DeliverTx status
// code.
type BlockTx struct {
	Tx   []byte
	Code uint32
}

// Workload is a simulator workload.
type Workload interface {
	// Init initializes the workload (and alters the genesis document as required).
	Init(*genesis.Document) error

	// Start starts the workload.
	//
	// Note: The genesis document is the initial chain state, after the fixups
	// from Init are applied, and existing state is loaded from disk.
	Start(*genesis.Document, <-chan struct{}, chan<- error) (<-chan []BlockTx, error)

	// Finalize is called after the workload is complete with the final chain state.
	Finalize(*genesis.Document) error

	// Cleanup cleans up the workload.
	Cleanup()
}

func newWorkload(rng *rand.Rand) (Workload, error) {
	wName := viper.GetString(cfgWorkload)

	switch strings.ToLower(wName) {
	case xferWorkloadName:
		return newXferWorkload(rng)
	case fileWorkloadName:
		return newFileWorkload(rng)
	default:
	}
	return nil, fmt.Errorf("consim: unsupported workload: '%v'", wName)
}
