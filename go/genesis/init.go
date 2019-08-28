// Package genesis defines the Ekiden genesis block.
package genesis

import (
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	"github.com/oasislabs/ekiden/go/genesis/api"
)

// New creates a new genesis document provider.
func New() (api.Provider, error) {
	filename := flags.GenesisFile()

	return NewFileProvider(filename)
}
