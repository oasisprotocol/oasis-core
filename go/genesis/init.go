// Package genesis defines the Oasis genesis block.
package genesis

import (
	"github.com/oasislabs/oasis-core/go/genesis/api"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
)

// New creates a new genesis document provider.
func New() (api.Provider, error) {
	filename := flags.GenesisFile()

	return NewFileProvider(filename)
}
