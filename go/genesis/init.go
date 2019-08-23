// Package genesis defines the Ekiden genesis block.
package genesis

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/genesis/api"
)

const cfgGenesisFile = "genesis.file"

// New creates a new genesis document provider.
func New() (api.Provider, error) {
	filename := viper.GetString(cfgGenesisFile)

	return NewFileProvider(filename)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgGenesisFile, "genesis.json", "path to genesis file")
	}

	for _, v := range []string{
		cfgGenesisFile,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
