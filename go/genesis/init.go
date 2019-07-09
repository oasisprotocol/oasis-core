// Package genesis defines the Ekiden genesis block.
package genesis

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/genesis/api"
	"github.com/oasislabs/ekiden/go/genesis/bootstrap"
)

const (
	cfgGenesisFile = "genesis.file"

	cfgDebugBootstrapAddress = "genesis.debug.bootstrap.address"
)

// New creates a new genesis document provider.
func New(identity *identity.Identity) (api.Provider, error) {
	filename := viper.GetString(cfgGenesisFile)
	bootstrapAddress := viper.GetString(cfgDebugBootstrapAddress)

	if bootstrapAddress != "" {
		return bootstrap.NewProvider(bootstrapAddress)
	}
	return NewFileProvider(filename, identity)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgGenesisFile, "genesis.json", "path to genesis file")
		cmd.Flags().String(cfgDebugBootstrapAddress, "", "debug bootstrap server address:port")
	}

	for _, v := range []string{
		cfgGenesisFile,
		cfgDebugBootstrapAddress,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
