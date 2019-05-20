package p2p

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgP2pPort      = "worker.p2p.port"
	cfgP2pAddresses = "worker.p2p.addresses"
)

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Uint16(cfgP2pPort, 9200, "Port to use for incoming P2P connections")
		cmd.Flags().StringSlice(cfgP2pAddresses, []string{}, "Address/port(s) to use for P2P connections when registering this node (if not set, all non-loopback local interfaces will be used)")
	}

	for _, v := range []string{
		cfgP2pAddresses,
		cfgP2pPort,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
