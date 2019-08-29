package p2p

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	cfgP2pPort      = "worker.p2p.port"
	cfgP2pAddresses = "worker.p2p.addresses"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

func init() {
	Flags.Uint16(cfgP2pPort, 9200, "Port to use for incoming P2P connections")
	Flags.StringSlice(cfgP2pAddresses, []string{}, "Address/port(s) to use for P2P connections when registering this node (if not set, all non-loopback local interfaces will be used)")

	_ = viper.BindPFlags(Flags)
}
