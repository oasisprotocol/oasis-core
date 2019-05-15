package common

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/worker/common/configparser"
)

var (
	cfgWorkerEnabled = "worker.enabled"

	cfgClientPort      = "worker.client.port"
	cfgClientAddresses = "worker.client.addresses"

	cfgRuntimeID = "worker.runtime.id"
)

// Config contains workers common config
type Config struct { // nolint: maligned
	ClientPort      uint16
	ClientAddresses []node.Address
	Runtimes        []signature.PublicKey

	logger *logging.Logger
}

// GetNodeAddresses returns worker node addresses.
func (c *Config) GetNodeAddresses() ([]node.Address, error) {
	var addresses []node.Address

	if len(c.ClientAddresses) > 0 {
		addresses = c.ClientAddresses
	} else {
		// Use all non-loopback addresses of this node.
		addrs, err := common.FindAllAddresses()
		if err != nil {
			c.logger.Error("failed to obtain addresses",
				"err", err)
			return nil, err
		}
		var address node.Address
		for _, addr := range addrs {
			if derr := address.FromIP(addr, c.ClientPort); derr != nil {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	return addresses, nil
}

// newConfig creates a new worker config.
func newConfig() (*Config, error) {
	// Parse register address overrides.
	clientAddresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgClientAddresses))
	if err != nil {
		return nil, err
	}
	runtimes, err := configparser.GetRuntimes(viper.GetStringSlice(cfgRuntimeID))
	if err != nil {
		return nil, err
	}

	return &Config{
		ClientPort:      uint16(viper.GetInt(cfgClientPort)),
		ClientAddresses: clientAddresses,
		Runtimes:        runtimes,
		logger:          logging.GetLogger("worker/config"),
	}, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgWorkerEnabled, false, "Enable worker processes")

		cmd.Flags().Uint16(cfgClientPort, 9100, "Port to use for incoming gRPC client connections")
		cmd.Flags().StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")

		cmd.Flags().StringSlice(cfgRuntimeID, []string{}, "List of IDs (hex) of runtimes that this node will participate in")
	}

	for _, v := range []string{
		cfgWorkerEnabled,

		cfgClientPort,
		cfgClientAddresses,

		cfgRuntimeID,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
