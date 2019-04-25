package common

import (
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
)

var (
	cfgClientPort      = "worker.client.port"
	cfgClientAddresses = "worker.client.addresses"

	cfgP2pPort      = "worker.p2p.port"
	cfgP2pAddresses = "worker.p2p.addresses"
)

// Config contains workers common config
type Config struct { // nolint: maligned
	ClientPort      uint16
	ClientAddresses []node.Address
	P2PPort         uint16
	P2PAddresses    []node.Address

	logger *logging.Logger
}

func parseAddressList(addresses []string) ([]node.Address, error) {
	var output []node.Address
	for _, rawAddress := range addresses {
		rawIP, rawPort, err := net.SplitHostPort(rawAddress)
		if err != nil {
			return nil, fmt.Errorf("malformed address: %s", err)
		}

		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("malformed port: %s", rawPort)
		}

		ip := net.ParseIP(rawIP)
		if ip == nil {
			return nil, fmt.Errorf("malformed ip address: %s", rawIP)
		}

		var address node.Address
		if err := address.FromIP(ip, uint16(port)); err != nil {
			return nil, fmt.Errorf("unknown address family: %s", rawIP)
		}

		output = append(output, address)
	}

	return output, nil
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

// NewConfig creates a new worker config.
func NewConfig() (*Config, error) {
	// Parse register address overrides.
	clientAddresses, err := parseAddressList(viper.GetStringSlice(cfgClientAddresses))
	if err != nil {
		return nil, err
	}
	p2pAddresses, err := parseAddressList(viper.GetStringSlice(cfgP2pAddresses))
	if err != nil {
		return nil, err
	}

	return &Config{
		ClientPort:      uint16(viper.GetInt(cfgClientPort)),
		ClientAddresses: clientAddresses,
		P2PPort:         uint16(viper.GetInt(cfgP2pPort)),
		P2PAddresses:    p2pAddresses,
		logger:          logging.GetLogger("worker/config"),
	}, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {

		cmd.Flags().Uint16(cfgClientPort, 9100, "Port to use for incoming gRPC client connections")
		cmd.Flags().StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")

		cmd.Flags().Uint16(cfgP2pPort, 9200, "Port to use for incoming P2P connections")
		cmd.Flags().StringSlice(cfgP2pAddresses, []string{}, "Address/port(s) to use for P2P connections when registering this node (if not set, all non-loopback local interfaces will be used)")
	}

	for _, v := range []string{
		cfgClientPort,
		cfgClientAddresses,

		cfgP2pAddresses,
		cfgP2pPort,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
