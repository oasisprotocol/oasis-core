package common

import (
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
)

var (
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

// ParseAddressList parses addresses.
func ParseAddressList(addresses []string) ([]node.Address, error) {
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

func getRuntimes(runtimeIDsHex []string) ([]signature.PublicKey, error) {
	var runtimes []signature.PublicKey
	for _, runtimeHex := range runtimeIDsHex {
		var runtime signature.PublicKey
		if err := runtime.UnmarshalHex(runtimeHex); err != nil {
			return nil, err
		}

		runtimes = append(runtimes, runtime)
	}
	return runtimes, nil
}

// NewConfig creates a new worker config.
func NewConfig() (*Config, error) {
	// Parse register address overrides.
	clientAddresses, err := ParseAddressList(viper.GetStringSlice(cfgClientAddresses))
	if err != nil {
		return nil, err
	}
	runtimes, err := getRuntimes(viper.GetStringSlice(cfgRuntimeID))
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

		cmd.Flags().Uint16(cfgClientPort, 9100, "Port to use for incoming gRPC client connections")
		cmd.Flags().StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")

		cmd.Flags().StringSlice(cfgRuntimeID, []string{}, "Runtime ID")
	}

	for _, v := range []string{
		cfgClientPort,
		cfgClientAddresses,

		cfgRuntimeID,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
