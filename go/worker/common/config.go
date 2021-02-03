package common

import (
	"fmt"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

var (
	// CfgClientPort configures the worker client port.
	CfgClientPort = "worker.client.port"

	cfgClientAddresses = "worker.client.addresses"

	// CfgSentryAddresses configures addresses and public keys of sentry nodes the worker should
	// connect to.
	CfgSentryAddresses = "worker.sentry.address"

	cfgStorageCommitTimeout = "worker.storage_commit_timeout"

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Config contains common worker config.
type Config struct { // nolint: maligned
	ClientPort      uint16
	ClientAddresses []node.Address
	SentryAddresses []node.TLSAddress

	StorageCommitTimeout time.Duration

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

// NewConfig creates a new worker config.
func NewConfig() (*Config, error) {
	// Parse register address overrides.
	clientAddresses, err := configparser.ParseAddressList(viper.GetStringSlice(cfgClientAddresses))
	if err != nil {
		return nil, err
	}

	// Parse sentry configuration.
	var sentryAddresses []node.TLSAddress
	for _, v := range viper.GetStringSlice(CfgSentryAddresses) {
		var tlsAddr node.TLSAddress
		if err = tlsAddr.UnmarshalText([]byte(v)); err != nil {
			return nil, fmt.Errorf("worker: bad sentry address (%s): %w", v, err)
		}
		sentryAddresses = append(sentryAddresses, tlsAddr)
	}

	cfg := Config{
		ClientPort:           uint16(viper.GetInt(CfgClientPort)),
		ClientAddresses:      clientAddresses,
		SentryAddresses:      sentryAddresses,
		StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),
		logger:               logging.GetLogger("worker/config"),
	}

	return &cfg, nil
}

func init() {
	Flags.Uint16(CfgClientPort, 9100, "Port to use for incoming gRPC client connections")
	Flags.StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")
	Flags.StringSlice(CfgSentryAddresses, []string{}, "Address(es) of sentry node(s) to connect to of the form [PubKey@]ip:port (where PubKey@ part represents base64 encoded node TLS public key)")

	Flags.Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

	_ = viper.BindPFlags(Flags)
}
