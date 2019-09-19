package common

import (
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/worker/common/configparser"
)

var (
	cfgClientPort      = "worker.client.port"
	cfgClientAddresses = "worker.client.addresses"

	cfgRuntimeID = "worker.runtime.id"

	cfgRuntimeBackend = "worker.runtime.backend"
	cfgRuntimeLoader  = "worker.runtime.loader"
	cfgRuntimeBinary  = "worker.runtime.binary"
	// XXX: This is needed till the code can watch the registry for runtimes.
	cfgRuntimeSGXIDs = "worker.runtime.sgx_ids"

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Config contains common worker config.
type Config struct { // nolint: maligned
	ClientPort      uint16
	ClientAddresses []node.Address
	Runtimes        []signature.PublicKey

	// RuntimeHost contains configuration for a worker that hosts
	// runtimes. It may be nil if the worker is not configured to
	// host runtimes.
	RuntimeHost *RuntimeHostConfig

	logger *logging.Logger
}

// RuntimeHostRuntimeConfig is a single runtime's host configuration.
type RuntimeHostRuntimeConfig struct {
	ID          signature.PublicKey
	Binary      string
	TEEHardware node.TEEHardware
}

// RuntimeHostConfig is configuration for a worker that hosts runtimes.
type RuntimeHostConfig struct {
	Backend  string
	Loader   string
	Runtimes map[signature.MapKey]RuntimeHostRuntimeConfig
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

func getSGXRuntimeIDs() (map[signature.MapKey]bool, error) {
	m := make(map[signature.MapKey]bool)

	for _, v := range viper.GetStringSlice(cfgRuntimeSGXIDs) {
		var id signature.PublicKey
		if err := id.UnmarshalHex(v); err != nil {
			return nil, err
		}

		m[id.ToMapKey()] = true
	}

	return m, nil
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

	cfg := Config{
		ClientPort:      uint16(viper.GetInt(cfgClientPort)),
		ClientAddresses: clientAddresses,
		Runtimes:        runtimes,
		logger:          logging.GetLogger("worker/config"),
	}

	// Check if runtime host is configured for the runtimes.
	if runtimeLoader := viper.GetString(cfgRuntimeLoader); runtimeLoader != "" {
		runtimeBinaries := viper.GetStringSlice(cfgRuntimeBinary)
		if len(runtimeBinaries) != len(runtimes) {
			return nil, fmt.Errorf("runtime binary/id count mismatch")
		}

		sgxRuntimeIDs, err := getSGXRuntimeIDs()
		if err != nil {
			return nil, err
		}

		cfg.RuntimeHost = &RuntimeHostConfig{
			Backend:  viper.GetString(cfgRuntimeBackend),
			Loader:   runtimeLoader,
			Runtimes: make(map[signature.MapKey]RuntimeHostRuntimeConfig),
		}

		for idx, runtimeBinary := range runtimeBinaries {
			runtimeID := runtimes[idx]

			var teeHardware node.TEEHardware
			if sgxRuntimeIDs[runtimeID.ToMapKey()] {
				teeHardware = node.TEEHardwareIntelSGX
			}

			cfg.RuntimeHost.Runtimes[runtimeID.ToMapKey()] = RuntimeHostRuntimeConfig{
				ID:          runtimeID,
				Binary:      runtimeBinary,
				TEEHardware: teeHardware,
			}
		}
	}

	return &cfg, nil
}

func init() {
	Flags.Uint16(cfgClientPort, 9100, "Port to use for incoming gRPC client connections")
	Flags.StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")

	Flags.StringSlice(cfgRuntimeID, []string{}, "List of IDs (hex) of runtimes that this node will participate in")

	Flags.String(cfgRuntimeBackend, "sandboxed", "Runtime worker host backend")
	Flags.String(cfgRuntimeLoader, "", "Path to runtime loader binary")
	Flags.StringSlice(cfgRuntimeBinary, nil, "Path to runtime binary")
	// XXX: This is needed till the code can watch the registry for runtimes.
	Flags.StringSlice(cfgRuntimeSGXIDs, nil, "SGX runtime IDs")

	_ = viper.BindPFlags(Flags)
}
