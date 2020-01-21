package common

import (
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	"github.com/oasislabs/oasis-core/go/worker/common/configparser"
)

var (
	// CfgClientPort configures the worker client port.
	CfgClientPort = "worker.client.port"

	cfgClientAddresses = "worker.client.addresses"

	// CfgRuntimeBackend configures the runtime backend.
	CfgRuntimeBackend = "worker.runtime.backend"
	// CfgRuntimeLoader configures the runtime loader binary.
	CfgRuntimeLoader = "worker.runtime.loader"
	// CfgRuntimeBinary confgures the runtime binary.
	CfgRuntimeBinary = "worker.runtime.binary"

	cfgStorageCommitTimeout = "worker.storage_commit_timeout"

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Config contains common worker config.
type Config struct { // nolint: maligned
	ClientPort      uint16
	ClientAddresses []node.Address

	// RuntimeHost contains configuration for a worker that hosts
	// runtimes. It may be nil if the worker is not configured to
	// host runtimes.
	RuntimeHost *RuntimeHostConfig

	StorageCommitTimeout time.Duration

	logger *logging.Logger
}

// RuntimeHostRuntimeConfig is a single runtime's host configuration.
type RuntimeHostRuntimeConfig struct {
	ID     common.Namespace
	Binary string
}

// RuntimeHostConfig is configuration for a worker that hosts runtimes.
type RuntimeHostConfig struct {
	Backend  string
	Loader   string
	Runtimes map[common.Namespace]RuntimeHostRuntimeConfig
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

	cfg := Config{
		ClientPort:           uint16(viper.GetInt(CfgClientPort)),
		ClientAddresses:      clientAddresses,
		StorageCommitTimeout: viper.GetDuration(cfgStorageCommitTimeout),
		logger:               logging.GetLogger("worker/config"),
	}

	// Check if runtime host is configured for the runtimes.
	if runtimeLoader := viper.GetString(CfgRuntimeLoader); runtimeLoader != "" {
		runtimeBinaries, err := runtimeRegistry.ParseRuntimeMap(viper.GetStringSlice(CfgRuntimeBinary))
		if err != nil {
			return nil, err
		}

		cfg.RuntimeHost = &RuntimeHostConfig{
			Backend:  viper.GetString(CfgRuntimeBackend),
			Loader:   runtimeLoader,
			Runtimes: make(map[common.Namespace]RuntimeHostRuntimeConfig),
		}

		for id, path := range runtimeBinaries {
			cfg.RuntimeHost.Runtimes[id] = RuntimeHostRuntimeConfig{
				ID:     id,
				Binary: path,
			}
		}
	}

	return &cfg, nil
}

func init() {
	Flags.Uint16(CfgClientPort, 9100, "Port to use for incoming gRPC client connections")
	Flags.StringSlice(cfgClientAddresses, []string{}, "Address/port(s) to use for client connections when registering this node (if not set, all non-loopback local interfaces will be used)")

	Flags.String(CfgRuntimeBackend, "sandboxed", "Runtime worker host backend")
	Flags.String(CfgRuntimeLoader, "", "Path to runtime loader binary")
	Flags.StringSlice(CfgRuntimeBinary, nil, "Path to runtime binary (format: <runtime-ID>:<path>)")

	Flags.Duration(cfgStorageCommitTimeout, 5*time.Second, "Storage commit timeout")

	_ = viper.BindPFlags(Flags)
}
