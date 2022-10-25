package common

import (
	"fmt"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
)

var (
	// CfgClientPort configures the worker client port.
	CfgClientPort = "worker.client.port"

	// CfgSentryAddresses configures addresses and public keys of sentry nodes the worker should
	// connect to.
	CfgSentryAddresses = "worker.sentry.address"

	cfgMaxTxPoolSize       = "worker.tx_pool.schedule_max_tx_pool_size"
	cfgScheduleTxCacheSize = "worker.tx_pool.schedule_tx_cache_size"
	cfgCheckTxMaxBatchSize = "worker.tx_pool.check_tx_max_batch_size"
	cfgRecheckInterval     = "worker.tx_pool.recheck_interval"

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Config contains common worker config.
type Config struct { // nolint: maligned
	ClientPort      uint16
	SentryAddresses []node.TLSAddress

	TxPool txpool.Config

	logger *logging.Logger
}

// GetNodeAddresses returns worker node addresses.
func (c *Config) GetNodeAddresses() ([]node.Address, error) {
	var addresses []node.Address

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

	return addresses, nil
}

// NewConfig creates a new worker config.
func NewConfig() (*Config, error) {
	// Parse sentry configuration.
	var sentryAddresses []node.TLSAddress
	for _, v := range viper.GetStringSlice(CfgSentryAddresses) {
		var tlsAddr node.TLSAddress
		if err := tlsAddr.UnmarshalText([]byte(v)); err != nil {
			return nil, fmt.Errorf("worker: bad sentry address (%s): %w", v, err)
		}
		sentryAddresses = append(sentryAddresses, tlsAddr)
	}

	cfg := Config{
		ClientPort:      uint16(viper.GetInt(CfgClientPort)),
		SentryAddresses: sentryAddresses,
		TxPool: txpool.Config{
			MaxPoolSize:          viper.GetUint64(cfgMaxTxPoolSize),
			MaxCheckTxBatchSize:  viper.GetUint64(cfgCheckTxMaxBatchSize),
			MaxLastSeenCacheSize: viper.GetUint64(cfgScheduleTxCacheSize),

			// TODO: Make these configurable.
			RepublishInterval: 60 * time.Second,

			RecheckInterval: viper.GetUint64(cfgRecheckInterval),
		},
		logger: logging.GetLogger("worker/config"),
	}

	return &cfg, nil
}

func init() {
	Flags.Uint16(CfgClientPort, 9100, "Port to use for incoming gRPC client connections")
	Flags.StringSlice(CfgSentryAddresses, []string{}, "Address(es) of sentry node(s) to connect to of the form [PubKey@]ip:port (where PubKey@ part represents base64 encoded node TLS public key)")

	Flags.Uint64(cfgMaxTxPoolSize, 50_000, "Maximum size of the scheduling transaction pool")
	Flags.Uint64(cfgScheduleTxCacheSize, 100_000, "Maximum cache size of recently scheduled transactions to prevent re-scheduling")
	Flags.Uint64(cfgCheckTxMaxBatchSize, 1000, "Maximum check tx batch size")
	Flags.Uint64(cfgRecheckInterval, 5, "Transaction recheck interval (in rounds)")

	_ = viper.BindPFlags(Flags)
}
