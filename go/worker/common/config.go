package common

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/config"
	tpConfig "github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
)

// Config contains common worker config.
type Config struct {
	SentryAddresses []node.TLSAddress

	TxPool tpConfig.Config

	logger *logging.Logger
}

// NewConfig creates a new worker config.
func NewConfig() (*Config, error) {
	// Parse sentry configuration.
	var sentryAddresses []node.TLSAddress
	for _, v := range config.GlobalConfig.Runtime.SentryAddresses {
		var tlsAddr node.TLSAddress
		if err := tlsAddr.UnmarshalText([]byte(v)); err != nil {
			return nil, fmt.Errorf("worker: bad sentry address (%s): %w", v, err)
		}
		sentryAddresses = append(sentryAddresses, tlsAddr)
	}

	cfg := Config{
		SentryAddresses: sentryAddresses,
		TxPool:          config.GlobalConfig.Runtime.TxPool,
		logger:          logging.GetLogger("worker/config"),
	}

	return &cfg, nil
}
