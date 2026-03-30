package common

import (
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	tpConfig "github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
)

// Config contains common worker config.
type Config struct {
	TxPool tpConfig.Config

	logger *logging.Logger
}

// NewConfig creates a new worker config.
func NewConfig() (*Config, error) {
	cfg := Config{
		TxPool: config.GlobalConfig.Runtime.TxPool,
		logger: logging.GetLogger("worker/config"),
	}

	return &cfg, nil
}
