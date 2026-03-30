package common

import (
	tpConfig "github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
)

// Config contains common worker config.
type Config struct {
	TxPool tpConfig.Config
}
