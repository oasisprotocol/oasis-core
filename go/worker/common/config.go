package common

import (
	tpConfig "github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
)

// Config contains common worker config.
type Config struct {
	TxPool tpConfig.Config

	// WillRegisterComputeRuntime specifies whether the node hosting RONL
	// components will be registered on the consensus layer as compute/observer node.
	WillRegisterComputeRuntime bool
}
