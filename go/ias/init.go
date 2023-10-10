// Package ias implements the IAS endpoints.
package ias

import (
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/ias/api"
	"github.com/oasisprotocol/oasis-core/go/ias/proxy/client"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

var logger = logging.GetLogger("ias")

// New creates a new IAS endpoint.
func New(identity *identity.Identity) ([]api.Endpoint, error) {
	if cmdFlags.DebugDontBlameOasis() {
		if config.GlobalConfig.IAS.DebugSkipVerify {
			logger.Warn("`ias.debug_skip_verify` set, AVR signature validation bypassed")
			ias.SetSkipVerify()
		}
	}

	return client.New(
		identity,
		config.GlobalConfig.IAS.ProxyAddresses,
	)
}
