// Package ias implements the IAS endpoints.
package ias

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/ias/api"
	"github.com/oasislabs/oasis-core/go/ias/proxy/client"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
)

const (
	CfgProxyAddress       = "ias.proxy_addr"
	CfgTLSCertFile        = "ias.tls"
	CfgDebugSkipVerify    = "ias.debug.skip_verify"
	CfgAllowDebugEnclaves = "ias.debug.allow_debug_enclaves"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

var logger = logging.GetLogger("ias")

// New creates a new IAS endpoint.
func New(identity *identity.Identity) (api.Endpoint, error) {
	if cmdFlags.DebugDontBlameOasis() {
		if viper.GetBool(CfgDebugSkipVerify) {
			logger.Warn("`ias.debug.skip_verify` set, AVR signature validation bypassed")
			ias.SetSkipVerify()
		}

		if viper.GetBool(CfgAllowDebugEnclaves) {
			logger.Warn("`ias.debug.allow_debug_enclaves` set, enclaves in debug mode will be allowed")
			ias.SetAllowDebugEnclaves()
		}
	}

	return client.New(
		identity,
		viper.GetString(CfgProxyAddress),
		viper.GetString(CfgTLSCertFile),
	)
}

func init() {
	Flags.String(CfgProxyAddress, "", "IAS proxy address")
	Flags.String(CfgTLSCertFile, "", "IAS proxy TLS certificate")
	Flags.Bool(CfgDebugSkipVerify, false, "skip IAS AVR signature verification (UNSAFE)")
	Flags.Bool(CfgAllowDebugEnclaves, false, "allow enclaves compiled in debug mode (UNSAFE)")

	_ = Flags.MarkHidden(CfgDebugSkipVerify)
	_ = Flags.MarkHidden(CfgAllowDebugEnclaves)

	_ = viper.BindPFlags(Flags)
}
