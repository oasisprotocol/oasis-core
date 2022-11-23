package bootstrap

import (
	"fmt"

	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

const (
	// ModuleName is a unique module name for the bootstrap discovery module.
	ModuleName = "p2p/discovery/bootstrap"

	// BootstrapProtocolName is the name for the bootstrap protocol.
	BootstrapProtocolName = "bootstrap"

	// MethodDiscover is the method name for the peer discovery handler.
	MethodDiscover = "discover"

	// MethodAdvertise is the method name for the service advertisement handler.
	MethodAdvertise = "advertise"

	// MaxPeers is the maximum number of peers the seed node will return.
	MaxPeers = 100
)

var (
	// ErrMethodNotSupported is an error raised when a given method is not supported.
	ErrMethodNotSupported = errors.New(ModuleName, 1, "bootstrap: method not supported")

	// ErrBadRequest is an error raised when a given request is malformed.
	ErrBadRequest = errors.New(ModuleName, 2, "bootstrap: bad request")

	// ErrMaliciousSeed is an error raised when a seed doesn't follow the bootstrap protocol.
	ErrMaliciousSeed = errors.New(ModuleName, 3, "bootstrap: malicious seed")

	// BootstrapProtocolVersion is the supported version of the bootstrap protocol.
	BootstrapProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}
)

// ProtocolID is a unique protocol identifier for the bootstrap protocol.
func ProtocolID() protocol.ID {
	return protocol.ID(fmt.Sprintf("/oasis/%s/%s",
		BootstrapProtocolName,
		BootstrapProtocolVersion.MaskNonMajor(),
	))
}
