// Package node implements common node identity routines.
//
// This package is meant for interoperability with the rust compute worker.
package node

import (
	"crypto/tls"
	"net"

	"golang.org/x/crypto/ed25519"
)

// Node represents public connectivity information about an Ekiden node.
type Node struct {
	ID ed25519.PublicKey
	EthAddress [20]byte
	EntityID ed25519.PublicKey
	Expiration uint64
	Addresses []net.Addr
	Certificate *tls.Certificate
	Stake []byte
}
