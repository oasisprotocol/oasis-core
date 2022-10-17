package common

import (
	"fmt"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
)

// ConsensusAddressesToTendermint converts given addresses from the form pubkey@IP:port to the form
// ID@IP:port where ID is the lowercase SHA256-20 hash of the pubkey.
func ConsensusAddressesToTendermint(addrs []string) ([]string, error) {
	tmAddrs := make([]string, 0, len(addrs))
	for _, a := range addrs {
		var addr node.ConsensusAddress
		if err := addr.UnmarshalText([]byte(a)); err != nil {
			return nil, err
		}

		// ID needs to be lowercase since Tendermint stores IDs in a map and uses a case sensitive
		// string comparison to check ID equality.
		// See: p2p/transport.go:MultiplexTransport.upgrade()
		id := strings.ToLower(crypto.PublicKeyToTendermint(&addr.ID).Address().String())
		tmAddr := fmt.Sprintf("%s@%s:%d", id, addr.Address.IP, addr.Address.Port)
		tmAddrs = append(tmAddrs, tmAddr)
	}
	return tmAddrs, nil
}

// PublicKeysToTendermint hashes given public keys using lowercase SHA256-20.
func PublicKeysToTendermint(keys []string) ([]string, error) {
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		var pk signature.PublicKey
		if err := pk.UnmarshalText([]byte(k)); err != nil {
			return nil, fmt.Errorf("malformed public key (%s): %w", k, err)
		}
		// ID needs to be lowercase since Tendermint stores IDs in a map and uses a case sensitive
		// string comparison to check ID equality.
		// See: p2p/transport.go:MultiplexTransport.upgrade()
		id := strings.ToLower(crypto.PublicKeyToTendermint(&pk).Address().String())
		ids = append(ids, id)
	}
	return ids, nil
}
