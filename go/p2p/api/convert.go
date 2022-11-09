package api

import (
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// PublicKeyToPeerID converts a public key to a peer identifier.
func PublicKeyToPeerID(pk signature.PublicKey) (core.PeerID, error) {
	pubKey, err := publicKeyToPubKey(pk)
	if err != nil {
		return "", err
	}

	id, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	return id, nil
}

// PublicKeyMapToPeerIDs converts a map of public keys to a list of peer identifiers.
func PublicKeyMapToPeerIDs(pks map[signature.PublicKey]bool) ([]core.PeerID, error) {
	ids := make([]core.PeerID, 0, len(pks))
	for pk := range pks {
		id, err := PublicKeyToPeerID(pk)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}
