package api

import (
	"fmt"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/version"
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

// NewTopicIDForRuntime constructs topic id from the given parameters.
func NewTopicIDForRuntime(chainContext string, runtimeID common.Namespace, kind TopicKind) string {
	return fmt.Sprintf("%s/%d/%s/%s",
		chainContext,
		version.RuntimeCommitteeProtocol.Major,
		runtimeID.String(),
		kind,
	)
}
