package node

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ed25519"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

func TestSerialization(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(nil)
	var publicKey signature.PublicKey
	_ = publicKey.UnmarshalBinary(key)

	n := Node{
		ID:       publicKey,
		EntityID: publicKey,
		Committee: CommitteeInfo{
			Certificate: []byte("I moon o'er you, Inis Mona, As long as I breathe, I'll call you my home"),
		},
		P2P: P2PInfo{
			ID: publicKey,
		},
		Consensus: ConsensusInfo{
			ID: publicKey,
		},
		Expiration: 42,
		Roles:      RoleComputeWorker,
	}

	np := n.ToProto()
	restored := Node{}
	require.NoError(t, restored.FromProto(np), "could not restore proto to node")
	require.Equal(t, n, restored, "Restored node not equal to original")
}
