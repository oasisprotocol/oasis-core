package node

import (
	"testing"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ethereum"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestSerialization(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(nil)
	n := Node{
		ID:         signature.PublicKey(key),
		EthAddress: &ethereum.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		EntityID:   signature.PublicKey(key),
		Expiration: 42,
	}

	np := n.ToProto()
	restored := Node{}
	require.NoError(t, restored.FromProto(np), "could not restore proto to node")
	require.Equal(t, n, restored, "Restored node not equal to original")
}
