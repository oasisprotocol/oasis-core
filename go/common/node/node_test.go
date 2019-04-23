package node

import (
	"testing"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestSerialization(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(nil)
	n := Node{
		ID:         signature.PublicKey(key),
		EntityID:   signature.PublicKey(key),
		Expiration: 42,
		Roles:  ComputeWorker,
	}

	np := n.ToProto()
	restored := Node{}
	require.NoError(t, restored.FromProto(np), "could not restore proto to node")
	require.Equal(t, n, restored, "Restored node not equal to original")
}
