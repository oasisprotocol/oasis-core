package api

import (
	"testing"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestSerialization(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(nil)
	c := Runtime{
		ID:                       signature.PublicKey(key),
		Code:                     []byte{0x12, 0x13, 0x14, 0x15, 0x16},
		TEEHardware:              node.TEEHardwareIntelSGX,
		ReplicaGroupSize:         63,
		ReplicaGroupBackupSize:   72,
		ReplicaAllowedStragglers: 81,
		StorageGroupSize:         90,
	}

	cp := c.ToProto()
	restored := Runtime{}
	require.NoError(t, restored.FromProto(cp), "could not restore proto to runtime")
	require.Equal(t, c, restored, "Restored runtime not equal to original")
}
