package api

import (
	"testing"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/version"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestSerialization(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(nil)
	c := Runtime{
		ID:                       signature.PublicKey(key),
		TEEHardware:              node.TEEHardwareIntelSGX,
		ReplicaGroupSize:         63,
		ReplicaGroupBackupSize:   72,
		ReplicaAllowedStragglers: 81,
		StorageGroupSize:         90,
		KeyManager:               signature.PublicKey(key),
		Kind:                     KindCompute,
		Version:                  version.Version{Major: 1, Minor: 2, Patch: 3},
	}

	cp := c.ToProto()
	restored := Runtime{}
	require.NoError(t, restored.FromProto(cp), "could not restore proto to runtime")
	require.Equal(t, c, restored, "Restored runtime not equal to original")
}
