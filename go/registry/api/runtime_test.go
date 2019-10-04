package api

import (
	"testing"

	"github.com/oasislabs/ed25519"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/version"

	"github.com/stretchr/testify/require"
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
		Version: VersionInfo{
			TEE:     []byte{},
			Version: version.Version{Major: 1, Minor: 2, Patch: 3},
		},
	}

	cp := c.ToProto()
	restored := Runtime{}
	require.NoError(t, restored.FromProto(cp), "could not restore proto to runtime")
	require.Equal(t, c, restored, "Restored runtime not equal to original")
}
