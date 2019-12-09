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

	var publicKey signature.PublicKey
	_ = publicKey.UnmarshalBinary(key)

	c := Runtime{
		ID:          publicKey,
		TEEHardware: node.TEEHardwareIntelSGX,
		Compute: ComputeParameters{
			GroupSize:         63,
			GroupBackupSize:   72,
			AllowedStragglers: 81,
		},
		Merge: MergeParameters{
			GroupSize:         63,
			GroupBackupSize:   72,
			AllowedStragglers: 81,
		},
		Storage:       StorageParameters{GroupSize: 90},
		KeyManagerOpt: &publicKey,
		Kind:          KindCompute,
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
