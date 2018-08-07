package contract

import (
	"testing"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func TestSerialization(t *testing.T) {
	key, _, _ := ed25519.GenerateKey(nil)
	c := Contract{
		ID:                       signature.PublicKey(key),
		StoreID:                  StoreID{100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131},
		Code:                     []byte{0x12, 0x13, 0x14, 0x15, 0x16},
		MinimumBond:              42,
		ModeNonDeterministic:     false,
		FeaturesSGX:              false,
		AdvertisementRate:        54,
		ReplicaGroupSize:         63,
		ReplicaGroupBackupSize:   72,
		ReplicaAllowedStragglers: 81,
		StorageGroupSize:         90,
	}

	cp := c.ToProto()
	restored := Contract{}
	require.NoError(t, restored.FromProto(cp), "could not restore proto to contract")
	require.Equal(t, c, restored, "Restored contract not equal to original")
}
