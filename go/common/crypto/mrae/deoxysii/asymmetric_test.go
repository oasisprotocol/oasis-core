package deoxysii

import (
	"encoding/hex"
	"testing"

	curve25519 "github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"github.com/oasisprotocol/deoxysii"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/mrae/api"
)

func Test_DeriveSymmetricKey(t *testing.T) {
	p, _ := hex.DecodeString("c07b151fbc1e7a11dff926111188f8d872f62eba0396da97c0a24adb75161750")
	var privateKey [32]byte
	copy(privateKey[:], p)
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	publicKeyHex := hex.EncodeToString(publicKey[:])
	require.EqualValues(t, publicKeyHex, "3046db3fa70ce605457dc47c48837ebd8bd0a26abfde5994d033e1ced68e2576", "derive public key")

	var sharedKey [deoxysii.KeySize]byte
	Box.DeriveSymmetricKey(sharedKey[:], &publicKey, &privateKey)
	sharedKeyHex := hex.EncodeToString(sharedKey[:])
	require.EqualValues(t, sharedKeyHex, "e69ac21066a8c2284e8fdc690e579af4513547b9b31dd144792c1904b45cf586", "derive symmetric key")
}

func TestDeoxysII_Box_Integration(t *testing.T) {
	api.TestBoxIntegration(t, Box, deoxysii.New, deoxysii.KeySize)
}
