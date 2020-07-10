package deoxysii

import (
	"testing"

	"github.com/oasisprotocol/deoxysii"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/mrae/api"
)

func TestDeoxysII_Box_Integration(t *testing.T) {
	api.TestBoxIntegration(t, Box, deoxysii.New, deoxysii.KeySize)
}
