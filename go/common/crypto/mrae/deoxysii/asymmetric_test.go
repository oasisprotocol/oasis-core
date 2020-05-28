package deoxysii

import (
	"testing"

	"github.com/oasislabs/oasis-core/go/common/crypto/mrae/api"
	"github.com/oasisprotocol/deoxysii"
)

func TestDeoxysII_Box_Integration(t *testing.T) {
	api.TestBoxIntegration(t, Box, deoxysii.New, deoxysii.KeySize)
}
