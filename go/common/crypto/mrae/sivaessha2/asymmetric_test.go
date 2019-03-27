package sivaessha2

import (
	"testing"

	"github.com/oasislabs/ekiden/go/common/crypto/mrae/api"
)

func TestSIV_AES_SHA2_Box_Integration(t *testing.T) {
	api.TestBoxIntegration(t, Box, New, KeySize)
}
