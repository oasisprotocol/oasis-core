package polypoint

import (
        "math/rand"
        "testing"

        "github.com/ncw/gmp"
	"github.com/Nik-U/pbc"
        "github.com/stretchr/testify/assert"
)

func TestNewZeroPoint(t *testing.T) {
        zero := gmp.NewInt(0)
        ZERO := NewZeroPoint()

        assert.Zero(t, ZERO.x)
        assert.Zero(t, ZERO.y.Cmp(zero))
        assert.Nil(t, ZERO.polywit)
}

func TestNewPoint(t *testing.T) {

        x := int32(rand.Intn(100))

	rnd := rand.New(rand.NewSource(11))
        rnd_rng := gmp.NewInt(100)
        y := gmp.NewInt(0)
        y.Rand(rnd, rnd_rng)

        params := pbc.GenerateA(160, 512)
        pairing := params.NewPairing()
        w := pairing.NewG1()

	POINT := NewPoint(x, y, w)

        assert.Equal(t, x, POINT.x)
        assert.Zero(t, POINT.y.Cmp(y))
        assert.True(t, POINT.polywit.Equals(w))
}
