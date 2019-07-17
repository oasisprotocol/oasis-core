package polypoint

import (
	"github.com/Nik-U/pbc"
	"github.com/ncw/gmp"
)

type PolyPoint struct {
	x       int32
	y       *gmp.Int
	polywit *pbc.Element
}

/// Construct a null polypoint
func NewZeroPoint() *PolyPoint {
	return &PolyPoint{
		x:       0,
		y:       gmp.NewInt(0),
		polywit: nil,
	}
}

/// Construct a new polypoint with the give value
func NewPoint(x int32, y *gmp.Int, w *pbc.Element) *PolyPoint {
	return &PolyPoint{
		x:       x,
		y:       y,
		polywit: w,
	}
}
