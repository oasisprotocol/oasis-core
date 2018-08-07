package alg

import (
	"bufio"
)

// Location is an interface abstraction.  It is an interface because for simulation purposes,
// we want to use simple integers to name memory locations (see TestLocation), but in real
// transactions, the location is likely to be a larger value, e.g., a concatentation of the
// contract address (160 bits) and the contract storage address (256 bits).
type Location interface {
	Read(r *bufio.Reader) (Location, error)

	Write(w *bufio.Writer) (int, error)

	// other must have the same underlying concrete type as the
	// receiver
	Less(other interface{}) bool

	Equal(other interface{}) bool
}
