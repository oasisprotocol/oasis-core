package alg

import (
	"bufio"
)

type Location interface {
	Read(r *bufio.Reader) (Location, error)

	Write(w *bufio.Writer) (int, error)

	// other must have the same underlying concrete type as the
	// receiver
	Less(other interface{}) bool

	Equal(other interface{}) bool
}
