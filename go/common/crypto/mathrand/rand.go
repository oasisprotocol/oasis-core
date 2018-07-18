// Package mathrand implements an adapter from a cryptographically secure
// entropy source that implements an io.Reader to a math/rand.Source64.
package mathrand

import (
	"encoding/binary"
	"io"
	"math/rand"
)

// bufferSize is the size (in entries) of the adapter's internal
// buffer.  Altering this value will break backward compatibility
// if the cryptographic source is deterministic.
const bufferSize = 128

type rngAdapter struct {
	r io.Reader

	buffer []uint64
	off    int
}

func (a *rngAdapter) Seed(seed int64) {
	panic("mathrand: Seed is not supported")
}

func (a *rngAdapter) Int63() int64 {
	return int64(a.Uint64() & ((1 << 63) - 1))
}

func (a *rngAdapter) Uint64() uint64 {
	if a.off >= len(a.buffer) {
		a.refill()
	}

	v := a.buffer[a.off]
	a.off++
	return v
}

func (a *rngAdapter) refill() {
	tmp := make([]byte, 8*len(a.buffer))
	if _, err := io.ReadFull(a.r, tmp); err != nil {
		panic(err)
	}
	for idx := range a.buffer {
		a.buffer[idx] = binary.BigEndian.Uint64(tmp[8*idx:])
	}
	a.off = 0
}

// New returns a new math/rand.Source64 backed by the provided io.Reader.
func New(src io.Reader) rand.Source64 {
	a := &rngAdapter{
		r:      src,
		buffer: make([]uint64, bufferSize),
		off:    bufferSize,
	}

	a.refill()

	return a
}
