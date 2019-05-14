// Package random provides a concurrency safe
// https://golang.org/pkg/math/rand/#Rand object.
package random

import (
	"math/rand"
	"sync"
)

// NewRand is a convenience function to generate a new
// https://golang.org/pkg/math/rand/#Rand object that is concurrency safe.
func NewRand(seed int64) *rand.Rand {
	source := NewConcurrencySafeSource(seed)
	random := rand.New(source)
	return random
}

// NewConcurrencySafeSource creates a concurrency safe source.
func NewConcurrencySafeSource(seed int64) rand.Source {
	source := rand.NewSource(seed)
	source64 := source.(rand.Source64)
	return &concurrenySafeSource{
		src: source64,
		mut: &sync.Mutex{},
	}
}

type concurrenySafeSource struct {
	src rand.Source64
	mut *sync.Mutex
}

func (c *concurrenySafeSource) Int63() int64 {
	c.mut.Lock()
	res := c.src.Int63()
	c.mut.Unlock()
	return res
}

func (c *concurrenySafeSource) Uint64() uint64 {
	c.mut.Lock()
	res := c.src.Uint64()
	c.mut.Unlock()
	return res
}

func (c *concurrenySafeSource) Seed(seed int64) {
	c.mut.Lock()
	c.src.Seed(seed)
	c.mut.Unlock()
}
