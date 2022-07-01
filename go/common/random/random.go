// Package random provides a concurrency safe
// https://golang.org/pkg/math/rand/#Rand object.
package random

import (
	"math/rand"
	"sync"
	"time"
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

// Borrowed from https://github.com/cenkalti/backoff.

// GetRandomValueFromInterval returns a random value from the following interval:
// 	[currentInterval - randomizationFactor * currentInterval, currentInterval + randomizationFactor * currentInterval].
func GetRandomValueFromInterval(randomizationFactor, random float64, currentInterval time.Duration) time.Duration {
	delta := randomizationFactor * float64(currentInterval)
	minInterval := float64(currentInterval) - delta
	maxInterval := float64(currentInterval) + delta

	// Get a random value from the range [minInterval, maxInterval].
	// The formula used below has a +1 because if the minInterval is 1 and the maxInterval is 3 then
	// we want a 33% chance for selecting either 1, 2 or 3.
	return time.Duration(minInterval + (random * (maxInterval - minInterval + 1)))
}
