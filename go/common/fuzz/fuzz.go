// +build gofuzz

// Package fuzz provides some common utilities useful for fuzzing other packages.
package fuzz

import (
	"encoding/binary"
	"math/rand"
	"reflect"

	gofuzz "github.com/google/gofuzz"
)

var (
	_ rand.Source64 = (*Source)(nil)
)

// Source is a randomness source for the standard random generator.
type Source struct {
	Backing   []byte
	Exhausted int

	pos   int
	track bool

	traceback []byte
}

func (s *Source) Int63() int64 {
	return int64(s.Uint64()&((1<<63)-1))
}

func (s *Source) Seed(_ int64) {
	// Nothing to do here.
}

func (s *Source) Uint64() uint64 {
	if s.pos+8 > len(s.Backing) {
		s.Exhausted += 8
		r := rand.Uint64()
		if s.track {
			chunk := make([]byte, 8)
			binary.BigEndian.PutUint64(chunk[0:], r)
			s.traceback = append(s.traceback, chunk...)
		}
		return r
	}

	s.pos += 8
	return binary.BigEndian.Uint64(s.Backing[s.pos-8 : s.pos])
}

// GetTraceback returns the array of bytes returned from the random generator so far.
func (s *Source) GetTraceback() []byte {
	return s.traceback
}

// NewRandSource returns a new random source with the given backing array.
func NewRandSource(backing []byte) *Source {
	return &Source{
		Backing: backing,
	}
}

// NewTrackingRandSource returns a new random source that keeps track of the bytes returned.
func NewTrackingRandSource() *Source {
	return &Source{
		Backing: []byte{},
		track:   true,
	}
}

// NewFilledInstance fills the given object with random values from the given blob.
func NewFilledInstance(data []byte, typ interface{}) (interface{}, bool) {
	if typ == nil {
		return nil, true
	}

	source := NewRandSource(data)
	fuzzer := gofuzz.New()
	fuzzer = fuzzer.RandSource(source)

	obj := reflect.New(reflect.TypeOf(typ)).Interface()

	fuzzer.Fuzz(obj)

	return obj, source.Exhausted == 0
}

// MakeSampleBlob creates and returns a sample blob of bytes for filling the given object.
func MakeSampleBlob(typ interface{}) []byte {
	if typ == nil {
		return []byte{}
	}

	source := NewTrackingRandSource()
	fuzzer := gofuzz.New()
	fuzzer = fuzzer.RandSource(source)

	obj := reflect.New(reflect.TypeOf(typ)).Interface()

	fuzzer.Fuzz(obj)

	return source.GetTraceback()
}
