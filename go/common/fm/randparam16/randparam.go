// Package randparam allows a []byte to be used as a source of random parameter values.
//
// The primary use case is to allow fzgo to use dvyukov/go-fuzz to fuzz rich signatures such as:
//    FuzzFunc(re string, input string, posix bool)
// google/gofuzz is used to walk the structure of parameters, but randparam uses custom random generators,
// including in the hopes of allowing dvyukov/go-fuzz literal injection to work,
// as well as to better exploit the genetic mutations of dvyukov/go-fuzz, etc.
package randparam

import (
	"fmt"
	"math/rand"

	gofuzz "github.com/google/gofuzz"
)

// Fuzzer generates random values for public members.
// It wires together dvyukov/go-fuzz (for randomness, instrumentation, managing corpus, etc.)
// with google/gofuzz (for walking a structure recursively), though it uses functions from
// this package to actually fill in string, []byte, and number values.
type Fuzzer struct {
	gofuzzFuzzer *gofuzz.Fuzzer
}

// randFuncs is a list of our custom variable generation functions
// that tap into our custom random number generator to pull values from
// the initial input []byte.
var randFuncs = []interface{}{
	randInt,
	randInt8,
	randInt16,
	randInt32,
	randInt64,
	randUint,
	randUint8,
	randUint16,
	randUint32,
	randUint64,
	randFloat32,
	randFloat64,
	randByte,
	randRune,
}

// NewFuzzer returns a *Fuzzer, initialized with the []byte as an input stream for drawing values via rand.Rand.
func NewFuzzer(data []byte) *Fuzzer {
	// create our random data stream that fill use data []byte for results.
	fzgoSrc := &randSource{data}
	randSrc := rand.New(fzgoSrc)

	// create some closures for custom fuzzing (so that we have direct access to fzgoSrc).
	randFuncsWithFzgoSrc := []interface{}{
		func(ptr *[]byte, c gofuzz.Continue) {
			randBytes(ptr, c, fzgoSrc)
		},
		func(ptr *string, c gofuzz.Continue) {
			randString(ptr, c, fzgoSrc)
		},
		func(ptr *[]string, c gofuzz.Continue) {
			randStringSlice(ptr, c, fzgoSrc)
		},
	}

	// combine our two custom fuzz function lists.
	funcs := append(randFuncs, randFuncsWithFzgoSrc...)

	// create the google/gofuzz fuzzer
	gofuzzFuzzer := gofuzz.New().RandSource(randSrc).Funcs(funcs...)

	// gofuzzFuzzer.NilChance(0).NumElements(2, 2)
	// TODO: pick parameters for NilChance, NumElements, e.g.:
	//     gofuzzFuzzer.NilChance(0.1).NumElements(0, 10)
	// Initially allowing too much variability with NumElements seemed
	// to be a problem, but more likely that was an early indication of
	// the need to better tune the exact string/[]byte encoding to work
	// better with sonar.

	// TODO: consider if we want to use the first byte for meta parameters.
	firstByte := fzgoSrc.Byte()
	switch {
	case firstByte < 32:
		gofuzzFuzzer.NilChance(0).NumElements(2, 2)
	case firstByte < 64:
		gofuzzFuzzer.NilChance(0).NumElements(1, 1)
	case firstByte < 96:
		gofuzzFuzzer.NilChance(0).NumElements(3, 3)
	case firstByte < 128:
		gofuzzFuzzer.NilChance(0).NumElements(4, 4)
	case firstByte <= 255:
		gofuzzFuzzer.NilChance(0.1).NumElements(0, 10)
	}

	// TODO: probably delete the alternative string encoding code.
	// Probably DON'T have different string encodings.
	// (I suspect it helped the fuzzer get 'stuck' if there multiple ways
	// to encode same "interesting" inputs).
	// if bits.OnesCount8(firstByte)%2 == 0 {
	// 	fzgoSrc.lengthEncodedStrings = false
	// }

	f := &Fuzzer{gofuzzFuzzer: gofuzzFuzzer}
	return f
}

// Fuzz fills in public members of obj. For numbers, strings, []bytes, it tries to populate the
// obj value with literals found in the initial input []byte.
func (f *Fuzzer) Fuzz(obj interface{}) {
	f.gofuzzFuzzer.Fuzz(obj)
}

// Fill fills in public members of obj. For numbers, strings, []bytes, it tries to populate the
// obj value with literals found in the initial input []byte.
// TODO: decide to call this Fill or Fuzz or something else. We support both Fill and Fuzz for now.
func (f *Fuzzer) Fill(obj interface{}) {
	f.gofuzzFuzzer.Fuzz(obj)
}

// Override google/gofuzz fuzzing approach for strings, []byte, and numbers

// randBytes is a custom fill function so that we have exact control over how
// strings and []byte are encoded.
//
// randBytes generates a byte slice using the input []byte stream.
// []byte are deserialized as length encoded, where a leading byte
// encodes the length in range [0-255], but the exact interpretation is a little subtle.
// There is surely room for improvement here, but this current approach is the result of some
// some basic experimentation with some different alternatives, with this approach
// yielding decent results in terms of fuzzing efficiency on basic tests,
// so using this approach at least for now.
//
// The current approach:
//
// 1. Do not use 0x0 to encode a zero length string (or zero length []byte).
//
// We need some way to encode nil byte slices and empty strings
// in the input data []byte. Using 0x0 is the obvious way to encode
// a zero length, but that was not a good choice based on some experimentation.
// I suspect partly because fuzzers (e.g,. go-fuzz) like to insert zeros,
// but more importantly because a 0x0 length field does not give go-fuzz sonar
// anything to work with when looking to substitute a value back in.
// If sonar sees [0x1][0x42] in the input data, and observes 0x42 being used live
// in a string comparison against the value "bingo", sonar can update the data
// to be [0x5][b][i][n][g][o] based on finding the 0x42 and guessing the 0x1
// is a length field that it then updates. In contrast, if sonar sees [0x0] in the input
// data and observes "" being used in a string comparison against "bingo",
// sonar can't currently hunt to find "" in the input data (though I suspect in
// theory sonar could be updated to look for a 0x0 and guess it is a zero length string).
// Net, we want something other than 0x0 to indicate a zero length string or byte slice.
// We pick 0xFF to indicate a zero length.
//
// 2. Do not cap the size at the bytes remaining.
//
// I suspect that also interferes with go-fuzz sonar, which attempts
// to find length fields to adjust when substituting literals.
// If we cap the number of bytes, it means the length field in the input []byte
// would not agree with the actual length used, which means
// sonar does not adjust the length field correctly.
// A concrete example is that if we were to cap the size of what we read,
// the meaning of [0xF1][0x1][0x2][EOD] would change once new data is appended,
// but more importantly sonar would not properly adjust the 0xF1 as a length
// field if sonar substituted in a more interesting string value in place of [0x1][0x2].
//
// 3. Do not drawing zeros past the end of the input []byte.
//
// This is similar reasons as 1 and 2. Drawing zeros past the end
// also means a value that shows  up in the live code under test
// does not have a byte-for-byte match with something in the input []byte.
//
// 4. Skip over any 0x0 byte values that would otherwise have been a size field.
//
// This is effectively an implementation detail of 1. In other words,
// if we don't use 0x0 to ecode a zero length string, we need to do
// something when we find a 0x0 in the spot where a length field would go.
//
// Summary: one way to think about it is the encoding of a length field is:
//      * 0-N 0x0 bytes prior to a non-zero byte, and
//      * that non-zero byte is the actual length used, unless that non-zero byte
//	      is 0xFF, in which case that signals a zero-length string/[]byte, and
//      * the length value used must be able to draw enough real random bytes from the input []byte.
func randBytes(ptr *[]byte, c gofuzz.Continue, fzgoSrc *randSource) {
	verbose := false // TODO: probably remove eventually.
	if verbose {
		fmt.Println("randBytes verbose:", verbose)
	}

	var bs []byte
	var size int

	// try to find a size field.
	// this is slightly more subtle than just reading one byte,
	// mainly in order to better work with go-fuzz sonar.
	// see long comment above.
	for {
		if fzgoSrc.Remaining() == 0 {
			if verbose {
				fmt.Println("ran out of bytes, 0 remaining")
			}
			// return nil slice (which will be empty string for string)
			*ptr = nil
			return

		}

		// draw a size in [0, 255] from our input byte[] stream
		sizeField := int(fzgoSrc.Byte())
		if verbose {
			fmt.Println("sizeField:", sizeField)
		}

		// If we don't have enough data, we want to
		// *not* use the size field or the data after sizeField,
		// in order to work better with sonar.
		if sizeField > fzgoSrc.Remaining() {
			if verbose {
				fmt.Printf("%d bytes requested via size field, %d remaining, drain rest\n",
					sizeField, fzgoSrc.Remaining())
			}
			// return nil slice (which will be empty string for string).
			// however, before we return, we consume all of our remaining bytes.
			fzgoSrc.Drain()

			*ptr = nil
			return
		}

		// skip over any zero bytes for our size field
		// In other words, the encoding is 0-N 0x0 bytes prior to a useful length
		// field we will use.
		if sizeField == 0x0 {
			continue
		}

		// 0xFF is our chosen value to represent a zero length string/[]byte.
		// (See long comment above for some rationale).
		if sizeField == 0xFF {
			size = 0
		} else {
			size = sizeField
		}

		// found a usable, non-zero sizeField. let's move on to use it on the next bytes!
		break
	}

	bs = make([]byte, size)
	for i := range bs {
		bs[i] = fzgoSrc.Byte()
	}
	*ptr = bs
}

// randString is a custom fill function so that we have exact control over how
// strings are encoded. It is a thin wrapper over randBytes.
func randString(s *string, c gofuzz.Continue, fzgoSrc *randSource) {
	var bs []byte
	randBytes(&bs, c, fzgoSrc)
	*s = string(bs)
}

// TODO: this might be temporary. Here we handle slices of strings as a preview of
// improvements we might get by dropping google/gofuzz for walking some of the data structures.
func randStringSlice(s *[]string, c gofuzz.Continue, fzgoSrc *randSource) {
	size, ok := calcSize(fzgoSrc)
	if !ok {
		*s = nil
		return
	}
	ss := make([]string, size)
	for i := range ss {
		var str string
		randString(&str, c, fzgoSrc)
		ss[i] = str
	}
	*s = ss
}

// TODO: temporarily extracted this from randBytes. Decide to drop vs. keep/unify.
func calcSize(fzgoSrc *randSource) (size int, ok bool) {
	verbose := false // TODO: probably remove eventually.

	// try to find a size field.
	// this is slightly more subtle than just reading one byte,
	// mainly in order to better work with go-fuzz sonar.
	// see long comment above.
	for {
		if fzgoSrc.Remaining() == 0 {
			if verbose {
				fmt.Println("ran out of bytes, 0 remaining")
			}
			// return nil slice (which will be empty string for string)

			return 0, false
		}

		// draw a size in [0, 255] from our input byte[] stream
		sizeField := int(fzgoSrc.Byte())
		if verbose {
			fmt.Println("sizeField:", sizeField)
		}

		// If we don't have enough data, we want to
		// *not* use the size field or the data after sizeField,
		// in order to work better with sonar.
		if sizeField > fzgoSrc.Remaining() {
			if verbose {
				fmt.Printf("%d bytes requested via size field, %d remaining, drain rest\n",
					sizeField, fzgoSrc.Remaining())
			}
			// return nil slice (which will be empty string for string).
			// however, before we return, we consume all of our remaining bytes.
			fzgoSrc.Drain()

			return 0, false
		}

		// skip over any zero bytes for our size field
		// In other words, the encoding is 0-N 0x0 bytes prior to a useful length
		// field we will use.
		if sizeField == 0x0 {
			continue
		}

		// 0xFF is our chosen value to represent a zero length string/[]byte.
		// (See long comment above for some rationale).
		if sizeField == 0xFF {
			size = 0
		} else {
			size = sizeField
		}

		// found a usable, non-zero sizeField. let's move on to use it on the next bytes!
		break
	}
	return size, true
}

// A set of custom numeric value filling funcs follows.
// These are currently simple implementations that only use gofuzz.Continue
// as a source for data, which means obtaining 64-bits of the input stream
// at a time. For sizes < 64 bits, this could be tighted up to waste less of the input stream
// by getting access to fzgo/randparam.randSource.
//
// Once the end of the input []byte is reached, zeros are drawn, including
// if in the middle of obtaining bytes for a >1 bye number.
// Tt is probably ok to draw zeros past the end
// for numbers because we use a little endian interpretation
// for numbers (which means if we find byte 0x1 then that's the end
// and we draw zeros for say a uint32, the result is 1; sonar
// seems to guess the length of numeric values, so it likely
// works end to end even if we draw zeros.
// TODO: The next bytes appended (via some mutation) after a number can change
// the result (e.g., if a 0x2 is appended in example above, result is no longer 1),
// so maybe better to also not draw zeros for numeric values?

func randInt(val *int, c gofuzz.Continue) {
	*val = int(c.Rand.Uint64())
}

func randInt8(val *int8, c gofuzz.Continue) {
	*val = int8(c.Rand.Uint64())
}

func randInt16(val *int16, c gofuzz.Continue) {
	*val = int16(c.Rand.Uint64())
}

func randInt32(val *int32, c gofuzz.Continue) {
	*val = int32(c.Rand.Uint64())
}

func randInt64(val *int64, c gofuzz.Continue) {
	*val = int64(c.Rand.Uint64())
}

func randUint(val *uint, c gofuzz.Continue) {
	*val = uint(c.Rand.Uint64())
}

func randUint8(val *uint8, c gofuzz.Continue) {
	*val = uint8(c.Rand.Uint64())
}

func randUint16(val *uint16, c gofuzz.Continue) {
	*val = uint16(c.Rand.Uint64())
}

func randUint32(val *uint32, c gofuzz.Continue) {
	*val = uint32(c.Rand.Uint64())
}

func randUint64(val *uint64, c gofuzz.Continue) {
	*val = uint64(c.Rand.Uint64())
}

func randFloat32(val *float32, c gofuzz.Continue) {
	*val = float32(c.Rand.Uint64())
}

func randFloat64(val *float64, c gofuzz.Continue) {
	*val = float64(c.Rand.Uint64())
}

func randByte(val *byte, c gofuzz.Continue) {
	*val = byte(c.Rand.Uint64())
}

func randRune(val *rune, c gofuzz.Continue) {
	*val = rune(c.Rand.Uint64())
}

// Note: complex64, complex128, uintptr are not supported by google/gofuzz, I think.
// TODO: Interfaces are also not currently supported by google/gofuzz, or at least not
// easily as far as I am aware. That said, currently have most of the pieces elsewhere
// for us to handle common interfaces like io.Writer, io.Reader, etc.
