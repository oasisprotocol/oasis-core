package randparam

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFuzzingParams(t *testing.T) {

	t.Run("string - 8 byte length, 8 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x8}, []byte("12345678")...)
		want := "12345678"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 9 byte length, 9 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x9}, []byte("123456789")...)
		want := "123456789"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 5 byte length, 6 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x5}, []byte("123456")...)
		want := "12345"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 9 byte length, 2 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x9}, []byte("12")...)
		want := ""

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - zero length string explicitly encoded", func(t *testing.T) {
		longByteSlice := make([]byte, 1000)
		input := append([]byte{0xFF}, longByteSlice...)
		want := ""

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - skip 0x0 size fields", func(t *testing.T) {
		input := append([]byte{0x0, 0x0, 0x2}, []byte("12")...)
		want := "12"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - two strings", func(t *testing.T) {
		input := []byte{0x0, 0x1, 0x42, 0x2, 0x43, 0x44}
		want1 := string([]byte{0x42})
		want2 := string([]byte{0x43, 0x44})

		fuzzer := NewFuzzer(input)
		var got1, got2 string
		fuzzer.Fuzz(&got1)
		fuzzer.Fuzz(&got2)

		if diff := cmp.Diff(want1, got1); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want1 +got1):\n%s", diff)
		}
		if diff := cmp.Diff(want2, got2); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want2 +got2):\n%s", diff)
		}
	})

	t.Run("string - exactly run out of bytes", func(t *testing.T) {
		input := []byte{0x0, 0x1, 0x42}
		want1 := string([]byte{0x42})
		want2 := ""

		fuzzer := NewFuzzer(input)
		var got1, got2 string
		fuzzer.Fuzz(&got1)
		fuzzer.Fuzz(&got2)

		if diff := cmp.Diff(want1, got1); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want1 +got1):\n%s", diff)
		}
		if diff := cmp.Diff(want2, got2); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want2 +got2):\n%s", diff)
		}
	})

	t.Run("byte slice - 8 byte length, 8 input bytes", func(t *testing.T) {
		input := append([]byte{0x0, 0x8}, []byte("12345678")...)
		want := []byte("12345678")

		fuzzer := NewFuzzer(input)
		var got []byte
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("byte slice - 3 byte length, 8 input bytes", func(t *testing.T) {
		input := append([]byte{0x0, 0x3}, []byte("12345678")...)
		want := []byte("123")

		fuzzer := NewFuzzer(input)
		var got []byte
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("uint64 - 8 bytes input", func(t *testing.T) {
		input := append([]byte{0x0}, make([]byte, 8)...)
		i := uint64(0xfeedfacedeadbeef)
		binary.LittleEndian.PutUint64(input[1:], i)
		want := uint64(0xfeedfacedeadbeef)

		fuzzer := NewFuzzer(input)
		var got uint64
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("uint64 - 4 bytes input", func(t *testing.T) {
		input := []byte{0x0, 0xef, 0xbe, 0xad, 0xde}
		want := uint64(0xdeadbeef)

		fuzzer := NewFuzzer(input)
		var got uint64
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("int32 - 4 bytes input with zeros", func(t *testing.T) {
		input := []byte{0x0, 0x42, 0x00, 0x00, 0x00}
		want := int32(0x42)

		fuzzer := NewFuzzer(input)
		var got int32
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("int32 - 1 byte input", func(t *testing.T) {
		input := []byte{0x0, 0x42}
		want := int32(0x42)

		fuzzer := NewFuzzer(input)
		var got int32
		fuzzer.Fuzz(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fuzz() mismatch (-want +got):\n%s", diff)
		}
	})
}
