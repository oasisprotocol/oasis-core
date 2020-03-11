package randparam

import (
	"encoding/binary"
	"testing"
)

func TestRandSource_Uint64(t *testing.T) {
	tests := []struct {
		name      string
		input     []uint64
		wantDraw1 uint64
		wantDraw2 uint64
	}{
		{"0 bytes", []uint64{}, 0x0, 0x0},
		{"4 bytes", []uint64{0xdeadbeef}, 0xdeadbeef, 0x0},
		{"8 bytes", []uint64{0xfeedfacedeadbeef}, 0xfeedfacedeadbeef, 0x0},
		{"16 bytes", []uint64{0xfeedfacedeadbeef, 0x1234}, 0xfeedfacedeadbeef, 0x1234},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 8*len(tt.input))
			for i := range tt.input {
				binary.LittleEndian.PutUint64(data[i*8:], tt.input[i])
			}
			src := randSource{data: data}
			if gotValue1 := src.Uint64(); gotValue1 != tt.wantDraw1 {
				t.Errorf("first RandSource.Uint64() = 0x%x, want 0x%x", gotValue1, tt.wantDraw1)
			}
			if gotValue2 := src.Uint64(); gotValue2 != tt.wantDraw2 {
				t.Errorf("second RandSource.Uint64() = 0x%x, want 0x%x", gotValue2, tt.wantDraw2)
			}

		})
	}
}
