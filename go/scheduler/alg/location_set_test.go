package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"
)

func ReadAndWriteLocationSet(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location
	proto = new(TestLocation)
	ls, err := ReadNewLocationSet(proto, bufr)
	if err != nil {
		t.Fatalf("Could not parse %s", input)
	}
	output_buffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(output_buffer)
	ls.Write(bufw)
	err = bufw.Flush()
	if err != nil {
		t.Errorf("Could not write as string")
	}
	fmt.Printf("Got %s\n", output_buffer.String())
	if input != output_buffer.String() {
		t.Errorf("Output differs")
	}
}

func RejectBadLocationSet(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location
	proto = new(TestLocation)
	_, err := ReadNewLocationSet(proto, bufr)
	if err == nil {
		t.Fatalf("Parsed bad input %s", input)
	}
	fmt.Printf("Rejected %s\n", input)
}

func TestLocationSetIO(t *testing.T) {
	ReadAndWriteLocationSet(t, "{}")
	ReadAndWriteLocationSet(t, "{123}")
	// The input string must be in canonical format wrt spacing
	ReadAndWriteLocationSet(t, "{1, 2, 100, 123}")

	RejectBadLocationSet(t, "")
	RejectBadLocationSet(t, "1, 2, 3}")
	RejectBadLocationSet(t, "{1, 2, 3)")
	RejectBadLocationSet(t, "(1, 2, 3)")
	RejectBadLocationSet(t, "{1, --2}")
	RejectBadLocationSet(t, "{1, 0xf}")
	RejectBadLocationSet(t, "{1, f}")
}
