package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"
)

func ReadAndWriteLocation(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location
	proto = new(TestLocation)
	loc, err := proto.Read(bufr)
	if err != nil {
		t.Fatalf("Could not parse %s", input)
	}
	output_buffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(output_buffer)
	loc.Write(bufw)
	err = bufw.Flush()
	if err != nil {
		t.Errorf("Could not write as string")
	}
	fmt.Printf("Got %s\n", output_buffer.String())
	if input != output_buffer.String() {
		t.Errorf("Output differs")
	}
}

func RejectBadLocation(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location
	proto = new(TestLocation)
	_, err := proto.Read(bufr)
	if err == nil {
		t.Fatalf("Parsed bad input %s", input)
	}
	fmt.Printf("Rejected %s\n", input)
}

func TestLocationIO(t *testing.T) {
	ReadAndWriteLocation(t, "0")
	ReadAndWriteLocation(t, "123")
	ReadAndWriteLocation(t, "9999")
	ReadAndWriteLocation(t, "-1")
	RejectBadLocation(t, "")
	RejectBadLocation(t, "--2")
	RejectBadLocation(t, "++2")
	RejectBadLocation(t, "a")
}
