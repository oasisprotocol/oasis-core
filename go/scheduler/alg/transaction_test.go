package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"
)

func ReadAndWriteTransaction(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location = new(TestLocation)
	tr, err := ReadNewTransaction(proto, bufr)
	if err != nil {
		t.Fatalf("Could not parse %s", input)
	}
	outputBuffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(outputBuffer)
	tr.Write(bufw)
	err = bufw.Flush()
	if err != nil {
		t.Errorf("Could not write as string")
	}
	fmt.Printf("Got %s\n", outputBuffer.String())
	if input != outputBuffer.String() {
		t.Errorf("Output differs")
	}
}

func RejectBadTransaction(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location = new(TestLocation)
	_, err := ReadNewTransaction(proto, bufr)
	if err == nil {
		t.Fatalf("Parsed bad input %s", input)
	}
	fmt.Printf("Rejected %s\n", input)
}

func TestTransaction(t *testing.T) {
	ReadAndWriteTransaction(t, "({}, {}, 314159, 271828)")
	ReadAndWriteTransaction(t, "({1, 2, 3}, {4, 5, 6}, 7, 8)")
	ReadAndWriteTransaction(t, "({}, {4, 5, 6}, 7, 8)")
	ReadAndWriteTransaction(t, "({4, 5, 6}, {}, 7, 8)")
	ReadAndWriteTransaction(t, "({-4, 5, 6}, {}, 7, 27)")

	RejectBadTransaction(t, "")
	RejectBadTransaction(t, "(123, {}, {}, 2)")
	RejectBadTransaction(t, "({1, 2, {3, 4}}, {}, 2, 3)")
	RejectBadTransaction(t, "({1, 2, 3, 4}, {-5, 2.2}, 2, 3)")
}
