package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"
)

func ReadAndWriteLocationSet(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location = new(TestLocation)
	ls, err := ReadNewLocationSet(proto, bufr)
	if err != nil {
		t.Fatalf("Could not parse %s", input)
	}
	outputBuffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(outputBuffer)
	ls.Write(bufw)
	err = bufw.Flush()
	if err != nil {
		t.Errorf("Could not write as string")
	}
	fmt.Printf("Got %s\n", outputBuffer.String())
	if input != outputBuffer.String() {
		t.Errorf("Output differs")
	}
}

func RejectBadLocationSet(t *testing.T, input string) {
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location = new(TestLocation)
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

func TestLocationSetOps(t *testing.T) {
	ls := NewLocationSet()
	fmt.Println("Empty: ", ls)
	expected := "{}"
	if s := ls.ToString(); s != expected {
		t.Error("Empty set should be ", expected, ", but is ", s)
	}
	ls.Add(TestLocation(0))
	fmt.Println("Singleton: ", ls)
	expected = "{0}"
	if s := ls.ToString(); s != expected {
		t.Error("Singleton ", expected, " expected, got ", s)
	}
	ls.Add(TestLocation(0))
	fmt.Println("Still singleton: ", ls)
	if s := ls.ToString(); s != expected {
		t.Error("Singleton ", expected, " expected, got ", s)
	}
	ls.Add(TestLocation(314159))
	fmt.Println("Two elts: ", ls)
	expected = "{0, 314159}"
	if s := ls.ToString(); s != expected {
		t.Error("Set {0, 314159} expected, got ", s)
	}
	ls.Delete(TestLocation(0))
	expected = "{314159}"
	fmt.Println("Back to singleton: ", ls)
	if s := ls.ToString(); s != expected {
		t.Error("Singleton ", expected, " expected, got ", s)
	}
	ls2 := NewLocationSet()
	ls2.Add(TestLocation(1))
	ls2.Add(TestLocation(271828))
	ls2.Add(TestLocation(161803))
	ls.Merge(ls2)
	fmt.Println("Merged: ", ls)
	expected = "{1, 161803, 271828, 314159}"
	if s := ls.ToString(); s != expected {
		t.Error("Expected ", expected, ", got ", s)
	}
}
