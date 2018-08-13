package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"
)

func ShouldPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from expected error in f", r)
		} else {
			t.Errorf("ShouldPanic: f() did not panic (in defer)")
		}
	}()
	f()
	t.Errorf("ShouldPanic: f() did not panic")
}

func TestLocationRangeInvarianceCheck(t *testing.T) {
	ShouldPanic(t, func() {
		lr := NewLocationRange(TestLocation(1), TestLocation(0))
		fmt.Printf("Should be unreached.\n")
		fmt.Printf("Got: %s\n", lr.String())
	})
	ShouldPanic(t, func() {
		lr := NewLocationRange(TestLocation(1000), TestLocation(10))
		fmt.Printf("Should be unreached.\n")
		fmt.Printf("Got: %s\n", lr.String())
	})
}

func TestLocationRangeSetContains(t *testing.T) {
	lrs := NewLocationRangeSet()
	lrs.Add(NewLocationRange(TestLocation(1), TestLocation(10)))
	lrs.Add(NewLocationRange(TestLocation(42), TestLocation(57)))
	lrs.Add(NewLocationRange(TestLocation(101), TestLocation(101)))
	s := lrs.String()
	fmt.Printf("lrs: %s\n", s)
	expected := "1:10, 42:57, 101"
	if s != expected {
		t.Errorf("String output wrong: expected '%s', got '%s'", expected, s)
	}
	if lrs.Contains(TestLocation(11)) {
		t.Errorf("Should not contain 11")
	}
	for elt := 1; elt <= 10; elt++ {
		if !lrs.Contains(TestLocation(elt)) {
			t.Errorf("Should contain %d", elt)
		}
	}
	for elt := 11; elt < 42; elt++ {
		if lrs.Contains(TestLocation(elt)) {
			t.Errorf("Should not contain %d", elt)
		}
	}
}

func TestLocationRangeRead(t *testing.T) {
	input := "2:4,9:15,7,23:71"
	expected := "2:4, 7, 9:15, 23:71"
	lrs, err := ReadNewLocationRangeSet(TestLocation(0), bufio.NewReader(bytes.NewReader([]byte(input))))
	if err != nil {
		t.Errorf("ReadNewLocationRangeSet error: %s", err.Error())
	}
	s := lrs.String()
	if s != expected {
		t.Errorf("Parsed from %s, stringified to %s, expected %s", input, s, expected)
	}
}

func TestLocationRangeParse(t *testing.T) {
	helper := func(in string) (*LocationRange, error) {
		return ReadNewLocationRange(TestLocation(0), bufio.NewReader(bytes.NewReader([]byte(in))))
	}

	input := "1"
	lr, err := helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	fmt.Printf("parsed: %s\n", lr.String())

	input = "1:1"
	lr, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	fmt.Printf("parsed: %s\n", lr.String())

	input = "100:1000"
	lr, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	fmt.Printf("parsed: %s\n", lr.String())

	input = "100:1"
	lr, err = helper(input)
	if err == nil {
		t.Errorf("Unexpected ability to parse/accept input '%s'", input)
		fmt.Printf("Input '%s' decodes as '%s'\n", input, lr.String())
	}
	fmt.Printf("could not parsed '%s' as expected\n", input)

	input = "-100:1"
	lr, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	fmt.Printf("parsed: %s\n", lr.String())
}

// nolint: gocyclo
func TestLocationRangeSetParse(t *testing.T) {
	helper := func(in string) (*LocationRangeSet, error) {
		return ReadNewLocationRangeSet(TestLocation(0), bufio.NewReader(bytes.NewReader([]byte(in))))
	}

	// single range
	input := "1"
	lrs, err := helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	fmt.Printf("parsed: %s\n", lrs.String())

	input = "1:1"
	lrs, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	fmt.Printf("parsed: %s\n", lrs.String())

	input = "100:1000"
	lrs, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	fmt.Printf("parsed: %s\n", lrs.String())

	input = "100:1"
	lrs, err = helper(input)
	if err == nil {
		t.Errorf("Unexpected ability to parse/accept input '%s'", input)
		fmt.Printf("Input '%s' decodes as '%s'\n", input, lrs.String())
	}
	fmt.Printf("could not parsed '%s' as expected\n", input)

	input = "-100:1"
	lrs, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	fmt.Printf("parsed: %s\n", lrs.String())

	// multiple ranges
	input = "1,10:23,11:12"
	expected := "1, 10:23, 11:12"
	lrs, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	s := lrs.String()
	fmt.Printf("parsed: %s\n", s)
	if s != expected {
		t.Errorf("Output string representation mismatch: expected '%s', got '%s'",
			expected, s)
	}

	input = "1:1, 100 : 103, 51:57"
	expected = "1, 51:57, 100:103"
	lrs, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	s = lrs.String()
	fmt.Printf("parsed: %s\n", s)
	if s != expected {
		t.Errorf("Output string representation mismatch: expected '%s', got '%s'",
			expected, s)
	}

	input = "100:1000, 101:2000, 11:13, 23, 31415, 2717:31415   "
	expected = "11:13, 23, 100:1000, 101:2000, 2717:31415, 31415"
	lrs, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	s = lrs.String()
	fmt.Printf("parsed: %s\n", s)
	if s != expected {
		t.Errorf("Output string representation mismatch: expected '%s', got '%s'",
			expected, s)
	}

	input = "100:1"
	lrs, err = helper(input)
	if err == nil {
		t.Errorf("Unexpected ability to parse/accept input '%s'", input)
		fmt.Printf("Input '%s' decodes as '%s'\n", input, lrs.String())
	}
	fmt.Printf("could not parsed '%s' as expected\n", input)

	input = "-100 : 1 , 23 : 27"
	expected = "-100:1, 23:27"
	lrs, err = helper(input)
	if err != nil {
		t.Errorf("Could not parse input '%s'", input)
	}
	s = lrs.String()
	fmt.Printf("parsed: %s\n", s)
	if s != expected {
		t.Errorf("Output string representation mismatch: expected '%s', got '%s'",
			expected, s)
	}
}
