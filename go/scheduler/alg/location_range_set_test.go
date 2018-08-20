package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ShouldPanic runs f, which is expected to panic.
func ShouldPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from expected panic in f", r)
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
	assert := assert.New(t)
	lrs := NewLocationRangeSet()
	lrs.Add(NewLocationRange(TestLocation(1), TestLocation(10)))
	lrs.Add(NewLocationRange(TestLocation(42), TestLocation(57)))
	lrs.Add(NewLocationRange(TestLocation(101), TestLocation(101)))
	s := lrs.String()
	fmt.Printf("lrs: %s\n", s)
	expected := "1:10, 42:57, 101"
	assert.Equal(expected, s, "String output wrong: expected '%s', got '%s'", expected, s)
	assert.False(lrs.Contains(TestLocation(11)), "Should not contain 11")

	for elt := 1; elt <= 10; elt++ {
		assert.True(lrs.Contains(TestLocation(elt)), "Should contain %d", elt)
	}
	for elt := 11; elt < 42; elt++ {
		assert.False(lrs.Contains(TestLocation(elt)), "Should not contain %d", elt)
	}
}

func TestLocationRangeSetRead(t *testing.T) {
	assert := assert.New(t)
	input := "2:4,9:15,7,23:71"
	expected := "2:4, 7, 9:15, 23:71"
	lrs, err := LocationRangeSetFromString(TestLocation(0), input)
	assert.NoError(err, "ReadNewLocationRangeSetFromString")

	s := lrs.String()
	assert.Equal(expected, s, "Parsed from %s, stringified to %s, expected %s", input, s, expected)
	fmt.Printf("Got via String %s\n", s)

	outputBuffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(outputBuffer)
	lrs.Write(bufw)
	err = bufw.Flush()
	assert.NoError(err, "Could not write as string")
	ws := outputBuffer.String()
	fmt.Printf("Got via Write %s\n", ws)
	assert.Equal(expected, ws, "Parsed from %s, written as %s, expected %s", input, ws, expected)
}

func TestLocationRangeParse(t *testing.T) {
	assert := assert.New(t)
	helper := func(in string) (*LocationRange, error) {
		return ReadNewLocationRange(TestLocation(0), bufio.NewReader(bytes.NewReader([]byte(in))))
	}

	input := "1"
	lr, err := helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	fmt.Printf("parsed: %s\n", lr.String())

	input = "1:1"
	lr, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	fmt.Printf("parsed: %s\n", lr.String())

	input = "100:1000"
	lr, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	fmt.Printf("parsed: %s\n", lr.String())

	input = "100:1"
	lr, err = helper(input)
	if err == nil && lr != nil {
		fmt.Printf("parsed %s as %s\n", input, lr.String())
	}
	assert.Error(err, "Unexpected ability to parse/accept input '%s'", input)
	fmt.Printf("could not parsed '%s' as expected\n", input)

	input = "-100:1"
	lr, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	fmt.Printf("parsed: %s\n", lr.String())
}

// nolint: gocyclo
func TestLocationRangeSetParse(t *testing.T) {
	assert := assert.New(t)
	helper := func(in string) (*LocationRangeSet, error) {
		return LocationRangeSetFromString(TestLocation(0), in)
	}

	// single range
	input := "1"
	lrs, err := helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	fmt.Printf("parsed: %s\n", lrs.String())

	input = "1:1"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	fmt.Printf("parsed: %s\n", lrs.String())

	input = "100:1000"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	fmt.Printf("parsed: %s\n", lrs.String())

	input = "100:1"
	lrs, err = helper(input)
	if err == nil && lrs != nil {
		fmt.Printf("parsed %s as %s\n", input, lrs.String())
	}
	assert.Error(err, "Unexpected ability to parse/accept input '%s'", input)
	fmt.Printf("could not parsed '%s' as expected\n", input)

	input = "-100:1"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	fmt.Printf("parsed: %s\n", lrs.String())

	// multiple ranges
	input = "1,10:23,11:12"
	expected := "1, 10:23, 11:12"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	s := lrs.String()
	fmt.Printf("parsed: %s\n", s)
	assert.Equal(expected, s, "Output string representation mismatch")

	input = "1:1, 100 : 103, 51:57"
	expected = "1, 51:57, 100:103"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)

	s = lrs.String()
	fmt.Printf("parsed: %s\n", s)
	assert.Equal(expected, s, "Output string representation mismatch")

	input = "100:1000, 101:2000, 11:13, 23, 31415, 2717:31415   "
	expected = "11:13, 23, 100:1000, 101:2000, 2717:31415, 31415"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)

	s = lrs.String()
	fmt.Printf("parsed: %s\n", s)
	assert.Equal(expected, s, "Output string representation mismatch")

	input = "100:1"
	lrs, err = helper(input)
	if err == nil && lrs != nil {
		fmt.Printf("parsed %s as %s\n", input, lrs.String())
	}
	assert.Error(err, "Unexpected ability to parse/accept input '%s'", input)
	fmt.Printf("could not parsed '%s' as expected\n", input)

	input = "-100 : 1 , 23 : 27"
	expected = "-100:1, 23:27"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)

	s = lrs.String()
	fmt.Printf("parsed: %s\n", s)
	assert.Equal(expected, s, "Output string representation mismatch")
}

func TestLocationRangeSetFindAndMinMax(t *testing.T) {
	assert := assert.New(t)
	helper := func(in string) (*LocationRangeSet, error) {
		return LocationRangeSetFromString(TestLocation(0), in)
	}

	input := "5:10, 103:9999, 123456:123465"
	lrs, err := helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)

	foundBad := false
	lrs.Find(func(lr *LocationRange) bool {
		lb := int64(lr.LowerBound.(TestLocation))
		ub := int64(lr.UpperBound.(TestLocation))
		if (lb == 5 && ub == 10) || (lb == 103 && ub == 9999) || (lb == 123456 && ub == 123465) {
			return false
		}
		foundBad = true
		fmt.Printf("Bad range: %d:%d\n", lb, ub)
		return true
	})

	assert.False(foundBad, "bad range found via Find")

	minLoc := int64(lrs.MinLoc().(TestLocation))
	assert.Equal(int64(5), minLoc, "MinLoc should be 5")
	maxLoc := int64(lrs.MaxLoc().(TestLocation))
	assert.Equal(int64(123465), maxLoc, "MaxLoc should be 123465")
}
