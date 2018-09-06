package alg

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocationRangeInvarianceCheck(t *testing.T) {
	assert := assert.New(t)
	assert.Panics(func() {
		lr := NewLocationRange(TestLocation(1), TestLocation(0))
		t.Logf("Should be unreached.\n")
		t.Logf("Got: %s\n", lr.String())
	}, "Range lowerbound greater than upperbound accepted (1:0)")
	assert.Panics(func() {
		lr := NewLocationRange(TestLocation(1000), TestLocation(10))
		t.Logf("Should be unreached.\n")
		t.Logf("Got: %s\n", lr.String())
	}, "Range lowerbound greater than upperbound accepted (1000:10)")
}

func TestLocationRangeSetContains(t *testing.T) {
	assert := assert.New(t)
	lrs := NewLocationRangeSet()
	lrs.Add(NewLocationRange(TestLocation(1), TestLocation(10)))
	lrs.Add(NewLocationRange(TestLocation(42), TestLocation(57)))
	lrs.Add(NewLocationRange(TestLocation(101), TestLocation(101)))
	s := lrs.String()
	t.Logf("lrs: %s\n", s)
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
	t.Logf("Got via String %s\n", s)

	outputBuffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(outputBuffer)
	_, _ = lrs.Write(bufw)
	err = bufw.Flush()
	assert.NoError(err, "Could not write as string")
	ws := outputBuffer.String()
	t.Logf("Got via Write %s\n", ws)
	assert.Equal(expected, ws, "Parsed from %s, written as %s, expected %s", input, ws, expected)

	input = "2:4, 5:2"
	_, err = LocationRangeSetFromString(TestLocation(0), input)
	assert.Error(err, "bad range should have been detected")

	input = "2:4; 5:10"
	expected = "2:4"
	lrs, err = LocationRangeSetFromString(TestLocation(0), input)
	assert.NoError(err, "bad range separator should have stopped parsing instead of generating error")
	assert.Equal(expected, lrs.String(), "should have decoded valid range prefix")

	input = "2:4, 5:10, 100:1000, x"
	_, err = LocationRangeSetFromString(TestLocation(0), input)
	assert.Error(err, "bad range after separator should have been detected")

	input = "2:4, 5:10, 100:1000; y"
	expected = "2:4, 5:10, 100:1000"
	lrs, err = LocationRangeSetFromString(TestLocation(0), input)
	assert.NoError(err, "bad range after separator should have stopped parsing")
	assert.Equal(expected, lrs.String(), "should have decoded valid ranges")
}

func TestMustReadLocationRange(t *testing.T) {
	assert := assert.New(t)
	assert.Panics(func() {
		_ = MustReadNewLocationRange(TestLocation(0), bufio.NewReader(bytes.NewReader([]byte("9:1"))))
	}, "MustReadLocationRange: 9:1 accepted")
	lr := MustReadNewLocationRange(TestLocation(0), bufio.NewReader(bytes.NewReader([]byte("1:9"))))
	assert.NotNil(lr, "MustReadNewLocationRange should work")
}

func TestReadNewLocationRange(t *testing.T) { // nolint: gocyclo
	assert := assert.New(t)
	helper := func(in string) (*LocationRange, error) {
		return ReadNewLocationRange(TestLocation(0), bufio.NewReader(bytes.NewReader([]byte(in))))
	}

	input := "1"
	lr, err := helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lr.String())

	input = "1:1"
	lr, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lr.String())

	input = "100:1000"
	lr, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lr.String())

	input = "100:1" // nolint: goconst
	lr, err = helper(input)
	if err == nil && lr != nil {
		t.Logf("parsed %s as %s\n", input, lr.String())
	}
	assert.Error(err, "Unexpected ability to parse/accept input '%s'", input)
	t.Logf("could not parsed '%s' as expected\n", input)

	input = "-100:1"
	lr, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lr.String())

	input = "-100:1,"
	lr, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lr.String())

	input = "garbage"
	lr, err = helper(input)
	if err == nil && lr != nil {
		t.Logf("parsed %s as %s\n", input, lr.String())
	}
	assert.Error(err, "Unexpected ability to parse input '%s'", input)

	input = ""
	lr, err = helper(input)
	if err == nil && lr != nil {
		t.Logf("parsed %s as %s\n", input, lr.String())
	}
	assert.Error(err, "Unexpected ability to parse input '%s'", input)

	input = "10:"
	lr, err = helper(input)
	if err == nil && lr != nil {
		t.Logf("parsed %s as %s\n", input, lr.String())
	}
	assert.Error(err, "Unexpected ability to parse input '%s'", input)

	input = ":10"
	lr, err = helper(input)
	if err == nil && lr != nil {
		t.Logf("parsed %s as %s\n", input, lr.String())
	}
	assert.Error(err, "Unexpected ability to parse input '%s'", input)
}

func TestLocationRangeSetParse(t *testing.T) { // nolint: gocyclo
	assert := assert.New(t)
	helper := func(in string) (*LocationRangeSet, error) {
		return LocationRangeSetFromString(TestLocation(0), in)
	}

	// single range
	input := "1"
	lrs, err := helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lrs.String())

	input = "1:1"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lrs.String())

	input = "100:1000"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lrs.String())

	input = "100:1"
	lrs, err = helper(input)
	if err == nil && lrs != nil {
		t.Logf("parsed %s as %s\n", input, lrs.String())
	}
	assert.Error(err, "Unexpected ability to parse/accept input '%s'", input)
	t.Logf("could not parsed '%s' as expected\n", input)

	input = "-100:1"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	t.Logf("parsed: %s\n", lrs.String())

	// multiple ranges
	input = "1,10:23,11:12"
	expected := "1, 10:23, 11:12"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)
	s := lrs.String()
	t.Logf("parsed: %s\n", s)
	assert.Equal(expected, s, "Output string representation mismatch")

	input = "1:1, 100 : 103, 51:57"
	expected = "1, 51:57, 100:103"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)

	s = lrs.String()
	t.Logf("parsed: %s\n", s)
	assert.Equal(expected, s, "Output string representation mismatch")

	input = "100:1000, 101:2000, 11:13, 23, 31415, 2717:31415   "
	expected = "11:13, 23, 100:1000, 101:2000, 2717:31415, 31415"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)

	s = lrs.String()
	t.Logf("parsed: %s\n", s)
	assert.Equal(expected, s, "Output string representation mismatch")

	input = "100:1"
	lrs, err = helper(input)
	if err == nil && lrs != nil {
		t.Logf("parsed %s as %s\n", input, lrs.String())
	}
	assert.Error(err, "Unexpected ability to parse/accept input '%s'", input)
	t.Logf("could not parsed '%s' as expected\n", input)

	input = "-100 : 1 , 23 : 27"
	expected = "-100:1, 23:27"
	lrs, err = helper(input)
	assert.NoError(err, "Could not parse input '%s'", input)

	s = lrs.String()
	t.Logf("parsed: %s\n", s)
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
		t.Logf("Bad range: %d:%d\n", lb, ub)
		return true
	})

	assert.False(foundBad, "bad range found via Find")

	minLoc := int64(lrs.MinLoc().(TestLocation))
	assert.Equal(int64(5), minLoc, "MinLoc should be 5")
	maxLoc := int64(lrs.MaxLoc().(TestLocation))
	assert.Equal(int64(123465), maxLoc, "MaxLoc should be 123465")
}
