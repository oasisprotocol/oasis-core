package alg

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ReadAndWriteLocationSet(t *testing.T, input string) {
	assert := assert.New(t)
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location = new(TestLocation)
	ls, err := ReadNewLocationSet(proto, bufr)
	assert.NoError(err, "Could not parse %s", input)

	t.Logf("Remaining %d bytes\n", bufr.Buffered())
	assert.Equal(0, bufr.Buffered(), "Should have consumed entire buffer")

	outputBuffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(outputBuffer)
	ls.Write(bufw)
	err = bufw.Flush()
	assert.NoError(err, "Could not write as string")

	t.Logf("Got %s\n", outputBuffer.String())
	assert.Equal(input, outputBuffer.String(), "Output differs")
}

func RejectBadLocationSet(t *testing.T, input string) {
	assert := assert.New(t)
	bufr := bufio.NewReader(bytes.NewReader([]byte(input)))
	var proto Location = new(TestLocation)
	_, err := ReadNewLocationSet(proto, bufr)
	assert.Error(err, "Parsed bad input %s", input)

	t.Logf("Rejected %s\n", input)
	t.Logf("Remaining %d bytes\n", bufr.Buffered())
	str, err := bufr.ReadString(byte(0))
	assert.Equal(io.EOF, err, "ReadString did not hit end of string")

	t.Logf("Remaining buffer: %s\n", str)
}

func TestLocationSetIO(t *testing.T) {
	t.Logf("Positive examples\n")
	ReadAndWriteLocationSet(t, "{}")
	ReadAndWriteLocationSet(t, "{123}")
	// The input string must be in canonical format wrt spacing
	ReadAndWriteLocationSet(t, "{100, 2718}")
	ReadAndWriteLocationSet(t, "{1, 2, 100, 123}")
	ReadAndWriteLocationSet(t, "{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31}")

	t.Logf("Negative examples\n")
	RejectBadLocationSet(t, "")
	RejectBadLocationSet(t, "1, 2, 3}")
	RejectBadLocationSet(t, "{1, 2, 3)")
	RejectBadLocationSet(t, "(1, 2, 3)")
	RejectBadLocationSet(t, "{1, --2}")
	RejectBadLocationSet(t, "{1, 0xf}")
	RejectBadLocationSet(t, "{1, f}")
}

func TestLocationSetOps(t *testing.T) {
	assert := assert.New(t)
	ls := NewLocationSet()
	expected := "{}"
	s := ls.String()
	assert.Equal(expected, s, "Empty set should be ", expected, ", but is ", s)

	ls.Add(TestLocation(0))
	expected = "{0}"
	s = ls.String()
	assert.Equal(expected, s, "Singleton ", expected, " expected, got ", s)

	ls.Add(TestLocation(0))
	s = ls.String()
	assert.Equal(expected, s, "Singleton ", expected, " expected, got ", s)

	ls.Add(TestLocation(314159))
	expected = "{0, 314159}"
	s = ls.String()
	assert.Equal(expected, s, "Set {0, 314159} expected, got ", s)

	ls.Delete(TestLocation(0))
	expected = "{314159}"
	s = ls.String()
	assert.Equal(expected, s, "Singleton ", expected, " expected, got ", s)

	ls2 := NewLocationSet()
	ls2.Add(TestLocation(1))
	ls2.Add(TestLocation(271828))
	ls2.Add(TestLocation(161803))
	ls.Merge(ls2)
	expected = "{1, 161803, 271828, 314159}"
	s = ls.String()
	assert.Equal(expected, s, "Expected ", expected, ", got ", s)
}

func TestLocationSetAddSliceAndSize(t *testing.T) {
	assert := assert.New(t)
	ls, err := LocationSetFromString(TestLocation(0), "{1, 3, 5, 7, 9, 11}")
	assert.NoError(err, "LocationSetFromString setup failed")
	assert.Equal(6, ls.Size(), "Size() failed, should be 6")
	ls.AddSlice([]Location{TestLocation(2), TestLocation(4), TestLocation(6)})
	expected := "{1, 2, 3, 4, 5, 6, 7, 9, 11}"
	assert.Equal(expected, ls.String())
	assert.Equal(9, ls.Size(), "Size() failed, should be 9")
}

func TestLocationSetOverlapsIntersects(t *testing.T) {
	assert := assert.New(t)
	ls1, err := LocationSetFromString(TestLocation(0), "{1, 3, 5, 7, 9, 11}")
	assert.NoError(err, "LocationSetFromString setup failed")
	ls2, err := LocationSetFromString(TestLocation(0), "{2, 4, 5, 7, 10, 12}")
	assert.NoError(err, "LocationSetFromString setup failed")
	assert.True(ls1.Overlaps(ls2), "the two sets overlap at 5, 7")
	assert.True(ls2.Overlaps(ls1), "the two sets overlap at 5, 7")

	ls3, err := LocationSetFromString(TestLocation(0), "{2, 4, 5, 7, 10, 11, 12, 14, 16}")
	assert.NoError(err, "LocationSetFromString setup failed")
	assert.True(ls1.Overlaps(ls3), "the two sets overlap at 5, 7")
	assert.True(ls3.Overlaps(ls1), "the two sets overlap at 5, 7")

	lsInt := ls1.Intersect(ls2)
	expected := "{5, 7}"
	assert.Equal(expected, lsInt.String())

	lsInt = ls1.Intersect(ls3)
	expected = "{5, 7, 11}"
	assert.Equal(expected, lsInt.String())
	lsInt = ls3.Intersect(ls1)
	assert.Equal(expected, lsInt.String())

	ls4, err := LocationSetFromString(TestLocation(0), "{2, 4, 6, 8, 10, 12}")
	assert.NoError(err, "LocationSetFromString setup failed")
	assert.False(ls1.Overlaps(ls4), "the two sets do not overlap")
	assert.False(ls4.Overlaps(ls1), "the two sets do not overlap")
}

func TestLocationSetFind(t *testing.T) {
	assert := assert.New(t)
	ls, err := LocationSetFromString(TestLocation(0), "{11, 9, 7, 5, 3, 1}")
	assert.NoError(err, "TestLocationSetFind setup failed")
	assert.True(ls.Find(func(loc Location) bool {
		return loc.(TestLocation) == 5
	}))
	assert.False(ls.Find(func(loc Location) bool {
		return loc.(TestLocation) == 6
	}))
	assert.True(ls.Find(func(loc Location) bool {
		return loc.(TestLocation) == 1
	}))
	assert.True(ls.Find(func(loc Location) bool {
		return loc.(TestLocation) == 11
	}))
}
