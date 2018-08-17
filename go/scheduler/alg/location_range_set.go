package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
)

// LocationRangeSet is a set of locations, similar to LocationSet, except that the members can
// be specified as a range of values.  This allows a more compact representation when most of
// the members are contiguous, and can be used for specifying rewrite or attack ranges.
//
//
// String parser for lists of test locations (integers) and ranges.
//
// The grammar that we accept is:
//
// LOCATION_RANGE_SET : empty
//                    | LOCATION_RANGE_LIST
//                    ;
//
// LOCATION_RANGE_LIST : LOC_OR_RANGE
//                     | LOCATION_RANGE_LIST COMMA LOC_OR_SET
//                     ;
//
// LOC_OR_RANGE : LOCATION
//              | LOCATION COLON LOCATION
//              ;
//
// Here LOCATION is a lexical token that typically starts with a '-' or '0'-'9' and can be read
// by Location interface's Read method.  For lookahead, since we have a fused lexer/parser, the
// only requirement is that there is no ambiguity wrt the other lexical elements, so this means
// that the concrete type implementing the Location interface cannot have a string
// representation where it may start with a ':' or ','.
//
// When M:N notation is used, M <= N must hold.  The list of locations may overlap, e.g., "3,
// 1:10" is valid.  INTEGER may be negative, so lookahead has to include '-' as well as
// '0'-'9'.  We only handle decimal notation for now (this is a property of the
// Location.Read() interface method).

// LocationRange is used to hold a single M:N range, representing all locations in the closed
// interval [M,N].  This type is also used for singleton values, setting M=N.
type LocationRange struct {
	LowerBound, UpperBound Location
}

// Contains is a predicate that returns true iff the Location argument is contained in the
// receiver LocationRange.
func (lr LocationRange) Contains(loc Location) bool {
	return loc.Equal(lr.LowerBound) || (lr.LowerBound.Less(loc) && loc.Less(lr.UpperBound)) || loc.Equal(lr.UpperBound)
}

// NewLocationRange constructs and returns a new LocationRange with the given bounds parameters.
// It panics on invariance violation.
func NewLocationRange(lb, ub Location) *LocationRange {
	if ub.Less(lb) {
		panic(fmt.Sprintf("NewLocationRange Invariance violation: lowBound <= highBound is required, but lowBound = %d > highBound = %d", lb, ub))
	}
	return &LocationRange{LowerBound: lb, UpperBound: ub}
}

// ReadNewLocationRange reads in a LocationRange from the string representation from the
// bufio.Reader, using the Read of the concrete type underlying the loc formal Location
// parameter.
func ReadNewLocationRange(loc Location, r *bufio.Reader) (*LocationRange, error) {
	var lb, ub Location
	var err error
	lb, err = loc.Read(r)
	if err != nil {
		return nil, err
	}
	peek, err := getNonspaceRune(r)
	if err == io.EOF {
		return NewLocationRange(lb, lb), nil
	}
	if err != nil {
		return nil, err
	}
	if peek == ':' {
		ub, err = loc.Read(r)
		if err != nil {
			return nil, fmt.Errorf("No Location after ':' range separator, error: %s", err.Error())
		}
		if ub.Less(lb) {
			return nil, fmt.Errorf("ReadNewLocationRange: lb <= ub is required, got lb = %s, ub = %s", lb.String(), ub.String())
		}
		return NewLocationRange(lb, ub), nil
	}
	if err = r.UnreadRune(); err != nil {
		return nil, err
	}
	return NewLocationRange(lb, lb), nil
}

// MustReadNewLocationRange is the panicking version of ReadNewLocationRange.  It must succeed.
// Do not use on user-controlled input -- this is intended for when the input is known to be
// clean, e.g., written by the Write member function, or where there is no reasonable way to
// handle the input error.
func MustReadNewLocationRange(loc Location, r *bufio.Reader) *LocationRange {
	lr, err := ReadNewLocationRange(loc, r)
	if err != nil {
		panic(fmt.Sprintf("MustReadNewLocationRange: %s", err.Error()))
	}
	return lr
}

// Write writes the string representation of the receiver LocationRange to the Writer argument.
func (lr *LocationRange) Write(w *bufio.Writer) (int, error) {
	var nbytes, b int
	var err error
	nbytes, err = lr.LowerBound.Write(w)
	if err != nil {
		return nbytes, err
	}
	if !lr.LowerBound.Equal(lr.UpperBound) {
		b, err = w.WriteRune(':')
		nbytes += b
		if err != nil {
			return nbytes, err
		}
		b, err = lr.UpperBound.Write(w)
		nbytes += b
	}
	return nbytes, err
}

// String returns the string representation of the receiver LocationRange.
func (lr *LocationRange) String() string {
	if lr.LowerBound == lr.UpperBound {
		return lr.LowerBound.String()
	}
	return fmt.Sprintf("%s:%s", lr.LowerBound.String(), lr.UpperBound.String())
}

// Add modifies the receiver LocationRangeSet to include the LocationRange in the set.
func (lrs *LocationRangeSet) Add(lr *LocationRange) {
	lrs.r = append(lrs.r, lr)
}

// LocationRangeSet is used to hold a set of Location values specified via LocationRange
// objects, providing the ability to test whether any given TestLocation is contained in one of
// the ranges.  We may consider implementing some fancier data structure than a slice of Range
// values.  We use a move-to-front heuristic, for now.  We do not provide the ability remove
// single Locations like LocationSet.
type LocationRangeSet struct {
	r []*LocationRange
}

// Contains is a predicate that returns true iff the Location argument is contained in the
// receiver LocationRangeSet.
func (lrs *LocationRangeSet) Contains(loc Location) bool {
	for ix, lr := range lrs.r {
		if lr.Contains(loc) {
			// move to front heuristic: move the *LocationRange to be before the
			// element at ix/2
			target := ix / 2
			v := lrs.r[ix]
			copy(lrs.r[target+1:], lrs.r[target:ix])
			lrs.r[target] = v
			return true
		}
	}
	return false
}

// NewLocationRangeSet returns a newly constructed empty LocationRangeSet
func NewLocationRangeSet() *LocationRangeSet {
	return &LocationRangeSet{r: nil}
}

// ReadNewLocationRangeSet reads in a LocationRangeSet from the bufio.Reader, and returns it
// when the input ends or the first unexpected rune is encountered.  It is up to the caller to
// determine if input is truly exhausted or if there is some unexpected rune -- e.g., by
// checking the bufio.Reader stream to see whether there is another rune available.
func ReadNewLocationRangeSet(loc Location, r *bufio.Reader) (*LocationRangeSet, error) {
	rv := &LocationRangeSet{}
	for {
		rs, err := ReadNewLocationRange(loc, r)
		if err == io.EOF {
			return rv, nil
		}
		if err != nil {
			return nil, err
		}
		rv.r = append(rv.r, rs)
		peek, err := getNonspaceRune(r)
		if err == io.EOF {
			return rv, nil
		}
		if err != nil {
			return nil, err
		}
		if peek != ',' {
			err = r.UnreadRune()
			return rv, err
		}
	}
}

// LocationRangeSetFromString converts a string representation of a LocationRangeSet (see
// grammar above) into a LocationRangeSet.
func LocationRangeSetFromString(loc Location, set string) (*LocationRangeSet, error) {
	return ReadNewLocationRangeSet(loc, bufio.NewReader(bytes.NewReader([]byte(set))))
}

type locationRangeOrder []*LocationRange

func (a locationRangeOrder) Len() int      { return len(a) }
func (a locationRangeOrder) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a locationRangeOrder) Less(i, j int) bool {
	if a[i].LowerBound.Less(a[j].LowerBound) {
		return true
	}
	if a[j].LowerBound.Less(a[i].LowerBound) {
		return false
	}
	return a[i].UpperBound.Less(a[j].UpperBound)
}

func (lrs *LocationRangeSet) sortedRanges() []*LocationRange {
	sorted := make([]*LocationRange, len(lrs.r))
	copy(sorted, lrs.r)
	sort.Sort(locationRangeOrder(sorted))
	return sorted
}

// IsEmpty is a boolean predicate that returns true iff there are no LocationRange values in
// the LocationRangeSet.  Since a LocationRange includes at least one Location, lrs.IsEmpty()
// means that there are no Locations to sample/visit.  !lrs.IsEmpty() is a pre-condition for
// MinLoc() and MaxLoc(), since the notion of a min (or max) is not well defined in this case.
func (lrs *LocationRangeSet) IsEmpty() bool {
	return len(lrs.r) == 0
}

// Write writes the string representation of the receiver LocationRangeSet to the Writer argument.
func (lrs *LocationRangeSet) Write(w *bufio.Writer) (int, error) {
	var nbytes, b int
	var err error
	first := true
	for _, lr := range lrs.sortedRanges() {
		if !first {
			b, err = fmt.Fprintf(w, ", ")
			nbytes += b
			if err != nil {
				return nbytes, err
			}
		}
		b, err = lr.Write(w)
		nbytes += b
		if err != nil {
			return nbytes, err
		}
		first = false
	}
	return nbytes, err
}

// String returns the receiver LocationRangeSet as a string.
func (lrs *LocationRangeSet) String() string {
	sorted := lrs.sortedRanges()
	stringRep := make([]string, len(sorted))
	for ix, lr := range sorted {
		stringRep[ix] = lr.String()
	}
	return strings.Join(stringRep, ", ")
}

// MinLoc returns the minimum Location in the LocationRangeSet.  It panics if the set is empty.
func (lrs *LocationRangeSet) MinLoc() Location {
	if lrs.IsEmpty() {
		panic("MinLoc pre-condition violation: empty LocationRangeSet used")
	}
	min := lrs.r[0].LowerBound
	for _, lr := range lrs.r {
		if lr.LowerBound.Less(min) {
			min = lr.LowerBound
		}
	}
	return min
}

// MaxLoc returns the maximum Location in the LocationRangeSet.  It panics if the set is empty.
func (lrs *LocationRangeSet) MaxLoc() Location {
	if lrs.IsEmpty() {
		panic("MaxLoc pre-condition violation: empty LocationRangeSet used")
	}
	max := lrs.r[0].UpperBound
	for _, lr := range lrs.r {
		if max.Less(lr.UpperBound) {
			max = lr.UpperBound
		}
	}
	return max
}

// Find invokes the f visitor predicate on each range entry in order, and short-circuits when f
// returns true, i.e., indicates that a satisfactory range has been found.  Using an f that
// always return false can be used to implement a visitor pattern where all entries are
// visited.
func (lrs *LocationRangeSet) Find(f func(*LocationRange) bool) {
	sorted := lrs.sortedRanges()
	for _, lr := range sorted {
		if f(lr) {
			break
		}
	}
}
