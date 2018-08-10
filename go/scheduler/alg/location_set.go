package alg

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
)

// LocationSet is an implementation of a `set` abstraction to hold memory addresses or
// locations.  The key `Location` is actually an interface, since for simulation purposes we
// want to use integers, but for actual use with real transactions this will be a bigger
// object.  Depending on the average size of the sets, we may want to look into replacing this
// with a simple array, possibly sorted, instead of a `map` object, since that may have better
// cache performance.
//
// The LocationSet has Read/Write methods.  These are used by the simulator to log generated
// synthetic load to files and to replay them into different scheduling algorithms / schedulers
// with different parameters.  The grammar of the string/file representation is
//
// LOCSET : LBRACE LOCATION_LIST_OPT RBRACE ;
//
// LOCATION_LIST_OPT : empty
//                   | LOCATION_LIST
//                   ;
//
// LOCATION_LIST : LOCATION
//               | LOCATION_LIST COMMA LOCATION  # comma is separator, not terminator
//               ;
//
// Optional non-newline white-space can occur between tokens.
type LocationSet struct {
	locations map[Location]struct{} // a struct with zero elements take no memory
}

// NewLocationSet constructs an empty LocationSet.
func NewLocationSet() *LocationSet {
	return &LocationSet{locations: make(map[Location]struct{})}
}

// Add a location to the LocationSet
func (ls *LocationSet) Add(loc Location) {
	ls.locations[loc] = struct{}{}
}

// Delete (remove) a location from the LocationSet
func (ls *LocationSet) Delete(loc Location) {
	delete(ls.locations, loc)
}

// Size returns the number of elements (locations) in the LocationSet
func (ls *LocationSet) Size() int {
	return len(ls.locations)
}

// Contains is a boolean predicate returning true iff the location is a member of the
// LocationSet
func (ls *LocationSet) Contains(loc Location) bool {
	_, exists := ls.locations[loc]
	return exists
}

// Merge the members of the given LocationSet to this one, i.e., ls \leftarrow ls union other.
func (ls *LocationSet) Merge(other *LocationSet) {
	for loc := range other.locations {
		ls.Add(loc)
	}
}

// MemberIteratorCallbackWithEarlyExit invokes the callback function `cb` on each element of
// the receiver LocationSet `ls`, in no particular order.  If `cb` returns true to indicate
// early exit, then the iteration stops and MemberIteratorCallbackWithEarlyAbort return true to
// indicate early exit (though `cb` may actually return true only on the last element in the
// set, so in that sense it may not be literally early).  Otherwise,
// MemberIteratorCallbackWithEarlyAbort returns false.
func (ls *LocationSet) MemberIteratorCallbackWithEarlyExit(cb func(Location) bool) bool {
	for loc := range ls.locations {
		if cb(loc) {
			return true
		}
	}
	return false // no abort
}

// Overlaps is a boolean predicate to determine of this recevier LocationSet `ls` and the
// parameter `other` have a non-empty intersection, without actually constructing the
// intersection.
func (ls *LocationSet) Overlaps(other *LocationSet) bool {
	if len(ls.locations) > len(other.locations) {
		return other.Overlaps(ls)
	}
	for loc := range ls.locations {
		if other.Contains(loc) {
			return true
		}
	}
	return false
}

// Intersect returns a new location set that contains elements that are present in the receiver
// LocationSet `ls` and in the `other` LocationSet.
func (ls *LocationSet) Intersect(other *LocationSet) *LocationSet {
	if len(ls.locations) > len(other.locations) {
		return other.Intersect(ls)
	}
	intersect := NewLocationSet()
	for loc := range ls.locations {
		if other.Contains(loc) {
			intersect.Add(loc)
		}
	}
	return intersect
}

// LocationOrder is a helper type that is used to sort the members of a location set.  We sort
// the members only when writing out a string representation, since this makes it easier to
// manually compare two location sets and check whether there are conflicts.
type LocationOrder []Location

func (a LocationOrder) Len() int           { return len(a) }
func (a LocationOrder) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a LocationOrder) Less(i, j int) bool { return a[i].Less(a[j]) }

// Write the receiver LocationSet to the bufio.Writer.  Calling code should check for I/O error
// via w.Flush().
func (ls LocationSet) Write(w *bufio.Writer) {
	// Canonicalize the set members
	members := make([]Location, 0, len(ls.locations))
	for m := range ls.locations {
		members = append(members, m)
	}
	sort.Sort(LocationOrder(members))
	_, _ = w.WriteString("{")
	doSep := false
	for _, elt := range members {
		if doSep {
			_, _ = w.WriteString(", ")
		}
		doSep = true
		_, _ = elt.Write(w)
	}
	_, _ = w.WriteString("}")
}

// ReadMerge reads in a string representations of a LocationSet from the *bufio.Reader, and
// merges it into the receiver LocationSet.  The Location interface argument `l` is needed
// because LocationSet objects do not know what is the actual type that implements the Location
// interface, so `l.Read` is used to read in the individual locations from the `*bufio.Reader`.
//
// nolint: gocyclo
func (ls *LocationSet) ReadMerge(l Location, r *bufio.Reader) (err error) {
	if err = expectRune('{', r); err != nil {
		return err
	}
	var loc Location
	var ch rune
	if ch, err = getNonspaceRune(r); err != nil {
		return err
	}
	if ch == '}' {
		return nil
	}
	if err = r.UnreadRune(); err != nil {
		return err // should never happen; panic might be better?
	}
	for {
		if loc, err = l.Read(r); err != nil {
			return err
		}
		ls.Add(loc)
		if ch, err = getNonspaceRune(r); err != nil {
			return err
		}
		if ch == '}' {
			return nil
		}
		if ch != ',' {
			if err = r.UnreadRune(); err != nil {
				// Both the non-',' and the UnreadRune error mean the input is
				// likely to be unusable, but UnreadRune is more serious.
				return err
			}
			return fmt.Errorf("Expected ',' or '}', got %c", ch)
		}
	}
}

// ToString returns the canonical string representation for the receiver LocationSet |ls|.
func (ls *LocationSet) ToString() string {
	outputBuffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(outputBuffer)
	ls.Write(bufw)
	if err := bufw.Flush(); err != nil {
		panic("Transaction.ToString conversion failed")
	}
	return outputBuffer.String()
}

// ReadNewLocationSet reads a LocationSet from the `r *bufio.Reader` and returns it.  The
// Location interface argument `l` is needed because LocationSet objects do not know what is
// the actual type that implements the Location interface, so `l.Read` is used to read in the
// individual locations from the `*bufio.Reader`.
func ReadNewLocationSet(l Location, r *bufio.Reader) (set *LocationSet, err error) {
	s := NewLocationSet()
	if err := s.ReadMerge(l, r); err != nil {
		return nil, err
	}
	return s, nil
}
