package alg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"
)

type LocationSet struct {
	Locations map[Location]bool
}

func NewLocationSet() *LocationSet {
	return &LocationSet{Locations: make(map[Location]bool)}
}

func (ls *LocationSet) Add(l Location) {
	ls.Locations[l] = true
}

func (ls *LocationSet) Size() int {
	return len(ls.Locations)
}

func (ls *LocationSet) Contains(loc Location) bool {
	return ls.Locations[loc]
}

func (ls *LocationSet) Merge(other *LocationSet) {
	for loc := range other.Locations {
		ls.Add(loc)
	}
}

// Non-empty intersection, without constructing the intersection
func (ls *LocationSet) Overlaps(other *LocationSet) bool {
	if len(ls.Locations) > len(other.Locations) {
		return other.Overlaps(ls)
	}
	for loc := range ls.Locations {
		if other.Contains(loc) {
			return true
		}
	}
	return false
}

func (ls *LocationSet) Intersect(other *LocationSet) *LocationSet {
	if len(ls.Locations) > len(other.Locations) {
		return other.Intersect(ls)
	}
	intersect := NewLocationSet()
	for loc := range ls.Locations {
		if other.Contains(loc) {
			intersect.Add(loc)
		}
	}
	return intersect
}

type LocationOrder []Location

func (a LocationOrder) Len() int           { return len(a) }
func (a LocationOrder) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a LocationOrder) Less(i, j int) bool { return a[i].Less(a[j]) }

// calling code should check for error via w.Flush()
func (s LocationSet) Write(w *bufio.Writer) {
	// Canonicalize the set members
	members := make([]Location, 0, len(s.Locations))
	for m := range s.Locations {
		members = append(members, m)
	}
	sort.Sort(LocationOrder(members))
	w.WriteString("{")
	do_sep := false
	for _, elt := range members {
		if do_sep {
			w.Write([]byte(", "))
		}
		do_sep = true
		elt.Write(w)
	}
	w.WriteString("}")
}

func (s *LocationSet) ReadMerge(l Location, r *bufio.Reader) (err error) {
	if err = expect_rune('{', r); err != nil {
		return err
	}
	var loc Location
	var ch rune
	if ch, err = get_nonspace_rune(r); err != nil {
		return err
	}
	if ch == '}' {
		return nil
	}
	r.UnreadRune()
	for {
		if loc, err = l.Read(r); err != nil {
			return err
		}
		s.Locations[loc] = true
		if ch, err = get_nonspace_rune(r); err != nil {
			return err
		}
		if ch == '}' {
			return nil
		}
		if ch != ',' {
			r.UnreadRune()
			return errors.New(fmt.Sprintf("Expected ',' or '}', got %c", ch))
		}
	}
}

func (s *LocationSet) ToString() string {
	output_buffer := new(bytes.Buffer)
	bufw := bufio.NewWriter(output_buffer)
	s.Write(bufw)
	if err := bufw.Flush(); err != nil {
		panic("Transaction.ToString conversion failed")
	}
	return output_buffer.String()
}

func ReadNewLocationSet(l Location, r *bufio.Reader) (set *LocationSet, err error) {
	s := NewLocationSet()
	if err := s.ReadMerge(l, r); err != nil {
		return nil, err
	}
	return s, nil
}
