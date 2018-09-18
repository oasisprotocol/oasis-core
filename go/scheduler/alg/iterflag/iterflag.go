package iterflag

/// iterflag defines a way to specify command-line flags (using the flag module) so that we can
/// use flags to specify parameters used in an iterative fashion, e.g., as controls to a
/// simulation run in a loop.  The code can specify the order in which the (abstract) flag
/// parameter loops are nested, e.g., the order of the flags when incremented in odometric
/// order.
///
/// Example usage:
///
///	fooFlag int
///	barFlag float64
///	bazFlag int64
///
///	func init() {
///		iterflag.IntVar(&fooFlag, "foo", 0, 10, 1, "foo controls the simulator...")
///		iterflag.Float64Var(&barFlag, "bar", 1.0, 10.0, 0.1, "bar controls...")
///		iterflag.Int64Var(&bazFlag, "baz", 10, 15, 1, "baz controls...")
///	}
///
///	func main() {
///		flag.Parse()
///		iterflag.Parse()
///
///		colWidth=16
///		precision=4 // for float64 values
///
///		iterator := iterflag.MakeIterator()
///		// Print varying headers
///		for _, c := range iterator.Control {
///			if c.WillIterate() {
///				fmt.Printf("|%*s", colWidth, c.Key())
///			}
///		}
///		fmt.Printf("|%*s|\n", colWidth, "Results")
///		for {
///			for _, c := range iterator.Control {
///				if c.WillIterate() {
///					fmt.Printf("|%*s", colWidth, c.Value(colWidth, precision))
///				}
///			}
///			fmt.Printf("|%*.*g|\n", colWidth, precision, runSimulation())
///		}
///		if !iterator.Incr() {
///			break
///		}
///	}
///
/// $ ./a.out --foo=0:10:1 --bar=1.0:10:0.1 -baz=9
///
/// foo will iterate through 0, 1, 2, ..., 9; bar will iterate through 1.0, 1.1, ... 9.9 (but
/// beware of floating point rounding: this may go to 10.0-epsilon as well); and baz will only
/// take on the value 9.  Because the flag baz does not iterate, it will be suppressed in the
/// tabular output via the WillIterate test.  (We omit the code to printout the controls that
/// do not iterate along with their values.)

import (
	"flag"
	"fmt"
	"sort"
)

type paramRegistration struct {
	spec    string // user setting
	control IterControl
}

var params []*paramRegistration

type Iterator struct {
	Control []IterControl
}

var nameToIter map[string]IterControl

func init() {
	// Set things up to keep track of flag variable registration
	params = nil
	nameToIter = make(map[string]IterControl)
}

// IntVar registers a location `loc` as an int flag variable with name `flagName`, that will
// iterate starting with the value `start`, incrementing by `incr` each time, stopping before
// the value at `*loc` goes pass `end`.  If `start < end` then `incr > 0` should hold, and if
// `start > end` then `incr < 0` should hold.  If `incr == 0`, then the flag will not iterate.
func IntVar(loc *int, flagName string, start, end, incr int, descr string) {
	c := NewIntIterControl(loc, flagName, start, end, incr)
	p := &paramRegistration{"", c}
	flag.StringVar(&p.spec, flagName, c.String(), descr)
	params = append(params, p)
}

// Int64Var registers a location `loc` as an int64 flag variable with name `flagName`, that
// will iterate starting with the value `start`, incrementing by `incr` each time, stopping
// before the value at `*loc` goes pass `end`.  If `start < end` then `incr > 0` should hold,
// and if `start > end` then `incr < 0` should hold.  If `incr == 0`, then the flag will not
// iterate.
func Int64Var(loc *int64, flagName string, start, end, incr int64, descr string) {
	c := NewInt64IterControl(loc, flagName, start, end, incr)
	p := &paramRegistration{"", c}
	flag.StringVar(&p.spec, flagName, c.String(), descr)
	params = append(params, p)
}

// Float64Var registers a location `loc` as a float64 flag variable with name `flagName`, that
// will iterate starting with the value `start`, incrementing by `incr` each time, stopping
// before the value at `*loc` goes pass `end`.  If `start < end` then `incr > 0` should hold,
// and if `start > end` then `incr < 0` should hold.  If `incr == 0`, then the flag will not
// iterate.
func Float64Var(loc *float64, flagName string, start, end, incr float64, descr string) {
	c := NewFloat64IterControl(loc, flagName, start, end, incr)
	p := &paramRegistration{"", c}
	flag.StringVar(&p.spec, flagName, c.String(), descr)
	params = append(params, p)
}

// AllIterableFlags returns a string slice containing all the registered iterable flag names.
// This is used for specifying a particular loop nesting order via MakeIteratorFlags.
func AllIterableFlags() []string {
	names := make([]string, 0)
	for _, p := range params {
		names = append(names, p.control.Key())
	}
	return names
}

// Parse parses the iterflag command-line flags for the start, end, incr values and performs
// internal bookkeeping to make it easier to construct the nested iterator Iterator object.
func Parse() {
	for _, pr := range params {
		if pr.spec != "" {
			err := pr.control.parse(pr.spec)
			if err != nil {
				panic(fmt.Sprintf("Could not parse param %s: %s", pr.control.Key(), err.Error()))
			}
		}
		// This should be dead code, since flag module registration should have
		// prevented duplicate Key().
		if _, found := nameToIter[pr.control.Key()]; found {
			panic(fmt.Sprintf("iterflag: Duplicate flag %s found", pr.control.Key()))
		}
		nameToIter[pr.control.Key()] = pr.control
		pr.control.reset()
		// We do reset() here so relying code can print values before creating an
		// Iterator object, since relying code has direct access to the location
		// holding the flag value.
	}
}

// AtStart returns true if all `numIters` least-signficant parameter iterators are at their
// start value.  Only WillIterate controls are counted.  Used to print "decade" separators.
func (it *Iterator) AtStart(numIters int) bool {
	if numIters <= 0 {
		return true
	}
	position := len(it.Control) - 1
	count := 0
	for {
		if position < 0 {
			return true
		}
		if it.Control[position].WillIterate() {
			if !it.Control[position].atStart() {
				return false
			}
			count++
			if count >= numIters {
				return true
			}
		}
		position--
	}
}

// Incr "increments" the iterator to the next state if possible.  It returns true iff this was
// successful.
func (it *Iterator) Incr() bool {
	pos := len(it.Control) - 1
	for {
		if pos < 0 {
			break
		}
		if it.Control[pos].WillIterate() {
			if it.Control[pos].hasNext() {
				it.Control[pos].increment()
				break // done!
			} else {
				it.Control[pos].reset()
				// carry to next control
			}
		} else {
			it.Control[pos].reset() // in case simulation code changed it
		}
		pos--
	}
	return pos >= 0
}

// iterSortOrder takes an []string representing the parameter positions in odometric order and
// return the mapping used for sorting the iterators.
func iterSortOrder(words []string) (map[string]int, error) {
	m := make(map[string]int)
	for ix, w := range words {
		if _, dup := m[w]; dup {
			return nil, fmt.Errorf("Duplicate entry %s found", w)
		}
		m[w] = ix
	}
	return m, nil
}

type iterOrder struct {
	data  []IterControl
	order map[string]int
}

func (a iterOrder) Len() int           { return len(a.data) }
func (a iterOrder) Swap(i, j int)      { a.data[i], a.data[j] = a.data[j], a.data[i] }
func (a iterOrder) Less(i, j int) bool { return a.order[a.data[i].Key()] < a.order[a.data[j].Key()] }

// sortIterControl sorts the entries referred to by the sic formal parameter in place, using the
// ordering specified by the order formal parameter, returning nil if successful or an error if
// there was a problem.
func sortIterControl(sic []IterControl, order map[string]int) error {
	for _, ic := range sic {
		if _, ok := order[ic.Key()]; !ok {
			return fmt.Errorf("Sort parameter %s not specified in enumeration order", ic.Key())
		}
	}
	sort.Sort(&iterOrder{data: sic, order: order})
	return nil
}

// MakeFlagsIterator returns an Iterator that will iterate over all named flags in its
// argument.  Those named flags in the flagName []string argument will be iterated as if there
// were nested loops in that order, with flagName[0] as the outermost loop, etc.  This accesses
// the registration list and is not thread-safe but is thread-compatible.  Once the Iterator is
// constructed, and another thread invokes MakeFlagsIterator, the threads could use those
// Iterators in parallel as long as the flag named in their construction are disjoint.
func MakeIteratorForFlags(flagName []string) (*Iterator, error) {
	order, err := iterSortOrder(flagName)
	if err != nil {
		return nil, err
	}
	// postcondition of successful iterSortOrder ensures no dups
	var iter []IterControl
	for _, fn := range flagName {
		if _, valid := nameToIter[fn]; !valid {
			return nil, fmt.Errorf("flag name %s not valid", fn)
		}
		it := nameToIter[fn]
		it.reset()
		// We reset() here in case the relying code creates two iterators to run
		// sequentially where the same flag(s) get iterated.
		iter = append(iter, it)
	}
	err = sortIterControl(iter, order)
	if err != nil {
		return nil, err
	}
	return &Iterator{Control: iter}, nil
}

// MakeIterator returns an Iterator that will iterate over all registered iterable flags in
// registration order.
func MakeIterator() (*Iterator, error) {
	var flagOrder []string
	for _, p := range params {
		flagOrder = append(flagOrder, p.control.Key())
	}
	return MakeIteratorForFlags(flagOrder)
}
