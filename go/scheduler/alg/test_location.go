package alg

import (
	"bufio"
	"errors"
	"fmt"
)

// TestLocation is a type implementing the Location interface used for testing.  It is just an
// int64.  For real use, the Location-implementing type (as-yet unnamed/unimplemented) is
// likely to be either a full Ethereum global address, which would be a contract address
// (uint160) and per-contract-storage address (uint256) tuple, the hash of that, the initial
// 160+256-10 = 406 bits (all addresses in a 1k region treated as equivalent), or something
// along those lines.
type TestLocation int64

// Read from bufio.Receiver a TestLocation and return it.  Receiver `tl` is unused, but golint
// insists receiver names not be an underscore.
func (tl TestLocation) Read(r *bufio.Reader) (Location, error) {
	var loc TestLocation
	converted, err := fmt.Fscanf(r, "%d", &loc)
	if err != nil {
		return TestLocation(0), err
	}
	if converted != 1 {
		return TestLocation(0), errors.New("Not a valid location")
	}
	return loc, nil
}

// Write the TestLocation to the bufio.Writer.
func (tl TestLocation) Write(w *bufio.Writer) (int, error) {
	return fmt.Fprintf(w, "%d", tl)
}

// Less returns true iff the receiver TestLocation tl is less than the argument.
// This panics if the argument interface object is not also a TestLocation.
func (tl TestLocation) Less(other interface{}) bool {
	switch other := other.(type) {
	case TestLocation:
		return tl < other
	default:
		panic(fmt.Sprintf("unexpected type %T: %v", other, other))
	}
}

// Equal returns true iff the receiver TestLocation tl is equal to the argument.
// This panics if the argumenet interface object is not also a TestLocation.
func (tl TestLocation) Equal(other interface{}) bool {
	switch other := other.(type) {
	case TestLocation:
		return tl == other
	default:
		panic(fmt.Sprintf("unexpected type %T: %v", other, other))
	}
}
