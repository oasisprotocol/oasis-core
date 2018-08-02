package alg

import (
	"bufio"
	"errors"
	"fmt"
)

// This is likely to be either a full Ethereum global address, which
// would be a contract address (uint160) and per-contract-storage
// address (uint256) tuple, or the hash of that.
type TestLocation int64

func (_ TestLocation) Read(r *bufio.Reader) (Location, error) {
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

func (l TestLocation) Write(w *bufio.Writer) (int, error) {
	return fmt.Fprintf(w, "%d", l)
}

func (l TestLocation) Less(other interface{}) bool {
	switch other := other.(type) {
	case TestLocation:
		return l < other
	default:
		panic(fmt.Sprintf("unexpected type %T: %v", other, other))
	}
}

func (l TestLocation) Equal(other interface{}) bool {
	switch other := other.(type) {
	case TestLocation:
		return l == other
	default:
		panic(fmt.Sprintf("unexpected type %T: %v", other, other))
	}
}
