package randgen

import (
	"time"
)

// Make sure we have a seed, and print it out so that if any test fails, the test framework
// will make the value available and the test can be manually re-run with the same seed.  The
// default value of zero is used as a seed, so that when used as a test that is run during
// continuous integration the test is deterministic.  While we might use a threshold in
// statistical tests so that the probability of passing is high, given enough continuous
// integration / continuous testing runs the error *will* occur.  We require that the test
// runner explicitly ask for a random seed, using -1 as the indicator value.
func handleTestSeed(logger func(format string, args ...interface{}), seedPtr *int64, name string) {
	if *seedPtr == -1 {
		*seedPtr = time.Now().UTC().UnixNano()
	}
	logger("%s seed = %d\n", name, *seedPtr)
}
