package full

import "time"

// Borrowed from https://github.com/cenkalti/backoff.

// Returns a random value from the following interval:
// 	[currentInterval - randomizationFactor * currentInterval, currentInterval + randomizationFactor * currentInterval].
func getRandomValueFromInterval(randomizationFactor, random float64, currentInterval time.Duration) time.Duration {
	delta := randomizationFactor * float64(currentInterval)
	minInterval := float64(currentInterval) - delta
	maxInterval := float64(currentInterval) + delta

	// Get a random value from the range [minInterval, maxInterval].
	// The formula used below has a +1 because if the minInterval is 1 and the maxInterval is 3 then
	// we want a 33% chance for selecting either 1, 2 or 3.
	return time.Duration(minInterval + (random * (maxInterval - minInterval + 1)))
}
