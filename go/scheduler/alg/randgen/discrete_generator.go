package randgen

// Rng is the interface for various discrete random number generators.  Rngs share one method:
// Generate() int.  The range and other distribution characteristics depend on the actual type
// implementing this interface.  See Uniform and Zipf.
type Rng interface {
	Generate() int
}
