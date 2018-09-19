package randgen

type Fixed struct {
	value int
}

// NewFixed returns a newly constructed Fixed Rng object.
func NewFixed(v int) Rng {
	return &Fixed{value: v}
}

// Generate a fixed random number.
func (f *Fixed) Generate() int {
	return f.value
}
