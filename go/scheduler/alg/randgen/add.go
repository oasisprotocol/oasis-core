package randgen

type Add struct {
	rngs []Rng
}

func NewAdd(rs []Rng) Rng {
	return &Add{rngs: rs}
}

// Generate a random number that is the sum of the outputs of all the rs values.
func (a *Add) Generate() int {
	// reduce sum
	sum := 0
	for _, r := range a.rngs {
		sum = sum + r.Generate()
	}
	return sum
}
