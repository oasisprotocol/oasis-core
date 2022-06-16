package common

// ExactlyOneTrue returns true iff exactly one of the passed conditions is true.
func ExactlyOneTrue(conds ...bool) bool {
	total := 0
	for _, c := range conds {
		if c {
			total++
		}
	}
	return total == 1
}
