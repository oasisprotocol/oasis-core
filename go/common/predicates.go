package common

func countTrue(conds ...bool) int {
	total := 0
	for _, c := range conds {
		if c {
			total++
		}
	}
	return total
}

// ExactlyOneTrue returns true iff exactly one of the passed conditions is true.
func ExactlyOneTrue(conds ...bool) bool {
	return countTrue(conds...) == 1
}

// AtMostOneTrue returns true iff at most one of the passed conditions is true.
func AtMostOneTrue(conds ...bool) bool {
	return countTrue(conds...) <= 1
}
