package randgen

import (
	"fmt"
	"math/rand"
)

// PickNFromM chooses n random values from the half-interval [0, m) without replacement.
// This is equivalent to
//
// ```code
//  ma := make([]int, m)
//  for ix := range(ma) {
//    ma[ix] = ix
//  }
//  r.Shuffle(m, func(i, j int) { ma[i], ma[j] = ma[j], ja[i] }
//  ma = ma[:n]
// ```
//
// except that we allow m to be large and will take O(n) memory, rather than O(m).  We allow
// both to be in64
//
// Pre-condition: n <= m && m > 0 && n >= 0
func PickNFromM(n, m int64, r *rand.Rand) []int64 {
	if n > m || n < 0 || m <= 0 {
		panic(fmt.Sprintf("PickNFromM: n <= m, both positve preconditions not satisfied (n=%d, m=%d)", n, m))
	}
	ret := make([]int64, 0, n)
	replace := make(map[int64]int64)
	for nprime := n; nprime > 0; nprime-- {
		ix := r.Int63n(m - int64(n - nprime))
		jx, remap := replace[ix]
		k := nprime - 1
		for {
			nk, mapped := replace[k]
			if !mapped {
				break
			}
			k = nk
		}
		replace[ix] = k
		if remap {
			ix = jx
		}

		ret = append(ret, ix)
	}
	return ret
}
