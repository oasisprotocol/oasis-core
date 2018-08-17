package randgen

import (
	"fmt"
	"math/rand"
)

// High-level Algorithm Description:
//
// Conceptually we keep an array of elements from [0, m).  We iterate, picking a random number
// (uniformly) from [0, m), [0, m-1), ..., [0, m-n+1), and within each iteration, we take the
// element out of the array and if it is not the last element, replace it with the last element
// and then shrink the conceptual array by one.  This is clearly uniform by the standard
// argument, since the first element is chosen with probability 1/m, the next is (m-1)/m *
// 1/(m-1), and so forth, so every element is chosen with probability 1/m.
//
// Of course, we don't actually create an array from 0 to m-1.  That would have O(m) cost.
// Instead, only we keep track of the replacements.  That is, when we pick an element from the
// interior of the range, we add to a hashmap from the location to the element at the last
// location of the conceptual array.  Note that the last element may also have been replaced,
// so we must follow the replacement mapping chain until we hit a value that no replacement
// mapping.
//
// The number of entries in the hashmap is O(n) -- total storage is possibly with rounding up
// to the next power of 2 or prime nearby, depending on the hashmap implementation.  The length
// of the replacement mapping chain is at most O(n), since that's the limit on the number of
// replacement mapping entries.  Each mapping entry is used once.

// PickNFromMRemapping chooses n random values from the half-interval [0, m) without
// replacement.  It uses the supplied random number generator, and the choice is uniform if
// r.Int63n is uniform.  This is equivalent to the following (inefficient) code:
//
// ```code
//  ma := make([]int, m)
//  for ix := range(ma) {
//    ma[ix] = ix
//  }
//  r.Shuffle(m, func(i, j int) { ma[i], ma[j] = ma[j], ja[i] }
//  return ma[:n]
// ```
//
// except that we allow m to be very large, and this implementation will use O(n) memory,
// rather than O(m).  We allow both n and m to be int64, but presumably n << m.
// (Much-less-than, not bit-shift.)
//
// Pre-condition: n <= m && m > 0 && n >= 0
func PickNFromMRemapping(n, m int64, r *rand.Rand) []int64 {
	if n > m || n < 0 || m <= 0 {
		panic(fmt.Sprintf("PickNFromM: n <= m, both positve preconditions not satisfied (n=%d, m=%d)", n, m))
	}
	ret := make([]int64, 0, n)
	replace := make(map[int64]int64)
	for count := int64(0); count < n; count++ {
		ix := r.Int63n(m - count)
		jx, remap := replace[ix]
		k := n - 1 - count
		nk, mapped := replace[k]
		if mapped {
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

// PickNFromMRejectionSampling picks n elements with uniform probability from m elements [0,
// m).  The algorithm used has expected O(n) cost if n << m: it iteratively picks from all
// possible values with uniform probability (if r.Int63n is uniform) and tries again if the
// pick was an element that had already been chosen earlier.  This has poor performance if n is
// close to m and both are large.
func PickNFromMRejectionSampling(n, m int64, r *rand.Rand) []int64 {
	if n > m || n < 0 || m <= 0 {
		panic(fmt.Sprintf("PickNFromM: n <= m, both positve preconditions not satisfied (n=%d, m=%d)", n, m))
	}
	ret := make([]int64, n)
	found := make(map[int64]struct{})
	for ix := int64(0); ix < n; ix++ {
		var elt int64
		for {
			elt = r.Int63n(m)
			if _, seen := found[elt]; !seen {
				break
			}
		}
		found[elt] = struct{}{}
		ret[ix] = elt
	}
	return ret
}

// PickNFromM chooses n random values from the half-interval [0, m) without replacement.  It
// uses either the remapping algorithm or the rejection sampling algorithm, depending on
// performance and/or ease of correctness proof.
func PickNFromM(n, m int64, r *rand.Rand) []int64 {
	return PickNFromMRemapping(n, m, r)
}
