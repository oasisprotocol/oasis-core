package mathrand

import (
	"crypto"
	"math/rand"
	"testing"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"

	"github.com/stretchr/testify/require"
)

func TestRngAdapter(t *testing.T) {
	const (
		entropy = "Anyone who attempts to generate random numbers by deterministic means is, of course, living in a state of sin."
		nonce   = "mathrand:tests"

		nrSamples = 1000 // XXX: ~30 is probably enough.
	)

	drbg, err := drbg.New(crypto.SHA512, []byte(entropy), []byte(nonce), nil)
	require.NoError(t, err, "DRBG initialization.")

	src := New(drbg)
	rng := rand.New(src)

	// Pearson's chi-squared test for goodness of fit.
	//
	// Sort of silly to do this repeatedly since the results are determinstic.
	samples := make([]int, 6)
	for i := 0; i < nrSamples; i++ {
		samples[rng.Intn(6)]++
	}

	chiSq, expected := float64(0), float64(nrSamples)/6
	for _, n := range samples {
		tmp := float64(n) - expected
		tmp *= tmp
		tmp /= expected
		chiSq += tmp
	}

	t.Logf("chiSq: %v", chiSq)
	require.True(t, chiSq < 15.086, "chiSquared < 15.086 (0.99)")
}
