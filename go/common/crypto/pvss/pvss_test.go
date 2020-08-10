package pvss

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

const (
	numNodes  = 5
	threshold = 3
)

func TestPVSS(t *testing.T) {
	t.Run("Basic", func(t *testing.T) {
		doTestPVSS(t, &testPVSSCfg{
			s11nChecks: true,
		})
	})
	t.Run("MissingCommits", func(t *testing.T) {
		doTestPVSS(t, &testPVSSCfg{
			numDiscardCommits: 2,
		})
	})
	t.Run("MissingReveals", func(t *testing.T) {
		doTestPVSS(t, &testPVSSCfg{
			numDiscardReveals: 2,
		})
	})
	t.Run("MissingVerifierReveals", func(t *testing.T) {
		doTestPVSS(t, &testPVSSCfg{
			numDiscardVerReveals: 2,
		})
	})
}

func BenchmarkPVSS(b *testing.B) {
	benchNodes := []int{3, 10, 20}

	doBench := func(name string, fn func(*testing.B, int)) {
		for _, n := range benchNodes {
			b.Run(fmt.Sprintf("%s/%d", name, n), func(b *testing.B) {
				fn(b, n)
			})
		}
	}

	// Note: The Commit number will always be larger than OnCommit,
	// because it calls OnCommit for the node's own share.
	doBench("Commit", doBenchCommit)
	doBench("OnCommit", doBenchOnCommit)
}

type testPVSSCfg struct {
	numDiscardCommits    int
	numDiscardReveals    int
	numDiscardVerReveals int

	s11nChecks bool
}

func doTestPVSS(t *testing.T, cfg *testPVSSCfg) {
	require := require.New(t)

	instances, publicKeys := initInstances(require, numNodes, threshold)

	verifier, err := New(&Config{
		Participants: publicKeys,
		Threshold:    threshold,
	})
	require.NoError(err, "New - verifier")

	var commits []*Commit
	for i, inst := range instances {
		var commit *Commit
		commit, err = inst.Commit()
		require.NoError(err, "inst[%d].Commit()", i)
		commits = append(commits, commit)
	}

	if n := cfg.numDiscardCommits; n > 0 {
		// Truncate from the head to catch dumb indexing errors.
		instances = instances[n:]
		commits = commits[n:]
		t.Logf("Commits: Discarding down to %d", len(commits))
	}

	if cfg.s11nChecks {
		commit := commits[0]
		b := cbor.Marshal(commit)
		var commit2 Commit
		err = cbor.Unmarshal(b, &commit2)
		require.NoError(err, "cbor.Unmarshal: Commit")
		require.EqualValues(commit, &commit2, "Commit s11n round-trips")
	}

	for i, commit := range commits {
		for ii, inst := range instances {
			err = inst.OnCommit(commit)
			switch ii {
			case i:
				// Own commit is handled when generating the commit.
				require.Error(err, "inst[%d].OnCommit(commit[%d])", ii, i)
			default:
				require.NoError(err, "inst[%d].OnCommit(commit[%d])", ii, i)
			}
		}
		err = verifier.OnCommit(commit)
		require.NoError(err, "verifier.OnCommit(commit[%d])", i)
	}

	var reveals []*Reveal
	for i, inst := range instances {
		var reveal *Reveal
		reveal, err = inst.Reveal()
		require.NoError(err, "inst[%d].Reveal()", i)
		reveals = append(reveals, reveal)
	}

	if cfg.s11nChecks {
		reveal := reveals[0]
		b := cbor.Marshal(reveal)
		var reveal2 Reveal
		err = cbor.Unmarshal(b, &reveal2)
		require.NoError(err, "cbor.Unmarshal: Reveal")
		require.EqualValues(reveal, &reveal2, "Reveal s11n round-trips")
	}

	if n := cfg.numDiscardReveals; n > 0 {
		n = numNodes - n
		instances = instances[:n]
		reveals = reveals[:n]
		t.Logf("Reveals: Discarding down to %d", len(reveals))
	}

	for i, reveal := range reveals {
		for ii, inst := range instances {
			err = inst.OnReveal(reveal)
			switch ii {
			case i:
				// Own reveal is handled when generating the reveal.
				require.Error(err, "inst[%d].OnReveal(reveal[%d])", i, ii)
			default:
				require.NoError(err, "inst[%d].OnReveal(reveal[%d])", i, ii)
			}
		}
		if n := cfg.numDiscardVerReveals; n > 0 {
			if i < numNodes-n {
				err = verifier.OnReveal(reveal)
				require.NoError(err, "verifier.OnReveal(reveal[%d]) - truncated", i)
			} else {
				t.Logf("Verifier: Skipping reveal[%d]", i)
			}
		} else {
			err = verifier.OnReveal(reveal)
			require.NoError(err, "verifier.OnReveal(reveal[%d])", i)
		}
	}

	resultMap := make(map[string]bool)
	for i, inst := range instances {
		var b []byte
		b, _, err = inst.Recover()
		require.NoError(err, "inst[%d].Recover()", i)

		resultMap[string(b)] = true
	}
	require.Len(resultMap, 1, "All nodes agree on the output")

	b, contributors, err := verifier.Recover()
	require.NoError(err, "verifier.Recover()")
	require.True(resultMap[string(b)], "Verifier agrees on the output")

	t.Logf("Entropy: %x", b)
	t.Logf("Contributors: %+v", contributors)

	if cfg.s11nChecks {
		// Use the verifier for this since it doesn't have a scalar.
		instance := verifier
		b = cbor.Marshal(instance)
		var instance2 Instance
		err = cbor.Unmarshal(b, &instance2)
		require.NoError(err, "cbor.Unmarshal: Instance")
		_ = instance2.participants() // But it does have this, so re-generate.
		require.EqualValues(instance, &instance2, "Instance s11n round-trips")
	}
}

func doBenchCommit(b *testing.B, n int) {
	require := require.New(b)

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		instances, _ := initInstances(require, n, n)
		b.StartTimer()

		_, err := instances[0].Commit()
		require.NoError(err, "Commit")
	}
}

func doBenchOnCommit(b *testing.B, n int) {
	require := require.New(b)

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		instances, publicKeys := initInstances(require, n, n)
		verifier, err := New(&Config{
			Participants: publicKeys,
			Threshold:    n,
		})
		require.NoError(err, "New - verifier")

		commit, err := instances[0].Commit()
		require.NoError(err, "Commit")
		b.StartTimer()

		err = verifier.OnCommit(commit)
		require.NoError(err, "OnCommit")
	}
}

func initInstances(require *require.Assertions, n, t int) ([]*Instance, []Point) {
	var (
		instances   []*Instance
		privateKeys []*Scalar
		publicKeys  []Point
	)

	// Initialize the long term key pairs.
	for i := 0; i < n; i++ {
		scalar, point, err := NewKeyPair()
		require.NoError(err, "NewKeyPair")

		privateKeys = append(privateKeys, scalar)
		publicKeys = append(publicKeys, *point)
	}
	for i, privateKey := range privateKeys {
		inst, err := New(&Config{
			PrivateKey:   privateKey,
			Participants: publicKeys,
			Threshold:    t,
		})
		require.NoError(err, "New(states[%d])", i)
		instances = append(instances, inst)
	}

	return instances, publicKeys
}
