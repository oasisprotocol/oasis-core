package workerpool

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPoolBackoff(t *testing.T) {
	require := require.New(t)

	// Test that the backoff is reset on success.
	pool := New("test", &PoolConfig{Backoff: &BackoffConfig{MinTimeout: 500 * time.Millisecond, MaxTimeout: 3 * time.Second}})
	pool.Resize(4)

	fnSuccess := func() error { return nil }
	fnFail := func() error { return fmt.Errorf("job failure") }

	// Ensure no backoff on successes.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-pool.Submit(fnSuccess)
		}()
	}
	wg.Wait()
	require.EqualValues(0, pool.backoff.Timeout(), "there should be no backoff on success")

	// Ensure max backoff on multilple failures.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-pool.Submit(fnFail)
		}()
	}
	wg.Wait()
	// Note: The exact backoff is not known as the backoff is randomized, and can even increase
	// beyond MaxBackoff by a bit due to the upstream backoff implementation.
	require.GreaterOrEqual(pool.backoff.Timeout(), 1*time.Second, "repeated failures should increase backoff")

	// Ensure backoff is reset on success.
	<-pool.Submit(fnSuccess)
	require.EqualValues(0, pool.backoff.Timeout(), "backoff should be reset on success")
}
