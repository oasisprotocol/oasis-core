package scheduling

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFixedRateScheduler(t *testing.T) {
	t.Run("No tasks", func(_ *testing.T) {
		scheduler := NewFixedRateScheduler(time.Millisecond, time.Millisecond)
		scheduler.Start()
		time.Sleep(5 * time.Millisecond)
		scheduler.Stop()
	})

	t.Run("Many tasks", func(t *testing.T) {
		require := require.New(t)

		n1, n2 := 0, 0
		t1 := func(_ context.Context) error { n1++; return nil }
		t2 := func(_ context.Context) error { n2++; return nil }

		scheduler := NewFixedRateScheduler(time.Millisecond, time.Millisecond)
		scheduler.AddTask("t1", t1)
		scheduler.AddTask("t2", t2)

		scheduler.Start()
		time.Sleep(5 * time.Millisecond)
		scheduler.Stop()

		require.Positive(n1)
		require.Positive(n2)
		require.Equal(n1, n2)
	})

	t.Run("New task while running", func(t *testing.T) {
		require := require.New(t)

		n1, n2 := 0, 0
		t1 := func(_ context.Context) error { n1++; return nil }
		t2 := func(_ context.Context) error { n2++; return nil }

		scheduler := NewFixedRateScheduler(time.Millisecond, time.Millisecond)
		scheduler.AddTask("t1", t1)

		scheduler.Start()
		time.Sleep(5 * time.Millisecond)
		scheduler.AddTask("t2", t2)
		time.Sleep(5 * time.Millisecond)
		scheduler.Stop()

		require.Positive(n1)
		require.Positive(n2)
		require.Greater(n1, n2)
	})

	t.Run("Stopped during initial delay", func(t *testing.T) {
		require := require.New(t)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		doneCh := make(chan struct{})

		go func() {
			scheduler := NewFixedRateScheduler(time.Hour, time.Millisecond)
			scheduler.Start()
			scheduler.Stop()
			close(doneCh)
		}()

		select {
		case <-ctx.Done():
			require.Fail("Scheduler should stop during initial delay")
		case <-doneCh:
		}
	})

	t.Run("Stopped between repetitions", func(t *testing.T) {
		require := require.New(t)

		scheduler := NewFixedRateScheduler(0, time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		doneCh := make(chan struct{})

		go func() {
			scheduler.Start()
			time.Sleep(time.Millisecond)
			scheduler.Stop()
			close(doneCh)
		}()

		select {
		case <-ctx.Done():
			require.Fail("Scheduler should stop between repetitions")
		case <-doneCh:
		}
	})

	t.Run("Stopped during task execution", func(t *testing.T) {
		require := require.New(t)

		t1 := func(ctx context.Context) error { <-ctx.Done(); return nil }

		scheduler := NewFixedRateScheduler(0, time.Millisecond)
		scheduler.AddTask("t1", t1)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		doneCh := make(chan struct{})

		go func() {
			scheduler.Start()
			time.Sleep(time.Millisecond)
			scheduler.Stop()
			close(doneCh)
		}()

		select {
		case <-ctx.Done():
			require.Fail("Scheduler should stop during task execution")
		case <-doneCh:
		}
	})
}
