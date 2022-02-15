package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
)

func TestStatusFaults(t *testing.T) {
	require := require.New(t)

	var testRuntimeID common.Namespace

	var ns NodeStatus
	require.False(ns.IsFrozen(), "default node status should be non-frozen")
	require.False(ns.IsSuspended(testRuntimeID, 1), "default node status should be non-suspended")

	// Simulate liveness failure in epoch 0, recorded when transitioning to epoch 1.
	ns.RecordFailure(testRuntimeID, 1)
	require.Len(ns.Faults, 1, "faults set should have a fault")
	require.False(ns.IsFrozen(), "should not be immediately frozen on failure")
	require.True(ns.IsSuspended(testRuntimeID, 1), "should be suspended in epoch 1")
	require.True(ns.IsSuspended(testRuntimeID, 2), "should be suspended in epoch 2")
	require.False(ns.IsSuspended(testRuntimeID, 3), "should not be suspended in epoch 3")
	require.False(ns.IsSuspended(testRuntimeID, 4), "should not be suspended in epoch 4")

	// Simulate another liveness failure in epoch 3, recorded when transitioning to epoch 4.
	ns.RecordFailure(testRuntimeID, 4)
	require.True(ns.IsSuspended(testRuntimeID, 4), "should be suspended in epoch 4")
	require.True(ns.IsSuspended(testRuntimeID, 5), "should be suspended in epoch 5")
	require.True(ns.IsSuspended(testRuntimeID, 6), "should be suspended in epoch 6")
	require.True(ns.IsSuspended(testRuntimeID, 7), "should be suspended in epoch 7")
	require.False(ns.IsSuspended(testRuntimeID, 8), "should not be suspended in epoch 8")

	// Simulate another liveness failure in epoch 8.
	ns.RecordFailure(testRuntimeID, 9)
	require.True(ns.IsSuspended(testRuntimeID, 11), "should be suspended in epoch 11")
	require.True(ns.IsSuspended(testRuntimeID, 12), "should be suspended in epoch 12")
	require.True(ns.IsSuspended(testRuntimeID, 13), "should be suspended in epoch 13")
	require.True(ns.IsSuspended(testRuntimeID, 14), "should be suspended in epoch 14")
	require.True(ns.IsSuspended(testRuntimeID, 15), "should be suspended in epoch 15")
	require.True(ns.IsSuspended(testRuntimeID, 16), "should be suspended in epoch 16")
	require.False(ns.IsSuspended(testRuntimeID, 17), "should not be suspended in epoch 17")

	// Simulate success in epoch 17.
	ns.RecordSuccess(testRuntimeID, 18)
	require.False(ns.IsFrozen(), "node should no longer be frozen")
	require.True(ns.IsSuspended(testRuntimeID, 18), "should be suspended in epoch 18")
	require.True(ns.IsSuspended(testRuntimeID, 19), "should be suspended in epoch 19")
	require.True(ns.IsSuspended(testRuntimeID, 20), "should be suspended in epoch 20")
	require.True(ns.IsSuspended(testRuntimeID, 21), "should be suspended in epoch 21")
	require.False(ns.IsSuspended(testRuntimeID, 22), "should not be suspended in epoch 22")

	// Simulate success in epoch 22.
	ns.RecordSuccess(testRuntimeID, 23)
	require.False(ns.IsFrozen(), "node should no longer be frozen")
	require.True(ns.IsSuspended(testRuntimeID, 23), "should be suspended in epoch 23")
	require.True(ns.IsSuspended(testRuntimeID, 24), "should be suspended in epoch 24")
	require.False(ns.IsSuspended(testRuntimeID, 25), "should not be suspended in epoch 25")

	// Simulate success in epoch 25.
	ns.RecordSuccess(testRuntimeID, 26)
	require.False(ns.IsFrozen(), "node should no longer be frozen")
	require.False(ns.IsSuspended(testRuntimeID, 26), "should not be suspended in epoch 26")
	require.Len(ns.Faults, 0, "faults set should be cleared")
}
