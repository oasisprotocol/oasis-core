package api

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// FreezeForever is an epoch that can be used to freeze a node for
// all (practical) time.
const FreezeForever beacon.EpochTime = 0xffffffffffffffff

// NodeStatus is live status of a node.
type NodeStatus struct {
	// ExpirationProcessed is a flag specifying whether the node expiration
	// has already been processed.
	//
	// If you want to check whether a node has expired, check the node
	// descriptor directly instead of this flag.
	ExpirationProcessed bool `json:"expiration_processed"`
	// FreezeEndTime is the epoch when a frozen node can become unfrozen.
	//
	// After the specified epoch passes, this flag needs to be explicitly
	// cleared (set to zero) in order for the node to become unfrozen.
	FreezeEndTime beacon.EpochTime `json:"freeze_end_time"`
	// ElectionEligibleAfter specifies the epoch after which a node is
	// eligible to be included in non-validator committee elections.
	//
	// Note: A value of 0 is treated unconditionally as "ineligible".
	ElectionEligibleAfter beacon.EpochTime `json:"election_eligible_after"`
	// Faults is a set of fault records for nodes that are experiencing
	// liveness failures when participating in specific committees.
	Faults map[common.Namespace]*Fault `json:"faults,omitempty"`
}

// IsFrozen returns true if the node is currently frozen (prevented
// from being considered in scheduling decisions).
func (ns NodeStatus) IsFrozen() bool {
	return ns.FreezeEndTime > 0
}

// Unfreeze makes the node unfrozen.
func (ns *NodeStatus) Unfreeze() {
	ns.FreezeEndTime = 0
}

// RecordFailure records a liveness failure in the epoch preceding the specified epoch.
func (ns *NodeStatus) RecordFailure(runtimeID common.Namespace, epoch beacon.EpochTime) {
	if ns.Faults == nil {
		ns.Faults = make(map[common.Namespace]*Fault)
	}
	fault, exists := ns.Faults[runtimeID]
	if !exists {
		fault = &Fault{}
		ns.Faults[runtimeID] = fault
	}

	fault.RecordFailure(epoch)
}

// RecordSuccess records success in the epoch preceding the specified epoch.
func (ns *NodeStatus) RecordSuccess(runtimeID common.Namespace, epoch beacon.EpochTime) {
	fault, exists := ns.Faults[runtimeID]
	if !exists {
		return
	}

	fault.RecordSuccess(epoch)
	if fault.Failures == 0 {
		// Remove failure record once the counter reaches zero.
		delete(ns.Faults, runtimeID)
	}
	if len(ns.Faults) == 0 {
		ns.Faults = nil
	}
}

// IsSuspended checks whether the node is suspended in the given epoch.
func (ns *NodeStatus) IsSuspended(runtimeID common.Namespace, epoch beacon.EpochTime) bool {
	// If a node is frozen it is also suspended.
	if ns.IsFrozen() {
		return true
	}

	fault, exists := ns.Faults[runtimeID]
	if !exists {
		return false
	}
	return fault.IsSuspended(epoch)
}

// Fault is used to track the state of nodes that are experiencing liveness failures.
type Fault struct {
	// Failures is the number of times a node has been declared faulty.
	Failures uint8 `json:"failures,omitempty"`
	// SuspendedUntil specifies the epoch number until the node is not eligible for being scheduled
	// into the committee for which it is deemed faulty.
	SuspendedUntil beacon.EpochTime `json:"suspended_until,omitempty"`
}

// RecordFailure records a liveness failure in the epoch preceding the specified epoch.
func (f *Fault) RecordFailure(epoch beacon.EpochTime) {
	f.Failures++
	f.scheduleSuspension(epoch)
}

// RecordSuccess records success in the epoch preceding the specified epoch.
func (f *Fault) RecordSuccess(epoch beacon.EpochTime) {
	// We reduce the failure counter.
	if f.Failures > 0 {
		f.Failures--
	}
	f.scheduleSuspension(epoch)
}

func (f *Fault) scheduleSuspension(epoch beacon.EpochTime) {
	// Determine how long the node should be suspended for.
	switch {
	case f.Failures == 0:
		// No failures, no suspension.
		f.SuspendedUntil = 0
	case f.Failures > 6:
		// Prevent suspending for too long (max 64 epochs).
		suspensionDuration := beacon.EpochTime(1 << 6)
		f.SuspendedUntil = epoch + suspensionDuration
	default:
		suspensionDuration := beacon.EpochTime(1 << f.Failures)
		f.SuspendedUntil = epoch + suspensionDuration
	}
}

// IsSuspended checks whether the node is suspended in the given epoch.
func (f *Fault) IsSuspended(epoch beacon.EpochTime) bool {
	return f.SuspendedUntil > 0 && epoch < f.SuspendedUntil
}

// UnfreezeNode is a request to unfreeze a frozen node.
type UnfreezeNode struct {
	NodeID signature.PublicKey `json:"node_id"`
}
