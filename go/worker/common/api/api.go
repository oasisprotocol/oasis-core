package api

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// StatusState is the concise status state of the common runtime worker.
type StatusState uint8

const (
	// StatusStateReady is the ready status state.
	StatusStateReady StatusState = 0
	// StatusStateWaitingConsensusSync is the waiting for consensus sync status state.
	StatusStateWaitingConsensusSync StatusState = 1
	// StatusStateWaitingRuntimeRegistry is the waiting for runtime registry descriptor status state.
	StatusStateWaitingRuntimeRegistry StatusState = 2
	// StatusStateWaitingKeymanager is the waiting for keymanager status state.
	StatusStateWaitingKeymanager StatusState = 3
	// StatusStateWaitingHostedRuntime is the waiting for the hosted runtime status state.
	StatusStateWaitingHostedRuntime StatusState = 4
	// StatusStateWaitingHistoryReindex is the waiting for runtime history reindex status state.
	StatusStateWaitingHistoryReindex StatusState = 5
	// StatusStateWaitingWorkersInit is the waiting for workers to initialize status state.
	StatusStateWaitingWorkersInit StatusState = 6
	// StatusStateRuntimeSuspended is the runtime suspended status state.
	StatusStateRuntimeSuspended StatusState = 7
)

// String returns a string representation of a status state.
func (s StatusState) String() string {
	switch s {
	case StatusStateReady:
		return "ready"
	case StatusStateWaitingConsensusSync:
		return "waiting for consensus sync"
	case StatusStateWaitingRuntimeRegistry:
		return "waiting for runtime registry descriptor"
	case StatusStateWaitingKeymanager:
		return "waiting for available keymanager"
	case StatusStateWaitingHostedRuntime:
		return "waiting for hosted runtime provision"
	case StatusStateWaitingHistoryReindex:
		return "waiting for history reindex"
	case StatusStateWaitingWorkersInit:
		return "waiting for workers to initialize"
	case StatusStateRuntimeSuspended:
		return "runtime suspended"
	default:
		return "[invalid status state]"
	}
}

// MarshalText encodes a StatusState into text form.
func (s StatusState) MarshalText() ([]byte, error) {
	switch s {
	case StatusStateReady:
		return []byte(StatusStateReady.String()), nil
	case StatusStateWaitingConsensusSync:
		return []byte(StatusStateWaitingConsensusSync.String()), nil
	case StatusStateWaitingRuntimeRegistry:
		return []byte(StatusStateWaitingRuntimeRegistry.String()), nil
	case StatusStateWaitingKeymanager:
		return []byte(StatusStateWaitingKeymanager.String()), nil
	case StatusStateWaitingHostedRuntime:
		return []byte(StatusStateWaitingHostedRuntime.String()), nil
	case StatusStateWaitingHistoryReindex:
		return []byte(StatusStateWaitingHistoryReindex.String()), nil
	case StatusStateWaitingWorkersInit:
		return []byte(StatusStateWaitingWorkersInit.String()), nil
	case StatusStateRuntimeSuspended:
		return []byte(StatusStateRuntimeSuspended.String()), nil
	default:
		return nil, fmt.Errorf("invalid StatusState: %d", s)
	}
}

// UnmarshalText decodes a text slice into a StatusState.
func (s *StatusState) UnmarshalText(text []byte) error {
	switch string(text) {
	case StatusStateReady.String():
		*s = StatusStateReady
	case StatusStateWaitingConsensusSync.String():
		*s = StatusStateWaitingConsensusSync
	case StatusStateWaitingRuntimeRegistry.String():
		*s = StatusStateWaitingRuntimeRegistry
	case StatusStateWaitingKeymanager.String():
		*s = StatusStateWaitingKeymanager
	case StatusStateWaitingHostedRuntime.String():
		*s = StatusStateWaitingHostedRuntime
	case StatusStateWaitingHistoryReindex.String():
		*s = StatusStateWaitingHistoryReindex
	case StatusStateWaitingWorkersInit.String():
		*s = StatusStateWaitingWorkersInit
	case StatusStateRuntimeSuspended.String():
		*s = StatusStateRuntimeSuspended
	default:
		return fmt.Errorf("invalid StatusState: %s", string(text))
	}
	return nil
}

// Status is the common runtime worker status.
type Status struct {
	// Status is a concise status of the committee node.
	Status StatusState `json:"status"`

	// ActiveVersion is the currently active version.
	ActiveVersion *version.Version `json:"active_version"`

	// LatestRound is the latest runtime round as seen by the committee node.
	LatestRound uint64 `json:"latest_round"`
	// LatestHeight is the consensus layer height containing the runtime block for the latest round.
	LatestHeight int64 `json:"latest_height"`

	// ExecutorRoles are the node's roles in the executor committee.
	ExecutorRoles []scheduler.Role `json:"executor_roles"`
	// IsTransactionScheduler indicates whether the node is a transaction scheduler in this round.
	IsTransactionScheduler bool `json:"is_txn_scheduler"`
	// Liveness is the node's liveness status for the current epoch.
	Liveness *LivenessStatus `json:"liveness,omitempty"`

	// Peers is the list of peers in the runtime P2P network.
	Peers []string `json:"peers"`

	// Host is the runtime host status.
	Host HostStatus `json:"host"`
}

// HostStatus is the runtime host status.
type HostStatus struct {
	// Versions are the locally supported versions.
	Versions []version.Version `json:"versions"`
}

// LivenessStatus is the liveness status for the current epoch.
type LivenessStatus struct {
	// TotalRounds is the total number of rounds in the last epoch, excluding any rounds generated
	// by the roothash service itself.
	TotalRounds uint64 `json:"total_rounds"`

	// LiveRounds is the number of rounds in which the node positively contributed.
	LiveRounds uint64 `json:"live_rounds"`
}
