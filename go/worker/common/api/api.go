package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/version"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// Status is the common runtime worker status.
type Status struct {
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
