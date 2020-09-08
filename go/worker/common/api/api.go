package api

import (
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// Status is the common runtime worker status.
type Status struct {
	// LatestRound is the latest runtime round as seen by the committee node.
	LatestRound uint64 `json:"latest_round"`
	// LatestHeight is the consensus layer height containing the runtime block for the latest round.
	LatestHeight int64 `json:"latest_height"`

	// LastCommitteeUpdateHeight is the consensus layer height of the last committee update.
	LastCommitteeUpdateHeight int64 `json:"last_committee_update_height"`

	// ExecutorRole is the node's role in the executor committee.
	ExecutorRole scheduler.Role `json:"executor_role"`
	// StorageRole is the node's role in the storage committee.
	StorageRole scheduler.Role `json:"storage_role"`

	// IsTransactionScheduler indicates whether the node is a transaction scheduler in this round.
	IsTransactionScheduler bool `json:"is_txn_scheduler"`

	// Peers is the list of peers in the runtime P2P network.
	Peers []string `json:"peers"`
}
