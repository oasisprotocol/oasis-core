package api

// LivenessStatistics has the per-epoch liveness statistics for nodes.
type LivenessStatistics struct {
	// TotalRounds is the total number of rounds in the last epoch, excluding any rounds generated
	// by the roothash service itself.
	TotalRounds uint64 `json:"total_rounds"`

	// LiveRounds is a list of counters, specified in committee order (e.g. counter at index i has
	// the value for node i in the committee).
	LiveRounds []uint64 `json:"good_rounds"`

	// FinalizedProposals is a list that records the number of finalized rounds when a node
	// acted as a proposer.
	//
	// The list is ordered according to the committee arrangement (i.e., the counter at index i
	// holds the value for the node at index i in the committee).
	FinalizedProposals []uint64 `json:"finalized_proposals"`

	// MissedProposals is a list that records the number of failed rounds when a node
	// acted as a proposer.
	//
	// The list is ordered according to the committee arrangement (i.e., the counter at index i
	// holds the value for the node at index i in the committee).
	MissedProposals []uint64 `json:"missed_proposals"`
}

// NewLivenessStatistics creates a new instance of per-epoch liveness statistics.
func NewLivenessStatistics(numNodes int) *LivenessStatistics {
	return &LivenessStatistics{
		TotalRounds:        0,
		LiveRounds:         make([]uint64, numNodes),
		FinalizedProposals: make([]uint64, numNodes),
		MissedProposals:    make([]uint64, numNodes),
	}
}
