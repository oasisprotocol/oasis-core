package api

// LivenessStatistics has the per-epoch liveness statistics for nodes.
type LivenessStatistics struct {
	// TotalRounds is the total number of rounds in the last epoch, excluding any rounds generated
	// by the roothash service itself.
	TotalRounds uint64 `json:"total_rounds"`

	// LiveRounds is a list of counters, specified in committee order (e.g. counter at index i has
	// the value for node i in the committee).
	LiveRounds []uint64 `json:"good_rounds"`
}

// NewLivenessStatistics creates a new instance of per-epoch liveness statistics.
func NewLivenessStatistics(numNodes int) *LivenessStatistics {
	return &LivenessStatistics{
		TotalRounds: 0,
		LiveRounds:  make([]uint64, numNodes),
	}
}
