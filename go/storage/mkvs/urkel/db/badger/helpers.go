package badger

// Timestamp at which database metadata is stored. This needs to be 1 so that we can discard any
// invalid/removed cruft while still keeping everything else even if pruning is not enabled.
const tsMetadata = 1

// roundToTs convers a MKVS round to a badger timestamp.
func roundToTs(round uint64) uint64 {
	// Round 0 starts at timestamp after metadata.
	return tsMetadata + 1 + round
}
