package pathbadger

// Timestamp at which database metadata is stored. This needs to be 1 so that we can discard any
// invalid/removed cruft while still keeping everything else even if pruning is not enabled.
const tsMetadata = 1

// versionToTs converts a MKVS version to a Badger timestamp.
func versionToTs(version uint64) uint64 {
	// Version 0 starts at timestamp after metadata.
	return tsMetadata + 1 + version
}
