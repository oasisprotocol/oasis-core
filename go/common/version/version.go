// Package version implements Ekiden protocol versioning.
package version

import "fmt"

// Version is a protocol version.
type Version struct {
	Major uint16
	Minor uint16
	Patch uint16
}

// ToU64 returns the protocol version as an uint64.
//
// NOTE: This ignores the patch version so that patches do not
//       consititute breaking versions.
func (v Version) ToU64() uint64 {
	return (uint64(v.Major) << 32) | (uint64(v.Minor) << 16)
}

// String returns the protocol version as a string.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

var (
	// ComputeCommitteeProtocol versions the P2P protocol used by the
	// compute committee members.
	ComputeCommitteeProtocol = Version{Major: 0, Minor: 0, Patch: 1}

	// BackendProtocol versions all data structures and processing used by
	// the epochtime, beacon, registry, roothash, etc.
	//
	// NOTE: Any change in the major or minor versions are considered
	//       breaking changes for the protocol.
	BackendProtocol = Version{Major: 0, Minor: 0, Patch: 1}
)

// Versions contains all known protocol versions.
var Versions = struct {
	ComputeCommitteeProtocol Version
	BackendProtocol          Version
}{
	ComputeCommitteeProtocol,
	BackendProtocol,
}
