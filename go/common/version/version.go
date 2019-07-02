// Package version implements Ekiden protocol versioning.
package version

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tendermint/tendermint/version"
)

// NOTE: This should be kept in sync with runtime/src/common/version.rs.

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
	// RuntimeProtocol versions the protocol between the Ekiden node(s) and
	// the runtime.
	//
	// NOTE: This version must be synced with runtime/src/common/version.rs.
	RuntimeProtocol = Version{Major: 0, Minor: 3, Patch: 0}

	// CommitteeProtocol versions the P2P protocol used by the
	// committee members.
	CommitteeProtocol = Version{Major: 0, Minor: 2, Patch: 0}

	// BackendProtocol versions all data structures and processing used by
	// the epochtime, beacon, registry, roothash, etc.
	//
	// NOTE: Any change in the major or minor versions are considered
	//       breaking changes for the protocol.
	BackendProtocol = Version{Major: 0, Minor: 3, Patch: 0}

	// Tendermint exposes the tendermint core version.
	Tendermint = parseSemVerStr(version.TMCoreSemVer)

	// ABCI is the version of the tendermint ABCI library.
	ABCI = parseSemVerStr(version.ABCIVersion)
)

// Versions contains all known protocol versions.
var Versions = struct {
	RuntimeProtocol   Version
	CommitteeProtocol Version
	BackendProtocol   Version
	Tendermint        Version
	ABCI              Version
}{
	RuntimeProtocol,
	CommitteeProtocol,
	BackendProtocol,
	Tendermint,
	ABCI,
}

func parseSemVerStr(s string) Version {
	split := strings.Split(s, ".")
	if len(split) != 3 {
		panic("version: failed to split SemVer")
	}

	var semVers []uint16
	for _, v := range split {
		i, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			panic("version: failed to parse SemVer: " + err.Error())
		}
		semVers = append(semVers, uint16(i))
	}

	return Version{Major: semVers[0], Minor: semVers[1], Patch: semVers[2]}
}
