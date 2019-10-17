// Package version implements Oasis protocol and runtime versioning.
package version

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tendermint/tendermint/version"
)

// NOTE: This should be kept in sync with runtime/src/common/version.rs.

// Version is a protocol or a runtime version.
type Version struct {
	Major uint16
	Minor uint16
	Patch uint16
}

// ToU64 returns the version as platform-dependent uint64.
func (v Version) ToU64() uint64 {
	return (uint64(v.Major) << 32) | (uint64(v.Minor) << 16) | (uint64(v.Patch))
}

// FromU64 returns the version from platform-dependent uint64.
func FromU64(v uint64) Version {
	return Version{
		Major: uint16((v >> 32) & 0xff),
		Minor: uint16((v >> 16) & 0xff),
		Patch: uint16(v & 0xff),
	}
}

// String returns the protocol version as a string.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// MajorMinor extracts major and minor segments of the Version only.
//
// This is useful for comparing protocol version since the patch segment can be
// ignored.
func (v Version) MajorMinor() Version {
	return Version{
		Major: v.Major,
		Minor: v.Minor,
		Patch: 0,
	}
}

var (
	// RuntimeProtocol versions the protocol between the Oasis node(s) and
	// the runtime.
	//
	// NOTE: This version must be synced with runtime/src/common/version.rs.
	RuntimeProtocol = Version{Major: 0, Minor: 7, Patch: 0}

	// CommitteeProtocol versions the P2P protocol used by the
	// committee members.
	CommitteeProtocol = Version{Major: 0, Minor: 5, Patch: 0}

	// BackendProtocol versions all data structures and processing used by
	// the epochtime, beacon, registry, roothash, etc.
	//
	// NOTE: Any change in the major or minor versions are considered
	//       breaking changes for the protocol.
	BackendProtocol = Version{Major: 0, Minor: 8, Patch: 0}

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
