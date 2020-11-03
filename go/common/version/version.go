// Package version implements Oasis protocol and runtime versioning.
package version

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/tendermint/tendermint/version"
)

// NOTE: This should be kept in sync with runtime/src/common/version.rs.

// Version is a protocol or a runtime version.
type Version struct {
	Major uint16 `json:"major,omitempty"`
	Minor uint16 `json:"minor,omitempty"`
	Patch uint16 `json:"patch,omitempty"`
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
	// SoftwareVersion represents the Oasis Core's version and should be set
	// by the linker.
	SoftwareVersion = "0.0-unset"

	// GitBranch is the name of the git branch of Oasis Core.
	//
	// This is mostly used for reporting and metrics.
	GitBranch = ""

	// RuntimeHostProtocol versions the protocol between the Oasis node(s) and
	// the runtime.
	//
	// NOTE: This version must be synced with runtime/src/common/version.rs.
	RuntimeHostProtocol = Version{Major: 1, Minor: 0, Patch: 0}

	// RuntimeCommitteeProtocol versions the P2P protocol used by the runtime
	// committee members.
	RuntimeCommitteeProtocol = Version{Major: 1, Minor: 0, Patch: 0}

	// ConsensusProtocol versions all data structures and processing used by
	// the epochtime, beacon, registry, roothash, etc. modules that are
	// backend by consensus.
	//
	// NOTE: Any change in the major or minor versions are considered
	//       breaking changes for the protocol.
	ConsensusProtocol = Version{Major: 2, Minor: 0, Patch: 0}

	// Tendermint exposes the tendermint core version.
	Tendermint = parseSemVerStr(version.TMCoreSemVer)

	// ABCI is the version of the tendermint ABCI library.
	ABCI = parseSemVerStr(version.ABCIVersion)

	// Toolchain is the version of the Go compiler/standard library.
	Toolchain = parseSemVerStr(strings.TrimPrefix(runtime.Version(), "go"))
)

// Versions contains all known protocol versions.
var Versions = struct {
	RuntimeHostProtocol      Version
	RuntimeCommitteeProtocol Version
	ConsensusProtocol        Version
	Tendermint               Version
	ABCI                     Version
	Toolchain                Version
}{
	RuntimeHostProtocol,
	RuntimeCommitteeProtocol,
	ConsensusProtocol,
	Tendermint,
	ABCI,
	Toolchain,
}

func parseSemVerStr(s string) Version {
	split := strings.SplitN(s, ".", 4)

	var semVers []uint16 = []uint16{0, 0, 0}
	for i, v := range split {
		if i >= 3 {
			break
		}
		ver, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			panic("version: failed to parse SemVer: " + err.Error())
		}
		semVers[i] = uint16(ver)
	}

	return Version{Major: semVers[0], Minor: semVers[1], Patch: semVers[2]}
}
