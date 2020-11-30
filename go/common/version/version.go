// Package version implements Oasis protocol and runtime versioning.
//
// For a more detailed explanation of Oasis Core's versioning, see:
// https://docs.oasis.dev/oasis-core/processes/versioning.
package version

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// NOTE: This should be kept in sync with runtime/src/common/version.rs.

// Version is a protocol version.
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

// MaskNonMajor masks all non-major version segments to 0 and returns a new
// protocol version.
//
// This is useful for comparing protocol versions for backward-incompatible
// changes.
func (v Version) MaskNonMajor() Version {
	return Version{
		Major: v.Major,
		Minor: 0,
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
	RuntimeCommitteeProtocol = Version{Major: 2, Minor: 0, Patch: 0}

	// ConsensusProtocol versions all data structures and processing used by
	// the epochtime, beacon, registry, roothash, etc. modules that are
	// backend by consensus.
	//
	// NOTE: Consensus protocol version compatibility is currently not directly
	// checked in Oasis Core.
	// It is converted to TendermintAppVersion whose compatibility is checked
	// via Tendermint's version checks.
	ConsensusProtocol = Version{Major: 3, Minor: 0, Patch: 0}

	// TendermintAppVersion is Tendermint ABCI application's version computed by
	// masking non-major consensus protocol version segments to 0 to be
	// compatible with Tendermint's version checks.
	//
	// NOTE: Tendermint's version checks compare the whole version uint64
	// directly. For example:
	// https://github.com/tendermint/tendermint/blob/1635d1339c73ae6a82e062cd2dc7191b029efa14/state/validation.go#L21-L22.
	TendermintAppVersion = ConsensusProtocol.MaskNonMajor().ToU64()

	// Toolchain is the version of the Go compiler/standard library.
	Toolchain = parseSemVerStr(strings.TrimPrefix(runtime.Version(), "go"))
)

// Versions contains all known protocol versions.
var Versions = struct {
	RuntimeHostProtocol      Version
	RuntimeCommitteeProtocol Version
	ConsensusProtocol        Version
	Toolchain                Version
}{
	RuntimeHostProtocol,
	RuntimeCommitteeProtocol,
	ConsensusProtocol,
	Toolchain,
}

func parseSemVerStr(s string) Version {
	// Trim potential pre-release suffix.
	s = strings.Split(s, "-")[0]
	split := strings.SplitN(s, ".", 4)

	var semVers []uint16 = []uint16{0, 0, 0}
	for i, v := range split {
		if i >= 3 {
			break
		}
		ver, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			panic(fmt.Errorf("version: failed to parse SemVer '%s': %w", s, err))
		}
		semVers[i] = uint16(ver)
	}

	return Version{Major: semVers[0], Minor: semVers[1], Patch: semVers[2]}
}
