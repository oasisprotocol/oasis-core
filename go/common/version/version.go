// Package version implements Oasis protocol and runtime versioning.
//
// For a more detailed explanation of Oasis Core's versioning, see:
// https://docs.oasis.dev/oasis-core/processes/versioning.
package version

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
)

// VersionUndefined represents an undefined version.
const VersionUndefined = "undefined"

var _ prettyprint.PrettyPrinter = (*ProtocolVersions)(nil)

// NOTE: This should be kept in sync with runtime/src/common/version.rs.

// Version is a protocol version.
type Version struct {
	Major uint16 `json:"major,omitempty"`
	Minor uint16 `json:"minor,omitempty"`
	Patch uint16 `json:"patch,omitempty"`
}

// ValidateBasic does basic validation of a protocol version.
func (v Version) ValidateBasic() error {
	empty := Version{}
	if v == empty {
		return fmt.Errorf("invalid version: %s", empty)
	}
	return nil
}

// ToU64 returns the version as platform-dependent uint64.
func (v Version) ToU64() uint64 {
	return (uint64(v.Major) << 32) | (uint64(v.Minor) << 16) | (uint64(v.Patch))
}

// FromU64 returns the version from platform-dependent uint64.
func FromU64(v uint64) Version {
	return Version{
		Major: uint16((v >> 32) & 0xffff),
		Minor: uint16((v >> 16) & 0xffff),
		Patch: uint16(v & 0xffff),
	}
}

// String returns the protocol version as a string.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// FromString parses version in semver format. e.g. "1.0.0"
// major.minor.patch components are considered where major is mandatory.
// Any component following patch is ignored.
func FromString(s string) (Version, error) {
	// Trim potential pre-release suffix.
	s = strings.Split(s, "-")[0]
	// Trim potential git commit.
	s = strings.Split(s, "+")[0]
	// Take at most four components: major.minor.patch.remainder.
	split := strings.SplitN(s, ".", 4)

	semVers := []uint16{0, 0, 0}
	for i, v := range split {
		if i >= 3 {
			// Ignore any components following major.minor.patch.
			break
		}
		ver, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return Version{}, fmt.Errorf("version: failed to parse SemVer '%s': %w", s, err)
		}
		semVers[i] = uint16(ver)
	}

	return Version{Major: semVers[0], Minor: semVers[1], Patch: semVers[2]}, nil
}

// MustFromString parses version in semver format and panics, if there is an error.
func MustFromString(s string) Version {
	ver, err := FromString(s)
	if err != nil {
		panic(err)
	}
	return ver
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

	// ConsensusProtocol versions all data structures and processing used by
	// the epochtime, beacon, registry, roothash, etc. modules that are
	// backend by consensus.
	//
	// NOTE: Consensus protocol version compatibility is currently not directly
	// checked in Oasis Core.
	// It is converted to TendermintAppVersion whose compatibility is checked
	// via Tendermint's version checks.
	ConsensusProtocol = Version{Major: 5, Minor: 0, Patch: 0}

	// RuntimeHostProtocol versions the protocol between the Oasis node(s) and
	// the runtime.
	//
	// NOTE: This version must be synced with runtime/src/common/version.rs.
	RuntimeHostProtocol = Version{Major: 4, Minor: 0, Patch: 0}

	// RuntimeCommitteeProtocol versions the P2P protocol used by the runtime
	// committee members.
	RuntimeCommitteeProtocol = Version{Major: 4, Minor: 0, Patch: 0}

	// TendermintAppVersion is Tendermint ABCI application's version computed by
	// masking non-major consensus protocol version segments to 0 to be
	// compatible with Tendermint's version checks.
	//
	// NOTE: Tendermint's version checks compare the whole version uint64
	// directly. For example:
	// https://github.com/tendermint/tendermint/blob/1635d1339c73ae6a82e062cd2dc7191b029efa14/state/validation.go#L21-L22.
	TendermintAppVersion = ConsensusProtocol.MaskNonMajor().ToU64()

	// Toolchain is the version of the Go compiler/standard library.
	Toolchain = MustFromString(strings.TrimPrefix(runtime.Version(), "go"))
)

// ProtocolVersions are the protocol versions.
type ProtocolVersions struct {
	ConsensusProtocol        Version `json:"consensus_protocol"`
	RuntimeHostProtocol      Version `json:"runtime_host_protocol"`
	RuntimeCommitteeProtocol Version `json:"runtime_committee_protocol"`
}

// ValidateBasic does basic validation checks of the protocol versions.
func (pv *ProtocolVersions) ValidateBasic() error {
	if err := pv.ConsensusProtocol.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid Consensus protocol version: %w", err)
	}
	if err := pv.RuntimeHostProtocol.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid Runtime Host protocol version: %w", err)
	}
	if err := pv.RuntimeCommitteeProtocol.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid Runtime Committee protocol version: %w", err)
	}
	return nil
}

// Compatible returns if the two protocol versions are compatible.
func (pv *ProtocolVersions) Compatible(other ProtocolVersions) bool {
	if pv.ConsensusProtocol.MaskNonMajor() != other.ConsensusProtocol.MaskNonMajor() {
		return false
	}
	if pv.RuntimeHostProtocol.MaskNonMajor() != other.RuntimeHostProtocol.MaskNonMajor() {
		return false
	}
	if pv.RuntimeCommitteeProtocol.MaskNonMajor() != other.RuntimeCommitteeProtocol.MaskNonMajor() {
		return false
	}
	return true
}

// String returns the protocol versions as a string.
func (pv ProtocolVersions) String() string {
	return fmt.Sprintf(
		"Consensus protocol: %s, Runtime Host protocol: %s, Runtime Committee protocol: %s",
		pv.ConsensusProtocol, pv.RuntimeHostProtocol, pv.RuntimeCommitteeProtocol,
	)
}

// PrettyPrint writes a pretty-printed representation of ProtocolVersions to the
// given writer.
func (pv ProtocolVersions) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sConsensus Protocol: %s\n", prefix, pv.ConsensusProtocol)
	fmt.Fprintf(w, "%sRuntime Host Protocol: %s\n", prefix, pv.RuntimeHostProtocol)
	fmt.Fprintf(w, "%sRuntime Committee Protocol: %s\n", prefix, pv.RuntimeCommitteeProtocol)
}

// PrettyType returns a representation of ProtocolVersions that can be used for
// pretty printing.
func (pv ProtocolVersions) PrettyType() (interface{}, error) {
	return pv, nil
}

// Versions are current protocol versions.
var Versions = ProtocolVersions{
	ConsensusProtocol,
	RuntimeHostProtocol,
	RuntimeCommitteeProtocol,
}

var goModulesVersionRegex = regexp.MustCompile(`v0.(?P<year>[0-9]{2})(?P<minor>[0-9]{2}).(?P<micro>[0-9]+)`)

// Convert Go Modules compatible version to Oasis Core's canonical version.
func ConvertGoModulesVersion(goModVersion string) string {
	match := goModulesVersionRegex.FindStringSubmatch(goModVersion)
	// NOTE: match[0] contains the whole matched string.
	if len(match) != 4 {
		return VersionUndefined
	}

	result := make(map[string]string)
	for i, name := range goModulesVersionRegex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}

	version := result["year"] + "." + strings.TrimPrefix(result["minor"], "0")
	if result["micro"] != "0" {
		version += "." + result["micro"]
	}
	return version
}
