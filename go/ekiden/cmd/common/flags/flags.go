// Package flags implements common flags used across multiple commands
// and backends.
package flags

import (
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
)

const (
	cfgVerbose = "verbose"
	cfgForce   = "force"
	cfgRetries = "retries"
	cfgEntity  = "entity"

	cfgConsensusBackend = "consensus.backend"

	cfgDebugTestEntity = "debug.test_entity"

	// CfgGenesisFile is the flag used to specify a genesis file.
	CfgGenesisFile = "genesis.file"
)

var (
	// VerboseFlags has the verbose flag.
	VerboseFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// ForceFlags has the force flag.
	ForceFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// RetriesFlags has the retries flag.
	RetriesFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// ConsensusBackendFlags has the consensus backend flag.
	ConsensusBackendFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// DebugTestEntityFlags has the test entity enable flag.
	DebugTestEntityFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// EntityFlags has the entity flag.
	EntityFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// GenesisFileFlags has the genesis file flag.
	GenesisFileFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Verbose returns true iff the verbose flag is set.
func Verbose() bool {
	return viper.GetBool(cfgVerbose)
}

// Force returns true iff the force flag is set.
func Force() bool {
	return viper.GetBool(cfgForce)
}

// Retries returns the retries flag value.
func Retries() int {
	return viper.GetInt(cfgRetries)
}

// ConsensusBackend returns the set consensus backend.
func ConsensusBackend() string {
	backend := viper.GetString(cfgConsensusBackend)

	switch strings.ToLower(backend) {
	case tmapi.BackendName:
		return tmapi.BackendName
	default:
		panic(fmt.Sprintf("consensus: unsupported backend: '%v'", backend))
	}
}

// DebugTestEntity returns true iff the test entity enable flag is set.
func DebugTestEntity() bool {
	return viper.GetBool(cfgDebugTestEntity)
}

// Entity returns the set entity directory.
func Entity() string {
	return viper.GetString(cfgEntity)
}

// GenesisFile returns the set genesis file.
func GenesisFile() string {
	return viper.GetString(CfgGenesisFile)
}

func init() {
	VerboseFlags.BoolP(cfgVerbose, "v", false, "verbose output")

	ForceFlags.Bool(cfgForce, false, "force")

	RetriesFlags.Int(cfgRetries, 0, "retries (-1 = forever)")

	ConsensusBackendFlags.String(cfgConsensusBackend, tmapi.BackendName, "force")

	DebugTestEntityFlags.Bool(cfgDebugTestEntity, false, "use the test entity (UNSAFE)")

	EntityFlags.String(cfgEntity, "", "Path to directory containing entity private key and descriptor")

	GenesisFileFlags.String(CfgGenesisFile, "genesis.json", "path to genesis file")

	for _, v := range []*flag.FlagSet{
		VerboseFlags,
		ForceFlags,
		RetriesFlags,
		ConsensusBackendFlags,
		DebugTestEntityFlags,
		EntityFlags,
		GenesisFileFlags,
	} {
		_ = viper.BindPFlags(v)
	}
}
