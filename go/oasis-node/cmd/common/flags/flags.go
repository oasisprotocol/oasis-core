// Package flags implements common flags used across multiple commands
// and backends.
package flags

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// CfgDebugTestEntity is the command line flag to enable the debug test
	// entity.
	CfgDebugTestEntity = "debug.test_entity"
	// CfgGenesisFile is the flag used to specify a genesis file.
	CfgGenesisFile = "genesis.file"
	// CfgConsensusValidator is the flag used to opt-in to being a validator.
	CfgConsensusValidator = "consensus.validator"

	cfgVerbose = "verbose"
	cfgForce   = "force"
	cfgRetries = "retries"
	cfgEntity  = "entity"
)

var (
	// VerboseFlags has the verbose flag.
	VerboseFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// ForceFlags has the force flag.
	ForceFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// RetriesFlags has the retries flag.
	RetriesFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// DebugTestEntityFlags has the test entity enable flag.
	DebugTestEntityFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// EntityFlags has the entity flag.
	EntityFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// GenesisFileFlags has the genesis file flag.
	GenesisFileFlags = flag.NewFlagSet("", flag.ContinueOnError)

	// ConsensusValidatorFlag has the consensus validator flag.
	ConsensusValidatorFlag = flag.NewFlagSet("", flag.ContinueOnError)
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

// ConsensusValidator returns true iff the node is opting in to be a consensus
// validator.
func ConsensusValidator() bool {
	return viper.GetBool(CfgConsensusValidator)
}

// DebugTestEntity returns true iff the test entity enable flag is set.
func DebugTestEntity() bool {
	return viper.GetBool(CfgDebugTestEntity)
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

	ConsensusValidatorFlag.Bool(CfgConsensusValidator, false, "node is a consensus validator")

	DebugTestEntityFlags.Bool(CfgDebugTestEntity, false, "use the test entity (UNSAFE)")

	EntityFlags.String(cfgEntity, "", "Path to directory containing entity private key and descriptor")

	GenesisFileFlags.String(CfgGenesisFile, "genesis.json", "path to genesis file")

	for _, v := range []*flag.FlagSet{
		VerboseFlags,
		ForceFlags,
		RetriesFlags,
		DebugTestEntityFlags,
		EntityFlags,
		GenesisFileFlags,
		ConsensusValidatorFlag,
	} {
		_ = viper.BindPFlags(v)
	}
}
