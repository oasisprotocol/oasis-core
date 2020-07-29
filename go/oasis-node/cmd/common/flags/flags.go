// Package flags implements common flags used across multiple commands and
// backends.
package flags

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// CfgDebugDontBlameOasis is the flag used to opt-in to unsafe/debug/test
	// behavior.
	CfgDebugDontBlameOasis = "debug.dont_blame_oasis"
	// CfgDebugTestEntity is the command line flag to enable the debug test
	// entity.
	CfgDebugTestEntity = "debug.test_entity"
	// CfgGenesisFile is the flag used to specify a genesis file.
	CfgGenesisFile = "genesis.file"
	// CfgConsensusValidator is the flag used to opt-in to being a validator.
	CfgConsensusValidator = "consensus.validator"

	cfgVerbose = "verbose"
	cfgForce   = "force"

	// CfgDryRun is the flag used to specify a dry-run of an operation.
	CfgDryRun = "dry_run"

	// CfgAssumeYes is the flag used to denote to answer all user prompts with
	// yes.
	CfgAssumeYes      = "assume_yes"
	cfgAssumeYesShort = "y"
)

var (
	// VerboseFlags has the verbose flag.
	VerboseFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// ForceFlags has the force flag.
	ForceFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// DebugTestEntityFlags has the test entity enable flag.
	DebugTestEntityFlags = flag.NewFlagSet("", flag.ContinueOnError)

	// GenesisFileFlags has the genesis file flag.
	GenesisFileFlags = flag.NewFlagSet("", flag.ContinueOnError)

	// ConsensusValidatorFlag has the consensus validator flag.
	ConsensusValidatorFlag = flag.NewFlagSet("", flag.ContinueOnError)
	// DebugDontBlameOasisFlag has the "don't blame oasis" flag.
	DebugDontBlameOasisFlag = flag.NewFlagSet("", flag.ContinueOnError)

	// DryRunFlag has the dry-run flag.
	DryRunFlag = flag.NewFlagSet("", flag.ContinueOnError)

	// AssumeYesFlag has the assume yes flag.
	AssumeYesFlag = flag.NewFlagSet("", flag.ContinueOnError)
)

// Verbose returns true iff the verbose flag is set.
func Verbose() bool {
	return viper.GetBool(cfgVerbose)
}

// Force returns true iff the force flag is set.
func Force() bool {
	return viper.GetBool(cfgForce)
}

// ConsensusValidator returns true iff the node is opting in to be a consensus
// validator.
func ConsensusValidator() bool {
	return viper.GetBool(CfgConsensusValidator)
}

// DebugTestEntity returns true iff the test entity enable flag is set.
func DebugTestEntity() bool {
	return DebugDontBlameOasis() && viper.GetBool(CfgDebugTestEntity)
}

// GenesisFile returns the set genesis file.
func GenesisFile() string {
	return viper.GetString(CfgGenesisFile)
}

// DebugDontBlameOasis returns true iff the "don't blame oasis" flag is set.
func DebugDontBlameOasis() bool {
	return viper.GetBool(CfgDebugDontBlameOasis)
}

// DryRun returns true iff the dry-run flag is set.
func DryRun() bool {
	return viper.GetBool(CfgDryRun)
}

// AssumeYes returns true iff the assume yes flag is set.
func AssumeYes() bool {
	return viper.GetBool(CfgAssumeYes)
}

func init() {
	VerboseFlags.BoolP(cfgVerbose, "v", false, "verbose output")

	ForceFlags.Bool(cfgForce, false, "force")

	ConsensusValidatorFlag.Bool(CfgConsensusValidator, false, "node is a consensus validator")

	DebugTestEntityFlags.Bool(CfgDebugTestEntity, false, "use the test entity (UNSAFE)")
	_ = DebugTestEntityFlags.MarkHidden(CfgDebugTestEntity)

	GenesisFileFlags.StringP(CfgGenesisFile, "g", "genesis.json", "path to genesis file")

	DebugDontBlameOasisFlag.Bool(CfgDebugDontBlameOasis, false, "Enable debug/unsafe/insecure options")
	_ = DebugDontBlameOasisFlag.MarkHidden(CfgDebugDontBlameOasis)

	DryRunFlag.BoolP(CfgDryRun, "n", false, "don't actually do anything, just show what will be done")

	AssumeYesFlag.BoolP(CfgAssumeYes, cfgAssumeYesShort, false, "automatically assume yes for all questions")

	for _, v := range []*flag.FlagSet{
		VerboseFlags,
		ForceFlags,
		DebugTestEntityFlags,
		GenesisFileFlags,
		ConsensusValidatorFlag,
		DebugDontBlameOasisFlag,
		DryRunFlag,
		AssumeYesFlag,
	} {
		_ = viper.BindPFlags(v)
	}
}
