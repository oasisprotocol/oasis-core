// Package flags implements common flags used across multiple commands
// and backends.
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

	cfgVerbose             = "verbose"
	cfgForce               = "force"
	cfgRetries             = "retries"
	cfgSigner              = "signer"
	cfgSignerFileDir       = "signer.file.dir"
	cfgSignerLedgerAddress = "signer.ledger.address"
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
	// SignerFlags has the signer-related flags.
	SignerFlags = flag.NewFlagSet("", flag.ContinueOnError)
	// GenesisFileFlags has the genesis file flag.
	GenesisFileFlags = flag.NewFlagSet("", flag.ContinueOnError)

	// ConsensusValidatorFlag has the consensus validator flag.
	ConsensusValidatorFlag = flag.NewFlagSet("", flag.ContinueOnError)
	// DebugDontBlameOasisFlag has the "don't blame oasis" flag.
	DebugDontBlameOasisFlag = flag.NewFlagSet("", flag.ContinueOnError)
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
	return DebugDontBlameOasis() && viper.GetBool(CfgDebugTestEntity)
}

// Signer returns the configured signer backend name.
func Signer() string {
	return viper.GetString(cfgSigner)
}

// SignerFileDir returns the directory with the signer keys (for file-based signer).
func SignerFileDir() string {
	return viper.GetString(cfgSignerFileDir)
}

// SignerLedgerAddress returns the address to search for (for Ledger-based signer).
func SignerLedgerAddress() string {
	return viper.GetString(cfgSignerLedgerAddress)
}

// GenesisFile returns the set genesis file.
func GenesisFile() string {
	return viper.GetString(CfgGenesisFile)
}

// DebugDontBlameOasis returns true iff the "don't blame oasis" flag is set.
func DebugDontBlameOasis() bool {
	return viper.GetBool(CfgDebugDontBlameOasis)
}

func init() {
	VerboseFlags.BoolP(cfgVerbose, "v", false, "verbose output")

	ForceFlags.Bool(cfgForce, false, "force")

	RetriesFlags.Int(cfgRetries, 0, "retries (-1 = forever)")

	ConsensusValidatorFlag.Bool(CfgConsensusValidator, false, "node is a consensus validator")

	DebugTestEntityFlags.Bool(CfgDebugTestEntity, false, "use the test entity (UNSAFE)")
	_ = DebugTestEntityFlags.MarkHidden(CfgDebugTestEntity)

	SignerFlags.StringP(cfgSigner, "s", "file", "Signer backend [file, ledger]")
	SignerFlags.String(cfgSignerFileDir, "", "File signer: path to directory containing private key")
	SignerFlags.String(cfgSignerLedgerAddress, "", "Ledger signer: select Ledger device based on this specified address. If blank, any available Ledger device will be connected to.")

	GenesisFileFlags.StringP(CfgGenesisFile, "g", "genesis.json", "path to genesis file")

	DebugDontBlameOasisFlag.Bool(CfgDebugDontBlameOasis, false, "Enable debug/unsafe/insecure options")
	_ = DebugDontBlameOasisFlag.MarkHidden(CfgDebugDontBlameOasis)

	for _, v := range []*flag.FlagSet{
		VerboseFlags,
		ForceFlags,
		RetriesFlags,
		DebugTestEntityFlags,
		SignerFlags,
		GenesisFileFlags,
		ConsensusValidatorFlag,
		DebugDontBlameOasisFlag,
	} {
		_ = viper.BindPFlags(v)
	}
}
