// Package flags implements common flags used across multiple commands
// and backends.
package flags

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
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
	VerboseFlags          = flag.NewFlagSet("", flag.ContinueOnError)
	ForceFlags            = flag.NewFlagSet("", flag.ContinueOnError)
	RetriesFlags          = flag.NewFlagSet("", flag.ContinueOnError)
	ConsensusBackendFlags = flag.NewFlagSet("", flag.ContinueOnError)
	DebugTestEntityFlags  = flag.NewFlagSet("", flag.ContinueOnError)
	EntityFlags           = flag.NewFlagSet("", flag.ContinueOnError)
	GenesisFileFlags      = flag.NewFlagSet("", flag.ContinueOnError)
)

// Verbose returns true iff the verbose flag is set.
func Verbose() bool {
	return viper.GetBool(cfgVerbose)
}

// RegisterVerbose registers the verbose flag for the provided command.
func RegisterVerbose(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(VerboseFlags)
	}
}

// Force returns true iff the force flag is set.
func Force() bool {
	return viper.GetBool(cfgForce)
}

// RegisterForce registers the force flag for the provided command.
func RegisterForce(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(ForceFlags)
	}
}

// Retries returns the retries flag value.
func Retries() int {
	return viper.GetInt(cfgRetries)
}

// RegisterRetries registers the retries flag for the provided command.
func RegisterRetries(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(RetriesFlags)
	}
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

// RegisterConsensusBackend registers the consensus backend flag for the provided command.
func RegisterConsensusBackend(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(ConsensusBackendFlags)
	}
}

// DebugTestEntity returns true iff the test entity enable flag is set.
func DebugTestEntity() bool {
	return viper.GetBool(cfgDebugTestEntity)
}

// RegisterDebugTestEntity registers the test entity enable flag.
func RegisterDebugTestEntity(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(DebugTestEntityFlags)
	}
}

// Entity returns the set entity directory.
func Entity() string {
	return viper.GetString(cfgEntity)
}

// RegisterEntity registers the entity flag.
func RegisterEntity(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(EntityFlags)
	}

}

// GenesisFile returns the set genesis file.
func GenesisFile() string {
	return viper.GetString(CfgGenesisFile)
}

// RegisterGenesisFile registers the genesis file flag.
func RegisterGenesisFile(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(GenesisFileFlags)
	}
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
