// Package flags implements common flags used across multiple commands
// and backends.
package flags

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
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
)

// Verbose returns true iff the verbose flag is set.
func Verbose() bool {
	return viper.GetBool(cfgVerbose)
}

// RegisterVerbose registers the verbose flag for the provided command.
func RegisterVerbose(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().BoolP(cfgVerbose, "v", false, "verbose output")
	}

	_ = viper.BindPFlag(cfgVerbose, cmd.Flags().Lookup(cfgVerbose))
}

// Force returns true iff the force flag is set.
func Force() bool {
	return viper.GetBool(cfgForce)
}

// RegisterForce registers the force flag for the provided command.
func RegisterForce(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgForce, false, "force")
	}

	_ = viper.BindPFlag(cfgForce, cmd.Flags().Lookup(cfgForce))
}

// Retries returns the retries flag value.
func Retries() int {
	return viper.GetInt(cfgRetries)
}

// RegisterRetries registers the retries flag for the provided command.
func RegisterRetries(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Int(cfgRetries, 0, "retries (-1 = forever)")
	}

	_ = viper.BindPFlag(cfgRetries, cmd.Flags().Lookup(cfgRetries))
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
		cmd.Flags().String(cfgConsensusBackend, tmapi.BackendName, "force")
	}

	_ = viper.BindPFlag(cfgConsensusBackend, cmd.Flags().Lookup(cfgConsensusBackend))
}

// DebugTestEntity returns true iff the test entity enable flag is set.
func DebugTestEntity() bool {
	return viper.GetBool(cfgDebugTestEntity)
}

// RegisterDebugTestEntity registers the test entity enable flag.
func RegisterDebugTestEntity(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgDebugTestEntity, false, "use the test entity (UNSAFE)")
	}

	_ = viper.BindPFlag(cfgDebugTestEntity, cmd.Flags().Lookup(cfgDebugTestEntity))
}

// Entity returns the set entity directory.
func Entity() string {
	return viper.GetString(cfgEntity)
}

// RegisterEntity registers the entity flag.
func RegisterEntity(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgEntity, "", "Path to directory containing entity private key and descriptor")
	}

	_ = viper.BindPFlag(cfgEntity, cmd.Flags().Lookup(cfgEntity))

}
