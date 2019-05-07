package keymanager

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ias"
	"github.com/oasislabs/ekiden/go/worker/common/enclaverpc"
)

const (
	cfgEnabled = "keymanager.enabled"

	cfgTEEHardware   = "keymanager.tee_hardware"
	cfgRuntimeLoader = "keymanager.loader"
	cfgRuntimeBinary = "keymanager.runtime"
	cfgPort          = "keymanager.port"

	// XXX: Remove once we automatically discover the key manager for each runtime.
	cfgClientAddress = "keymanager.client.address"
	cfgClientCert    = "keymanager.client.certificate"
)

// New creates a new key manager service.
func New(
	dataDir string,
	ias *ias.IAS,
	identity *identity.Identity,
) (*KeyManager, error) {
	var teeHardware node.TEEHardware
	s := viper.GetString(cfgTEEHardware)
	switch strings.ToLower(s) {
	case "":
	case "invalid":
	case "intel-sgx":
		teeHardware = node.TEEHardwareIntelSGX
	default:
		return nil, fmt.Errorf("invalid TEE hardware: %s", s)
	}

	workerRuntimeLoaderBinary := viper.GetString(cfgRuntimeLoader)
	runtimeBinary := viper.GetString(cfgRuntimeBinary)
	port := uint16(viper.GetInt(cfgPort))

	// XXX: Remove once we automatically discover the key manager for each runtime.
	var client *enclaverpc.Client
	keyManagerAddress := viper.GetString(cfgClientAddress)
	if keyManagerAddress != "" {
		keyManagerCert := viper.GetString(cfgClientCert)

		var err error
		client, err = enclaverpc.NewClient(keyManagerAddress, keyManagerCert, "key-manager")
		if err != nil {
			return nil, err
		}
	}

	return newKeyManager(dataDir, viper.GetBool(cfgEnabled), teeHardware, workerRuntimeLoaderBinary,
		runtimeBinary, port, ias, identity, client)
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgEnabled, false, "Enable key manager process")

		cmd.Flags().String(cfgTEEHardware, "", "TEE hardware to use for the key manager")
		cmd.Flags().String(cfgRuntimeLoader, "", "Path to key manager worker process binary")
		cmd.Flags().String(cfgRuntimeBinary, "", "Path to key manager runtime binary")
		cmd.Flags().Uint16(cfgPort, 9003, "Port to use for incoming key manager gRPC connections")

		cmd.Flags().String(cfgClientAddress, "", "Key manager address")
		cmd.Flags().String(cfgClientCert, "", "Key manager TLS certificate")
	}

	for _, v := range []string{
		cfgEnabled,

		cfgTEEHardware,
		cfgRuntimeLoader,
		cfgRuntimeBinary,
		cfgPort,

		cfgClientAddress,
		cfgClientCert,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
