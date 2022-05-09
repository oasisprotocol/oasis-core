// Package signer implements helpers for configuring the signer.
package signer

import (
	"errors"
	"fmt"
	"os"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	compositeSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/composite"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	pluginSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/plugin"
	remoteSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/remote"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
)

const (
	// CfgSigner is the flag used to specify the backend of the signer.
	CfgSigner = "signer.backend"

	// CfgCLISignerDir is the flag used to specify the directory with the
	// entity files, for the purpose of some of the node sub-command's
	// wonky behavior.
	//
	// It also contains the private keys of a signer if using a file backend.
	CfgCLISignerDir = "signer.dir"

	cfgSignerRemoteAddress    = "signer.remote.address"
	cfgSignerRemoteClientCert = "signer.remote.client.certificate"
	cfgSignerRemoteClientKey  = "signer.remote.client.key"
	cfgSignerRemoteServerCert = "signer.remote.server.certificate"

	cfgSignerCompositeBackends = "signer.composite.backends"

	cfgSignerPluginName   = "signer.plugin.name"
	cfgSignerPluginPath   = "signer.plugin.path"
	cfgSignerPluginConfig = "signer.plugin.config"
)

var (
	// Flags has the signer related flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	// CLIFlags has the oasis-node specific signer related flags.
	CLIFlags = flag.NewFlagSet("", flag.ContinueOnError)

	testingAllowMemory bool
)

// Backend returns the configured signer backend name.
func Backend() string {
	return viper.GetString(CfgSigner)
}

// CLIDirOrPwd returns the directory with the entity files, (and the signer
// keys for file-based signer).
//
// XXX: Why this doesn't use the perfectly good datadir is beyond me.
func CLIDirOrPwd() (string, error) {
	signerDir := viper.GetString(CfgCLISignerDir)
	if signerDir == "" {
		var err error
		if signerDir, err = os.Getwd(); err != nil {
			return "", err
		}
	}
	return signerDir, nil
}

// NewFactory returns the appropriate SignerFactory based on flags.
func NewFactory(signerBackend, signerDir string, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	signerBackend = strings.ToLower(signerBackend)
	if signerBackend != compositeSigner.SignerName {
		return doNewFactory(signerBackend, signerDir, roles...)
	}

	// The composite signer needs to instantiate multiple signer factories
	// and aggregate them together.

	return doNewComposite(signerDir, roles...)
}

func doNewFactory(signerBackend, signerDir string, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	switch signerBackend {
	case fileSigner.SignerName:
		return fileSigner.NewFactory(signerDir, roles...)
	case memorySigner.SignerName:
		if !testingAllowMemory {
			return nil, fmt.Errorf("memory signer backend is only for testing")
		}
		return memorySigner.NewFactory(), nil
	case remoteSigner.SignerName:
		config := &remoteSigner.FactoryConfig{
			Address: viper.GetString(cfgSignerRemoteAddress),
		}

		if !config.IsLocal() {
			clientCert, err := tls.Load(
				viper.GetString(cfgSignerRemoteClientCert),
				viper.GetString(cfgSignerRemoteClientKey),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to load client certificate: %w", err)
			}
			config.ClientCertificate = clientCert

			serverCert, err := tls.LoadCertificate(viper.GetString(cfgSignerRemoteServerCert))
			if err != nil {
				return nil, fmt.Errorf("failed to load server certificate: %w", err)
			}
			config.ServerCertificate = serverCert
		}

		return remoteSigner.NewFactory(config, roles...)
	case pluginSigner.SignerName:
		config := &pluginSigner.FactoryConfig{
			Name:   viper.GetString(cfgSignerPluginName),
			Path:   viper.GetString(cfgSignerPluginPath),
			Config: viper.GetString(cfgSignerPluginConfig),
		}
		return pluginSigner.NewFactory(config, roles...)
	default:
		return nil, fmt.Errorf("unsupported signer backend: %s", signerBackend)
	}
}

func doNewComposite(signerDir string, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	signerRolesMap := make(map[string][]signature.SignerRole)

	s := viper.GetString(cfgSignerCompositeBackends)
	sp := strings.Split(s, ",")
	for _, v := range sp {
		roleSigner := strings.Split(v, ":")
		if len(roleSigner) != 2 {
			return nil, fmt.Errorf("malformed composite role assignment")
		}

		var role signature.SignerRole
		if err := role.UnmarshalText([]byte(roleSigner[0])); err != nil {
			if errors.Is(err, signature.ErrInvalidRole) {
				var validRoles []string
				for _, role := range signature.SignerRoles {
					validRoles = append(validRoles, role.String())
				}
				return nil, fmt.Errorf("%w (valid roles are: %s)", err, strings.Join(validRoles, ", "))
			}
			return nil, err
		}

		signerStr := strings.ToLower(roleSigner[1])
		signerRolesMap[signerStr] = append(signerRolesMap[signerStr], role)
	}

	signerMap := make(map[string]signature.SignerFactory)
	for k, v := range signerRolesMap {
		signer, err := doNewFactory(k, signerDir, v...)
		if err != nil {
			return nil, err
		}
		signerMap[k] = signer
	}

	cfg := make(compositeSigner.FactoryConfig)
	for k, v := range signerRolesMap {
		for _, role := range v {
			if cfg[role] != nil {
				return nil, fmt.Errorf("multiple backends configured for role: %v", role)
			}
			cfg[role] = signerMap[k]
		}
	}

	return compositeSigner.NewFactory(cfg, roles...)
}

func init() {
	Flags.StringP(CfgSigner, "s", "file", "signer backend [file, plugin, remote, composite]")
	Flags.String(cfgSignerRemoteAddress, "", "remote signer server address")
	Flags.String(cfgSignerRemoteClientCert, "", "remote signer client certificate path")
	Flags.String(cfgSignerRemoteClientKey, "", "remote signer client certificate key path")
	Flags.String(cfgSignerRemoteServerCert, "", "remote signer server certificate path")
	Flags.String(cfgSignerCompositeBackends, "", "composite signer backends")
	Flags.String(cfgSignerPluginName, "", "plugin signer backend name")
	Flags.String(cfgSignerPluginPath, "", "plugin signer binary path")
	Flags.String(cfgSignerPluginConfig, "", "plugin signer configuration")

	_ = viper.BindPFlags(Flags)

	CLIFlags.String(CfgCLISignerDir, "", "path to directory containing the entity files. If file signer backend is being used, the directory must also contain the private key. If blank, defaults to the working directory.")
	_ = viper.BindPFlags(CLIFlags)
}
