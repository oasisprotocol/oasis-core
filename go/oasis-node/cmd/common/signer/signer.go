// Package signer implements helpers for configuring the signer.
package signer

import (
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	ledgerSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/ledger"
	remoteSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/remote"
	"github.com/oasislabs/oasis-core/go/common/crypto/tls"
)

const (
	// CfgSigner is the flag used to specify the backend of the signer.
	CfgSigner = "signer"

	// CfgCLISignerDir is the flag used to specify the directory with the
	// entity files, for the purpose of some of the node sub-command's
	// wonky behavior.
	//
	// It also contains the private keys of a signer if using a file backend.
	CfgCLISignerDir = "signer.dir"

	cfgSignerLedgerAddress = "signer.ledger.address"
	cfgSignerLedgerIndex   = "signer.ledger.index"

	cfgSignerRemoteAddress    = "signer.remote.address"
	cfgSignerRemoteClientCert = "signer.remote.client.certificate"
	cfgSignerRemoteClientKey  = "signer.remote.client.key"
	cfgSignerRemoteServerCert = "signer.remote.server.certificate"
)

var (
	// Flags has the signer related flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	// CLIFlags has the oasis-node specific signer related flags.
	CLIFlags = flag.NewFlagSet("", flag.ContinueOnError)
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

// LedgerAddress returns the address to search for (for Ledger-based signer).
func LedgerAddress() string {
	return viper.GetString(cfgSignerLedgerAddress)
}

// LedgerIndex returns the address index to be used for address derivation.
func LedgerIndex() uint32 {
	return viper.GetUint32(cfgSignerLedgerIndex)
}

// NewFactory returns the appropriate SignerFactory based on flags.
func NewFactory(signerBackend string, signerDir string, roles ...signature.SignerRole) (signature.SignerFactory, error) {
	switch signerBackend {
	case ledgerSigner.SignerName:
		config := &ledgerSigner.FactoryConfig{
			Address: LedgerAddress(),
			Index:   LedgerIndex(),
		}
		return ledgerSigner.NewFactory(config, roles...)
	case fileSigner.SignerName:
		return fileSigner.NewFactory(signerDir, roles...)
	case remoteSigner.SignerName:
		config := &remoteSigner.FactoryConfig{
			Address: viper.GetString(cfgSignerRemoteAddress),
		}
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

		return remoteSigner.NewFactory(config, roles...)
	default:
		return nil, fmt.Errorf("unsupported signer backend: %s", signerBackend)
	}
}

func init() {
	Flags.StringP(CfgSigner, "s", "file", "signer backend [file, ledger, remote]")
	Flags.String(cfgSignerLedgerAddress, "", "Ledger signer: select Ledger device based on this specified address. If blank, any available Ledger device will be connected to.")
	Flags.Uint32(cfgSignerLedgerIndex, 0, "Ledger signer: address index used to derive address on Ledger device")
	Flags.String(cfgSignerRemoteAddress, "", "remote signer server address")
	Flags.String(cfgSignerRemoteClientCert, "", "remote signer client certificate path")
	Flags.String(cfgSignerRemoteClientKey, "", "remote signer client certificate key path")
	Flags.String(cfgSignerRemoteServerCert, "", "remote signer server certificate path")

	_ = viper.BindPFlags(Flags)

	CLIFlags.String(CfgCLISignerDir, "", "path to directory containing the entity files. If file signer backend is being used, the directory must also contain the private key. If blank, defaults to the working directory.")
	_ = viper.BindPFlags(CLIFlags)
}
