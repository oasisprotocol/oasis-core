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
)

const (
	// CfgSigner is the flag used to specify the backend of the signer.
	CfgSigner = "signer"
	// CfgSignerDir is the flag used to specify the directory with the entity files.
	// It also contains the private keys of a signer if using a file backend.
	CfgSignerDir           = "signer.dir"
	cfgSignerLedgerAddress = "signer.ledger.address"
	cfgSignerLedgerIndex   = "signer.ledger.index"
)

// SignerFlags has the signer-related flags.
var SignerFlags = flag.NewFlagSet("", flag.ContinueOnError)

// Backend returns the configured signer backend name.
func Backend() string {
	return viper.GetString(CfgSigner)
}

// DirOrPwd returns the directory with the entity files, (and the signer keys for file-based signer).
func DirOrPwd() (string, error) {
	signerDir := viper.GetString(CfgSignerDir)
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
func NewFactory(signerBackend string, signerDir string) (signature.SignerFactory, error) {
	switch signerBackend {
	case ledgerSigner.SignerName:
		config := ledgerSigner.FactoryConfig{
			Address: LedgerAddress(),
			Index:   LedgerIndex(),
		}
		return ledgerSigner.NewFactory(&config, signature.SignerEntity), nil
	case fileSigner.SignerName:
		return fileSigner.NewFactory(signerDir, signature.SignerEntity), nil
	default:
		return nil, fmt.Errorf("unsupported signer backend: %s", signerBackend)
	}
}

func init() {
	SignerFlags.StringP(CfgSigner, "s", "file", "signer backend [file, ledger]")
	SignerFlags.String(CfgSignerDir, "", "path to directory containing the entity files. If file signer backend is being used, the directory must also contain the private key. If blank, defaults to the working directory.")
	SignerFlags.String(cfgSignerLedgerAddress, "", "Ledger signer: select Ledger device based on this specified address. If blank, any available Ledger device will be connected to.")
	SignerFlags.Uint32(cfgSignerLedgerIndex, 0, "Ledger signer: address index used to derive address on Ledger device")

	_ = viper.BindPFlags(SignerFlags)
}
