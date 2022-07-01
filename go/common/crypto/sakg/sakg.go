// Package sakg implements ADR 0008: Standard Account Key Generation.
package sakg

import (
	"fmt"

	bip39 "github.com/tyler-smith/go-bip39"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/slip10"
)

// MaxAccountKeyNumber is the maximum allowed key number when using ADR 0008.
const MaxAccountKeyNumber = uint32(0x7fffffff)

// BIP32PathPrefix is the Oasis Network's BIP-0032 path prefix as defined by
// ADR 0008.
const BIP32PathPrefix = "m/44'/474'"

// GetAccountSigner generates a signer for the given mnemonic, passphrase and
// account according to ADR 0008.
func GetAccountSigner(
	mnemonic string,
	passphrase string,
	number uint32,
) (signature.Signer, BIP32Path, error) {
	if number > MaxAccountKeyNumber {
		return nil, nil, fmt.Errorf(
			"sakg: invalid key number: %d (maximum: %d)",
			number,
			MaxAccountKeyNumber,
		)
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, nil, fmt.Errorf("sakg: invalid mnemonic")
	}

	seed := bip39.NewSeed(mnemonic, passphrase)

	signer, chainCode, err := slip10.NewMasterKey(seed)
	if err != nil {
		return nil, nil, fmt.Errorf("sakg: error deriving master key: %w", err)
	}

	pathStr := fmt.Sprintf("%s/%d'", BIP32PathPrefix, number)
	path, err := NewBIP32Path(pathStr)
	if err != nil {
		return nil, nil, fmt.Errorf("sakg: error creating BIP-0032 path %s: %w", pathStr, err)
	}

	for _, index := range path {
		signer, chainCode, err = slip10.NewChildKey(signer, chainCode, index)
		if err != nil {
			return nil, nil, fmt.Errorf("sakg: error deriving child key: %w", err)
		}
	}

	return signer, path, nil
}
