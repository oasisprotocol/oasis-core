// gen_account_vectors generates test vectors for ADR 0008: Standard Account Key
// Generation.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	bip39 "github.com/tyler-smith/go-bip39"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/sakg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Custom byte slice type that encodes to a hex string when marshaling to JSON.
type byteSlice []byte

func (bs byteSlice) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(bs))
}

// oasisAccount contains information for a particular Oasis staking account:
// BIP-0032 path, private and public keys and the account's address.
type oasisAccount struct {
	BIP32Path  sakg.BIP32Path  `json:"bip32_path"`
	PrivateKey byteSlice       `json:"private_key"`
	PublicKey  byteSlice       `json:"public_key"`
	Address    staking.Address `json:"address"`
}

type testVector struct {
	Kind            string         `json:"kind"`
	BIP39Mnemonic   string         `json:"bip39_mnemonic"`
	BIP39PassPhrase string         `json:"bip39_passphrase"`
	BIP39Seed       byteSlice      `json:"bip39_seed"`
	OasisAccounts   []oasisAccount `json:"oasis_accounts"`
}

func main() {
	extendedSet := flag.Bool(
		"extended",
		false,
		"Generate extended set of ADR 0008 (Standard Account Key Generation) test vectors",
	)
	flag.Parse()

	// BIP-0039 passphrases.
	passphrases := []string{
		"",
	}
	// BIP-0039 mnemonics.
	mnemonics := []string{
		// The popular "standard" mnemonic used for testing.
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		// Oasis Ledger app's development mnemonic.
		"equip will roof matter pink blind book anxiety banner elbow sun young",
	}
	// Add additional BIP-0039 passphrases and mnemonics when generating the
	// extended set of ADR 0008 test vectors.
	if *extendedSet {
		passphrases = append(passphrases, "p4ssphr4se")
		mnemonics = append(mnemonics, []string{
			// Randomly chosen mnemonics.
			"network want title crash employ twelve elegant unlock arrow marriage cat april",
			"grape weapon help home entire invest warfare curious advance immense group vintage",
			"vibrant length learn peanut garlic boil battle jeans fan cliff alone round setup dove shoe twist dumb trophy imitate coil team grocery when else",
			// Trust Wallet Core's test mnemonic:
			// https://github.com/trustwallet/wallet-core/blob/219b85286b6d042f9306402acefd33c08b2b3b66/android/app/src/androidTest/java/com/trustwallet/core/app/blockchains/CoinAddressDerivationTests.kt#L18,
			// https://github.com/trustwallet/wallet-core/blob/219b85286b6d042f9306402acefd33c08b2b3b66/swift/Tests/CoinAddressDerivationTests.swift#L13.
			"shoot island position soft burden budget tooth cruel issue economy destroy above",
		}...)
	}

	// Generate ADR 0008 test vectors.
	var vectors []testVector
	for _, passphrase := range passphrases {
		for _, mnemonic := range mnemonics {
			// NOTE: This is only for test vector's BIP39Seed field,
			// GetAccountKey() computes the BIP-0039 seed automatically.
			seed := bip39.NewSeed(mnemonic, passphrase)

			accountNumbers := []uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, sakg.MaxAccountKeyNumber}
			nAccounts := len(accountNumbers)
			accounts := make([]oasisAccount, nAccounts)
			for i, num := range accountNumbers {
				signer, path, err := sakg.GetAccountSigner(mnemonic, passphrase, num)
				if err != nil {
					panic(fmt.Sprintf("error obtaining account key: %v", err))
				}
				pubKey := signer.Public()
				pubKeyBytes, _ := pubKey.MarshalBinary()
				unsafeSigner := signer.(signature.UnsafeSigner)
				privKey := unsafeSigner.UnsafeBytes()
				accounts[i] = oasisAccount{
					BIP32Path:  path,
					PrivateKey: byteSlice(privKey),
					PublicKey:  byteSlice(pubKeyBytes),
					Address:    staking.NewAddress(pubKey),
				}
			}
			vector := testVector{
				Kind:            "standard account key generation",
				BIP39Mnemonic:   mnemonic,
				BIP39PassPhrase: passphrase,
				BIP39Seed:       seed,
				OasisAccounts:   accounts,
			}
			vectors = append(vectors, vector)
		}
	}

	// Generate output.
	jsonOut, err := json.MarshalIndent(&vectors, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding test vectors: %v\n", err)
	}
	fmt.Printf("%s\n", jsonOut)
}
