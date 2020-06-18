// Package bech32 provides implementation of Bech32 encoding specified in
// BIP 173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki.
package bech32

import (
	"fmt"

	"github.com/btcsuite/btcutil/bech32"
)

// Encode encodes 8-bits per byte byte-slice to a Bech32-encoded string.
func Encode(hrp string, data []byte) (string, error) {
	// NOTE: Taken from github.com/tendermint/tendermint/libs/bech32 (licensed under Apache-2).
	converted, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("encoding bech32 failed: %w", err)
	}
	return bech32.Encode(hrp, converted)
}

// Decode decodes a Bech32-encoded string to a 8-bits per byte byte-slice.
func Decode(text string) (string, []byte, error) {
	// NOTE: Taken from github.com/tendermint/tendermint/libs/bech32 (licensed under Apache-2).
	hrp, data, err := bech32.Decode(text)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}
	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}
	return hrp, converted, nil
}
