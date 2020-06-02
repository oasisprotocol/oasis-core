// Package bech32 provides implementation of Bech32 encoding specified in
// BIP 173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki.
package bech32

import "github.com/tendermint/tendermint/libs/bech32"

// Encode encodes 8-bits per byte byte-slice to a Bech32-encoded string.
func Encode(hrp string, data []byte) (string, error) {
	return bech32.ConvertAndEncode(hrp, data)
}

// Decode decodes a Bech32-encoded string to a 8-bits per byte byte-slice.
func Decode(text string) (string, []byte, error) {
	return bech32.DecodeAndConvert(text)
}
