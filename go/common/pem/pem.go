// Package pem provides handy wrappers for dealing with PEM files.
package pem

import (
	"bytes"
	"encoding/pem"
	"errors"
)

var (
	errNilPEM          = errors.New("pem: data does not contain a block")
	errTrailingGarbage = errors.New("pem: data has trailing garbage")
	errMalformedPEM    = errors.New("pem: malformed, unexpected type")
)

// Unmarshal decodes a raw PEM formatted buffer containing a PEM block with
// the given type, and returns the data.
func Unmarshal(pemType string, data []byte) ([]byte, error) {
	blk, rest := pem.Decode(data)
	if blk == nil {
		return nil, errNilPEM
	}
	if len(rest) != 0 {
		return nil, errTrailingGarbage
	}
	if blk.Type != pemType {
		return nil, errMalformedPEM
	}

	return blk.Bytes, nil
}

// Marshal encodes a blob into a PEM formatted buffer, with the PEM
// specified PEM type and data.
func Marshal(pemType string, data []byte) ([]byte, error) {
	blk := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, blk); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
