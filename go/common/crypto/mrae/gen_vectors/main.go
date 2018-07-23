// gen_vectors generates test vectors for AEAD primitives that implement
// Go's `crypto/cipher.AEAD` interface.
package main

import (
	"crypto/cipher"
	"encoding/json"
	"io/ioutil"

	"github.com/oasislabs/ekiden/go/common/crypto/mrae/gen_vectors/testvector"
	"github.com/oasislabs/ekiden/go/common/crypto/mrae/sivaessha2"
)

type primitiveDef struct {
	name      string
	ctor      func([]byte) (cipher.AEAD, error)
	keySize   int
	nonceSize int
}

func main() {
	// This is loosely based off the public domain `genkat.c` program
	// from the NORX source code package, because it's simple.
	msg, aad := testvector.KATInputs()

	primitives := []primitiveDef{
		{
			name:      "SIV_CTR-AES128_HMAC-SHA256-128",
			ctor:      sivaessha2.New,
			keySize:   sivaessha2.KeySize,
			nonceSize: sivaessha2.NonceSize,
		},
	}

	for _, primitive := range primitives {
		katOut := &testvector.KnownAnswerTests{
			Name:    primitive.name,
			MsgData: msg,
			AADData: aad,
		}

		key := make([]byte, primitive.keySize)
		nonce := make([]byte, primitive.nonceSize)

		for i := range key {
			key[i] = byte(255 & (i*191 + 123))
		}
		for i := range nonce {
			nonce[i] = byte(255 & (i*181 + 123))
		}

		aead, err := primitive.ctor(key)
		if err != nil {
			panic(err)
		}

		katOut.Key, katOut.Nonce = key, nonce

		for i := range msg {
			ct := aead.Seal(nil, nonce, msg[:i], aad[:i])

			// Assume that ct = ciphertext | tag.
			tag := ct[i:]
			ct = ct[:i]

			vec := &testvector.TestVector{
				Ciphertext: ct,
				Tag:        tag,
				Length:     i,
			}

			katOut.KnownAnswers = append(katOut.KnownAnswers, vec)
		}

		jsonOut, _ := json.Marshal(&katOut)
		_ = ioutil.WriteFile(primitive.name+".json", jsonOut, 0600)
	}
}
