package main

import (
	"reflect"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
)

const keySeedPrefix = "oasis-core staking test vectors: "

// TestTransactions is a test transaction suitable for JSON serialization.
//
// The only difference between this and transaction.Transaction is that
// body is not represented as raw bytes but rather as an interface so
// it contains the actual body document.
type TestTransaction struct {
	Nonce  uint64                 `json:"nonce"`
	Fee    *transaction.Fee       `json:"fee,omitempty"`
	Method transaction.MethodName `json:"method"`
	Body   interface{}            `json:"body,omitempty"`
}

// TestVector is a staking message test vector.
type TestVector struct {
	Kind             string                        `json:"kind"`
	SignatureContext string                        `json:"signature_context"`
	Tx               TestTransaction               `json:"tx"`
	SignedTx         transaction.SignedTransaction `json:"signed_tx"`
	EncodedTx        []byte                        `json:"encoded_tx"`
	EncodedSignedTx  []byte                        `json:"encoded_signed_tx"`
	Valid            bool                          `json:"valid"`
	SignerPrivateKey []byte                        `json:"signer_private_key"`
	SignerPublicKey  signature.PublicKey           `json:"signer_public_key"`
}

func makeTestVector(kind string, tx *transaction.Transaction) TestVector {
	signer := memorySigner.NewTestSigner(keySeedPrefix + kind)
	sigTx, err := transaction.Sign(signer, tx)
	if err != nil {
		panic(err)
	}

	sigCtx, err := signature.PrepareSignerContext(transaction.SignatureContext)
	if err != nil {
		panic(err)
	}

	bodyType := tx.Method.BodyType()
	v := reflect.New(reflect.TypeOf(bodyType)).Interface()
	if err = cbor.Unmarshal(tx.Body, v); err != nil {
		panic(err)
	}

	testTx := TestTransaction{
		Nonce:  tx.Nonce,
		Fee:    tx.Fee,
		Method: tx.Method,
		Body:   v,
	}

	return TestVector{
		Kind:             kind,
		SignatureContext: string(sigCtx),
		Tx:               testTx,
		SignedTx:         *sigTx,
		EncodedTx:        cbor.Marshal(tx),
		EncodedSignedTx:  cbor.Marshal(sigTx),
		Valid:            true,
		SignerPrivateKey: signer.(signature.UnsafeSigner).UnsafeBytes(),
		SignerPublicKey:  signer.Public(),
	}
}
