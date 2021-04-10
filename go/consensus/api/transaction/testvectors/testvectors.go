package testvectors

import (
	"reflect"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

const keySeedPrefix = "oasis-core test vectors: "

// TestVector is an Oasis transaction test vector.
type TestVector struct {
	Kind             string                        `json:"kind"`
	SignatureContext string                        `json:"signature_context"`
	Tx               interface{}                   `json:"tx"`
	SignedTx         transaction.SignedTransaction `json:"signed_tx"`
	EncodedTx        []byte                        `json:"encoded_tx"`
	EncodedSignedTx  []byte                        `json:"encoded_signed_tx"`
	// Valid indicates whether the transaction is (statically) valid.
	// NOTE: This means that the transaction passes basic static validation, but
	// it may still not be valid on the given network due to invalid nonce,
	// or due to some specific parameters set on the network.
	Valid            bool                `json:"valid"`
	SignerPrivateKey []byte              `json:"signer_private_key"`
	SignerPublicKey  signature.PublicKey `json:"signer_public_key"`
}

// MakeTestVector generates a new test vector from a transaction.
func MakeTestVector(kind string, tx *transaction.Transaction, valid bool) TestVector {
	signer := memorySigner.NewTestSigner(keySeedPrefix + kind)
	return MakeTestVectorWithSigner(kind, tx, valid, signer)
}

// MakeTestVectorWithSigner generates a new test vector from a transaction using a specific signer.
func MakeTestVectorWithSigner(kind string, tx *transaction.Transaction, valid bool, signer signature.Signer) TestVector {
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

	prettyTx, err := tx.PrettyType()
	if err != nil {
		panic(err)
	}

	return TestVector{
		Kind:             kind,
		SignatureContext: string(sigCtx),
		Tx:               prettyTx,
		SignedTx:         *sigTx,
		EncodedTx:        cbor.Marshal(tx),
		EncodedSignedTx:  cbor.Marshal(sigTx),
		Valid:            valid,
		SignerPrivateKey: signer.(signature.UnsafeSigner).UnsafeBytes(),
		SignerPublicKey:  signer.Public(),
	}
}
