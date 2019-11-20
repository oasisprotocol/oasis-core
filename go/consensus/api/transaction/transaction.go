package transaction

import (
	"fmt"
	"sync"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
)

// moduleName is the module name used for error definitions.
const moduleName = "consensus/transaction"

var (
	// ErrInvalidNonce is the error returned when a nonce is invalid.
	ErrInvalidNonce = errors.New(moduleName, 1, "transaction: invalid nonce")

	// SignatureContext is the context used for signing transactions.
	SignatureContext = signature.NewContext("oasis-core/consensus: tx", signature.WithChainSeparation())

	registeredMethods sync.Map
)

// Transaction is an unsigned consensus transaction.
type Transaction struct {
	// Nonce is a nonce to prevent replay.
	Nonce uint64 `json:"nonce"`
	// Fee is an optional fee that the sender commits to pay to execute this
	// transaction.
	Fee *Fee `json:"fee,omitempty"`

	// Method is the method that should be called.
	Method MethodName `json:"method"`
	// Body is the method call body.
	Body cbor.RawMessage `json:"body,omitempty"`
}

// SanityCheck performs a basic sanity check on the transaction.
func (t *Transaction) SanityCheck() error {
	return t.Method.SanityCheck()
}

// NewTransaction creates a new transaction.
func NewTransaction(nonce uint64, fee *Fee, method MethodName, body interface{}) *Transaction {
	var rawBody []byte
	if body != nil {
		rawBody = cbor.Marshal(body)
	}

	return &Transaction{
		Nonce:  nonce,
		Fee:    fee,
		Method: method,
		Body:   cbor.RawMessage(rawBody),
	}
}

// SignedTransaction is a signed transaction.
type SignedTransaction struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedTransaction) Open(tx *Transaction) error { // nolint: interfacer
	return s.Signed.Open(SignatureContext, tx)
}

// Sign signs a transaction.
func Sign(signer signature.Signer, tx *Transaction) (*SignedTransaction, error) {
	signed, err := signature.SignSigned(signer, SignatureContext, tx)
	if err != nil {
		return nil, err
	}

	return &SignedTransaction{Signed: *signed}, nil
}

// MethodSeparator is the separator used to separate backend name from method name.
const MethodSeparator = "."

// MethodName is a method name.
type MethodName string

// SanityCheck performs a basic sanity check on the method name.
func (m MethodName) SanityCheck() error {
	if len(m) == 0 {
		return fmt.Errorf("transaction: empty method")
	}

	return nil
}

// NewMethodName creates a new method name.
//
// Backend name and method pair must be unique. If they are not, this method
// will panic.
func NewMethodName(backendName, method string) MethodName {
	// Check for duplicate method names.
	name := backendName + MethodSeparator + method
	if _, isRegistered := registeredMethods.Load(name); isRegistered {
		panic(fmt.Errorf("transaction: method already registered: %s", name))
	}
	registeredMethods.Store(name, true)

	return MethodName(name)
}
