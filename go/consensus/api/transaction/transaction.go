package transaction

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
)

// moduleName is the module name used for error definitions.
const moduleName = "consensus/transaction"

var (
	// ErrInvalidNonce is the error returned when a nonce is invalid.
	ErrInvalidNonce = errors.New(moduleName, 1, "transaction: invalid nonce")

	// SignatureContext is the context used for signing transactions.
	SignatureContext = signature.NewContext("oasis-core/consensus: tx", signature.WithChainSeparation())

	registeredMethods sync.Map

	_ prettyprint.PrettyPrinter = (*Transaction)(nil)
	_ prettyprint.PrettyPrinter = (*SignedTransaction)(nil)
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

// PrettyPrintBody writes a pretty-printed representation of transaction's body
// to the given writer.
func (t Transaction) PrettyPrintBody(ctx context.Context, prefix string, w io.Writer) {
	bodyType := t.Method.BodyType()
	if bodyType == nil {
		fmt.Fprintf(w, "%s<unknown method body: %s>\n", prefix, base64.StdEncoding.EncodeToString(t.Body))
		return
	}

	// Deserialize into correct type.
	v := reflect.New(reflect.TypeOf(bodyType)).Interface()
	if err := cbor.Unmarshal(t.Body, v); err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
		fmt.Fprintf(w, "%s<malformed: %s>\n", prefix, base64.StdEncoding.EncodeToString(t.Body))
		return
	}

	// If the body type supports pretty printing, use that.
	if pp, ok := v.(prettyprint.PrettyPrinter); ok {
		pp.PrettyPrint(ctx, prefix, w)
		return
	}

	// Otherwise, just serialize into JSON and display that.
	data, err := json.MarshalIndent(v, prefix, "  ")
	if err != nil {
		fmt.Fprintf(w, "%s  <raw: %s>\n", prefix, base64.StdEncoding.EncodeToString(t.Body))
		return
	}
	fmt.Fprintf(w, "%s%s\n", prefix, data)
}

// PrettyPrint writes a pretty-printed representation of the transaction to the
// given writer.
func (t Transaction) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sNonce:  %d\n", prefix, t.Nonce)
	if t.Fee != nil {
		fmt.Fprintf(w, "%sFee:\n", prefix)
		t.Fee.PrettyPrint(ctx, prefix+"  ", w)
	} else {
		fmt.Fprintf(w, "%sFee:   none\n", prefix)
	}
	fmt.Fprintf(w, "%sMethod: %s\n", prefix, t.Method)
	fmt.Fprintf(w, "%sBody:\n", prefix)
	t.PrettyPrintBody(ctx, prefix+"  ", w)

	if genesisHash, ok := ctx.Value(prettyprint.ContextKeyGenesisHash).(hash.Hash); ok {
		fmt.Println("Other info:")
		fmt.Printf("  Genesis document's hash: %s\n", genesisHash)
	}
}

// PrettyType returns a representation of the type that can be used for pretty printing.
func (t *Transaction) PrettyType() (interface{}, error) {
	bodyType := t.Method.BodyType()
	if bodyType == nil {
		return nil, fmt.Errorf("unknown method body type")
	}

	// Deserialize into correct type.
	body := reflect.New(reflect.TypeOf(bodyType)).Interface()
	if err := cbor.Unmarshal(t.Body, body); err != nil {
		return nil, fmt.Errorf("failed to unmarshal transaction body: %w", err)
	}

	// If the body type supports pretty printing, use that.
	if pp, ok := body.(prettyprint.PrettyPrinter); ok {
		var err error
		if body, err = pp.PrettyType(); err != nil {
			return nil, fmt.Errorf("failed to pretty print transaction body: %w", err)
		}
	}

	return &PrettyTransaction{
		Nonce:  t.Nonce,
		Fee:    t.Fee,
		Method: t.Method,
		Body:   body,
	}, nil
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

// PrettyTransaction is used for pretty-printing transactions so that the actual content is
// displayed instead of the binary blob.
//
// It should only be used for pretty printing.
type PrettyTransaction struct {
	Nonce  uint64      `json:"nonce"`
	Fee    *Fee        `json:"fee,omitempty"`
	Method MethodName  `json:"method"`
	Body   interface{} `json:"body,omitempty"`
}

// SignedTransaction is a signed transaction.
type SignedTransaction struct {
	signature.Signed
}

// Hash returns the cryptographic hash of the encoded transaction.
func (s *SignedTransaction) Hash() hash.Hash {
	return hash.NewFrom(s)
}

// PrettyPrint writes a pretty-printed representation of the type
// to the given writer.
func (s SignedTransaction) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sHash: %s\n", prefix, s.Hash())

	fmt.Fprintf(w, "%sSigner: %s\n", prefix, s.Signature.PublicKey)
	fmt.Fprintf(w, "%s        (signature: %s)\n", prefix, s.Signature.Signature)

	// Check if signature is valid.
	if !s.Signature.Verify(SignatureContext, s.Blob) {
		fmt.Fprintf(w, "%s        [INVALID SIGNATURE]\n", prefix)
	}

	// Display the blob even if signature verification failed as it may
	// be useful to look into it regardless.
	var tx Transaction
	fmt.Fprintf(w, "%sContent:\n", prefix)
	if err := cbor.Unmarshal(s.Blob, &tx); err != nil {
		fmt.Fprintf(w, "%s  <error: %s>\n", prefix, err)
		fmt.Fprintf(w, "%s  <malformed: %s>\n", prefix, base64.StdEncoding.EncodeToString(s.Blob))
		return
	}

	tx.PrettyPrint(ctx, prefix+"  ", w)
}

// PrettyType returns a representation of the type that can be used for pretty printing.
func (s SignedTransaction) PrettyType() (interface{}, error) {
	var tx Transaction
	if err := cbor.Unmarshal(s.Blob, &tx); err != nil {
		return nil, fmt.Errorf("malformed signed blob: %w", err)
	}
	return signature.NewPrettySigned(s.Signed, tx)
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

// BodyType returns the registered body type associated with this method.
func (m MethodName) BodyType() interface{} {
	bodyType, _ := registeredMethods.Load(string(m))
	return bodyType
}

// NewMethodName creates a new method name.
//
// Module and method pair must be unique. If they are not, this method
// will panic.
func NewMethodName(module, method string, bodyType interface{}) MethodName {
	// Check for duplicate method names.
	name := module + MethodSeparator + method
	if _, isRegistered := registeredMethods.Load(name); isRegistered {
		panic(fmt.Errorf("transaction: method already registered: %s", name))
	}
	registeredMethods.Store(name, bodyType)

	return MethodName(name)
}
