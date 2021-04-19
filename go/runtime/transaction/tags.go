package transaction

import "github.com/oasisprotocol/oasis-core/go/common/crypto/hash"

// TagBlockTxHash is the hash used for block emitted tags not tied to a specific
// transaction.
var TagBlockTxHash = hash.Hash([32]byte{})

// Tag is a key/value pair of arbitrary byte blobs with runtime-dependent
// semantics which can be indexed to allow easier lookup of transactions
// on runtime clients.
type Tag struct {
	// Key is the tag key.
	Key []byte
	// Value is the tag value.
	Value []byte
	// TxHash is the hash of the transaction that emitted the tag.
	TxHash hash.Hash
}

// Tags is a set of tags.
type Tags []Tag
