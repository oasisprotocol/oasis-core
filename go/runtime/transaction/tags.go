package transaction

import "github.com/oasislabs/ekiden/go/common/crypto/hash"

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
