package tests

const (
	// OpInsert is the tree insert operation name.
	OpInsert = "Insert"
	// OpRemove is the tree remove operation name.
	OpRemove = "Remove"
	// OpGet is the tree get operation name.
	OpGet = "Get"
	// OpIteratorSeek is the tree iterator seek operation name.
	OpIteratorSeek = "IteratorSeek"
)

// Op is a tree operation.
type Op struct {
	// Op is the operation name.
	Op string `json:"op"`
	// Key is the key that is inserted, removed or looked up.
	Key []byte `json:"key,omitempty"`
	// Value is the value that is inserted or that is expected for the given key during lookup.
	Value []byte `json:"value,omitempty"`
	// ExpectedKey is the key that is expected for the given operation (e.g., iterator seek).
	ExpectedKey []byte `json:"expected_key,omitempty"`
}

// TestVector is a MKVS tree test vector (a series of tree operations).
type TestVector []*Op
