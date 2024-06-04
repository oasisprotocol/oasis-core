package runtime

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
)

const (
	// plaintextTxKind refers to a key/value transaction where the data
	// is unencrypted.
	plaintextTxKind uint = iota
	// encryptedWithSecretsTxKind refers to a key/value transaction where
	// the data is encrypted using a state key derived from master secrets.
	encryptedWithSecretsTxKind
	// encryptedWithChurpTxKind refers to a key/value transaction where
	// the data is encrypted using a state key derived from CHURP.
	encryptedWithChurpTxKind
)

// KeyValueQuery queries the value stored under the given key for the specified round from
// the database, and verifies that the response (current value) contains the expected data.
type KeyValueQuery struct {
	Key      string
	Response string
	Round    uint64
}

// EncryptDecryptTx encrypts and decrypts a message while verifying if the original message
// matches the decrypted result.
type EncryptDecryptTx struct {
	Message   []byte
	KeyPairID string
	Epoch     beacon.EpochTime
}

// InsertKeyValueTx inserts a key/value pair to the database, and verifies that the response
// (previous value) contains the expected data.
type InsertKeyValueTx struct {
	Key        string
	Value      string
	Response   string
	Generation uint64
	ChurpID    uint8
	Kind       uint
}

// GetKeyValueTx retrieves the value stored under the given key from the database,
// and verifies that the response (current value) contains the expected data.
type GetKeyValueTx struct {
	Key        string
	Response   string
	Generation uint64
	ChurpID    uint8
	Kind       uint
}

// KeyExistsTx retrieves the value stored under the given key from the database and verifies that
// the response (current value) is non-empty.
type KeyExistsTx struct {
	Key        string
	Generation uint64
	ChurpID    uint8
	Kind       uint
}

// RemoveKeyValueTx removes the value stored under the given key from the database.
type RemoveKeyValueTx struct {
	Key        string
	Response   string
	Generation uint64
	ChurpID    uint8
	Kind       uint
}

// InsertMsg inserts an incoming runtime message.
type InsertMsg struct {
	Key        string
	Value      string
	Generation uint64
	ChurpID    uint8
	Kind       uint
}

// GetRuntimeIDTx retrieves the runtime ID.
type GetRuntimeIDTx struct{}

// ConsensusTransferTx submits and empty consensus staking transfer.
type ConsensusTransferTx struct{}

// ConsensusAccountsTx tests consensus account query.
type ConsensusAccountsTx struct{}
