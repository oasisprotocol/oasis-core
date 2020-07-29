package writelog

import (
	"bytes"
	"encoding/json"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// WriteLog is a write log.
//
// The keys in the write log must be unique.
type WriteLog []LogEntry

// Equal compares vs another write log for equality.
func (wl WriteLog) Equal(cmp WriteLog) bool {
	if len(wl) != len(cmp) {
		return false
	}
	for k, v := range wl {
		if !v.Equal(&cmp[k]) {
			return false
		}
	}
	return true
}

// LogEntry is a write log entry.
type LogEntry struct {
	_ struct{} `cbor:",toarray"` // nolint

	Key   []byte
	Value []byte
}

// Equal compares vs another log entry for equality.
func (k *LogEntry) Equal(cmp *LogEntry) bool {
	if !bytes.Equal(k.Key, cmp.Key) {
		return false
	}
	if !bytes.Equal(k.Value, cmp.Value) {
		return false
	}
	return true
}

func (k *LogEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal([2][]byte{k.Key, k.Value})
}

func (k *LogEntry) UnmarshalJSON(src []byte) error {
	var kv [2][]byte
	if err := json.Unmarshal(src, &kv); err != nil {
		return err
	}

	k.Key = kv[0]
	k.Value = kv[1]

	return nil
}

// LogEntryType is a type of a write log entry.
type LogEntryType int

const (
	LogInsert LogEntryType = iota
	LogDelete
)

// Type returns the type of the write log entry.
func (k *LogEntry) Type() LogEntryType {
	if k.Value == nil {
		return LogDelete
	}

	return LogInsert
}

// Annotations are extra metadata about write log entries.
//
// This should always be passed alongside a WriteLog.
type Annotations []LogEntryAnnotation

// LogEntryAnnotation is an annotation for a single write log entry.
//
// Entries in a WriteLogAnnotation correspond to WriteLog entries at their respective indexes.
type LogEntryAnnotation struct {
	InsertedNode *node.Pointer
}
