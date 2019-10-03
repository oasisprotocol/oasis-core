package writelog

import (
	"encoding/json"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

// WriteLog is a write log.
//
// The keys in the write log must be unique.
type WriteLog []LogEntry

// LogEntry is a write log entry.
type LogEntry struct {
	_struct struct{} `codec:",toarray"` // nolint

	Key   []byte
	Value []byte
}

func (le *LogEntry) UnmarshalJSON(src []byte) error {
	var kv [2][]byte
	if err := json.Unmarshal(src, &kv); err != nil {
		return err
	}

	le.Key = kv[0]
	le.Value = kv[1]

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
	if len(k.Value) == 0 {
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
