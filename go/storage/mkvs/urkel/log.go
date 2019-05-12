package urkel

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
