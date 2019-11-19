package transaction

// RawBatch is a list of opaque bytes.
type RawBatch [][]byte

// String returns a string representation of a batch.
func (b RawBatch) String() string {
	return "<RawBatch>"
}
