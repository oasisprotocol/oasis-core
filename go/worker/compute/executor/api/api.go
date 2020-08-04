package api

// Tx is a runtime transaction being sent to the executor node.
type Tx struct {
	Data []byte `json:"data"`
}
