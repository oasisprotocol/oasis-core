package block

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

// Message is a message that can be sent by a runtime.
type Message struct {
	Noop *NoopMessage `json:"noop,omitempty"`
}

// ValidateBasic performs basic validation of the runtime message.
func (m *Message) ValidateBasic() error {
	switch {
	case m.Noop != nil:
		return m.Noop.ValidateBasic()
	default:
		return fmt.Errorf("runtime message has no fields set")
	}
}

// MessagesHash returns a hash of provided runtime messages.
func MessagesHash(msgs []Message) (h hash.Hash) {
	if len(msgs) == 0 {
		// Special case if there are no messages.
		h.Empty()
		return
	}
	return hash.NewFrom(msgs)
}

// NoopMessage is a runtime message that doesn't result in any actions being performed and it always
// returns success when delivered.
type NoopMessage struct {
	// Noop message has no fields.
}

// ValidateBasic performs basic validation of the runtime message.
func (nm *NoopMessage) ValidateBasic() error {
	return nil
}
