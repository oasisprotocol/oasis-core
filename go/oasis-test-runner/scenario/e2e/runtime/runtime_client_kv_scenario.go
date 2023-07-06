package runtime

import (
	"fmt"
)

var (
	InsertKeyValueScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", false},
		GetKeyValueTx{"my_key", "my_value", false},
	})

	InsertKeyValueEncScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", true},
		GetKeyValueTx{"my_key", "my_value", true},
	})

	RemoveKeyValueScenario = NewTestClientScenario([]interface{}{
		GetKeyValueTx{"my_key", "my_value", false},
	})

	RemoveKeyValueEncScenario = NewTestClientScenario([]interface{}{
		GetKeyValueTx{"my_key", "my_value", true},
	})

	InsertTransferKeyValueScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", false},
		GetKeyValueTx{"my_key", "my_value", false},
		ConsensusTransferTx{},
	})

	InsertRemoveKeyValueEncScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", true},
		GetKeyValueTx{"my_key", "my_value", true},
		RemoveKeyValueTx{"my_key", "my_value", true},
		GetKeyValueTx{"my_key", "", true},
	})

	InsertRemoveKeyValueEncScenarioV2 = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key2", "my_value2", "", true},
		GetKeyValueTx{"my_key2", "my_value2", true},
		RemoveKeyValueTx{"my_key2", "my_value2", true},
		GetKeyValueTx{"my_key2", "", true},
	})

	SimpleKeyValueScenario = newSimpleKeyValueScenario(false, false)

	SimpleKeyValueEncScenario = newSimpleKeyValueScenario(false, true)

	SimpleKeyValueScenarioRepeated = newSimpleKeyValueScenario(true, false)
)

func newSimpleKeyValueScenario(repeat bool, encrypted bool) TestClientScenario {
	return func(submit func(req interface{}) error) error {
		// Check whether Runtime ID is also set remotely.
		//
		// XXX: This would check that the response is sensible but the Rust
		// side `to_string()` returns `8000…0000`, and the original Rust
		// test client was doing a string compare so no one ever noticed
		// that truncated values were being compared.
		if err := submit(GetRuntimeIDTx{}); err != nil {
			return err
		}

		for iter := 0; ; iter++ {
			// Test simple [set,get] calls.
			key := "hello_key"
			value := fmt.Sprintf("hello_value_from_%s:%d", runtimeID, iter)
			response := ""
			if iter > 0 {
				response = fmt.Sprintf("hello_value_from_%s:%d", runtimeID, iter-1)
			}

			if err := submit(InsertKeyValueTx{key, value, response, encrypted}); err != nil {
				return err
			}
			if err := submit(GetKeyValueTx{key, value, encrypted}); err != nil {
				return err
			}

			// Test [set, get] long key calls
			key = "I laud Agni the priest, the divine minister of sacrifice, who invokes the gods, and is the most rich in gems."
			value = "May Agni, the invoker, the sage, the true, the most renowned, a god, come hither with the gods!"
			response = ""
			if iter > 0 {
				response = value
			}

			if err := submit(InsertKeyValueTx{key, value, response, encrypted}); err != nil {
				return err
			}
			if err := submit(ConsensusTransferTx{}); err != nil {
				return err
			}
			if err := submit(GetKeyValueTx{key, value, encrypted}); err != nil {
				return err
			}

			if !repeat {
				break
			}
		}

		// Test submission and processing of incoming messages.
		const (
			inMsgKey   = "in_msg"
			inMsgValue = "hello world from inmsg"
		)
		if err := submit(InsertMsg{inMsgKey, inMsgValue, encrypted}); err != nil {
			return err
		}
		if err := submit(GetKeyValueTx{inMsgKey, inMsgValue, encrypted}); err != nil {
			return err
		}
		if err := submit(ConsensusAccountsTx{}); err != nil {
			return err
		}

		return nil
	}
}

// KeyValueQuery queries the value stored under the given key for the specified round from
// the database, and verifies that the response (current value) contains the expected data.
type KeyValueQuery struct {
	Key      string
	Response string
	Round    uint64
}

// InsertKeyValueTx inserts a key/value pair to the database, and verifies that the response
// (previous value) contains the expected data.
type InsertKeyValueTx struct {
	Key       string
	Value     string
	Response  string
	Encrypted bool
}

// GetKeyValueTx retrieves the value stored under the given key from the database,
// and verifies that the response (current value) contains the expected data.
type GetKeyValueTx struct {
	Key       string
	Response  string
	Encrypted bool
}

// RemoveKeyValueTx removes the value stored under the given key from the database.
type RemoveKeyValueTx struct {
	Key       string
	Response  string
	Encrypted bool
}

// InsertMsg inserts an incoming runtime message.
type InsertMsg struct {
	Key       string
	Value     string
	Encrypted bool
}

// GetRuntimeIDTx retrieves the runtime ID.
type GetRuntimeIDTx struct{}

// ConsensusTransferTx submits and empty consensus staking transfer.
type ConsensusTransferTx struct{}

// ConsensusAccountsTx tests consensus account query.
type ConsensusAccountsTx struct{}

// TestClientScenario is a test scenario for a key-value runtime test client.
type TestClientScenario func(submit func(req interface{}) error) error

// NewTestClientScenario creates a new test client scenario.
func NewTestClientScenario(requests []interface{}) TestClientScenario {
	return func(submit func(req interface{}) error) error {
		for _, req := range requests {
			if err := submit(req); err != nil {
				return err
			}
		}
		return nil
	}
}
