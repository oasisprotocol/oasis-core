package runtime

import (
	"fmt"
)

var (
	InsertScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", 0, 0, plaintextTxKind},
		GetKeyValueTx{"my_key", "my_value", 0, 0, plaintextTxKind},
	})

	InsertEncWithSecretsScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", 0, 0, encryptedWithSecretsTxKind},
		GetKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithSecretsTxKind},
	})

	RemoveScenario = NewTestClientScenario([]interface{}{
		GetKeyValueTx{"my_key", "my_value", 0, 0, plaintextTxKind},
	})

	RemoveEncWithSecretsScenario = NewTestClientScenario([]interface{}{
		GetKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithSecretsTxKind},
	})

	InsertTransferScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", 0, 0, plaintextTxKind},
		GetKeyValueTx{"my_key", "my_value", 0, 0, plaintextTxKind},
		ConsensusTransferTx{},
	})

	InsertRemoveEncWithSecretsScenario = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key", "my_value", "", 0, 0, encryptedWithSecretsTxKind},
		GetKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithSecretsTxKind},
		RemoveKeyValueTx{"my_key", "my_value", 0, 0, encryptedWithSecretsTxKind},
		GetKeyValueTx{"my_key", "", 0, 0, encryptedWithSecretsTxKind},
	})

	InsertRemoveEncWithSecretsScenarioV2 = NewTestClientScenario([]interface{}{
		InsertKeyValueTx{"my_key2", "my_value2", "", 0, 0, encryptedWithSecretsTxKind},
		GetKeyValueTx{"my_key2", "my_value2", 0, 0, encryptedWithSecretsTxKind},
		RemoveKeyValueTx{"my_key2", "my_value2", 0, 0, encryptedWithSecretsTxKind},
		GetKeyValueTx{"my_key2", "", 0, 0, encryptedWithSecretsTxKind},
	})

	SimpleScenario               = newSimpleKeyValueScenario(false, plaintextTxKind)
	SimpleRepeatedScenario       = newSimpleKeyValueScenario(true, plaintextTxKind)
	SimpleEncWithSecretsScenario = newSimpleKeyValueScenario(false, encryptedWithSecretsTxKind)
)

func newSimpleKeyValueScenario(repeat bool, kind uint) TestClientScenario {
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
			value := fmt.Sprintf("hello_value_from_%s:%d", KeyValueRuntimeID, iter)
			response := ""
			if iter > 0 {
				response = fmt.Sprintf("hello_value_from_%s:%d", KeyValueRuntimeID, iter-1)
			}

			if err := submit(InsertKeyValueTx{key, value, response, 0, 0, kind}); err != nil {
				return err
			}
			if err := submit(GetKeyValueTx{key, value, 0, 0, kind}); err != nil {
				return err
			}

			// Test [set, get] long key calls
			key = "I laud Agni the priest, the divine minister of sacrifice, who invokes the gods, and is the most rich in gems."
			value = "May Agni, the invoker, the sage, the true, the most renowned, a god, come hither with the gods!"
			response = ""
			if iter > 0 {
				response = value
			}

			if err := submit(InsertKeyValueTx{key, value, response, 0, 0, kind}); err != nil {
				return err
			}
			if err := submit(ConsensusTransferTx{}); err != nil {
				return err
			}
			if err := submit(GetKeyValueTx{key, value, 0, 0, kind}); err != nil {
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
		if err := submit(InsertMsg{inMsgKey, inMsgValue, 0, 0, kind}); err != nil {
			return err
		}
		if err := submit(GetKeyValueTx{inMsgKey, inMsgValue, 0, 0, kind}); err != nil {
			return err
		}
		return submit(ConsensusAccountsTx{})
	}
}

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

// JoinTestClientScenarios joins an arbitrary number of test client scenarios into a single scenario
// that executes them in the order they were provided.
func JoinTestClientScenarios(scenarios ...TestClientScenario) TestClientScenario {
	return func(submit func(req interface{}) error) error {
		for _, scenario := range scenarios {
			if err := scenario(submit); err != nil {
				return err
			}
		}
		return nil
	}
}
