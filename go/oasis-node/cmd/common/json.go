package common

import (
	"encoding/json"
	"fmt"
)

// PrettyJSONMarshal returns pretty-printed JSON encoding of v.
func PrettyJSONMarshal(v interface{}) ([]byte, error) {
	formatted, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to pretty JSON: %w", err)
	}
	return formatted, nil
}
