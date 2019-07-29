package log

import (
	"encoding/json"
	"fmt"
	"strings"
)

type assertBase struct {
	message string
}

func (a *assertBase) fail() error {
	return fmt.Errorf("log assertion failed: %s", a.message)
}

func (a *assertBase) Line(line string) error {
	return nil
}

func (a *assertBase) Finish() error {
	return nil
}

type assertContains struct {
	assertBase

	text     string
	seen     bool
	expected bool
}

func (a *assertContains) Line(line string) error {
	if strings.Contains(line, a.text) {
		a.seen = true
	}
	return nil
}

func (a *assertContains) Finish() error {
	if a.seen != a.expected {
		return a.fail()
	}
	return nil
}

// AssertContains returns a handler which checks that given text is
// contained in the log output.
func AssertContains(text, message string) WatcherHandler {
	return &assertContains{
		assertBase: assertBase{message},
		text:       text,
		expected:   true,
	}
}

// AssertNotContains returns a handler which checks that given text
// is not contained in the log output.
func AssertNotContains(text, message string) WatcherHandler {
	return &assertContains{
		assertBase: assertBase{message},
		text:       text,
		expected:   false,
	}
}

type assertJSONContains struct {
	assertBase

	key      string
	value    string
	seen     bool
	expected bool
}

func (a *assertJSONContains) Line(line string) error {
	var kvs map[string]interface{}
	if err := json.Unmarshal([]byte(line), &kvs); err != nil {
		return nil
	}

	// TODO: Support arbitrary nested paths as keys.
	v := kvs[a.key]
	if v == nil {
		return nil
	}

	// TODO: Support other types.
	switch v.(type) {
	case string:
		if v == a.value {
			a.seen = true
		}
	}

	return nil
}

func (a *assertJSONContains) Finish() error {
	if a.seen != a.expected {
		return a.fail()
	}
	return nil
}

// AssertJSONContains returns a handler which checks that a given key/value
// pair is contained encoded as JSON in the log output.
func AssertJSONContains(key, value, message string) WatcherHandler {
	return &assertJSONContains{
		assertBase: assertBase{message},
		key:        key,
		value:      value,
		expected:   true,
	}
}

// AssertNotJSONContains returns a handler which checks that a given key/value
// pair is not contained encoded as JSON in the log output.
func AssertNotJSONContains(key, value, message string) WatcherHandler {
	return &assertJSONContains{
		assertBase: assertBase{message},
		key:        key,
		value:      value,
		expected:   false,
	}
}
