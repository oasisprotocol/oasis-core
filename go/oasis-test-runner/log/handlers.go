package log

import (
	"encoding/json"
	"fmt"
	"strings"
)

var (
	_ WatcherHandler        = (*assertBaseHandler)(nil)
	_ WatcherHandler        = (*assertContainsHandler)(nil)
	_ WatcherHandler        = (*assertJSONContainsHandler)(nil)
	_ WatcherHandlerFactory = (*assertBaseFactory)(nil)
	_ WatcherHandlerFactory = (*assertContainsFactory)(nil)
	_ WatcherHandlerFactory = (*assertJSONContainsFactory)(nil)
)

type assertBase struct {
	message string
}

func (a *assertBase) fail() error {
	return fmt.Errorf("log assertion failed: %s", a.message)
}

func (a *assertBase) String() string {
	return fmt.Sprintf("assertBase{message: %s}", a.message)
}

type assertBaseHandler assertBase

func (h *assertBaseHandler) Line(line string) error {
	return nil
}

func (h *assertBaseHandler) Finish() error {
	return nil
}

type assertBaseFactory assertBase

func (fac *assertBaseFactory) New() (WatcherHandler, error) {
	return &assertBaseHandler{
		message: fac.message,
	}, nil
}

type assertContains struct {
	assertBase

	text     string
	expected bool
}

func (a *assertContains) String() string {
	return fmt.Sprintf("assertContains{message: %s text: %s expected: %t}", a.message, a.text, a.expected)
}

type assertContainsHandler struct {
	assertContains

	seen bool
}

func (h *assertContainsHandler) Line(line string) error {
	if strings.Contains(line, h.text) {
		h.seen = true
	}
	return nil
}

func (h *assertContainsHandler) Finish() error {
	if h.seen != h.expected {
		return h.fail()
	}
	return nil
}

type assertContainsFactory struct {
	assertContains
}

func (fac *assertContainsFactory) New() (WatcherHandler, error) {
	return &assertContainsHandler{
		assertContains: fac.assertContains,
	}, nil
}

// AssertContains returns a factory of log handlers which check that the given
// text is contained in the log output.
func AssertContains(text, message string) WatcherHandlerFactory {
	return &assertContainsFactory{
		assertContains: assertContains{
			assertBase: assertBase{message},
			text:       text,
			expected:   true,
		},
	}
}

// AssertNotContains returns a factory of log handlers which check that the
// given text is not contained in the log output.
func AssertNotContains(text, message string) WatcherHandlerFactory {
	return &assertContainsFactory{
		assertContains: assertContains{
			assertBase: assertBase{message},
			text:       text,
			expected:   false,
		},
	}
}

type assertJSONContains struct {
	assertBase

	key      string
	value    string
	expected bool
}

func (a *assertJSONContains) String() string {
	return fmt.Sprintf("assertJSONContains{message: %s key: %s value: %s expected: %t}", a.message, a.key, a.value, a.expected)
}

type assertJSONContainsHandler struct {
	assertJSONContains

	seen bool
}

func (h *assertJSONContainsHandler) Line(line string) error {
	var kvs map[string]interface{}
	if err := json.Unmarshal([]byte(line), &kvs); err != nil {
		return nil
	}

	// TODO: Support arbitrary nested paths as keys.
	v := kvs[h.key]
	if v == nil {
		return nil
	}

	// TODO: Support other types.
	switch v.(type) {
	case string:
		if v == h.value {
			h.seen = true
		}
	}

	return nil
}

func (h *assertJSONContainsHandler) Finish() error {
	if h.seen != h.expected {
		return h.fail()
	}
	return nil
}

type assertJSONContainsFactory struct {
	assertJSONContains
}

func (fac *assertJSONContainsFactory) New() (WatcherHandler, error) {
	return &assertJSONContainsHandler{
		assertJSONContains: fac.assertJSONContains,
	}, nil
}

// AssertJSONContains returns a factory of log handlers which check that the
// given key/value pair is contained encoded as JSON in the log output.
func AssertJSONContains(key, value, message string) WatcherHandlerFactory {
	return &assertJSONContainsFactory{
		assertJSONContains: assertJSONContains{
			assertBase: assertBase{message},
			key:        key,
			value:      value,
			expected:   true,
		},
	}
}

// AssertNotJSONContains returns a factory of log handlers which check that the
// given key/value pair is not contained encoded as JSON in the log output.
func AssertNotJSONContains(key, value, message string) WatcherHandlerFactory {
	return &assertJSONContainsFactory{
		assertJSONContains: assertJSONContains{
			assertBase: assertBase{message},
			key:        key,
			value:      value,
			expected:   false,
		},
	}
}
