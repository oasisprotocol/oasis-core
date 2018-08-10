package alg

// Utilities for parsing string representation of transactions / location sets.

import (
	"fmt"
	"io"
	"unicode"
)

func skipSpaces(r io.RuneScanner) error {
	var ch rune
	var err error
	for {
		if ch, _, err = r.ReadRune(); err != nil {
			return err
		}
		if !unicode.IsSpace(ch) {
			// NB: if UnreadRune fails, caller cannot see the non-space rune!
			return r.UnreadRune()
		}
	}
}

func getNonspaceRune(r io.RuneScanner) (ch rune, err error) {
	if err = skipSpaces(r); err != nil {
		return 0, err
	}
	ch, _, err = r.ReadRune()
	return ch, err
}

func expectRune(expect rune, r io.RuneScanner) error {
	actual, err := getNonspaceRune(r)
	if err != nil {
		return err
	}
	if actual == expect {
		return nil // consume the rune
	}
	// If there is an error on UnreadRune(), the input stream is already in a bad state.
	_ = r.UnreadRune()
	return fmt.Errorf("Expected %c, got %c", expect, actual)
}
