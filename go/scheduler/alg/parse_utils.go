package alg

// Utilities for parsing string representation of transactions / location sets.

import (
	"bufio"
	"errors"
	"fmt"
	"unicode"
)

func skip_spaces(r *bufio.Reader) error {
	var ch rune
	var err error
	for {
		if ch, _, err = r.ReadRune(); err != nil {
			return err
		}
		if !unicode.IsSpace(ch) {
			r.UnreadRune()
			return nil
		}
	}
}

func get_nonspace_rune(r *bufio.Reader) (ch rune, err error) {
	if err = skip_spaces(r); err != nil {
		return 0, err
	}
	ch, _, err = r.ReadRune()
	return ch, err
}

func expect_rune(expect rune, r *bufio.Reader) error {
	actual, err := get_nonspace_rune(r)
	if err != nil {
		return err
	}
	if actual == expect {
		return nil // consume the rune
	}
	r.UnreadRune()
	return errors.New(fmt.Sprintf("Expected %c, got %c", expect, actual))
}
