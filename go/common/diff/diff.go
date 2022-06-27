// Package diff implements helpers for comparing objects.
package diff

import (
	"fmt"

	"github.com/goki/go-difflib/difflib"
)

// Number of surrounding lines to show in unified diff.
const unifiedDiffContextLines = 3

// UnifiedDiffString returns unified diff between the given actual and expected
// strings.
//
// actualName and expectedName are the names of the "files" in the unified diff
// header.
func UnifiedDiffString(actual, expected, actualName, expectedName string) (string, error) {
	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(actual),
		B:        difflib.SplitLines(expected),
		FromFile: actualName,
		ToFile:   expectedName,
		Context:  unifiedDiffContextLines,
	}
	diffStr, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return "", fmt.Errorf("failed to obtain unified diff: %w", err)
	}
	return diffStr, nil
}
