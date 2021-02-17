package diff

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnifiedDiffString(t *testing.T) {
	require := require.New(t)

	testVectors := []struct {
		actual       string
		expected     string
		expectedDiff string
		valid        bool
	}{
		// Simple example.
		{
			"Bla\nFoo\nBar",
			"Bla\nBaz\nBar",
			`--- Actual
+++ Expected
@@ -1,3 +1,3 @@
 Bla
-Foo
+Baz
 Bar
`,
			true,
		},
		// Newline missing.
		{
			"Foo\nBar\nBaz",
			"Foo\nBar\nBaz\n",
			`--- Actual
+++ Expected
@@ -1,3 +1,4 @@
 Foo
 Bar
 Baz
+
`,
			true,
		},
		// Different indentation in a JSON string.
		{
			`{
    "foo": "bar"
}`,
			`{
  "foo": "bar"
}`,
			`--- Actual
+++ Expected
@@ -1,3 +1,3 @@
 {
-    "foo": "bar"
+  "foo": "bar"
 }
`,
			true,
		},
	}

	for _, v := range testVectors {

		actualDiff, err := UnifiedDiffString(v.actual, v.expected, "Actual", "Expected")
		if !v.valid {
			require.Errorf(err, "Obtaining unified diff should fail for:\n\nActual:\n%s\n\nExpected:\n%s\n", v.actual, v.expected)
			continue
		}
		require.NoErrorf(err, "Failed to obtain unified diff for:\n\nActual:\n%s\n\nExpected:\n%s\n", v.actual, v.expected)
		require.Equal(v.expectedDiff, actualDiff, "Obtained diff should equal expected diff")
	}
}
