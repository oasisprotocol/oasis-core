package prettyprint

import "io"

// PrettyPrinter is an interface for types that know how to pretty
// print themselves (e.g., to be displayed in a CLI).
type PrettyPrinter interface {
	// PrettyPrint writes a pretty-printed representation of the type
	// to the given writer.
	PrettyPrint(prefix string, w io.Writer)
}
