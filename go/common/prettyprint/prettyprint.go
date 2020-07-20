package prettyprint

import (
	"context"
	"io"
)

// PrettyPrinter is an interface for types that know how to pretty
// print themselves (e.g., to be displayed in a CLI).
type PrettyPrinter interface {
	// PrettyPrint writes a pretty-printed representation of the type
	// to the given writer.
	PrettyPrint(ctx context.Context, prefix string, w io.Writer)

	// PrettyType returns a representation of the type that can be used for pretty printing.
	PrettyType() (interface{}, error)
}
