package common

// argSeparator is the argument separator token.
const argSeparator = "--"

// TrimArgs removes all arguments in the argument list occurring before the "--" separator. The
// first argument is treated as the binary name (as in os.Args) and is left unchanged.
//
// If the argument list does not include the separator, a slice containing only the first argument
// is returned.
//
// It is an error to call this function with an empty slice.
func TrimArgs(osArgs []string) []string {
	if len(osArgs) < 1 {
		panic("TrimArgs called with an empty argument list")
	}

	for i, w := range osArgs {
		if w == argSeparator {
			return append([]string{osArgs[0]}, osArgs[i+1:]...)
		}
	}
	return osArgs[0:1]
}
