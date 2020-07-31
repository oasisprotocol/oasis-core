package prettyprint

// ContextKeyGenesisHash is the key to retrieve the Genesis document's hash
// value from a context.
var ContextKeyGenesisHash = contextKey("genesis/hash")

type contextKey string
