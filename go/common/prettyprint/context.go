package prettyprint

var (
	// ContextKeyGenesisHash is the key to retrieve the Genesis document's hash
	// value from a context.
	ContextKeyGenesisHash = contextKey("genesis/hash")
	// ContextKeyTokenSymbol is the key to retrieve the token's ticker symbol
	// value from a context.
	ContextKeyTokenSymbol = contextKey("staking/token-symbol")
	// ContextKeyTokenValueExponent is the key to retrieve the token's value
	// base-10 exponent from a context.
	ContextKeyTokenValueExponent = contextKey("staking/token-value-exponent")
	// ContextKeyCommissionScheduleIndex is the key to retrieve the rate (bound)
	// index in a commission schedule (amendment).
	ContextKeyCommissionScheduleIndex = contextKey("staking/commission-schedule-index")
)

type contextKey string
