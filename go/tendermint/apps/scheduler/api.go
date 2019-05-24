package scheduler

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the scheduler application.
	TransactionTag byte = 0x06

	// AppName is the ABCI application name.
	AppName string = "999_scheduler"
)

const (
	// QueryTest (no merge)
	QueryTest = AppName + "/test"
)
