package state

import "github.com/oasisprotocol/oasis-core/go/common/keyformat"

// rejectTransactionsKeyFmt is the key format used to disable transactions.
var deprecatedRejectTransactionsKeyFmt = keyformat.New(0x23) //nolint:deadcode,unused,varcheck
