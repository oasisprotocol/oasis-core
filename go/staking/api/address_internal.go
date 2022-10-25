package api

import "github.com/oasisprotocol/oasis-core/go/common/crypto/signature"

var (
	// CommonPoolAddress is the common pool address.
	// The address is reserved to prevent it being accidentally used in the actual ledger.
	//
	// oasis1qrmufhkkyyf79s5za2r8yga9gnk4t446dcy3a5zm
	CommonPoolAddress = NewReservedAddress(
		signature.NewPublicKey("1abe11edc001ffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)

	// FeeAccumulatorAddress is the per-block fee accumulator address.
	// It holds all fees from txs in a block which are later disbursed to validators appropriately.
	// The address is reserved to prevent it being accidentally used in the actual ledger.
	//
	// oasis1qqnv3peudzvekhulf8v3ht29z4cthkhy7gkxmph5
	FeeAccumulatorAddress = NewReservedAddress(
		signature.NewPublicKey("1abe11edfeeaccffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)

	// GovernanceDepositsAddress is the governance deposits address.
	// This address is reserved to prevent it from being accidentally used in the actual ledger.
	//
	// oasis1qp65laz8zsa9a305wxeslpnkh9x4dv2h2qhjz0ec
	GovernanceDepositsAddress = NewReservedAddress(
		signature.NewPublicKey("1abe11eddeaccfffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)

	// BurnAddress is the burn address.  Transfers sent to this address
	// are treated identically to token burn by the transfer originator.
	//
	// This address is reserved to prevent it beign accidentally used in
	// the actual ledger.
	//
	// oasis1qzq8u7xs328puu2jy524w3fygzs63rv3u5967970
	BurnAddress = func() Address {
		// Use h2c to generate a public key with an unknown private key.
		burnPublicKey := signature.HashToPublicKey(
			[]byte("oasis-core/reserved-address"),
			[]byte("Do Kwon Memorial SafeLunaRoseInu Burn Address"),
		)

		// And mark the address and public key as reserved.
		return NewReservedAddress(burnPublicKey)
	}()
)
