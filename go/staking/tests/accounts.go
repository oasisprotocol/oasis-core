package tests

import (
	"crypto/rand"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

// mustGenerateSigner returns a new memory signer or panics.
func mustGenerateSigner() signature.Signer {
	k, err := memorySigner.NewSigner(rand.Reader)
	if err != nil {
		panic(err)
	}

	return k
}

// account holds information about a staking account.
type account struct {
	Signer  signature.Signer
	Address api.Address
}

// newAccount returns a new account with a new memory signer or panics.
func newAccount() account {
	signer := mustGenerateSigner()
	return account{
		Signer:  signer,
		Address: api.NewAddress(signer.Public()),
	}
}

// AccountList holds information about a list of staking accounts.
type AccountList []account

// GetAddress returns the address of the i-th account in the list or panics.
//
// NOTE: Indexing is 1-based, NOT 0-based.
func (a AccountList) GetAddress(index int) api.Address {
	i := index - 1
	if i < 0 || i >= len(a) {
		panic(fmt.Sprintf("Account with index: %d doesn't exist", index))
	}
	return a[i].Address
}

// GetSigner returns the signer of the i-th account in the list or panics.
//
// NOTE: Indexing is 1-based, NOT 0-based.
func (a AccountList) GetSigner(index int) signature.Signer {
	i := index - 1
	if i < 0 || i >= len(a) {
		panic(fmt.Sprintf("Account with index: %d doesn't exist", index))
	}
	return a[i].Signer
}

// getAccount returns the i-th account in the list or panics.
//
// NOTE: Indexing is 1-based, NOT 0-based.
func (a AccountList) getAccount(index int) account {
	i := index - 1
	if i < 0 || i >= len(a) {
		panic(fmt.Sprintf("Account with index: %d doesn't exist", index))
	}
	return a[i]
}

// AddressFromString returns a staking account address from its string
// representation or panics.
func AddressFromString(s string) api.Address {
	var addr api.Address
	if err := addr.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return addr
}
