package stake

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
)

const beneficiaryFieldName = "Beneficiary:"

// allowanceDescription is a description of an allowance.
type allowanceDescription struct {
	beneficiary api.Address
	self        bool
	amount      quantity.Quantity
}

// byAmountAddress sorts the allowanceDescription list by:
// 1. decreasing amount,
// 2. increasing address.
//
// Later criteria is only applicable when multiple allowances are equal
// according to preceding criteria.
type byAmountAddress []allowanceDescription

func (a byAmountAddress) Len() int {
	return len(a)
}

func (a byAmountAddress) Less(i, j int) bool {
	if a[i].amount.Cmp(&a[j].amount) == 0 {
		return a[i].beneficiary.String() < a[j].beneficiary.String()
	}
	return a[i].amount.Cmp(&a[j].amount) > 0
}

func (a byAmountAddress) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// prettyPrintAllowanceDescriptions pretty-prints the given list of allowance
// descriptions.
func prettyPrintAllowanceDescriptions(
	ctx context.Context,
	allowDescriptions []allowanceDescription,
	prefix string,
	w io.Writer,
) {
	fmt.Fprintf(w, "%sAllowances:\n", prefix)

	sort.Sort(byAmountAddress(allowDescriptions))

	// Get the length of name of the longest field to display for each
	// element so we can align all values.
	lenLongest := lenLongestString(beneficiaryFieldName, amountFieldName)

	for _, desc := range allowDescriptions {
		fmt.Fprintf(w, "%s  - %-*s %s", prefix, lenLongest, beneficiaryFieldName, desc.beneficiary)
		if desc.self {
			fmt.Fprintf(w, " (self)")
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s    %-*s ", prefix, lenLongest, amountFieldName)
		token.PrettyPrintAmount(ctx, desc.amount, w)
		fmt.Fprintln(w)
	}
}

// prettyPrintAllowances pretty-prints the given incoming allowances to the
// given account.
func prettyPrintAllowances(
	ctx context.Context,
	addr api.Address,
	allowances map[api.Address]quantity.Quantity,
	prefix string,
	w io.Writer,
) {
	totalAllowanceAmount := prettyprint.NewQuantity()

	allowanceDescs := make([]allowanceDescription, 0, len(allowances))

	for beneficiary, amount := range allowances {
		allowDesc := allowanceDescription{
			beneficiary,
			beneficiary.Equal(addr),
			amount,
		}
		allowanceDescs = append(allowanceDescs, allowDesc)
		totalAllowanceAmount.Add(prettyprint.NewFromQuanQuantity(&allowDesc.amount))
	}

	fmt.Fprintf(w, "%sTotal: ", prefix)
	token.PrettyPrintAmount(ctx, totalAllowanceAmount, w)
	fmt.Fprintln(w)

	sort.Sort(byAmountAddress(allowanceDescs))
	prettyPrintAllowanceDescriptions(ctx, allowanceDescs, prefix, w)
}
