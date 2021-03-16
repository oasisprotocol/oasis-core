package stake

import (
	"context"
	"fmt"
	"io"
	"sort"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
)

const endTimeFieldName = "End Time:"

// delegationDescription is a description of a (debonding) delegation.
type delegationDescription struct {
	address api.Address
	self    bool
	amount  quantity.Quantity
	shares  quantity.Quantity
	endTime beacon.EpochTime
}

// byEndTimeAmountAddress sorts the delegationDescription list by:
// 1. increasing end time (only applicable to debonding delegations),
// 2. decreasing amount,
// 3. increasing address.
//
// Later criteria is only applicable when multiple delegations are equal
// according to preceding criteria.
type byEndTimeAmountAddress []delegationDescription

func (a byEndTimeAmountAddress) Len() int {
	return len(a)
}

func (a byEndTimeAmountAddress) Less(i, j int) bool {
	if a[i].endTime == a[j].endTime {
		if a[i].amount.Cmp(&a[j].amount) == 0 {
			return a[i].address.String() < a[j].address.String()
		}
		return a[i].amount.Cmp(&a[j].amount) > 0
	}
	return a[i].endTime < a[j].endTime
}

func (a byEndTimeAmountAddress) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

// delegationAmount returns the number of base units the given amount of shares
// represent in the given share pool.
func delegationAmount(shares quantity.Quantity, sharePool api.SharePool) quantity.Quantity {
	amount, _ := sharePool.StakeForShares(&shares)
	return *amount
}

// lenLongestString returns the length of the longest string passed to it.
func lenLongestString(strs ...string) int {
	max := 0
	for _, s := range strs {
		if len(s) > max {
			max = len(s)
		}
	}
	return max
}

// prettyPrintDelegationDescriptions pretty-prints the given list of delegation
// descriptions.
func prettyPrintDelegationDescriptions(
	ctx context.Context,
	delDescriptions []delegationDescription,
	addressFieldName string,
	prefix string,
	w io.Writer,
) {
	fmt.Fprintf(w, "%sDelegations:\n", prefix)

	sort.Sort(byEndTimeAmountAddress(delDescriptions))

	// Get the length of name of the longest field to display for each
	// element so we can align all values.
	// NOTE: We assume the delegation descriptions are either all for
	// (active) delegations or all for debonding delegations.
	lenLongest := 0
	if delDescriptions[0].endTime == beacon.EpochInvalid {
		// Active delegations.
		lenLongest = lenLongestString(addressFieldName, amountFieldName)
	} else {
		// Debonding delegations.
		lenLongest = lenLongestString(addressFieldName, amountFieldName, endTimeFieldName)
	}

	for _, desc := range delDescriptions {
		fmt.Fprintf(w, "%s  - %-*s %s", prefix, lenLongest, addressFieldName, desc.address)
		if desc.self {
			fmt.Fprintf(w, " (self)")
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s    %-*s ", prefix, lenLongest, amountFieldName)
		token.PrettyPrintAmount(ctx, desc.amount, w)
		fmt.Fprintf(w, " (%s shares)\n", desc.shares)
		if desc.endTime != beacon.EpochInvalid {
			fmt.Fprintf(w, "%s    %-*s epoch %d\n", prefix, lenLongest, endTimeFieldName, desc.endTime)
		}
	}
}

// prettyPrintAccountBalanceAndDelegationsFrom pretty-prints the given account's
// general balance and (outgoing) delegations from this account.
func prettyPrintAccountBalanceAndDelegationsFrom(
	ctx context.Context,
	addr api.Address,
	generalAccount api.GeneralAccount,
	actDelegationInfos map[api.Address]*api.DelegationInfo,
	debDelegationInfos map[api.Address][]*api.DebondingDelegationInfo,
	prefix string,
	w io.Writer,
) {
	availableAmount := generalAccount.Balance
	totalAmount := prettyprint.NewFromQuanQuantity(&availableAmount)
	totalActDelegationsAmount := prettyprint.NewQuantity()
	totalDebDelegationsAmount := prettyprint.NewQuantity()

	actDelegationDescs := make([]delegationDescription, 0, len(actDelegationInfos))

	for delAddr, delInfo := range actDelegationInfos {
		delDesc := delegationDescription{
			delAddr,
			delAddr.Equal(addr),
			delegationAmount(delInfo.Shares, delInfo.Pool),
			delInfo.Shares,
			beacon.EpochInvalid,
		}
		actDelegationDescs = append(actDelegationDescs, delDesc)
		totalActDelegationsAmount.Add(prettyprint.NewFromQuanQuantity(&delDesc.amount))
	}
	totalAmount.Add(totalActDelegationsAmount)

	debDelegationDescs := make([]delegationDescription, 0, len(debDelegationInfos))

	for delAddr, delInfoList := range debDelegationInfos {
		for _, delInfo := range delInfoList {
			delDesc := delegationDescription{
				delAddr,
				delAddr.Equal(addr),
				delegationAmount(delInfo.Shares, delInfo.Pool),
				delInfo.Shares,
				delInfo.DebondEndTime,
			}
			debDelegationDescs = append(debDelegationDescs, delDesc)
			totalDebDelegationsAmount.Add(prettyprint.NewFromQuanQuantity(&delDesc.amount))
		}
	}
	totalAmount.Add(totalDebDelegationsAmount)

	fmt.Fprintf(w, "%sTotal: ", prefix)
	token.PrettyPrintAmount(ctx, totalAmount, w)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%sAvailable: ", prefix)
	token.PrettyPrintAmount(ctx, availableAmount, w)
	fmt.Fprintln(w)

	innerPrefix := prefix + "  "
	addressFieldName := "To:"

	if len(actDelegationDescs) > 0 {
		fmt.Fprintf(w, "%sActive Delegations from this Account:\n", prefix)
		fmt.Fprintf(w, "%sTotal: ", innerPrefix)
		token.PrettyPrintAmount(ctx, totalActDelegationsAmount, w)
		fmt.Fprintln(w)

		sort.Sort(byEndTimeAmountAddress(actDelegationDescs))
		prettyPrintDelegationDescriptions(ctx, actDelegationDescs, addressFieldName, innerPrefix, w)
	}

	if len(debDelegationDescs) > 0 {
		fmt.Fprintf(w, "%sDebonding Delegations from this Account:\n", prefix)
		fmt.Fprintf(w, "%sTotal: ", innerPrefix)
		token.PrettyPrintAmount(ctx, totalDebDelegationsAmount, w)
		fmt.Fprintln(w)

		sort.Sort(byEndTimeAmountAddress(debDelegationDescs))
		prettyPrintDelegationDescriptions(ctx, debDelegationDescs, addressFieldName, innerPrefix, w)
	}
}

// prettyPrintDelegationsTo pretty-prints the given incoming (debonding)
// delegations to the given escrow account.
func prettyPrintDelegationsTo(
	ctx context.Context,
	addr api.Address,
	sharePool api.SharePool,
	delegations interface{},
	prefix string,
	w io.Writer,
) {
	delDescs := []delegationDescription{}

	switch dels := delegations.(type) {
	case map[api.Address]*api.Delegation:
		for delAddr, del := range dels {
			delDesc := delegationDescription{
				delAddr,
				delAddr.Equal(addr),
				delegationAmount(del.Shares, sharePool),
				del.Shares,
				beacon.EpochInvalid,
			}
			delDescs = append(delDescs, delDesc)
		}
	case map[api.Address][]*api.DebondingDelegation:
		for delAddr, delList := range dels {
			for _, del := range delList {
				delDesc := delegationDescription{
					delAddr,
					delAddr.Equal(addr),
					delegationAmount(del.Shares, sharePool),
					del.Shares,
					del.DebondEndTime,
				}
				delDescs = append(delDescs, delDesc)
			}
		}
	default:
		fmt.Fprintf(w, "%sERROR: Unsupported delegations type: %T)\n", prefix, dels)
		return
	}

	fmt.Fprintf(w, "%sTotal: ", prefix)
	token.PrettyPrintAmount(ctx, sharePool.Balance, w)
	fmt.Fprintf(w, " (%s shares)", sharePool.TotalShares)
	fmt.Fprintln(w)

	addressFieldName := "From:"

	sort.Sort(byEndTimeAmountAddress(delDescs))
	prettyPrintDelegationDescriptions(ctx, delDescs, addressFieldName, prefix, w)
}
