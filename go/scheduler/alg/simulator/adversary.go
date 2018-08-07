package simulator

// Adversary transaction generator filter.

// The configuration parameters control how the adversary submit spammy transactions to try to
// affect the system throughput -- essentially, can an adversary easily mount a
// denial-of-service attack.  For DOS-resilience, we want to primarily measure the amount of
// resources that the adversary needs versus the amount of additional resources that they
// system has to expend to maintain the same (or only mildly degraded) level of service
// (throughput, in this case).  Some of the attack vectors are easily blocked, e.g., raw number
// of transactions; others, e.g., transactions that accesses certain transactions that cause
// casacading access conflicts, may require complex analysis.
//
// - Percentage affected: the number of spammy versus real transactions.  This can be a real
//   number representing the probability of injecting a spam transaction, delaying Get() from
//   the underlying true TransactionSource.
//
// - Spam transaction batch size:  how many spammy transactions should be injected each time we
//   decide to mount an attack?
//
// - Number of addresses in each spammy transaction: how many read/write or write/write
//   conflict can the adversary create?
//
//   The address(es) to use for spammy transactions is another potential design parameter.  For
//   now, we can just spread this out among the highest-probability [m, ..., n)
//   contracts/accounts.  Note that m = 0 normally, but in case of logical sharding, m is a
//   negative number.  If logical sharding is by sender address, the adversary is assumed to be
//   able to create enough accounts so that the

type AdversaryConfig struct {
	injection_prob   float64
	spam_batch_size  uint
	target_addresses string
}
