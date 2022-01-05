//! Consensus staking structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/staking/api.
//!
use std::collections::BTreeMap;

use crate::{
    common::quantity::Quantity,
    consensus::{address::Address, beacon::EpochTime},
};

/// A stake transfer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Transfer {
    pub to: Address,
    pub amount: Quantity,
}

/// A withdrawal from an account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Withdraw {
    pub from: Address,
    pub amount: Quantity,
}

/// A stake escrow.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Escrow {
    pub account: Address,
    pub amount: Quantity,
}

/// A reclaim escrow.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ReclaimEscrow {
    pub account: Address,
    pub shares: Quantity,
}

/// Kind of staking threshold.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, cbor::Encode, cbor::Decode)]
#[repr(i32)]
pub enum ThresholdKind {
    /// Entity staking threshold.
    KindEntity = 0,
    /// Validator node staking threshold.
    KindNodeValidator = 1,
    /// Compute node staking threshold.
    KindNodeCompute = 2,
    /// Keymanager node staking threshold.
    KindNodeKeyManager = 4,
    /// Compute runtime staking threshold.
    KindRuntimeCompute = 5,
    /// Keymanager runtime staking threshold.
    KindRuntimeKeyManager = 6,
}

/// Entry in the staking ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Account {
    #[cbor(optional)]
    #[cbor(default)]
    pub general: GeneralAccount,

    #[cbor(optional)]
    #[cbor(default)]
    pub escrow: EscrowAccount,
}

/// General purpose account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct GeneralAccount {
    #[cbor(optional)]
    #[cbor(default)]
    pub balance: Quantity,

    #[cbor(optional)]
    #[cbor(default)]
    pub nonce: u64,

    #[cbor(optional)]
    pub allowances: Option<BTreeMap<Address, Quantity>>,
}

/// Escrow account.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct EscrowAccount {
    #[cbor(optional)]
    #[cbor(default)]
    pub active: SharePool,

    #[cbor(optional)]
    #[cbor(default)]
    pub debonding: SharePool,

    #[cbor(optional)]
    #[cbor(default)]
    pub commission_schedule: CommissionSchedule,

    #[cbor(optional)]
    #[cbor(default)]
    pub stake_accumulator: StakeAccumulator,
}

/// Combined balance of serval entries, the relative sizes of which are tracked through shares.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct SharePool {
    #[cbor(optional)]
    #[cbor(default)]
    pub balance: Quantity,

    #[cbor(optional)]
    #[cbor(default)]
    pub total_shares: Quantity,
}

/// Defines a list of commission rates and commission rate bounds with their starting times.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct CommissionSchedule {
    #[cbor(optional)]
    pub rates: Option<Vec<CommissionRateStep>>,

    #[cbor(optional)]
    pub bounds: Option<Vec<CommissionRateBoundStep>>,
}

/// Commission rate and its starting time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct CommissionRateStep {
    pub start: EpochTime,
    pub rate: Quantity,
}

/// Commission rate bound and its starting time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct CommissionRateBoundStep {
    #[cbor(optional)]
    #[cbor(default)]
    pub start: EpochTime,

    #[cbor(optional)]
    #[cbor(default)]
    pub rate_min: Quantity,

    #[cbor(optional)]
    #[cbor(default)]
    pub rate_max: Quantity,
}

/// Per escrow account stake accumulator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct StakeAccumulator {
    #[cbor(optional)]
    pub claims: Option<BTreeMap<StakeClaim, Vec<StakeThreshold>>>,
}

/// Unique stake claim identifier.
pub type StakeClaim = String;

/// Stake threshold used in the stake accumulator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct StakeThreshold {
    #[cbor(optional)]
    pub global: Option<ThresholdKind>,

    #[cbor(rename = "const")]
    #[cbor(optional)]
    pub constant: Option<Quantity>,
}

/// Delegation descriptor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct Delegation {
    pub shares: Quantity,
}

/// Debonding delegation descriptor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct DebondingDelegation {
    pub shares: Quantity,

    #[cbor(rename = "debond_end")]
    pub debond_end_time: EpochTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::address::{COMMON_POOL_ADDRESS, GOVERNANCE_DEPOSITS_ADDRESS};

    #[test]
    fn test_consistent_accounts() {
        let tcs = vec![
        ("oA==", Account::default()),
        (
            "oWdnZW5lcmFsomVub25jZRghZ2JhbGFuY2VBCg==",
            Account {
                general: GeneralAccount {
                    balance: Quantity::from(10u32),
                    nonce: 33,
                    ..Default::default()
                },
                ..Default::default()
            },
        ),
        (
            "oWdnZW5lcmFsoWphbGxvd2FuY2VzolUAdU/0RxQ6XsX0cbMPhna5TVaxV1BBIVUA98Te1iET4sKC6oZyI6VE7VXWum5BZA==",
            {
                Account {
                    general: GeneralAccount {
                        allowances: Some([
                            (COMMON_POOL_ADDRESS.clone(), Quantity::from(100u32)),
                            (GOVERNANCE_DEPOSITS_ADDRESS.clone(), Quantity::from(33u32))
                        ].iter().cloned().collect()),
                        ..Default::default()
                        },
                    ..Default::default()
                }
                },
        ),
        (
            "oWZlc2Nyb3ejZmFjdGl2ZaJnYmFsYW5jZUIETGx0b3RhbF9zaGFyZXNBC3FzdGFrZV9hY2N1bXVsYXRvcqFmY2xhaW1zoWZlbnRpdHmCoWVjb25zdEFNoWZnbG9iYWwCc2NvbW1pc3Npb25fc2NoZWR1bGWhZmJvdW5kc4GjZXN0YXJ0GCFocmF0ZV9tYXhCA+hocmF0ZV9taW5BCg==",
            Account {
                escrow: EscrowAccount {
                    active: SharePool{
                        balance: Quantity::from(1100u32),
                        total_shares: Quantity::from(11u32),
                    },
                    debonding: SharePool::default(),
                    commission_schedule: CommissionSchedule {
                        bounds: Some(vec![CommissionRateBoundStep{
                            start: 33,
                            rate_min: Quantity::from(10u32),
                            rate_max: Quantity::from(1000u32),
                        }]),
                        ..Default::default()
                    },
                    stake_accumulator: StakeAccumulator {
                        claims: Some([
                            (
                                "entity".to_string(),
                                vec![
                                    StakeThreshold{
                                        constant: Some(Quantity::from(77u32)),
                                        ..Default::default()
                                    },
                                    StakeThreshold{
                                        global: Some(ThresholdKind::KindNodeCompute),
                                        ..Default::default()
                                    },
                                ]
                            )
                        ].iter().cloned().collect())
                    }
                },
                ..Default::default()
            },
        )
    ];
        for (encoded_base64, rr) in tcs {
            let dec: Account = cbor::from_slice(&base64::decode(encoded_base64).unwrap())
                .expect("account should deserialize correctly");
            assert_eq!(dec, rr, "decoded account should match the expected value");
        }
    }

    #[test]
    fn test_consistent_delegations() {
        let tcs = vec![
            ("oWZzaGFyZXNA", Delegation::default()),
            (
                "oWZzaGFyZXNBZA==",
                Delegation {
                    shares: Quantity::from(100u32),
                },
            ),
        ];
        for (encoded_base64, rr) in tcs {
            let dec: Delegation = cbor::from_slice(&base64::decode(encoded_base64).unwrap())
                .expect("delegation should deserialize correctly");
            assert_eq!(dec, rr, "decoded account should match the expected value");
        }
    }

    #[test]
    fn test_consistent_debonding_delegations() {
        let tcs = vec![
            (
                "omZzaGFyZXNAamRlYm9uZF9lbmQA",
                DebondingDelegation::default(),
            ),
            (
                "omZzaGFyZXNBZGpkZWJvbmRfZW5kFw==",
                DebondingDelegation {
                    shares: Quantity::from(100u32),
                    debond_end_time: 23,
                },
            ),
        ];
        for (encoded_base64, rr) in tcs {
            let dec: DebondingDelegation =
                cbor::from_slice(&base64::decode(encoded_base64).unwrap())
                    .expect("debonding delegation should deserialize correctly");
            assert_eq!(dec, rr, "decoded account should match the expected value");
        }
    }
}
