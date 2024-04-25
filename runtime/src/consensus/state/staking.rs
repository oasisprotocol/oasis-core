//! Staking state in the consensus layer.
use std::collections::BTreeMap;

use anyhow::anyhow;

use crate::{
    common::{
        key_format::{KeyFormat, KeyFormatAtom},
        quantity::Quantity,
    },
    consensus::{
        address::Address,
        beacon::EpochTime,
        staking::{Account, DebondingDelegation, Delegation},
        state::StateError,
    },
    key_format,
    storage::mkvs::ImmutableMKVS,
};

/// Consensus staking state wrapper.
pub struct ImmutableState<'a, T: ImmutableMKVS> {
    mkvs: &'a T,
}

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Constructs a new ImmutableMKVS.
    pub fn new(mkvs: &'a T) -> ImmutableState<'a, T> {
        ImmutableState { mkvs }
    }
}

key_format!(AccountsKeyFmt, 0x50, Address);
key_format!(TotalSupplyKeyFmt, 0x51, ());
key_format!(CommonPoolKeyFmt, 0x52, ());
key_format!(DelegationKeyFmt, 0x53, (Address, Address));
key_format!(
    DebondingDelegationKeyFmt,
    0x54,
    (Address, Address, EpochTime)
);
key_format!(DebondingQueueKeyFmt, 0x55, (EpochTime, Address, Address));
key_format!(ParametersKeyFmt, 0x56, ());
key_format!(LastBlockFees, 0x57, ());
key_format!(EpochSigningKeyFmt, 0x58, ());
key_format!(GovernanceDepositsKeyFmt, 0x59, ());

impl<'a, T: ImmutableMKVS> ImmutableState<'a, T> {
    /// Returns the staking account for the given account address.
    pub fn account(&self, address: Address) -> Result<Account, StateError> {
        match self.mkvs.get(&AccountsKeyFmt(address).encode()) {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))
            }
            Ok(None) => Ok(Account::default()),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    fn load_stored_balance<K: KeyFormat>(&self, key_format: K) -> Result<Quantity, StateError> {
        match self.mkvs.get(&key_format.encode()) {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))
            }
            Ok(None) => Ok(Quantity::default()),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns the total supply.
    pub fn total_supply(&self) -> Result<Quantity, StateError> {
        self.load_stored_balance(TotalSupplyKeyFmt(()))
    }

    /// Returns the balance of the global common pool.
    pub fn common_pool(&self) -> Result<Quantity, StateError> {
        self.load_stored_balance(CommonPoolKeyFmt(()))
    }

    /// Returns the last block fees balance.
    pub fn last_block_fees(&self) -> Result<Quantity, StateError> {
        self.load_stored_balance(LastBlockFees(()))
    }

    /// Returns the governance deposits balance.
    pub fn governance_deposits(&self) -> Result<Quantity, StateError> {
        self.load_stored_balance(GovernanceDepositsKeyFmt(()))
    }

    /// Returns the non-empty addresses from the staking ledger.
    pub fn addresses(&self) -> Result<Vec<Address>, StateError> {
        let mut it = self.mkvs.iter();
        it.seek(&AccountsKeyFmt::default().encode_partial(0));

        Ok(it
            .map_while(|(key, _)| AccountsKeyFmt::decode(&key))
            .map(|AccountsKeyFmt(addr)| addr)
            .collect())
    }

    /// Returns the delegation.
    pub fn delegation(
        &self,
        delegator_addr: Address,
        escrow_addr: Address,
    ) -> Result<Delegation, StateError> {
        match self
            .mkvs
            .get(&DelegationKeyFmt((escrow_addr, delegator_addr)).encode())
        {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))
            }
            Ok(None) => Ok(Delegation::default()),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns all active delegations.
    pub fn delegations(
        &self,
    ) -> Result<BTreeMap<Address, BTreeMap<Address, Delegation>>, StateError> {
        let mut it = self.mkvs.iter();
        it.seek(&DelegationKeyFmt::default().encode_partial(0));

        let mut result: BTreeMap<Address, BTreeMap<Address, Delegation>> = BTreeMap::new();

        while let Some((DelegationKeyFmt((escrow_addr, delegator_addr)), value)) = it
            .next()
            .and_then(|(key, value)| DelegationKeyFmt::decode(&key).zip(value.into()))
        {
            if !result.contains_key(&escrow_addr) {
                result.insert(escrow_addr.clone(), BTreeMap::new());
            }
            let inner = result.get_mut(&escrow_addr).expect("inner map must exist");

            inner.insert(
                delegator_addr,
                cbor::from_slice(&value).map_err(|err| StateError::Unavailable(anyhow!(err)))?,
            );
        }

        Ok(result)
    }

    /// Returns the debonding delegation.
    pub fn debonding_delegation(
        &self,
        delegator_addr: Address,
        escrow_addr: Address,
        epoch: EpochTime,
    ) -> Result<DebondingDelegation, StateError> {
        match self
            .mkvs
            .get(&DebondingDelegationKeyFmt((delegator_addr, escrow_addr, epoch)).encode())
        {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))
            }
            Ok(None) => Ok(DebondingDelegation::default()),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns all debonding delegations.
    pub fn debonding_delegations(
        &self,
    ) -> Result<BTreeMap<Address, BTreeMap<Address, Vec<DebondingDelegation>>>, StateError> {
        let mut it = self.mkvs.iter();
        it.seek(&DebondingDelegationKeyFmt::default().encode_partial(0));

        let mut result: BTreeMap<Address, BTreeMap<Address, Vec<DebondingDelegation>>> =
            BTreeMap::new();

        while let Some((DebondingDelegationKeyFmt((delegator_addr, escrow_addr, _)), value)) = it
            .next()
            .and_then(|(key, value)| DebondingDelegationKeyFmt::decode(&key).zip(value.into()))
        {
            if !result.contains_key(&escrow_addr) {
                result.insert(escrow_addr.clone(), BTreeMap::new());
            }
            let inner = result.get_mut(&escrow_addr).expect("inner map must exist");
            if !inner.contains_key(&delegator_addr) {
                inner.insert(delegator_addr.clone(), Vec::new());
            }
            let in_inner = inner
                .get_mut(&delegator_addr)
                .expect("inner vec in inner map must exist");
            in_inner.push(
                cbor::from_slice(&value).map_err(|err| StateError::Unavailable(anyhow!(err)))?,
            );
        }

        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        common::crypto::{hash::Hash, signature::PublicKey},
        consensus::staking::{EscrowAccount, GeneralAccount, SharePool},
        storage::mkvs::{
            interop::{Fixture, ProtocolServer},
            Root, RootType, Tree,
        },
    };

    use super::*;

    #[test]
    fn test_staking_state_interop() {
        // Keep in sync with go/consensus/cometbft/apps/staking/state/interop/interop.go.
        // If mock consensus state changes, update the root hash bellow.
        // See protocol server stdout for hash.
        // To make the hash show up during tests, run "cargo test" as
        // "cargo test -- --nocapture".

        // Setup protocol server with initialized mock consensus state.
        let server = ProtocolServer::new(Fixture::ConsensusMock.into());
        let mock_consensus_root = Root {
            version: 1,
            root_type: RootType::State,
            hash: Hash::from("8e39bf193f8a954ab8f8d7cb6388c591fd0785ea060bbd8e3752e266b54499d3"),
            ..Default::default()
        };
        let mkvs = Tree::builder()
            .with_capacity(100_000, 10_000_000)
            .with_root(mock_consensus_root)
            .build(server.read_sync());
        let staking_state = ImmutableState::new(&mkvs);

        let pk =
            PublicKey::from("7e57baaad01fffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let pk2 =
            PublicKey::from("7e57baaad02fffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let pk3 =
            PublicKey::from("7e57baaad03fffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let expected_addrs = vec![
            Address::from_pk(&pk),
            Address::from_pk(&pk2),
            Address::from_pk(&pk3),
        ];

        // Test all addresses and accounts.
        let addrs = staking_state
            .addresses()
            .expect("addresses query should work");
        assert_eq!(expected_addrs, addrs, "expected addresses should match");

        let mut accounts = Vec::new();
        for addr in &addrs {
            let acc = staking_state
                .account(addr.clone())
                .expect("accounts query should work");
            accounts.push(acc);
        }

        let expected_accounts = vec![
            Account {
                general: GeneralAccount {
                    balance: Quantity::from(23u32),
                    nonce: 13,
                    ..Default::default()
                },
                escrow: EscrowAccount {
                    active: SharePool {
                        balance: Quantity::from(100u32),
                        total_shares: Quantity::from(10u32),
                    },
                    debonding: SharePool {
                        balance: Quantity::from(5u32),
                        total_shares: Quantity::from(5u32),
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            Account {
                general: GeneralAccount {
                    balance: Quantity::from(23u32),
                    nonce: 1,
                    ..Default::default()
                },
                escrow: EscrowAccount {
                    active: SharePool {
                        balance: Quantity::from(500u32),
                        total_shares: Quantity::from(5u32),
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            Account {
                general: GeneralAccount {
                    balance: Quantity::from(113u32),
                    nonce: 17,
                    ..Default::default()
                },
                escrow: EscrowAccount {
                    active: SharePool {
                        balance: Quantity::from(400u32),
                        total_shares: Quantity::from(35u32),
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
        ];
        assert_eq!(
            expected_accounts, accounts,
            "expected addresses should match"
        );

        // Test all delegations.
        let delegations = staking_state
            .delegations()
            .expect("delegations query should work");
        for (escrow_addr, dels) in &delegations {
            for (delegator_addr, del) in dels.clone() {
                let d = staking_state
                    .delegation(delegator_addr, escrow_addr.clone())
                    .expect("delegation query should work");
                assert_eq!(del, d, "delegation should match")
            }
        }

        let mut expected_delegations: BTreeMap<Address, BTreeMap<Address, Delegation>> =
            BTreeMap::new();
        // Delegations to address[0].
        expected_delegations.insert(
            addrs[0].clone(),
            [
                (
                    addrs[0].clone(),
                    Delegation {
                        shares: Quantity::from(5u32),
                    },
                ),
                (
                    addrs[1].clone(),
                    Delegation {
                        shares: Quantity::from(5u32),
                    },
                ),
            ]
            .iter()
            .cloned()
            .collect(),
        );
        // Delegations to address[1].
        expected_delegations.insert(
            addrs[1].clone(),
            [(
                addrs[2].clone(),
                Delegation {
                    shares: Quantity::from(5u32),
                },
            )]
            .iter()
            .cloned()
            .collect(),
        );
        // Delegations to address[2].
        expected_delegations.insert(
            addrs[2].clone(),
            [
                (
                    addrs[0].clone(),
                    Delegation {
                        shares: Quantity::from(20u32),
                    },
                ),
                (
                    addrs[1].clone(),
                    Delegation {
                        shares: Quantity::from(6u32),
                    },
                ),
                (
                    addrs[2].clone(),
                    Delegation {
                        shares: Quantity::from(10u32),
                    },
                ),
            ]
            .iter()
            .cloned()
            .collect(),
        );
        assert_eq!(
            expected_delegations, delegations,
            "expected delegations should match"
        );

        // Test all debonding delegations.
        let debonding_delegations = staking_state
            .debonding_delegations()
            .expect("debonding delegations query should work");
        for (escrow_addr, debss) in &debonding_delegations {
            for (delegator_addr, debs) in debss {
                for deb in debs {
                    let d = staking_state
                        .debonding_delegation(
                            delegator_addr.clone(),
                            escrow_addr.clone(),
                            deb.debond_end_time,
                        )
                        .expect("debonding delegation query should work");
                    assert_eq!(deb.clone(), d, "debonding delegation should match")
                }
            }
        }
        let mut expected_debonding: BTreeMap<Address, BTreeMap<Address, Vec<DebondingDelegation>>> =
            BTreeMap::new();
        // Debonding delegations in address[0].
        expected_debonding.insert(
            addrs[0].clone(),
            [
                (
                    addrs[0].clone(),
                    vec![DebondingDelegation {
                        shares: Quantity::from(1u32),
                        debond_end_time: 33,
                    }],
                ),
                (
                    addrs[1].clone(),
                    vec![
                        DebondingDelegation {
                            shares: Quantity::from(1u32),
                            debond_end_time: 15,
                        },
                        DebondingDelegation {
                            shares: Quantity::from(1u32),
                            debond_end_time: 21,
                        },
                    ],
                ),
                (
                    addrs[2].clone(),
                    vec![DebondingDelegation {
                        shares: Quantity::from(2u32),
                        debond_end_time: 100,
                    }],
                ),
            ]
            .iter()
            .cloned()
            .collect(),
        );
        assert_eq!(
            expected_debonding, debonding_delegations,
            "expected debonding delegations should match"
        );

        // Test all stored balances.
        let total_supply = staking_state
            .total_supply()
            .expect("total supply query should work");
        assert_eq!(
            Quantity::from(10000u32),
            total_supply,
            "total supply should match expected"
        );

        let common_pool = staking_state
            .common_pool()
            .expect("common pool query should work");
        assert_eq!(
            Quantity::from(1000u32),
            common_pool,
            "common pool should match expected"
        );

        let last_block_fees = staking_state
            .last_block_fees()
            .expect("last block fees query should work");
        assert_eq!(
            Quantity::from(33u32),
            last_block_fees,
            "last block fees should match expected"
        );

        let governance_deposits = staking_state
            .governance_deposits()
            .expect("governance deposits query should work");
        assert_eq!(
            Quantity::from(12u32),
            governance_deposits,
            "governance deposits should match expected"
        );
    }
}
