use std::collections::BTreeMap;

use anyhow::anyhow;
use io_context::Context;

use crate::{
    common::{
        cbor,
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
    pub fn account(&self, ctx: Context, address: Address) -> Result<Account, StateError> {
        match self.mkvs.get(ctx, &AccountsKeyFmt(address).encode()) {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))
            }
            Ok(None) => Ok(Account::default()),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    fn load_stored_balance<K: KeyFormat>(
        &self,
        ctx: Context,
        key_format: K,
    ) -> Result<Quantity, StateError> {
        match self.mkvs.get(ctx, &key_format.encode()) {
            Ok(Some(b)) => {
                cbor::from_slice(&b).map_err(|err| StateError::Unavailable(anyhow!(err)))
            }
            Ok(None) => Ok(Quantity::default()),
            Err(err) => Err(StateError::Unavailable(anyhow!(err))),
        }
    }

    /// Returns the total supply.
    pub fn total_supply(&self, ctx: Context) -> Result<Quantity, StateError> {
        self.load_stored_balance(ctx, TotalSupplyKeyFmt(()))
    }

    /// Returns the balance of the global common pool.
    pub fn common_pool(&self, ctx: Context) -> Result<Quantity, StateError> {
        self.load_stored_balance(ctx, CommonPoolKeyFmt(()))
    }

    /// Returns the last block fees balance.
    pub fn last_block_fees(&self, ctx: Context) -> Result<Quantity, StateError> {
        self.load_stored_balance(ctx, LastBlockFees(()))
    }

    /// Returns the governance deposits balance.
    pub fn governance_deposits(&self, ctx: Context) -> Result<Quantity, StateError> {
        self.load_stored_balance(ctx, GovernanceDepositsKeyFmt(()))
    }

    /// Returns the non-empty addresses from the staking ledger.
    pub fn addresses(&self, ctx: Context) -> Result<Vec<Address>, StateError> {
        let mut it = self.mkvs.iter(ctx);
        it.seek(&AccountsKeyFmt::default().encode_partial(0));

        Ok(it
            .map_while(|(key, _)| AccountsKeyFmt::decode(&key))
            .map(|AccountsKeyFmt(addr)| addr)
            .collect())
    }

    /// Returns the delegation.
    pub fn delegation(
        &self,
        ctx: Context,
        delegator_addr: Address,
        escrow_addr: Address,
    ) -> Result<Delegation, StateError> {
        match self.mkvs.get(
            ctx,
            &DelegationKeyFmt((escrow_addr, delegator_addr)).encode(),
        ) {
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
        ctx: Context,
    ) -> Result<BTreeMap<Address, BTreeMap<Address, Delegation>>, StateError> {
        let mut it = self.mkvs.iter(ctx);
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
        ctx: Context,
        delegator_addr: Address,
        escrow_addr: Address,
        epoch: EpochTime,
    ) -> Result<DebondingDelegation, StateError> {
        match self.mkvs.get(
            ctx,
            &DebondingDelegationKeyFmt((delegator_addr, escrow_addr, epoch)).encode(),
        ) {
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
        ctx: Context,
    ) -> Result<BTreeMap<Address, BTreeMap<Address, Vec<DebondingDelegation>>>, StateError> {
        let mut it = self.mkvs.iter(ctx);
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
