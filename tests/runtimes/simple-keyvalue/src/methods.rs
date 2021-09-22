//! Test method implementations.

use std::collections::BTreeMap;

use io_context::Context as IoContext;

use oasis_core_keymanager_client::KeyPairId;
use oasis_core_runtime::{
    common::{
        crypto::{hash::Hash, mrae::deoxysii::NONCE_SIZE},
        key_format::KeyFormat,
        versioned::Versioned,
    },
    consensus::{
        address::Address,
        roothash::{Message, RegistryMessage, StakingMessage},
        staking::{Account, Delegation},
        state::staking::ImmutableState as StakingImmutableState,
    },
    storage::MKVS,
    types::Error as RuntimeError,
};

use super::{crypto::EncryptionContext, types::*, Context, TxContext};

/// Implementation of the transaction methods supported by the test runtime.
pub struct Methods;

impl Methods {
    /// Gets runtime ID of the runtime.
    pub fn get_runtime_id(ctx: &mut TxContext, _args: ()) -> Result<Option<String>, String> {
        Ok(Some(format!("{:?}", ctx.parent.host_info.runtime_id)))
    }

    /// Queries all consensus accounts.
    /// Note: this is a transaction but could be a query in a non-test runtime.
    pub fn consensus_accounts(
        ctx: &mut TxContext,
        _args: (),
    ) -> Result<
        (
            BTreeMap<Address, Account>,
            BTreeMap<Address, BTreeMap<Address, Delegation>>,
        ),
        String,
    > {
        if ctx.parent.core.check_only {
            return Ok((Default::default(), Default::default()));
        }

        let state = StakingImmutableState::new(&ctx.parent.core.consensus_state);
        let mut result = BTreeMap::new();
        let addrs = state
            .addresses(IoContext::create_child(&ctx.parent.core.io_ctx))
            .map_err(|err| err.to_string())?;
        for addr in addrs {
            result.insert(
                addr.clone(),
                state
                    .account(IoContext::create_child(&ctx.parent.core.io_ctx), addr)
                    .map_err(|err| err.to_string())?,
            );
        }

        let delegations = state
            .delegations(IoContext::create_child(&ctx.parent.core.io_ctx))
            .map_err(|err| err.to_string())?;

        Ok((result, delegations))
    }

    fn check_nonce(ctx: &mut TxContext, nonce: u64) -> Result<(), String> {
        let nonce_key = NonceKeyFormat { nonce: nonce }.encode();
        match ctx
            .parent
            .core
            .runtime_state
            .get(IoContext::create_child(&ctx.parent.core.io_ctx), &nonce_key)
        {
            Some(_) => Err(format!("Duplicate nonce: {}", nonce)),
            None => {
                if !ctx.parent.core.check_only {
                    ctx.parent.core.runtime_state.insert(
                        IoContext::create_child(&ctx.parent.core.io_ctx),
                        &nonce_key,
                        &[0x1],
                    );
                }
                Ok(())
            }
        }
    }

    fn check_max_messages(ctx: &mut TxContext) -> Result<(), String> {
        if ctx.parent.core.max_messages < 1 {
            return Err("message limit too low".to_string());
        }
        Ok(())
    }

    /// Withdraw from the consensus layer into the runtime account.
    pub fn consensus_withdraw(ctx: &mut TxContext, args: Withdraw) -> Result<(), String> {
        Self::check_nonce(ctx, args.nonce)?;
        Self::check_max_messages(ctx)?;

        if ctx.parent.core.check_only {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Staking(Versioned::new(
            0,
            StakingMessage::Withdraw(args.withdraw.clone()),
        )));

        ctx.parent.core.runtime_state.insert(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            &PendingMessagesKeyFormat { index }.encode(),
            b"withdraw",
        );

        Ok(())
    }

    /// Transfer from the runtime account to another account in the consensus layer.
    pub fn consensus_transfer(ctx: &mut TxContext, args: Transfer) -> Result<(), String> {
        Self::check_nonce(ctx, args.nonce)?;
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Staking(Versioned::new(
            0,
            StakingMessage::Transfer(args.transfer.clone()),
        )));

        ctx.parent.core.runtime_state.insert(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            &PendingMessagesKeyFormat { index }.encode(),
            b"transfer",
        );

        Ok(())
    }

    /// Add escrow from the runtime account to an account in the consensus layer.
    pub fn consensus_add_escrow(ctx: &mut TxContext, args: AddEscrow) -> Result<(), String> {
        Self::check_nonce(ctx, args.nonce)?;
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Staking(Versioned::new(
            0,
            StakingMessage::AddEscrow(args.escrow.clone()),
        )));

        ctx.parent.core.runtime_state.insert(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            &PendingMessagesKeyFormat { index }.encode(),
            b"add_escrow",
        );

        Ok(())
    }

    /// Reclaim escrow to the runtime account.
    pub fn consensus_reclaim_escrow(
        ctx: &mut TxContext,
        args: ReclaimEscrow,
    ) -> Result<(), String> {
        Self::check_nonce(ctx, args.nonce)?;
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Staking(Versioned::new(
            0,
            StakingMessage::ReclaimEscrow(args.reclaim_escrow.clone()),
        )));

        ctx.parent.core.runtime_state.insert(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            &PendingMessagesKeyFormat { index }.encode(),
            b"reclaim_escrow",
        );

        Ok(())
    }

    /// Update existing runtime with given descriptor.
    pub fn update_runtime(ctx: &mut TxContext, args: UpdateRuntime) -> Result<(), String> {
        Self::check_nonce(ctx, args.nonce)?;
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Registry(Versioned::new(
            0,
            RegistryMessage::UpdateRuntime(args.update_runtime.clone()),
        )));

        ctx.parent.core.runtime_state.insert(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            &PendingMessagesKeyFormat { index }.encode(),
            b"update_runtime",
        );

        Ok(())
    }

    /// Insert a key/value pair.
    pub fn insert(ctx: &mut TxContext, args: KeyValue) -> Result<Option<String>, String> {
        Self::check_nonce(ctx, args.nonce)?;

        if args.value.as_bytes().len() > 128 {
            return Err("Value too big to be inserted.".to_string());
        }
        if ctx.is_check_only() {
            return Ok(None);
        }
        ctx.emit_tag(b"kv_op", b"insert");
        ctx.emit_tag(b"kv_key", args.key.as_bytes());

        let existing = ctx.parent.core.runtime_state.insert(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
            args.value.as_bytes(),
        );
        Ok(existing
            .map(|v| String::from_utf8(v))
            .transpose()
            .map_err(|err| err.to_string())?)
    }

    /// Retrieve a key/value pair.
    pub fn get(ctx: &mut TxContext, args: Key) -> Result<Option<String>, String> {
        Self::check_nonce(ctx, args.nonce)?;

        if ctx.is_check_only() {
            return Ok(None);
        }
        ctx.emit_tag(b"kv_op", b"get");
        ctx.emit_tag(b"kv_key", args.key.as_bytes());

        let existing = ctx.parent.core.runtime_state.get(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
        );
        Ok(existing
            .map(|v| String::from_utf8(v))
            .transpose()
            .map_err(|err| err.to_string())?)
    }

    /// Remove a key/value pair.
    pub fn remove(ctx: &mut TxContext, args: Key) -> Result<Option<String>, String> {
        Self::check_nonce(ctx, args.nonce)?;

        if ctx.is_check_only() {
            return Ok(None);
        }
        ctx.emit_tag(b"kv_op", b"remove");
        ctx.emit_tag(b"kv_key", args.key.as_bytes());

        let existing = ctx.parent.core.runtime_state.remove(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
        );
        Ok(existing
            .map(|v| String::from_utf8(v))
            .transpose()
            .map_err(|err| err.to_string())?)
    }

    /// Helper for doing encrypted MKVS operations.
    fn get_encryption_context(
        ctx: &mut TxContext,
        key: &[u8],
    ) -> Result<EncryptionContext, String> {
        // Derive key pair ID based on key.
        let key_pair_id = KeyPairId::from(Hash::digest_bytes(key).as_ref());

        // Fetch encryption keys.
        let io_ctx = IoContext::create_child(&ctx.parent.core.io_ctx);
        let result = ctx
            .parent
            .key_manager
            .get_or_create_keys(io_ctx, key_pair_id);
        let key = tokio::runtime::Handle::current()
            .block_on(result)
            .map_err(|err| err.to_string())?;

        Ok(EncryptionContext::new(key.state_key.as_ref()))
    }

    /// (encrypted) Insert a key/value pair.
    pub fn enc_insert(ctx: &mut TxContext, args: KeyValue) -> Result<Option<String>, String> {
        Self::check_nonce(ctx, args.nonce)?;

        if ctx.is_check_only() {
            return Ok(None);
        }
        // NOTE: This is only for example purposes, the correct way would be
        //       to also generate a (deterministic) nonce.
        let nonce = [0u8; NONCE_SIZE];

        let enc_ctx = Self::get_encryption_context(ctx, args.key.as_bytes())?;
        let existing = enc_ctx.insert(
            ctx.parent.core.runtime_state,
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
            args.value.as_bytes(),
            &nonce,
        );
        Ok(existing
            .map(|v| String::from_utf8(v))
            .transpose()
            .map_err(|err| err.to_string())?)
    }

    /// (encrypted) Retrieve a key/value pair.
    pub fn enc_get(ctx: &mut TxContext, args: Key) -> Result<Option<String>, String> {
        Self::check_nonce(ctx, args.nonce)?;

        if ctx.is_check_only() {
            return Ok(None);
        }
        let enc_ctx = Self::get_encryption_context(ctx, args.key.as_bytes())?;
        let existing = enc_ctx.get(
            ctx.parent.core.runtime_state,
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
        );
        Ok(existing
            .map(|v| String::from_utf8(v))
            .transpose()
            .map_err(|err| err.to_string())?)
    }

    /// (encrypted) Remove a key/value pair.
    pub fn enc_remove(ctx: &mut TxContext, args: Key) -> Result<Option<String>, String> {
        Self::check_nonce(ctx, args.nonce)?;

        if ctx.is_check_only() {
            return Ok(None);
        }
        let enc_ctx = Self::get_encryption_context(ctx, args.key.as_bytes())?;
        let existing = enc_ctx.remove(
            ctx.parent.core.runtime_state,
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
        );
        Ok(existing
            .map(|v| String::from_utf8(v))
            .transpose()
            .map_err(|err| err.to_string())?)
    }
}

/// Implementation of a test block handler.
pub struct BlockHandler;

impl BlockHandler {
    pub fn begin_block(ctx: &mut Context) -> Result<(), RuntimeError> {
        // Process any message results.
        for ev in &ctx.core.round_results.messages {
            // Fetch and remove message metadata.
            let meta = ctx.core.runtime_state.remove(
                IoContext::create_child(&ctx.core.io_ctx),
                &PendingMessagesKeyFormat { index: ev.index }.encode(),
            );

            // Make sure metadata is as expected.
            match meta.as_ref().map(|v| v.as_slice()) {
                Some(b"withdraw") => {
                    // Withdraw.
                }

                Some(b"transfer") => {
                    // Transfer.
                }

                Some(b"add_escrow") => {
                    // AddEscrow.
                }

                Some(b"reclaim_escrow") => {
                    // ReclaimEscrow.
                }

                meta => panic!("unexpected message metadata: {:?}", meta),
            }
        }

        // Check if there are any leftover pending messages metadata.
        let mut it = ctx
            .core
            .runtime_state
            .iter(IoContext::create_child(&ctx.core.io_ctx));
        it.seek(&PendingMessagesKeyFormat { index: 0 }.encode_partial(0));
        // Either there should be no next key...
        it.next().and_then(|(key, _value)| {
            assert!(
                // ...or the next key should be something else.
                PendingMessagesKeyFormat::decode(&key).is_none(),
                "leftover message metadata (some messages not processed?): key={:?}",
                key
            );
            Some(())
        });
        drop(it);

        // Store current epoch to test consistency.
        ctx.core.runtime_state.insert(
            IoContext::create_child(&ctx.core.io_ctx),
            &[0x02],
            &ctx.core.epoch.to_be_bytes(),
        );

        Ok(())
    }
}
