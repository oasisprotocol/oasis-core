//! Test method implementations.

use std::{collections::BTreeMap, convert::TryInto};

use io_context::Context as IoContext;
use x25519_dalek;

use super::{crypto::EncryptionContext, types::*, Context, TxContext};
use oasis_core_keymanager::crypto::KeyPairId;
use oasis_core_runtime::{
    common::{
        crypto::{
            hash::Hash,
            mrae::deoxysii::{self, NONCE_SIZE},
        },
        key_format::KeyFormat,
        versioned::Versioned,
    },
    consensus::{
        self,
        address::Address,
        registry::Runtime,
        roothash::{Message, RegistryMessage, StakingMessage},
        staking::{
            self, Account, AddEscrowResult, Delegation, ReclaimEscrowResult, TransferResult,
            WithdrawResult,
        },
        state::staking::ImmutableState as StakingImmutableState,
    },
    storage::MKVS,
    types::{Error as RuntimeError, EventKind},
};

/// Implementation of the transaction methods supported by the test runtime.
pub struct Methods;

impl Methods {
    /// Gets runtime ID of the runtime.
    pub fn get_runtime_id(ctx: &mut TxContext, _args: ()) -> Result<Option<String>, String> {
        Ok(Some(format!("{:?}", ctx.parent.host_info.runtime_id)))
    }

    /// Queries all consensus accounts.
    /// Note: this is a transaction but could be a query in a non-test runtime.
    #[allow(clippy::type_complexity)]
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
        if ctx.is_check_only() {
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

    pub fn check_nonce(ctx: &mut TxContext, nonce: u64) -> Result<(), String> {
        let nonce_key = NonceKeyFormat { nonce }.encode();
        match ctx
            .parent
            .core
            .runtime_state
            .get(IoContext::create_child(&ctx.parent.core.io_ctx), &nonce_key)
        {
            Some(_) => Err(format!("Duplicate nonce: {}", nonce)),
            None => {
                if !ctx.is_check_only() {
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
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Staking(Versioned::new(
            0,
            StakingMessage::Withdraw(args.withdraw),
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
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Staking(Versioned::new(
            0,
            StakingMessage::Transfer(args.transfer),
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
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Staking(Versioned::new(
            0,
            StakingMessage::AddEscrow(args.escrow),
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
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Staking(Versioned::new(
            0,
            StakingMessage::ReclaimEscrow(args.reclaim_escrow),
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
        Self::check_max_messages(ctx)?;

        if ctx.is_check_only() {
            return Ok(());
        }

        let index = ctx.emit_message(Message::Registry(Versioned::new(
            0,
            RegistryMessage::UpdateRuntime(args.update_runtime),
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
        existing
            .map(String::from_utf8)
            .transpose()
            .map_err(|err| err.to_string())
    }

    /// Retrieve a key/value pair.
    pub fn get(ctx: &mut TxContext, args: Key) -> Result<Option<String>, String> {
        if ctx.is_check_only() {
            return Ok(None);
        }
        ctx.emit_tag(b"kv_op", b"get");
        ctx.emit_tag(b"kv_key", args.key.as_bytes());

        let existing = ctx.parent.core.runtime_state.get(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
        );
        existing
            .map(String::from_utf8)
            .transpose()
            .map_err(|err| err.to_string())
    }

    /// Remove a key/value pair.
    pub fn remove(ctx: &mut TxContext, args: Key) -> Result<Option<String>, String> {
        if ctx.is_check_only() {
            return Ok(None);
        }
        ctx.emit_tag(b"kv_op", b"remove");
        ctx.emit_tag(b"kv_key", args.key.as_bytes());

        let existing = ctx.parent.core.runtime_state.remove(
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
        );
        existing
            .map(String::from_utf8)
            .transpose()
            .map_err(|err| err.to_string())
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
        existing
            .map(String::from_utf8)
            .transpose()
            .map_err(|err| err.to_string())
    }

    /// (encrypted) Retrieve a key/value pair.
    pub fn enc_get(ctx: &mut TxContext, args: Key) -> Result<Option<String>, String> {
        if ctx.is_check_only() {
            return Ok(None);
        }
        let enc_ctx = Self::get_encryption_context(ctx, args.key.as_bytes())?;
        let existing = enc_ctx.get(
            ctx.parent.core.runtime_state,
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
        );
        existing
            .map(String::from_utf8)
            .transpose()
            .map_err(|err| err.to_string())
    }

    /// (encrypted) Remove a key/value pair.
    pub fn enc_remove(ctx: &mut TxContext, args: Key) -> Result<Option<String>, String> {
        if ctx.is_check_only() {
            return Ok(None);
        }
        let enc_ctx = Self::get_encryption_context(ctx, args.key.as_bytes())?;
        let existing = enc_ctx.remove(
            ctx.parent.core.runtime_state,
            IoContext::create_child(&ctx.parent.core.io_ctx),
            args.key.as_bytes(),
        );
        existing
            .map(String::from_utf8)
            .transpose()
            .map_err(|err| err.to_string())
    }

    /// ElGamal encryption.
    pub fn encrypt(ctx: &mut TxContext, args: Encrypt) -> Result<Option<Vec<u8>>, String> {
        if ctx.is_check_only() {
            return Ok(None);
        }

        // Derive key pair ID based on the given ID.
        let hash = Hash::digest_bytes(args.key_pair_id.as_bytes()).0;
        let key_pair_id = KeyPairId::from(hash.as_ref());

        // Fetch public key.
        let io_ctx = IoContext::create_child(&ctx.parent.core.io_ctx);
        let result =
            ctx.parent
                .key_manager
                .get_public_ephemeral_key(io_ctx, key_pair_id, args.epoch);
        let long_term_pk = tokio::runtime::Handle::current()
            .block_on(result)
            .map_err(|err| err.to_string())?
            .ok_or("public ephemeral key not available")?;

        // Generate ephemeral key. Not secure, but good enough for testing purposes.
        let ephemeral_sk = x25519_dalek::StaticSecret::from(hash);
        let ephemeral_pk = x25519_dalek::PublicKey::from(&ephemeral_sk);

        // ElGamal encryption.
        let ciphertext = deoxysii::box_seal(
            &[0u8; NONCE_SIZE],
            args.plaintext,
            vec![],
            &long_term_pk.key.0,
            &ephemeral_sk.to_bytes(),
        )
        .map_err(|err| format!("failed to encrypt plaintext: {}", err))?;

        // Return ephemeral_pk || ciphertext.
        let mut c = ephemeral_pk.as_bytes().to_vec();
        c.extend(ciphertext);

        Ok(Some(c))
    }

    /// ElGamal decryption.
    pub fn decrypt(ctx: &mut TxContext, args: Decrypt) -> Result<Option<Vec<u8>>, String> {
        if ctx.is_check_only() {
            return Ok(None);
        }

        // Derive key pair ID based on the given ID.
        let hash = Hash::digest_bytes(args.key_pair_id.as_bytes()).0;
        let key_pair_id = KeyPairId::from(hash.as_ref());

        // Fetch private key.
        let io_ctx = IoContext::create_child(&ctx.parent.core.io_ctx);
        let result =
            ctx.parent
                .key_manager
                .get_or_create_ephemeral_keys(io_ctx, key_pair_id, args.epoch);
        let long_term_sk = tokio::runtime::Handle::current()
            .block_on(result)
            .map_err(|err| format!("private ephemeral key not available: {}", err))?;

        // Decode ephemeral_pk || ciphertext.
        let ephemeral_pk = args
            .ciphertext
            .get(0..32)
            .ok_or("invalid ciphertext")?
            .try_into()
            .unwrap();
        let ciphertext = args
            .ciphertext
            .get(32..)
            .ok_or("invalid ciphertext")?
            .to_vec();

        // ElGamal decryption.
        let plaintext = deoxysii::box_open(
            &[0u8; NONCE_SIZE],
            ciphertext,
            vec![],
            ephemeral_pk,
            &long_term_sk.input_keypair.sk.0,
        )
        .map_err(|err| format!("failed to decrypt ciphertext: {}", err))?;

        Ok(Some(plaintext))
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
            match meta.as_deref() {
                Some(b"withdraw") => {
                    let _: WithdrawResult =
                        cbor::from_value(ev.result.clone().expect("withdraw result should exist"))
                            .expect("withdraw result should deserialize correctly");
                }

                Some(b"transfer") => {
                    let xfer: TransferResult =
                        cbor::from_value(ev.result.clone().expect("transfer result should exist"))
                            .expect("transfer result should deserialize correctly");

                    // Test that we can query the corresponding transfer event.
                    let mut height = ctx.core.consensus_state.height();
                    let mut found = false;
                    while height > 0 {
                        let events = ctx
                            .consensus_verifier
                            .events_at(height, EventKind::Staking)
                            .expect("should be able to query events");

                        found = events.iter().any(|ev| {
                            matches!(ev, consensus::Event::Staking(staking::Event {
                            transfer: Some(staking::TransferEvent { from, to, amount }),
                                ..
                            }) if from == &xfer.from
                                && to == &xfer.to
                                && amount == &xfer.amount)
                        });
                        if found {
                            break;
                        }

                        height -= 1;
                    }

                    assert!(found, "should find the corresponding transfer event");
                }

                Some(b"add_escrow") => {
                    let _: AddEscrowResult = cbor::from_value(
                        ev.result.clone().expect("add escrow result should exist"),
                    )
                    .expect("add escrow result should deserialize correctly");
                }

                Some(b"reclaim_escrow") => {
                    let _: ReclaimEscrowResult = cbor::from_value(
                        ev.result
                            .clone()
                            .expect("reclaim escrow result should exist"),
                    )
                    .expect("reclaim escrow result should deserialize correctly");
                }

                Some(b"update_runtime") => {
                    let _: Runtime = cbor::from_value(
                        ev.result
                            .clone()
                            .expect("update runtime result should exist"),
                    )
                    .expect("update runtime result should deserialize correctly");
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
        if let Some((key, _value)) = it.next() {
            assert!(
                // ...or the next key should be something else.
                PendingMessagesKeyFormat::decode(&key).is_none(),
                "leftover message metadata (some messages not processed?): key={:?}",
                key
            );
        };
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
