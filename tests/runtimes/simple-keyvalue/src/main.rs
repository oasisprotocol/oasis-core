use std::{io::Cursor, sync::Arc};

use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use io_context::Context as IoContext;

use oasis_core_keymanager_client::{KeyManagerClient, KeyPairId};
use oasis_core_runtime::{
    common::{
        crypto::{
            hash::Hash,
            mrae::deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE, TAG_SIZE},
        },
        key_format::KeyFormat,
        roothash::{Message, StakingMessage},
        runtime::RuntimeId,
        version::Version,
    },
    executor::Executor,
    rak::RAK,
    register_runtime_txn_methods, runtime_context,
    storage::{StorageContext, MKVS},
    transaction::{
        dispatcher::{BatchHandler, CheckOnlySuccess},
        Context as TxnContext,
    },
    version_from_cargo, Protocol, RpcDemux, RpcDispatcher, TxnDispatcher, TxnMethDispatcher,
};
use simple_keymanager::trusted_policy_signers;
use simple_keyvalue_api::{with_api, Key, KeyValue, Transfer, Withdraw};

/// Key format used for transaction artifacts.
#[derive(Debug)]
struct PendingMessagesKeyFormat {
    index: u32,
}

impl KeyFormat for PendingMessagesKeyFormat {
    fn prefix() -> u8 {
        0x00
    }

    fn size() -> usize {
        4
    }

    fn encode_atoms(self, atoms: &mut Vec<Vec<u8>>) {
        let mut index: Vec<u8> = Vec::with_capacity(4);
        index.write_u32::<BigEndian>(self.index).unwrap();
        atoms.push(index);
    }

    fn decode_atoms(data: &[u8]) -> Self {
        let mut reader = Cursor::new(data);
        Self {
            index: reader.read_u32::<BigEndian>().unwrap(),
        }
    }
}

struct Context {
    test_runtime_id: RuntimeId,
    km_client: Arc<dyn KeyManagerClient>,
}

/// Return previously set runtime ID of this runtime.
fn get_runtime_id(_args: &(), ctx: &mut TxnContext) -> Result<Option<String>> {
    let rctx = runtime_context!(ctx, Context);

    Ok(Some(rctx.test_runtime_id.to_string()))
}

/// Emit a message and schedule to check its result in the next round.
fn message(_args: &u64, ctx: &mut TxnContext) -> Result<()> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }

    StorageContext::with_current(|mkvs, _untrusted_local| {
        // Emit a message.
        let index = ctx.emit_message(Message::Noop {});

        let existing = mkvs.insert(
            IoContext::create_child(&ctx.io_ctx),
            &PendingMessagesKeyFormat { index }.encode(),
            b"noop", // Value is ignored.
        );
        assert!(
            existing.is_none(),
            "all messages should have been processed"
        );
    });
    Ok(())
}

/// Withdraw from the consensus layer into the runtime account.
fn consensus_withdraw(args: &Withdraw, ctx: &mut TxnContext) -> Result<()> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }

    StorageContext::with_current(|mkvs, _untrusted_local| {
        let index = ctx.emit_message(Message::Staking {
            v: 0,
            msg: StakingMessage::Withdraw(args.withdraw.clone()),
        });

        mkvs.insert(
            IoContext::create_child(&ctx.io_ctx),
            &PendingMessagesKeyFormat { index }.encode(),
            b"withdraw",
        );
    });

    Ok(())
}

/// Transfer from the runtime account to another account in the consensus layer.
fn consensus_transfer(args: &Transfer, ctx: &mut TxnContext) -> Result<()> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }

    StorageContext::with_current(|mkvs, _untrusted_local| {
        let index = ctx.emit_message(Message::Staking {
            v: 0,
            msg: StakingMessage::Transfer(args.transfer.clone()),
        });

        mkvs.insert(
            IoContext::create_child(&ctx.io_ctx),
            &PendingMessagesKeyFormat { index }.encode(),
            b"transfer",
        );
    });

    Ok(())
}

/// Insert a key/value pair.
fn insert(args: &KeyValue, ctx: &mut TxnContext) -> Result<Option<String>> {
    if args.value.as_bytes().len() > 128 {
        return Err(anyhow!("Value too big to be inserted."));
    }
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    ctx.emit_txn_tag(b"kv_op", b"insert");
    ctx.emit_txn_tag(b"kv_key", args.key.as_bytes());

    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        mkvs.insert(
            IoContext::create_child(&ctx.io_ctx),
            args.key.as_bytes(),
            args.value.as_bytes(),
        )
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Retrieve a key/value pair.
fn get(args: &Key, ctx: &mut TxnContext) -> Result<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    ctx.emit_txn_tag(b"kv_op", b"get");
    ctx.emit_txn_tag(b"kv_key", args.key.as_bytes());

    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        mkvs.get(IoContext::create_child(&ctx.io_ctx), args.key.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Remove a key/value pair.
fn remove(args: &Key, ctx: &mut TxnContext) -> Result<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    ctx.emit_txn_tag(b"kv_op", b"remove");
    ctx.emit_txn_tag(b"kv_key", args.key.as_bytes());

    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        mkvs.remove(IoContext::create_child(&ctx.io_ctx), args.key.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Helper for doing encrypted MKVS operations.
fn get_encryption_context(ctx: &mut TxnContext, key: &[u8]) -> Result<EncryptionContext> {
    let rctx = runtime_context!(ctx, Context);

    // Derive key pair ID based on key.
    let key_pair_id = KeyPairId::from(Hash::digest_bytes(key).as_ref());

    // Fetch encryption keys.
    let io_ctx = IoContext::create_child(&ctx.io_ctx);
    let result = rctx.km_client.get_or_create_keys(io_ctx, key_pair_id);
    let key = Executor::with_current(|executor| executor.block_on(result))?;

    Ok(EncryptionContext::new(key.state_key.as_ref()))
}

/// (encrypted) Insert a key/value pair.
fn enc_insert(args: &KeyValue, ctx: &mut TxnContext) -> Result<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    // NOTE: This is only for example purposes, the correct way would be
    //       to also generate a (deterministic) nonce.
    let nonce = [0u8; NONCE_SIZE];

    let enc_ctx = get_encryption_context(ctx, args.key.as_bytes())?;
    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        enc_ctx.insert(
            mkvs,
            IoContext::create_child(&ctx.io_ctx),
            args.key.as_bytes(),
            args.value.as_bytes(),
            &nonce,
        )
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// (encrypted) Retrieve a key/value pair.
fn enc_get(args: &Key, ctx: &mut TxnContext) -> Result<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    let enc_ctx = get_encryption_context(ctx, args.key.as_bytes())?;
    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        enc_ctx.get(
            mkvs,
            IoContext::create_child(&ctx.io_ctx),
            args.key.as_bytes(),
        )
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// (encrypted) Remove a key/value pair.
fn enc_remove(args: &Key, ctx: &mut TxnContext) -> Result<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    let enc_ctx = get_encryption_context(ctx, args.key.as_bytes())?;
    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        enc_ctx.remove(
            mkvs,
            IoContext::create_child(&ctx.io_ctx),
            args.key.as_bytes(),
        )
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// A keyed storage encryption context, for use with a MKVS instance.
struct EncryptionContext {
    d2: DeoxysII,
}

impl EncryptionContext {
    /// Initialize a new EncryptionContext with the given MRAE key.
    pub fn new(key: &[u8]) -> Self {
        if key.len() != KEY_SIZE {
            panic!("mkvs: invalid encryption key size {}", key.len());
        }
        let mut raw_key = [0u8; KEY_SIZE];
        raw_key.copy_from_slice(&key[..KEY_SIZE]);

        let d2 = DeoxysII::new(&raw_key);
        //raw_key.zeroize();

        Self { d2 }
    }

    /// Get encrypted MKVS entry.
    pub fn get(&self, mkvs: &dyn MKVS, ctx: IoContext, key: &[u8]) -> Option<Vec<u8>> {
        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.get(ctx, &key) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    /// Insert encrypted MKVS entry.
    pub fn insert(
        &self,
        mkvs: &mut dyn MKVS,
        ctx: IoContext,
        key: &[u8],
        value: &[u8],
        nonce: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce = Self::derive_nonce(&nonce);
        let mut ciphertext = self.d2.seal(&nonce, value.to_vec(), vec![]);
        ciphertext.extend_from_slice(&nonce);

        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.insert(ctx, &key, &ciphertext) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    /// Remove encrypted MKVS entry.
    pub fn remove(&self, mkvs: &mut dyn MKVS, ctx: IoContext, key: &[u8]) -> Option<Vec<u8>> {
        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.remove(ctx, &key) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // ciphertext || tag || nonce.
        if ciphertext.len() < TAG_SIZE + NONCE_SIZE {
            return None;
        }

        let nonce_offset = ciphertext.len() - NONCE_SIZE;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&ciphertext[nonce_offset..]);
        let ciphertext = &ciphertext[..nonce_offset];

        let plaintext = self.d2.open(&nonce, ciphertext.to_vec(), vec![]);
        plaintext.ok()
    }

    fn derive_encrypted_key(&self, key: &[u8]) -> Vec<u8> {
        // XXX: The plan is eventually to use a lighter weight transform
        // for the key instead of a full fledged MRAE algorithm.  For now
        // approximate it with a Deoxys-II call with an all 0 nonce.

        let nonce = [0u8; NONCE_SIZE];
        self.d2.seal(&nonce, key.to_vec(), vec![])
    }

    fn derive_nonce(nonce: &[u8]) -> [u8; NONCE_SIZE] {
        // Just a copy for type safety.
        let mut n = [0u8; NONCE_SIZE];
        if nonce.len() != NONCE_SIZE {
            panic!("invalid nonce size: {}", nonce.len());
        }
        n.copy_from_slice(nonce);

        n
    }
}

struct BlockHandler;

impl BlockHandler {
    fn process_message_results(&self, ctx: &mut TxnContext) {
        for ev in ctx.message_results {
            // Fetch and remove message metadata.
            let meta = StorageContext::with_current(|mkvs, _| {
                mkvs.remove(
                    IoContext::create_child(&ctx.io_ctx),
                    &PendingMessagesKeyFormat { index: ev.index }.encode(),
                )
            });

            // Make sure metadata is as expected.
            match meta.as_ref().map(|v| v.as_slice()) {
                Some(b"noop") => {
                    // Make sure the message was successfully processed.
                    assert!(
                        ev.is_success(),
                        "messages should have been successfully processed"
                    );
                }

                Some(b"withdraw") => {
                    // Withdraw.
                }

                Some(b"transfer") => {
                    // Transfer.
                }

                meta => panic!("unexpected message metadata: {:?}", meta),
            }
        }

        // Check if there are any leftover pending messages metadata.
        StorageContext::with_current(|mkvs, _| {
            let mut it = mkvs.iter(IoContext::create_child(&ctx.io_ctx));
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
        })
    }
}

impl BatchHandler for BlockHandler {
    fn start_batch(&self, ctx: &mut TxnContext) {
        if ctx.check_only {
            return;
        }

        self.process_message_results(ctx);
    }

    fn end_batch(&self, _ctx: &mut TxnContext) {}
}

pub fn main() {
    // Initializer.
    let init = |protocol: &Arc<Protocol>,
                rak: &Arc<RAK>,
                _rpc_demux: &mut RpcDemux,
                rpc: &mut RpcDispatcher|
     -> Option<Box<dyn TxnDispatcher>> {
        let mut txn = TxnMethDispatcher::new();
        with_api! { register_runtime_txn_methods!(txn, api); }

        // Create the key manager client.
        let rt_id = protocol.get_runtime_id();
        let km_client = Arc::new(oasis_core_keymanager_client::RemoteClient::new_runtime(
            rt_id,
            protocol.clone(),
            rak.clone(),
            1024,
            trusted_policy_signers(),
        ));
        let initializer_km_client = km_client.clone();

        #[cfg(not(target_env = "sgx"))]
        let _ = rpc;
        #[cfg(target_env = "sgx")]
        rpc.set_keymanager_policy_update_handler(Some(Box::new(move |raw_signed_policy| {
            km_client
                .set_policy(raw_signed_policy)
                .expect("failed to update km client policy");
        })));

        txn.set_batch_handler(BlockHandler);
        txn.set_context_initializer(move |ctx: &mut TxnContext| {
            ctx.runtime = Box::new(Context {
                test_runtime_id: rt_id.clone(),
                km_client: initializer_km_client.clone(),
            })
        });

        Some(Box::new(txn))
    };

    // Start the runtime.
    oasis_core_runtime::start_runtime(Box::new(init), version_from_cargo!());
}
