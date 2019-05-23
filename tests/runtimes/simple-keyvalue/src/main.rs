extern crate ekiden_keymanager_client;
extern crate ekiden_runtime;
extern crate failure;
extern crate io_context;
extern crate simple_keyvalue_api;

use std::sync::Arc;

use failure::{format_err, Fallible};
use io_context::Context as IoContext;

use ekiden_keymanager_client::{ContractId, KeyManagerClient};
use ekiden_runtime::{
    common::{
        crypto::{
            hash::Hash,
            mrae::deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE, TAG_SIZE},
        },
        runtime::RuntimeId,
    },
    executor::Executor,
    rak::RAK,
    register_runtime_txn_methods, runtime_context,
    storage::{StorageContext, MKVS},
    transaction::{dispatcher::CheckOnlySuccess, Context as TxnContext},
    Protocol, RpcDispatcher, TxnDispatcher,
};
use simple_keyvalue_api::{with_api, KeyValue};

// Include key manager enclave hash.
include!(concat!(env!("OUT_DIR"), "/km_enclave_hash.rs"));

struct Context {
    km_client: Arc<KeyManagerClient>,
}

/// Insert a key/value pair.
fn insert(args: &KeyValue, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if args.value.as_bytes().len() > 128 {
        return Err(format_err!("Value too big to be inserted."));
    }
    if ctx.check_only {
        return Err(CheckOnlySuccess.into());
    }
    ctx.emit_block_tag(b"kv_hello", b"insert");
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
fn get(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess.into());
    }
    ctx.emit_block_tag(b"kv_hello", b"get");
    ctx.emit_txn_tag(b"kv_op", b"get");
    ctx.emit_txn_tag(b"kv_key", args.as_bytes());

    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        mkvs.get(IoContext::create_child(&ctx.io_ctx), args.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Remove a key/value pair.
fn remove(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess.into());
    }
    ctx.emit_block_tag(b"kv_hello", b"remove");
    ctx.emit_txn_tag(b"kv_op", b"remove");
    ctx.emit_txn_tag(b"kv_key", args.as_bytes());

    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        mkvs.remove(IoContext::create_child(&ctx.io_ctx), args.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Helper for doing encrypted MKVS operations.
fn get_encryption_context(ctx: &mut TxnContext, key: &[u8]) -> Fallible<EncryptionContext> {
    let rctx = runtime_context!(ctx, Context);

    // Derive contract ID based on key.
    let contract_id = ContractId::from(Hash::digest_bytes(key).as_ref());

    // Fetch encryption keys.
    let io_ctx = IoContext::create_child(&ctx.io_ctx);
    let result = rctx.km_client.get_or_create_keys(io_ctx, contract_id);
    let key = Executor::with_current(|executor| executor.block_on(result))?;

    Ok(EncryptionContext::new(key.state_key.as_ref()))
}

/// (encrypted) Insert a key/value pair.
fn enc_insert(args: &KeyValue, ctx: &mut TxnContext) -> Fallible<Option<String>> {
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
fn enc_get(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    let enc_ctx = get_encryption_context(ctx, args.as_bytes())?;
    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        enc_ctx.get(mkvs, IoContext::create_child(&ctx.io_ctx), args.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// (encrypted) Remove a key/value pair.
fn enc_remove(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    let enc_ctx = get_encryption_context(ctx, args.as_bytes())?;
    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        enc_ctx.remove(mkvs, IoContext::create_child(&ctx.io_ctx), args.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Insert a key/value pair (untrusted local).
fn local_insert(args: &KeyValue, _ctx: &mut TxnContext) -> Fallible<()> {
    StorageContext::with_current(|_mkvs, untrusted_local| {
        untrusted_local.insert(args.key.as_bytes().to_vec(), args.value.as_bytes().to_vec())
    })
}

/// Retrive a key (untrusted local).
fn local_get(args: &String, _ctx: &mut TxnContext) -> Fallible<String> {
    let existing = StorageContext::with_current(|_mkvs, untrusted_local| {
        untrusted_local.get(args.as_bytes().to_vec())
    })?;
    Ok(String::from_utf8(existing)?)
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
    pub fn get(&self, mkvs: &MKVS, ctx: IoContext, key: &[u8]) -> Option<Vec<u8>> {
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
        mkvs: &mut MKVS,
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
    pub fn remove(&self, mkvs: &mut MKVS, ctx: IoContext, key: &[u8]) -> Option<Vec<u8>> {
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

fn main() {
    // Initializer.
    let init = |protocol: &Arc<Protocol>,
                rak: &Arc<RAK>,
                _rpc: &mut RpcDispatcher,
                txn: &mut TxnDispatcher| {
        with_api! { register_runtime_txn_methods!(txn, api); }

        // Create the key manager client.
        let km_client = Arc::new(ekiden_keymanager_client::RemoteClient::new_runtime(
            RuntimeId::default(), // HACK: Tests always use the all 0 runtime ID.
            #[cfg(target_env = "sgx")]
            Some(KM_ENCLAVE_HASH),
            #[cfg(not(target_env = "sgx"))]
            None,
            protocol.clone(),
            rak.clone(),
        ));

        txn.set_context_initializer(move |ctx: &mut TxnContext| {
            ctx.runtime = Box::new(Context {
                km_client: km_client.clone(),
            })
        });
    };

    // Start the runtime.
    ekiden_runtime::start_runtime(Some(Box::new(init)));
}
