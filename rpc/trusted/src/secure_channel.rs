//! Secure channel handling.
use protobuf;
use protobuf::Message;
use sodalite;

use std::collections::HashMap;
#[cfg(not(target_env = "sgx"))]
use std::sync::{Mutex, MutexGuard};
#[cfg(target_env = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(target_env = "sgx")]
use std::sync::SgxMutexGuard as MutexGuard;

use ekiden_common::error::{Error, Result};
use ekiden_common::random;
use ekiden_enclave_common;
use ekiden_enclave_common::quote::MrEnclave;
use ekiden_enclave_trusted;
use ekiden_enclave_trusted::crypto::{SecretSeed, SECRET_SEED_LEN};
use ekiden_rpc_common::api;
use ekiden_rpc_common::secure_channel::{self, MonotonicNonceGenerator, RandomNonceGenerator,
                                        SessionState};

use super::request::Request;

/// Single secure channel session between client and contract.
#[derive(Default)]
pub struct ClientSession {
    /// Client short-term public key.
    client_public_key: sodalite::BoxPublicKey,
    /// Contract short-term public key.
    contract_public_key: sodalite::BoxPublicKey,
    /// Contract short-term private key.
    contract_private_key: sodalite::BoxSecretKey,
    /// Cached shared key.
    shared_key: Option<sodalite::SecretboxKey>,
    /// Short-term nonce generator.
    nonce_generator: MonotonicNonceGenerator,
    /// Session state.
    state: SessionState,
    /// Client long-term public key (if authenticated).
    client_long_term_public_key: Option<sodalite::BoxPublicKey>,
    /// Client MRENCLAVE (if authenticated).
    client_mr_enclave: Option<MrEnclave>,
}

/// Secure channel context.
pub struct SecureChannelContext {
    /// Contract short-term keypairs, keyed with client short-term keys.
    sessions: HashMap<sodalite::BoxPublicKey, ClientSession>,
    /// Long-term nonce generator.
    nonce_generator: RandomNonceGenerator,
}

impl SecureChannelContext {
    /// Create new secure channel context.
    pub fn new() -> Self {
        SecureChannelContext {
            sessions: HashMap::new(),
            nonce_generator: RandomNonceGenerator::new(),
        }
    }

    /// Global secure channel context instance.
    ///
    /// Calling this method will take a lock on the global instance which
    /// will be released once the value goes out of scope.
    pub fn get<'a>() -> MutexGuard<'a, Self> {
        SECURE_CHANNEL_CTX.lock().unwrap()
    }

    /// Convert client short-term public key into session hash map key.
    fn get_session_key(public_key: &[u8]) -> Result<sodalite::BoxPublicKey> {
        if public_key.len() != sodalite::BOX_PUBLIC_KEY_LEN {
            return Err(Error::new("Bad short-term client key"));
        }

        let mut key: sodalite::BoxPublicKey = [0; sodalite::BOX_PUBLIC_KEY_LEN];
        key.copy_from_slice(&public_key);

        Ok(key)
    }

    /// Create a new client session.
    ///
    /// Returns a cryptographic box, encrypted to the client short-term key and
    /// authenticated by the contract long-term key.
    pub fn create_session(
        &mut self,
        public_key: &[u8],
    ) -> Result<api::AuthenticatedShortTermPublicKey> {
        let key = SecureChannelContext::get_session_key(&public_key)?;

        if self.sessions.contains_key(&key) {
            return Err(Error::new("Session already exists"));
        }

        let mut session = ClientSession::new(key.clone())?;
        session.transition_to(SessionState::Established)?;

        let box_inner = secure_channel::create_box(
            session.get_contract_public_key(),
            &secure_channel::NONCE_CONTEXT_INIT,
            &mut self.nonce_generator,
            session.get_client_public_key(),
            &ekiden_enclave_trusted::identity::get_identity().rpc_key_e_priv,
            &mut None,
        )?;
        let mut astpk = api::AuthenticatedShortTermPublicKey::new();
        astpk.set_identity_proof(ekiden_enclave_trusted::identity::get_proof());
        astpk.set_boxed_short_term_public_key(box_inner);

        // TODO: What about session table overflows?

        self.sessions.insert(key, session);

        Ok(astpk)
    }

    /// Lookup existing client session.
    /// Pass our `sessions` field, so that we don't have to borrow the whole channel context.
    fn get_session<'a>(
        sessions: &'a mut HashMap<sodalite::BoxPublicKey, ClientSession>,
        public_key: &[u8],
    ) -> Result<&'a mut ClientSession> {
        let key = SecureChannelContext::get_session_key(&public_key)?;

        match sessions.get_mut(&key) {
            Some(session) => Ok(session),
            None => Err(Error::new("Client session not found")),
        }
    }

    /// Authenticate a session's client.
    pub fn authenticate_client(&mut self, box_outer: &api::CryptoBox) -> Result<()> {
        let session =
            SecureChannelContext::get_session(&mut self.sessions, box_outer.get_public_key())?;

        let astpk_bytes = secure_channel::open_box(
            &box_outer,
            &secure_channel::NONCE_CONTEXT_AUTHOUT,
            &mut session.nonce_generator,
            &session.client_public_key,
            &session.contract_private_key,
            &mut session.shared_key,
        )?;
        let astpk: api::AuthenticatedShortTermPublicKey = protobuf::parse_from_bytes(&astpk_bytes)?;

        let iai = ekiden_enclave_common::quote::verify(astpk.get_identity_proof())?;

        let bound_client_stpk_bytes = secure_channel::open_box(
            astpk.get_boxed_short_term_public_key(),
            &secure_channel::NONCE_CONTEXT_AUTHIN,
            &mut self.nonce_generator,
            &iai.identity.rpc_key_e_pub,
            &ekiden_enclave_trusted::identity::get_identity().rpc_key_e_priv,
            &mut None,
        )?;
        if &bound_client_stpk_bytes != &session.client_public_key {
            return Err(Error::new(
                "Key in client's authentication request doesn't match channel key",
            ));
        }

        session.client_long_term_public_key = Some(iai.identity.rpc_key_e_pub);
        session.client_mr_enclave = Some(iai.mr_enclave);

        Ok(())
    }

    /// Close an existing session.
    pub fn close_session(&mut self, public_key: &[u8]) -> Result<()> {
        let key = SecureChannelContext::get_session_key(&public_key)?;

        self.sessions.remove(&key);

        Ok(())
    }
}

impl ClientSession {
    /// Create a new client session.
    pub fn new(public_key: sodalite::BoxPublicKey) -> Result<Self> {
        let mut session = ClientSession::default();
        session.transition_to(SessionState::Init)?;
        session.client_public_key = public_key;

        // Generate new keypair.
        let mut seed: SecretSeed = [0; SECRET_SEED_LEN];
        match random::get_random_bytes(&mut seed) {
            Ok(_) => {}
            Err(_) => return Err(Error::new("Keypair generation failed")),
        }

        sodalite::box_keypair_seed(
            &mut session.contract_public_key,
            &mut session.contract_private_key,
            &seed,
        );

        // Cache shared channel key.
        {
            let mut key = session
                .shared_key
                .get_or_insert([0u8; sodalite::SECRETBOX_KEY_LEN]);
            sodalite::box_beforenm(
                &mut key,
                &session.client_public_key,
                &session.contract_private_key,
            );
        }

        Ok(session)
    }

    /// Get client short-term public key.
    pub fn get_client_public_key(&self) -> &sodalite::BoxPublicKey {
        &self.client_public_key
    }

    /// Get contract short-term public key.
    pub fn get_contract_public_key(&self) -> &sodalite::BoxPublicKey {
        &self.contract_public_key
    }

    /// Open cryptographic box with RPC request.
    pub fn open_request_box(&mut self, request: &api::CryptoBox) -> Result<Request<Vec<u8>>> {
        let plain_request = secure_channel::open_box(
            &request,
            &secure_channel::NONCE_CONTEXT_REQUEST,
            &mut self.nonce_generator,
            &self.client_public_key,
            &self.contract_private_key,
            &mut self.shared_key,
        )?;

        let mut plain_request: api::PlainClientRequest =
            protobuf::parse_from_bytes(&plain_request)?;

        // Check if this request is allowed based on current channel state.
        match self.state {
            SessionState::Established => {}
            _ => {
                return Err(Error::new("Invalid method call in this state"));
            }
        }

        Ok(Request::new(
            plain_request.take_payload(),
            plain_request.take_method(),
            Some(self.client_public_key.to_vec()),
            self.client_mr_enclave.clone(),
        ))
    }

    /// Create cryptographic box with RPC response.
    pub fn create_response_box(
        &mut self,
        response: &api::PlainClientResponse,
    ) -> Result<api::CryptoBox> {
        Ok(secure_channel::create_box(
            &response.write_to_bytes()?,
            &secure_channel::NONCE_CONTEXT_RESPONSE,
            &mut self.nonce_generator,
            &self.client_public_key,
            &self.contract_private_key,
            &mut self.shared_key,
        )?)
    }

    /// Transition secure channel to a new state.
    pub fn transition_to(&mut self, new_state: SessionState) -> Result<()> {
        Ok(self.state.transition_to(new_state)?)
    }
}

lazy_static! {
    // Global secure channel context.
    static ref SECURE_CHANNEL_CTX: Mutex<SecureChannelContext> =
        Mutex::new(SecureChannelContext::new());
}

/// Initialize secure channel.
pub fn channel_init(request: &api::ChannelInitRequest) -> Result<api::ChannelInitResponse> {
    let mut channel = SECURE_CHANNEL_CTX.lock().unwrap();

    // Create new session.
    let astpk = channel.create_session(request.get_short_term_public_key())?;

    let mut response = api::ChannelInitResponse::new();
    response.set_authenticated_short_term_public_key(astpk);

    Ok(response)
}

/// Authenticate client.
pub fn channel_auth(request: &api::ChannelAuthRequest) -> Result<api::ChannelAuthResponse> {
    let mut channel = SECURE_CHANNEL_CTX.lock().unwrap();
    let box_outer = request.get_boxed_authenticated_short_term_public_key();

    channel.authenticate_client(box_outer)?;

    Ok(api::ChannelAuthResponse::new())
}

/// Close secure channel.
pub fn channel_close(public_key: &[u8]) -> Result<()> {
    let mut channel = SECURE_CHANNEL_CTX.lock().unwrap();

    channel.close_session(&public_key)?;

    Ok(())
}

/// Open cryptographic box with RPC request.
pub fn open_request_box(request: &api::CryptoBox) -> Result<Request<Vec<u8>>> {
    let mut channel = SECURE_CHANNEL_CTX.lock().unwrap();

    Ok(
        SecureChannelContext::get_session(&mut channel.sessions, &request.get_public_key())?
            .open_request_box(&request)?,
    )
}

/// Create cryptographic box with RPC response.
pub fn create_response_box(
    public_key: &[u8],
    response: &api::PlainClientResponse,
) -> Result<api::CryptoBox> {
    let mut channel = SECURE_CHANNEL_CTX.lock().unwrap();

    Ok(
        SecureChannelContext::get_session(&mut channel.sessions, &public_key)?
            .create_response_box(&response)?,
    )
}
