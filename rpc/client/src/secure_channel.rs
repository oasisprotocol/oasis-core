use sodalite;

use protobuf;
use protobuf::Message;

use ekiden_common::error::{Error, Result};
use ekiden_common::random;
use ekiden_enclave_common;
use ekiden_rpc_common::api;
use ekiden_rpc_common::secure_channel::{create_box, open_box, MonotonicNonceGenerator,
                                        NonceGenerator, RandomNonceGenerator, SessionState,
                                        NONCE_CONTEXT_AUTHIN, NONCE_CONTEXT_AUTHOUT,
                                        NONCE_CONTEXT_INIT, NONCE_CONTEXT_REQUEST,
                                        NONCE_CONTEXT_RESPONSE};

// Secret seed used for generating private and public keys.
const SECRET_SEED_LEN: usize = 32;
type SecretSeed = [u8; SECRET_SEED_LEN];

/// Secure channel context.
///
/// Contains state and methods needed for secure communication with the remote
/// contract.
#[derive(Default)]
pub struct SecureChannelContext {
    /// Client short-term private key.
    client_private_key: sodalite::BoxSecretKey,
    /// Client short-term public key.
    client_public_key: sodalite::BoxPublicKey,
    /// Contract contract long-term public key.
    contract_long_term_public_key: sodalite::BoxPublicKey,
    /// Contract contract short-term public key.
    contract_short_term_public_key: sodalite::BoxPublicKey,
    /// Cached shared key.
    shared_key: Option<sodalite::SecretboxKey>,
    /// Session state.
    state: SessionState,
    /// Long-term nonce generator.
    long_term_nonce_generator: RandomNonceGenerator,
    /// Short-term nonce generator.
    short_term_nonce_generator: MonotonicNonceGenerator,
}

impl SecureChannelContext {
    /// Reset secure channel context.
    ///
    /// Calling this function will generate new short-term keys for the client
    /// and clear any contract public keys.
    pub fn reset(&mut self) -> Result<()> {
        // Generate new short-term key pair for the client.
        let mut seed: SecretSeed = [0u8; SECRET_SEED_LEN];
        random::get_random_bytes(&mut seed)?;

        sodalite::box_keypair_seed(
            &mut self.client_public_key,
            &mut self.client_private_key,
            &seed,
        );

        // Clear contract keys.
        self.contract_long_term_public_key = [0; sodalite::BOX_PUBLIC_KEY_LEN];
        self.contract_short_term_public_key = [0; sodalite::BOX_PUBLIC_KEY_LEN];

        // Clear session keys.
        self.shared_key = None;

        // Reset session nonce.
        self.short_term_nonce_generator.reset();

        self.state.transition_to(SessionState::Init)?;

        Ok(())
    }

    /// Setup secure channel.
    pub fn setup(
        &mut self,
        contract_astpk: &api::AuthenticatedShortTermPublicKey,
        client_authentication_required: bool,
    ) -> Result<ekiden_enclave_common::quote::IdentityAuthenticatedInfo> {
        let iai = ekiden_enclave_common::quote::verify(contract_astpk.get_identity_proof())?;

        self.contract_long_term_public_key = iai.identity.rpc_key_e_pub.clone();

        // Open boxed short term contract public key.
        let mut shared_key: Option<sodalite::SecretboxKey> = None;
        let contract_short_term_public_key = open_box(
            contract_astpk.get_boxed_short_term_public_key(),
            &NONCE_CONTEXT_INIT,
            &mut self.long_term_nonce_generator,
            &self.contract_long_term_public_key,
            &self.client_private_key,
            &mut shared_key,
        )?;

        self.contract_short_term_public_key
            .copy_from_slice(&contract_short_term_public_key);

        if client_authentication_required {
            self.state
                .transition_to(SessionState::ClientAuthenticating)?;
        } else {
            self.state.transition_to(SessionState::Established)?;
        }

        // Cache shared channel key.
        let mut key = self.shared_key
            .get_or_insert([0u8; sodalite::SECRETBOX_KEY_LEN]);
        sodalite::box_beforenm(
            &mut key,
            &self.contract_short_term_public_key,
            &self.client_private_key,
        );

        Ok(iai)
    }

    /// Generate a client authentication box.
    pub fn get_authentication(
        &mut self,
        client_ltsk: &sodalite::BoxSecretKey,
        identity_proof: ekiden_enclave_common::api::IdentityProof,
    ) -> Result<api::CryptoBox> {
        if self.state != SessionState::ClientAuthenticating {
            return Err(Error::new("Invalid secure channel access"));
        }
        let box_inner = create_box(
            &self.client_public_key,
            &NONCE_CONTEXT_AUTHIN,
            &mut self.long_term_nonce_generator,
            &self.contract_long_term_public_key,
            client_ltsk,
            &mut None,
        )?;
        let mut astpk = api::AuthenticatedShortTermPublicKey::new();
        astpk.set_identity_proof(identity_proof);
        astpk.set_boxed_short_term_public_key(box_inner);
        let astpk_bytes = astpk.write_to_bytes()?;
        let mut box_outer = create_box(
            &astpk_bytes,
            &NONCE_CONTEXT_AUTHOUT,
            &mut self.short_term_nonce_generator,
            &self.contract_short_term_public_key,
            &self.client_private_key,
            &mut self.shared_key,
        )?;
        box_outer.set_public_key(self.client_public_key.to_vec());
        Ok(box_outer)
    }

    /// Call this after sending the client authentication box.
    /// There's no response message to pass to this method.
    /// It transitions the channel to Established state.
    pub fn authentication_sent(&mut self) -> Result<()> {
        self.state.transition_to(SessionState::Established)?;

        Ok(())
    }

    /// Close secure channel.
    ///
    /// After the secure channel is closed, it must be reset to be used again.
    pub fn close(&mut self) {
        self.state.transition_to(SessionState::Closed).unwrap();
    }

    /// Check if secure channel is closed.
    pub fn is_closed(&self) -> bool {
        self.state == SessionState::Closed
    }

    /// Check if messages must be encrypted based on current channel state.
    ///
    /// Messages can only be unencrypted when the channel is in initialization state
    /// and must be encrypted in all other states.
    pub fn must_encrypt(&self) -> bool {
        self.state == SessionState::Established
    }

    /// Get client short-term public key.
    pub fn get_client_public_key(&self) -> &sodalite::BoxPublicKey {
        &self.client_public_key
    }

    /// Create cryptographic box with RPC request.
    pub fn create_request_box(
        &mut self,
        request: &api::PlainClientRequest,
    ) -> Result<api::CryptoBox> {
        let mut crypto_box = create_box(
            &request.write_to_bytes()?,
            &NONCE_CONTEXT_REQUEST,
            &mut self.short_term_nonce_generator,
            &self.contract_short_term_public_key,
            &self.client_private_key,
            &mut self.shared_key,
        )?;

        // Set public key so the contract knows which client this is.
        crypto_box.set_public_key(self.client_public_key.to_vec());

        Ok(crypto_box)
    }

    /// Open cryptographic box with RPC response.
    pub fn open_response_box(
        &mut self,
        response: &api::CryptoBox,
    ) -> Result<api::PlainClientResponse> {
        let plain_response = open_box(
            &response,
            &NONCE_CONTEXT_RESPONSE,
            &mut self.short_term_nonce_generator,
            &self.contract_short_term_public_key,
            &self.client_private_key,
            &mut self.shared_key,
        )?;

        Ok(protobuf::parse_from_bytes(&plain_response)?)
    }
}
