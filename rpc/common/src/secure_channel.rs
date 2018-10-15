//! Common structures for secure channels.
use byteorder::{ByteOrder, LittleEndian};

use sodalite;

use ekiden_common::error::{Error, Result};
use ekiden_common::random;

use super::api;

// Nonce context is used to prevent message reuse in a different context.
pub const NONCE_CONTEXT_LEN: usize = 16;
type NonceContext = [u8; NONCE_CONTEXT_LEN];
/// Nonce for use in channel initialization context, enclave -> client.
pub const NONCE_CONTEXT_INIT: NonceContext = *b"EkidenS-----Init";
/// Nonce for use in channel authentication context, client -> enclave.
pub const NONCE_CONTEXT_AUTHIN: NonceContext = *b"EkidenS---AuthIn";
/// Nonce for use in channel authentication context, client -> enclave.
pub const NONCE_CONTEXT_AUTHOUT: NonceContext = *b"EkidenS--AuthOut";
/// Nonce for use in request context.
pub const NONCE_CONTEXT_REQUEST: NonceContext = *b"EkidenS--Request";
/// Nonce for use in response context.
pub const NONCE_CONTEXT_RESPONSE: NonceContext = *b"EkidenS-Response";

/// Nonce generator.
pub trait NonceGenerator {
    /// Reset nonce generator.
    fn reset(&mut self);

    /// Generate a new nonce.
    fn get_nonce(&mut self, context: &NonceContext) -> Result<sodalite::BoxNonce>;

    /// Unpack nonce from a cryptographic box.
    fn unpack_nonce(
        &mut self,
        crypto_box: &api::CryptoBox,
        context: &NonceContext,
    ) -> Result<sodalite::BoxNonce> {
        let mut nonce = [0u8; sodalite::BOX_NONCE_LEN];
        nonce.copy_from_slice(&crypto_box.get_nonce());

        // Ensure that the nonce context is correct.
        if nonce[..NONCE_CONTEXT_LEN] != context[..NONCE_CONTEXT_LEN] {
            return Err(Error::new("Invalid nonce"));
        }

        Ok(nonce)
    }
}

/// Random nonce generator.
pub struct RandomNonceGenerator {}

impl RandomNonceGenerator {
    /// Create new random nonce generator.
    pub fn new() -> Self {
        RandomNonceGenerator {}
    }
}

impl NonceGenerator for RandomNonceGenerator {
    fn reset(&mut self) {
        // No reset needed.
    }

    fn get_nonce(&mut self, context: &NonceContext) -> Result<sodalite::BoxNonce> {
        let mut nonce: sodalite::BoxNonce = [0; sodalite::BOX_NONCE_LEN];
        random::get_random_bytes(&mut nonce)?;

        nonce[..NONCE_CONTEXT_LEN].copy_from_slice(context);

        Ok(nonce)
    }
}

impl Default for RandomNonceGenerator {
    fn default() -> RandomNonceGenerator {
        RandomNonceGenerator::new()
    }
}

/// Monotonic nonce generator.
pub struct MonotonicNonceGenerator {
    /// Next nonce to be sent.
    next_send_nonce: u64,
    /// Last nonce that was received.
    last_received_nonce: Option<u64>,
}

impl MonotonicNonceGenerator {
    /// Create new monotonic nonce generator.
    pub fn new() -> Self {
        MonotonicNonceGenerator {
            next_send_nonce: 0, // TODO: Random initialization between 0 and 2**48 - 1?
            last_received_nonce: None,
        }
    }
}

impl NonceGenerator for MonotonicNonceGenerator {
    /// Reset nonce generator.
    fn reset(&mut self) {
        self.next_send_nonce = 0;
        self.last_received_nonce = None;
    }

    fn get_nonce(&mut self, context: &NonceContext) -> Result<sodalite::BoxNonce> {
        let mut nonce: Vec<u8> = context.to_vec();
        nonce.append(&mut vec![0; 8]);

        LittleEndian::write_u64(&mut nonce[NONCE_CONTEXT_LEN..], self.next_send_nonce);
        self.next_send_nonce += 1;

        assert_eq!(nonce.len(), sodalite::BOX_NONCE_LEN);

        let mut fixed_nonce: sodalite::BoxNonce = [0; sodalite::BOX_NONCE_LEN];
        fixed_nonce.copy_from_slice(&nonce);

        Ok(fixed_nonce)
    }

    fn unpack_nonce(
        &mut self,
        crypto_box: &api::CryptoBox,
        context: &NonceContext,
    ) -> Result<sodalite::BoxNonce> {
        let mut nonce = [0u8; sodalite::BOX_NONCE_LEN];
        nonce.copy_from_slice(&crypto_box.get_nonce());

        // Ensure that the nonce context is correct.
        if nonce[..NONCE_CONTEXT_LEN] != context[..NONCE_CONTEXT_LEN] {
            return Err(Error::new("Invalid nonce"));
        }

        // Decode counter.
        let counter_value = LittleEndian::read_u64(&nonce[NONCE_CONTEXT_LEN..]);

        // Ensure that the nonce has increased.
        match self.last_received_nonce {
            Some(last_nonce) => {
                if counter_value <= last_nonce {
                    return Err(Error::new("Invalid nonce"));
                }
            }
            None => {}
        }

        self.last_received_nonce = Some(counter_value);

        Ok(nonce)
    }
}

impl Default for MonotonicNonceGenerator {
    fn default() -> MonotonicNonceGenerator {
        MonotonicNonceGenerator::new()
    }
}

/// Current state of the secure channel session.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Session has been closed and must be reset.
    ///
    /// After the session is reset, it will transition into `Init`.
    Closed,
    /// Session is being initialized.
    ///
    /// From this state, the session will transition into `ClientAuthenticating` or `Established`.
    Init,
    /// Client is authenticating (client only).
    ///
    /// From this state, the session will transition into `Established`.
    /// The enclave does not use this state. The enclave is in the `Established` state while the
    /// client is in this state. The enclave tracks client authentication status in
    /// `ekiden_rpc_trusted::secure_channel::ClientSession::client_mr_enclave`.
    ClientAuthenticating,
    /// Secure channel is established.
    Established,
}

impl SessionState {
    /// Transition secure channel to a new state.
    pub fn transition_to(&mut self, new_state: SessionState) -> Result<()> {
        match (*self, new_state) {
            (SessionState::Closed, SessionState::Init) => {}
            (SessionState::Init, SessionState::Established) => {}
            (SessionState::Init, SessionState::ClientAuthenticating) => {}
            (SessionState::ClientAuthenticating, SessionState::Established) => {}
            (_, SessionState::Closed) => {}
            transition => {
                return Err(Error::new(format!(
                    "Invalid secure channel state transition: {:?}",
                    transition
                )))
            }
        }

        // Update state if transition is allowed.
        *self = new_state;

        Ok(())
    }
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState::Closed
    }
}

/// Create cryptographic box (encrypted and authenticated).
pub fn create_box<NG: NonceGenerator>(
    payload: &[u8],
    nonce_context: &NonceContext,
    nonce_generator: &mut NG,
    public_key: &sodalite::BoxPublicKey,
    private_key: &sodalite::BoxSecretKey,
    shared_key: &mut Option<sodalite::SecretboxKey>,
) -> Result<api::CryptoBox> {
    let mut crypto_box = api::CryptoBox::new();
    let mut key_with_payload = vec![0u8; payload.len() + 32];
    let mut encrypted = vec![0u8; payload.len() + 32];
    let nonce = nonce_generator.get_nonce(&nonce_context)?;

    // First 32 bytes is used to store the shared secret key, so we must make
    // room for it. The box_ method also requires that it is zero-initialized.
    key_with_payload[32..].copy_from_slice(payload);

    if shared_key.is_none() {
        // Compute shared key so we can speed up subsequent box operations.
        let mut key = shared_key.get_or_insert([0u8; sodalite::SECRETBOX_KEY_LEN]);
        sodalite::box_beforenm(&mut key, &public_key, &private_key);
    }

    match sodalite::box_afternm(
        &mut encrypted,
        &key_with_payload,
        &nonce,
        &shared_key.unwrap(),
    ) {
        Ok(_) => {}
        _ => return Err(Error::new("Box operation failed")),
    };

    crypto_box.set_nonce(nonce.to_vec());
    crypto_box.set_payload(encrypted);

    Ok(crypto_box)
}

/// Open cryptographic box.
pub fn open_box<NG: NonceGenerator>(
    crypto_box: &api::CryptoBox,
    nonce_context: &NonceContext,
    nonce_generator: &mut NG,
    public_key: &sodalite::BoxPublicKey,
    private_key: &sodalite::BoxSecretKey,
    shared_key: &mut Option<sodalite::SecretboxKey>,
) -> Result<Vec<u8>> {
    // Reserve space for payload.
    let mut payload = vec![0u8; crypto_box.get_payload().len()];

    if shared_key.is_none() {
        // Compute shared key so we can speed up subsequent box operations.
        let mut key = shared_key.get_or_insert([0u8; sodalite::SECRETBOX_KEY_LEN]);
        sodalite::box_beforenm(&mut key, &public_key, &private_key);
    }

    match sodalite::box_open_afternm(
        &mut payload,
        &crypto_box.get_payload(),
        &nonce_generator.unpack_nonce(&crypto_box, &nonce_context)?,
        &shared_key.unwrap(),
    ) {
        Ok(_) => {
            // Trim first all-zero 32 bytes that were used to allocate space for the shared
            // secret key.
            Ok(payload[32..].to_vec())
        }
        _ => Err(Error::new("Failed to open box")),
    }
}
