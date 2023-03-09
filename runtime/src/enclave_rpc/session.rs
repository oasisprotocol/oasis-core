//! Secure channel session.
use std::{collections::HashSet, io::Write, mem, sync::Arc};

use anyhow::Result;
use snow;
use thiserror::Error;

use super::types::Message;
use crate::{
    common::{
        crypto::signature::{self, PublicKey, Signature, Signer},
        namespace::Namespace,
        sgx::{ias, EnclaveIdentity, Quote, QuotePolicy, VerifiedQuote},
    },
    consensus::{state::registry::ImmutableState as RegistryState, verifier::Verifier},
    identity::Identity,
};

/// Noise protocol pattern.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// RAK signature session binding context.
const RAK_SESSION_BINDING_CONTEXT: [u8; 8] = *b"EkRakRpc";

/// Session-related error.
#[derive(Error, Debug)]
enum SessionError {
    #[error("invalid input")]
    InvalidInput,
    #[error("invalid state")]
    InvalidState,
    #[error("session closed")]
    Closed,
    #[error("mismatched enclave identity")]
    MismatchedEnclaveIdentity,
    #[error("missing quote policy")]
    MissingQuotePolicy,
    #[error("remote node not set")]
    NodeNotSet,
    #[error("remote node already set")]
    NodeAlreadySet,
    #[error("remote node not registered")]
    NodeNotRegistered,
    #[error("RAK not published in the consensus layer")]
    RAKNotFound,
    #[error("runtime id not set")]
    RuntimeNotSet,
}

/// Information about a session.
pub struct SessionInfo {
    pub rak_binding: RAKBinding,
    pub verified_quote: VerifiedQuote,
}

enum State {
    Handshake1(snow::HandshakeState),
    Handshake2(snow::HandshakeState),
    Transport(snow::TransportState),
    Closed,
}

/// An encrypted and authenticated RPC session.
pub struct Session {
    consensus_verifier: Option<Arc<dyn Verifier>>,
    local_static_pub: Vec<u8>,
    identity: Option<Arc<Identity>>,
    remote_enclaves: Option<HashSet<EnclaveIdentity>>,
    remote_node: Option<signature::PublicKey>,
    remote_runtime_id: Option<Namespace>,
    policy: Option<Arc<QuotePolicy>>,
    info: Option<Arc<SessionInfo>>,
    state: State,
    buf: Vec<u8>,
}

impl Session {
    fn new(
        consensus_verifier: Option<Arc<dyn Verifier>>,
        handshake_state: snow::HandshakeState,
        local_static_pub: Vec<u8>,
        identity: Option<Arc<Identity>>,
        remote_enclaves: Option<HashSet<EnclaveIdentity>>,
        remote_runtime_id: Option<Namespace>,
        policy: Option<Arc<QuotePolicy>>,
    ) -> Self {
        Self {
            consensus_verifier,
            local_static_pub,
            identity,
            remote_enclaves,
            remote_node: None,
            remote_runtime_id,
            policy,
            info: None,
            state: State::Handshake1(handshake_state),
            buf: vec![0u8; 65535],
        }
    }

    /// Process incoming data.
    ///
    /// In case the session is in transport mode the returned result will
    /// contained a parsed message. The `writer` will be used in case any
    /// protocol replies need to be generated.
    pub fn process_data<W: Write>(
        &mut self,
        data: Vec<u8>,
        mut writer: W,
    ) -> Result<Option<Message>> {
        // Replace the state with a closed state. In case processing fails for whatever
        // reason, this will cause the session to be torn down.
        match mem::replace(&mut self.state, State::Closed) {
            State::Handshake1(mut state) => {
                if state.is_initiator() {
                    // Initiator only sends in this state.
                    if !data.is_empty() {
                        return Err(SessionError::InvalidInput.into());
                    }

                    // -> e
                    let len = state.write_message(&[], &mut self.buf)?;
                    writer.write_all(&self.buf[..len])?;
                } else {
                    // <- e
                    state.read_message(&data, &mut self.buf)?;

                    // -> e, ee, s, es
                    let len = state.write_message(&self.get_rak_binding(), &mut self.buf)?;
                    writer.write_all(&self.buf[..len])?;
                }

                self.state = State::Handshake2(state);
            }
            State::Handshake2(mut state) => {
                if state.is_initiator() {
                    // <- e, ee, s, es
                    let len = state.read_message(&data, &mut self.buf)?;
                    let remote_static = state
                        .get_remote_static()
                        .expect("dh exchange just happened");
                    self.info = self.verify_rak_binding(&self.buf[..len], remote_static)?;

                    // -> s, se
                    let len = state.write_message(&self.get_rak_binding(), &mut self.buf)?;
                    writer.write_all(&self.buf[..len])?;
                } else {
                    // <- s, se
                    let len = state.read_message(&data, &mut self.buf)?;
                    let remote_static = state
                        .get_remote_static()
                        .expect("dh exchange just happened");
                    self.info = self.verify_rak_binding(&self.buf[..len], remote_static)?;
                }

                // Move into transport mode.
                self.state = State::Transport(state.into_transport_mode()?);
            }
            State::Transport(mut state) => {
                // TODO: Restore session in case of errors.
                let len = state.read_message(&data, &mut self.buf)?;
                let msg = cbor::from_slice(&self.buf[..len])?;

                self.state = State::Transport(state);
                return Ok(Some(msg));
            }
            State::Closed => {
                return Err(SessionError::Closed.into());
            }
        }

        Ok(None)
    }

    /// Write message to session.
    ///
    /// The `writer` will be used for protocol message output which should
    /// be transmitted to the remote session counterpart.
    pub fn write_message<W: Write>(&mut self, msg: Message, mut writer: W) -> Result<()> {
        if let State::Transport(ref mut state) = self.state {
            let msg = cbor::to_vec(msg);
            let len = state.write_message(&msg, &mut self.buf)?;
            writer.write_all(&self.buf[..len])?;

            Ok(())
        } else {
            Err(SessionError::InvalidState.into())
        }
    }

    /// Mark the session as closed.
    ///
    /// After the session is closed it can no longer be used to transmit
    /// or receive messages and any such use will result in an error.
    pub fn close(&mut self) {
        self.state = State::Closed;
    }

    fn get_rak_binding(&self) -> Vec<u8> {
        match self.identity {
            Some(ref identity) => {
                if identity.quote().is_none() {
                    return vec![];
                }

                let rak_pub = identity.public_rak();
                let quote = identity.quote().expect("quote is configured");
                let binding = identity
                    .sign(&RAK_SESSION_BINDING_CONTEXT, &self.local_static_pub)
                    .unwrap();

                // TODO: Change this once all runtimes have migrated to the new scheme.
                let rak_binding = if let Quote::Ias(ref avr) = *quote {
                    RAKBinding::V0 {
                        rak_pub,
                        binding,
                        avr: avr.clone(),
                    }
                } else {
                    RAKBinding::V1 {
                        rak_pub,
                        binding,
                        quote: (*quote).clone(),
                    }
                };

                cbor::to_vec(rak_binding)
            }
            None => vec![],
        }
    }

    fn verify_rak_binding(
        &self,
        rak_binding: &[u8],
        remote_static: &[u8],
    ) -> Result<Option<Arc<SessionInfo>>> {
        if rak_binding.is_empty() {
            // If enclave identity verification is required and no RAK binding
            // has been provided, we must abort the session.
            if self.remote_enclaves.is_some() {
                return Err(SessionError::MismatchedEnclaveIdentity.into());
            }
            return Ok(None);
        }

        let policy = self
            .policy
            .as_ref()
            .ok_or(SessionError::MissingQuotePolicy)?;

        let rak_binding: RAKBinding = cbor::from_slice(rak_binding)?;
        let verified_quote = rak_binding.verify(remote_static, &self.remote_enclaves, policy)?;

        // Verify node identity if verification is enabled.
        if self.consensus_verifier.is_some() {
            let rak = rak_binding.rak_pub();
            self.verify_node_identity(rak)?;
        }

        Ok(Some(Arc::new(SessionInfo {
            rak_binding,
            verified_quote,
        })))
    }

    /// Session information.
    pub fn session_info(&self) -> Option<Arc<SessionInfo>> {
        self.info.clone()
    }

    /// Whether the session handshake has completed and the session
    /// is in transport mode.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, State::Transport(_))
    }

    /// Whether the session is connected to one of the given nodes.
    pub fn is_connected_to(&self, nodes: &Vec<signature::PublicKey>) -> bool {
        nodes.iter().any(|&node| Some(node) == self.remote_node)
    }

    /// Whether the session is in closed state.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    /// Return remote node identifier.
    pub fn get_node(&self) -> Result<signature::PublicKey> {
        self.remote_node.ok_or(SessionError::NodeNotSet.into())
    }

    /// Set the remote node identifier.
    pub fn set_remote_node(&mut self, node: signature::PublicKey) -> Result<()> {
        if self.remote_node.is_some() {
            return Err(SessionError::NodeAlreadySet.into());
        }
        self.remote_node = Some(node);
        Ok(())
    }

    /// Verify the identity of the remote node by comparing the given RAK with the trusted RAK
    /// obtained from the consensus layer registry service.
    fn verify_node_identity(&self, rak: signature::PublicKey) -> Result<()> {
        let consensus_verifier = self
            .consensus_verifier
            .as_ref()
            .expect("consensus verifier should be set");
        let runtime_id = self.remote_runtime_id.ok_or(SessionError::RuntimeNotSet)?;
        let node = self.remote_node.ok_or(SessionError::NodeNotSet)?;

        let consensus_state = consensus_verifier.latest_state()?;
        let registry_state = RegistryState::new(&consensus_state);
        let node = registry_state
            .node(&node)?
            .ok_or(SessionError::NodeNotRegistered)?;
        let verified = node
            .runtimes
            .unwrap_or_default()
            .iter()
            .filter(|rt| rt.id == runtime_id)
            .flat_map(|rt| &rt.capabilities.tee)
            .any(|tee| tee.rak == rak);

        if !verified {
            return Err(SessionError::RAKNotFound.into());
        }
        Ok(())
    }
}

/// Binding of the session's static public key to a remote attestation
/// verification report through the use of the remote attestation key.
///
/// The signature chain is as follows:
///
/// * `avr` contains the remote attestation verification report which
///   binds RAK to the remote attestation.
/// * `rak_pub` contains the public part of RAK.
/// * `binding` is signed by `rak_pub` and binds the session's static
///   public key to RAK.
#[derive(Clone, Debug, cbor::Encode, cbor::Decode)]
#[cbor(tag = "v")]
pub enum RAKBinding {
    /// Old V0 format that only supported IAS quotes.
    #[cbor(rename = 0, missing)]
    V0 {
        rak_pub: PublicKey,
        binding: Signature,
        avr: ias::AVR,
    },

    /// New V1 format that supports both IAS and PCS quotes.
    #[cbor(rename = 1)]
    V1 {
        rak_pub: PublicKey,
        binding: Signature,
        quote: Quote,
    },
}

impl RAKBinding {
    /// Public part of the RAK.
    pub fn rak_pub(&self) -> PublicKey {
        match self {
            Self::V0 { rak_pub, .. } => *rak_pub,
            Self::V1 { rak_pub, .. } => *rak_pub,
        }
    }

    /// Signature from RAK, binding the session's static public key to RAK.
    pub fn binding(&self) -> Signature {
        match self {
            Self::V0 { binding, .. } => *binding,
            Self::V1 { binding, .. } => *binding,
        }
    }

    /// Verify the RAK binding.
    pub fn verify(
        &self,
        remote_static: &[u8],
        remote_enclaves: &Option<HashSet<EnclaveIdentity>>,
        policy: &QuotePolicy,
    ) -> Result<VerifiedQuote> {
        let verified_quote = self.verify_quote(policy)?;

        // Verify MRENCLAVE/MRSIGNER.
        if let Some(ref remote_enclaves) = remote_enclaves {
            if !remote_enclaves.contains(&verified_quote.identity) {
                return Err(SessionError::MismatchedEnclaveIdentity.into());
            }
        }

        // Verify RAK binding.
        Identity::verify_binding(&verified_quote, &self.rak_pub())?;

        // Verify remote static key binding.
        self.binding()
            .verify(&self.rak_pub(), &RAK_SESSION_BINDING_CONTEXT, remote_static)?;

        Ok(verified_quote)
    }

    /// Verify the quote that is part of the RAK binding.
    pub fn verify_quote(&self, policy: &QuotePolicy) -> Result<VerifiedQuote> {
        match self {
            Self::V0 { ref avr, .. } => ias::verify(avr, &policy.ias.clone().unwrap_or_default()),
            Self::V1 { ref quote, .. } => quote.verify(policy),
        }
    }
}

/// Session builder.
#[derive(Clone, Default)]
pub struct Builder {
    consensus_verifier: Option<Arc<dyn Verifier>>,
    identity: Option<Arc<Identity>>,
    remote_enclaves: Option<HashSet<EnclaveIdentity>>,
    remote_runtime_id: Option<Namespace>,
    policy: Option<Arc<QuotePolicy>>,
}

impl Builder {
    /// Return remote enclave identities if configured in the builder.
    pub fn get_remote_enclaves(&self) -> &Option<HashSet<EnclaveIdentity>> {
        &self.remote_enclaves
    }

    /// Enable remote enclave identity verification.
    pub fn remote_enclaves(mut self, enclaves: Option<HashSet<EnclaveIdentity>>) -> Self {
        self.remote_enclaves = enclaves;
        self
    }

    /// Return remote runtime ID if configured in the builder.
    pub fn get_remote_runtime_id(&self) -> &Option<Namespace> {
        &self.remote_runtime_id
    }

    /// Set remote runtime ID for node identity verification.
    pub fn remote_runtime_id(mut self, id: Option<Namespace>) -> Self {
        self.remote_runtime_id = id;
        self
    }

    /// Enable remote node identity verification.
    pub fn consensus_verifier(mut self, verifier: Option<Arc<dyn Verifier>>) -> Self {
        self.consensus_verifier = verifier;
        self
    }

    /// Return quote policy if configured in the builder.
    pub fn get_quote_policy(&self) -> &Option<Arc<QuotePolicy>> {
        &self.policy
    }

    /// Configure quote policy used for remote quote verification.
    pub fn quote_policy(mut self, policy: Option<Arc<QuotePolicy>>) -> Self {
        self.policy = policy;
        self
    }

    /// Enable RAK binding.
    pub fn local_identity(mut self, identity: Arc<Identity>) -> Self {
        self.identity = Some(identity);
        self
    }

    #[allow(clippy::type_complexity)]
    fn build<'a>(
        mut self,
    ) -> (
        snow::Builder<'a>,
        snow::Keypair,
        Option<Namespace>,
        Option<Arc<dyn Verifier>>,
        Option<Arc<Identity>>,
        Option<HashSet<EnclaveIdentity>>,
        Option<Arc<QuotePolicy>>,
    ) {
        let noise_builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
        let verifier = self.consensus_verifier.take();
        let identity = self.identity.take();
        let remote_enclaves = self.remote_enclaves.take();
        let remote_runtime_id = self.remote_runtime_id.take();
        let quote_policy = self.policy.take();
        let keypair = noise_builder.generate_keypair().unwrap();

        (
            noise_builder,
            keypair,
            remote_runtime_id,
            verifier,
            identity,
            remote_enclaves,
            quote_policy,
        )
    }

    /// Build initiator session.
    pub fn build_initiator(self) -> Session {
        let (builder, keypair, runtime_id, verifier, identity, enclaves, policy) = self.build();
        let session = builder
            .local_private_key(&keypair.private)
            .build_initiator()
            .unwrap();
        Session::new(
            verifier,
            session,
            keypair.public,
            identity,
            enclaves,
            runtime_id,
            policy,
        )
    }

    /// Build responder session.
    pub fn build_responder(self) -> Session {
        let (builder, keypair, runtime_id, verifier, identity, enclaves, policy) = self.build();
        let session = builder
            .local_private_key(&keypair.private)
            .build_responder()
            .unwrap();
        Session::new(
            verifier,
            session,
            keypair.public,
            identity,
            enclaves,
            runtime_id,
            policy,
        )
    }
}
