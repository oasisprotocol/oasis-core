//! Secure channel session.
use std::{collections::HashSet, io::Write, mem, sync::Arc};

use anyhow::Result;
use thiserror::Error;

use super::types::Message;
use crate::{
    common::{
        crypto::signature::{self, PublicKey, Signature, Signer},
        namespace::Namespace,
        sgx::{ias, EnclaveIdentity, Quote, QuotePolicy},
    },
    consensus::{
        registry::{EndorsedCapabilityTEE, VerifiedAttestation, VerifiedEndorsedCapabilityTEE},
        state::registry::ImmutableState as RegistryState,
        verifier::Verifier,
    },
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
    /// RAK binding.
    pub rak_binding: RAKBinding,
    /// Verified TEE remote attestation.
    pub verified_attestation: VerifiedAttestation,
    /// Identifier of the node that endorsed the TEE.
    pub endorsed_by: Option<PublicKey>,
}

enum State {
    Handshake1(snow::HandshakeState),
    Handshake2(snow::HandshakeState),
    Transport(snow::TransportState),
    UnauthenticatedTransport(snow::TransportState),
    Closed,
}

/// An encrypted and authenticated RPC session.
pub struct Session {
    cfg: Config,
    local_static_pub: Vec<u8>,
    remote_node: Option<signature::PublicKey>,
    info: Option<Arc<SessionInfo>>,
    state: State,
    buf: Vec<u8>,
}

impl Session {
    fn new(handshake_state: snow::HandshakeState, local_static_pub: Vec<u8>, cfg: Config) -> Self {
        Self {
            cfg,
            local_static_pub,
            remote_node: None,
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
    pub async fn process_data<W: Write>(
        &mut self,
        data: &[u8],
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
                    state.read_message(data, &mut self.buf)?;

                    // -> e, ee, s, es
                    let len = state.write_message(&self.get_rak_binding(), &mut self.buf)?;
                    writer.write_all(&self.buf[..len])?;
                }

                self.state = State::Handshake2(state);
            }
            State::Handshake2(mut state) => {
                // Process data sent during Handshake1 phase.
                let len = state.read_message(data, &mut self.buf)?;
                let remote_static = state
                    .get_remote_static()
                    .expect("dh exchange just happened");
                let auth_info = self
                    .verify_rak_binding(&self.buf[..len], remote_static)
                    .await;

                if state.is_initiator() {
                    // -> s, se
                    let len = state.write_message(&self.get_rak_binding(), &mut self.buf)?;
                    writer.write_all(&self.buf[..len])?;
                }

                match auth_info {
                    Ok(auth_info) => {
                        self.info = auth_info;
                        self.state = State::Transport(state.into_transport_mode()?);
                    }
                    Err(_) if state.is_initiator() => {
                        // There was an error authenticating the session and we are the initiator.
                        // Transition into unauthenticated transport state so we can notify the
                        // other side of the close.
                        self.state = State::UnauthenticatedTransport(state.into_transport_mode()?);
                    }
                    Err(err) => {
                        // There was an authentication error and we are not the initiator, abort.
                        return Err(err);
                    }
                }
            }
            State::Transport(mut state) => {
                // TODO: Restore session in case of errors.
                let len = state.read_message(data, &mut self.buf)?;
                let msg = cbor::from_slice(&self.buf[..len])?;

                self.state = State::Transport(state);
                return Ok(Some(msg));
            }
            State::Closed | State::UnauthenticatedTransport(_) => {
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
        let state = match self.state {
            State::Transport(ref mut state) => state,
            State::UnauthenticatedTransport(ref mut state) if matches!(msg, Message::Close) => {
                state
            }
            _ => return Err(SessionError::InvalidState.into()),
        };

        let len = state.write_message(&cbor::to_vec(msg), &mut self.buf)?;
        writer.write_all(&self.buf[..len])?;

        Ok(())
    }

    /// Mark the session as closed.
    ///
    /// After the session is closed it can no longer be used to transmit
    /// or receive messages and any such use will result in an error.
    pub fn close(&mut self) {
        self.state = State::Closed;
    }

    fn get_rak_binding(&self) -> Vec<u8> {
        match self.cfg.identity {
            Some(ref identity) => {
                if identity.quote().is_none() {
                    return vec![];
                }

                let binding = identity
                    .sign(&RAK_SESSION_BINDING_CONTEXT, &self.local_static_pub)
                    .unwrap();

                if self.cfg.use_endorsement {
                    // Use endorsed TEE capability when available.
                    if let Some(ect) = identity.endorsed_capability_tee() {
                        return cbor::to_vec(RAKBinding::V2 { ect, binding });
                    }
                }

                // Use the local RAK and quote.
                let rak_pub = identity.public_rak();
                let quote = identity.quote().expect("quote is configured");

                cbor::to_vec(RAKBinding::V1 {
                    rak_pub,
                    binding,
                    quote: (*quote).clone(),
                })
            }
            None => vec![],
        }
    }

    async fn verify_rak_binding(
        &self,
        rak_binding: &[u8],
        remote_static: &[u8],
    ) -> Result<Option<Arc<SessionInfo>>> {
        if rak_binding.is_empty() {
            // If enclave identity verification is required and no RAK binding
            // has been provided, we must abort the session.
            if self.cfg.remote_enclaves.is_some() {
                return Err(SessionError::MismatchedEnclaveIdentity.into());
            }
            return Ok(None);
        }

        let policy = self
            .cfg
            .policy
            .as_ref()
            .ok_or(SessionError::MissingQuotePolicy)?;

        let rak_binding: RAKBinding = cbor::from_slice(rak_binding)?;
        let vect = rak_binding.verify(remote_static, &self.cfg.remote_enclaves, policy)?;

        // Verify node identity if verification is enabled.
        if self.cfg.consensus_verifier.is_some() {
            let rak = rak_binding.rak_pub();
            self.verify_node_identity(rak).await?;
        }

        Ok(Some(Arc::new(SessionInfo {
            rak_binding,
            verified_attestation: vect.verified_attestation,
            endorsed_by: vect.node_id,
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
    pub fn is_connected_to(&self, nodes: &[signature::PublicKey]) -> bool {
        nodes.iter().any(|&node| Some(node) == self.remote_node)
    }

    /// Whether the session is in closed state.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    /// Whether the session is in unauthenticated transport state. In this state the session can
    /// only be used to transmit a close notification.
    pub fn is_unauthenticated(&self) -> bool {
        matches!(self.state, State::UnauthenticatedTransport(_))
    }

    /// Return remote node identifier.
    pub fn get_remote_node(&self) -> Result<signature::PublicKey> {
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
    async fn verify_node_identity(&self, rak: signature::PublicKey) -> Result<()> {
        let consensus_verifier = self
            .cfg
            .consensus_verifier
            .as_ref()
            .expect("consensus verifier should be set");
        let runtime_id = self
            .cfg
            .remote_runtime_id
            .ok_or(SessionError::RuntimeNotSet)?;
        let node = self.remote_node.ok_or(SessionError::NodeNotSet)?;

        let consensus_state = consensus_verifier.latest_state().await?;
        // TODO: Make this access async.
        let node = tokio::task::block_in_place(move || -> Result<_> {
            let registry_state = RegistryState::new(&consensus_state);
            Ok(registry_state
                .node(&node)?
                .ok_or(SessionError::NodeNotRegistered)?)
        })?;

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

    /// V2 format which supports endorsed CapabilityTEE structures.
    #[cbor(rename = 2)]
    V2 {
        ect: EndorsedCapabilityTEE,
        binding: Signature,
    },
}

impl RAKBinding {
    /// Public part of the RAK.
    pub fn rak_pub(&self) -> PublicKey {
        match self {
            Self::V0 { rak_pub, .. } => *rak_pub,
            Self::V1 { rak_pub, .. } => *rak_pub,
            Self::V2 { ect, .. } => ect.capability_tee.rak,
        }
    }

    /// Signature from RAK, binding the session's static public key to RAK.
    fn binding(&self) -> Signature {
        match self {
            Self::V0 { binding, .. } => *binding,
            Self::V1 { binding, .. } => *binding,
            Self::V2 { binding, .. } => *binding,
        }
    }

    /// Verify the RAK binding.
    pub fn verify(
        &self,
        remote_static: &[u8],
        remote_enclaves: &Option<HashSet<EnclaveIdentity>>,
        policy: &QuotePolicy,
    ) -> Result<VerifiedEndorsedCapabilityTEE> {
        let vect = self.verify_inner(policy)?;

        // Ensure that the report data includes the hash of the node's RAK.
        // NOTE: For V2 this check is part of verify_inner so it is not really needed.
        Identity::verify_binding(&vect.verified_attestation.quote, &self.rak_pub())?;

        // Verify MRENCLAVE/MRSIGNER.
        if let Some(ref remote_enclaves) = remote_enclaves {
            if !remote_enclaves.contains(&vect.verified_attestation.quote.identity) {
                return Err(SessionError::MismatchedEnclaveIdentity.into());
            }
        }

        // Verify remote static key binding.
        self.binding()
            .verify(&self.rak_pub(), &RAK_SESSION_BINDING_CONTEXT, remote_static)?;

        Ok(vect)
    }

    fn verify_inner(&self, policy: &QuotePolicy) -> Result<VerifiedEndorsedCapabilityTEE> {
        match self {
            Self::V0 { ref avr, .. } => {
                ias::verify(avr, &policy.ias.clone().unwrap_or_default()).map(|vq| vq.into())
            }
            Self::V1 { ref quote, .. } => quote.verify(policy).map(|vq| vq.into()),
            Self::V2 { ref ect, .. } => ect.verify(policy),
        }
    }
}

/// Session configuration.
#[derive(Clone, Default)]
struct Config {
    consensus_verifier: Option<Arc<dyn Verifier>>,
    identity: Option<Arc<Identity>>,
    remote_enclaves: Option<HashSet<EnclaveIdentity>>,
    remote_runtime_id: Option<Namespace>,
    use_endorsement: bool,
    policy: Option<Arc<QuotePolicy>>,
}

/// Session builder.
#[derive(Clone, Default)]
pub struct Builder {
    cfg: Config,
}

impl Builder {
    /// Return remote enclave identities if configured in the builder.
    pub fn get_remote_enclaves(&self) -> &Option<HashSet<EnclaveIdentity>> {
        &self.cfg.remote_enclaves
    }

    /// Enable remote enclave identity verification.
    pub fn remote_enclaves(mut self, enclaves: Option<HashSet<EnclaveIdentity>>) -> Self {
        self.cfg.remote_enclaves = enclaves;
        self
    }

    /// Return remote runtime ID if configured in the builder.
    pub fn get_remote_runtime_id(&self) -> &Option<Namespace> {
        &self.cfg.remote_runtime_id
    }

    /// Set remote runtime ID for node identity verification.
    pub fn remote_runtime_id(mut self, id: Option<Namespace>) -> Self {
        self.cfg.remote_runtime_id = id;
        self
    }

    /// Enable remote node identity verification.
    pub fn consensus_verifier(mut self, verifier: Option<Arc<dyn Verifier>>) -> Self {
        self.cfg.consensus_verifier = verifier;
        self
    }

    /// Return quote policy if configured in the builder.
    pub fn get_quote_policy(&self) -> &Option<Arc<QuotePolicy>> {
        &self.cfg.policy
    }

    /// Configure quote policy used for remote quote verification.
    pub fn quote_policy(mut self, policy: Option<Arc<QuotePolicy>>) -> Self {
        self.cfg.policy = policy;
        self
    }

    /// Use endorsement from host node when establishing sessions.
    pub fn use_endorsement(mut self, use_endorsement: bool) -> Self {
        self.cfg.use_endorsement = use_endorsement;
        self
    }

    /// Return the local identity if configured in the builder.
    pub fn get_local_identity(&self) -> &Option<Arc<Identity>> {
        &self.cfg.identity
    }

    /// Enable RAK binding.
    pub fn local_identity(mut self, identity: Arc<Identity>) -> Self {
        self.cfg.identity = Some(identity);
        self
    }

    fn build<'a>(self) -> (snow::Builder<'a>, snow::Keypair, Config) {
        let noise_builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
        let keypair = noise_builder.generate_keypair().unwrap();
        let cfg = self.cfg;

        (noise_builder, keypair, cfg)
    }

    /// Build initiator session.
    pub fn build_initiator(self) -> Session {
        let (builder, keypair, cfg) = self.build();
        let session = builder
            .local_private_key(&keypair.private)
            .build_initiator()
            .unwrap();
        Session::new(session, keypair.public, cfg)
    }

    /// Build responder session.
    pub fn build_responder(self) -> Session {
        let (builder, keypair, cfg) = self.build();
        let session = builder
            .local_private_key(&keypair.private)
            .build_responder()
            .unwrap();
        Session::new(session, keypair.public, cfg)
    }
}
