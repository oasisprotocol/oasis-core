//! Secure channel session.
use std::{collections::HashSet, io::Write, mem, sync::Arc};

use anyhow::Result;
use snow;
use thiserror::Error;

use super::types::Message;
use crate::{
    common::{
        crypto::signature::{PublicKey, Signature, Signer},
        sgx::avr,
    },
    rak::RAK,
};

/// Noise protocol pattern.
const NOISE_PATTERN: &'static str = "Noise_XX_25519_ChaChaPoly_SHA256";
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
}

/// Information about a session.
pub struct SessionInfo {
    pub rak_binding: RAKBinding,
    pub authenticated_avr: avr::AuthenticatedAVR,
}

enum State {
    Handshake1(snow::HandshakeState),
    Handshake2(snow::HandshakeState),
    Transport(snow::TransportState),
    Closed,
}

/// An encrypted and authenticated RPC session.
pub struct Session {
    local_static_pub: Vec<u8>,
    rak: Option<Arc<RAK>>,
    remote_enclaves: Option<HashSet<avr::EnclaveIdentity>>,
    info: Option<Arc<SessionInfo>>,
    state: State,
    buf: Vec<u8>,
}

impl Session {
    fn new(
        handshake_state: snow::HandshakeState,
        local_static_pub: Vec<u8>,
        rak: Option<Arc<RAK>>,
        remote_enclaves: Option<HashSet<avr::EnclaveIdentity>>,
    ) -> Self {
        Self {
            local_static_pub,
            rak,
            remote_enclaves,
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
        match self.rak {
            Some(ref rak) => {
                if rak.public_key().is_none() || rak.avr().is_none() {
                    return vec![];
                }

                let rak_pub = rak.public_key().expect("rak is configured").clone();
                let avr = rak.avr().expect("avr is configured").clone();
                let rak_binding = RAKBinding {
                    avr: (*avr).clone(),
                    rak_pub,
                    binding: rak
                        .sign(&RAK_SESSION_BINDING_CONTEXT, &self.local_static_pub)
                        .unwrap(),
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

        let rak_binding: RAKBinding = cbor::from_slice(rak_binding)?;
        let authenticated_avr = avr::verify(&rak_binding.avr)?;

        // Verify MRENCLAVE/MRSIGNER.
        if let Some(ref remote_enclaves) = self.remote_enclaves {
            if !remote_enclaves.contains(&authenticated_avr.identity) {
                return Err(SessionError::MismatchedEnclaveIdentity.into());
            }
        }

        // Verify RAK binding.
        RAK::verify_binding(&authenticated_avr, &rak_binding.rak_pub)?;

        // Verify remote static key binding.
        rak_binding.binding.verify(
            &rak_binding.rak_pub,
            &RAK_SESSION_BINDING_CONTEXT,
            remote_static,
        )?;

        Ok(Some(Arc::new(SessionInfo {
            rak_binding,
            authenticated_avr,
        })))
    }

    /// Session information.
    pub fn session_info(&self) -> Option<Arc<SessionInfo>> {
        self.info.clone()
    }

    /// Whether the session handshake has completed and the session
    /// is in transport mode.
    pub fn is_connected(&self) -> bool {
        if let State::Transport(_) = self.state {
            true
        } else {
            false
        }
    }

    /// Whether the session is in closed state.
    pub fn is_closed(&self) -> bool {
        if let State::Closed = self.state {
            true
        } else {
            false
        }
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
#[derive(Clone, cbor::Encode, cbor::Decode)]
pub struct RAKBinding {
    pub avr: avr::AVR,
    pub rak_pub: PublicKey,
    pub binding: Signature,
}

/// Session builder.
#[derive(Clone)]
pub struct Builder {
    rak: Option<Arc<RAK>>,
    remote_enclaves: Option<HashSet<avr::EnclaveIdentity>>,
}

impl Builder {
    /// Create new session builder.
    pub fn new() -> Self {
        Self {
            rak: None,
            remote_enclaves: None,
        }
    }

    /// Return remote enclave identities if configured in the builder.
    pub fn get_remote_enclaves(&self) -> &Option<HashSet<avr::EnclaveIdentity>> {
        &self.remote_enclaves
    }

    /// Enable remote enclave identity verification.
    pub fn remote_enclaves(mut self, enclaves: Option<HashSet<avr::EnclaveIdentity>>) -> Self {
        self.remote_enclaves = enclaves;
        self
    }

    /// Enable RAK binding.
    pub fn local_rak(mut self, rak: Arc<RAK>) -> Self {
        self.rak = Some(rak);
        self
    }

    fn build<'a>(
        mut self,
    ) -> (
        snow::Builder<'a>,
        snow::Keypair,
        Option<Arc<RAK>>,
        Option<HashSet<avr::EnclaveIdentity>>,
    ) {
        let noise_builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
        let rak = self.rak.take();
        let remote_enclaves = self.remote_enclaves.take();
        let keypair = noise_builder.generate_keypair().unwrap();

        (noise_builder, keypair, rak, remote_enclaves)
    }

    /// Build initiator session.
    pub fn build_initiator(self) -> Session {
        let (builder, keypair, rak, enclaves) = self.build();
        let session = builder
            .local_private_key(&keypair.private)
            .build_initiator()
            .unwrap();
        Session::new(session, keypair.public, rak, enclaves)
    }

    /// Build responder session.
    pub fn build_responder(self) -> Session {
        let (builder, keypair, rak, enclaves) = self.build();
        let session = builder
            .local_private_key(&keypair.private)
            .build_responder()
            .unwrap();
        Session::new(session, keypair.public, rak, enclaves)
    }
}
