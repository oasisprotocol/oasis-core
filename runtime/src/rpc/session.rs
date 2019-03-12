//! Secure channel session.
use std::{io::Write, sync::Arc};

use failure::Fallible;
use serde_cbor;
use serde_derive::{Deserialize, Serialize};
use snow;

use super::types::Message;
use crate::{
    common::{
        crypto::signature::{PublicKey, Signature},
        sgx::avr,
    },
    rak::RAK,
};

/// Noise protocol pattern.
const NOISE_PATTERN: &'static str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// RAK signature session binding context.
const RAK_SESSION_BINDING_CONTEXT: [u8; 8] = *b"EkRakRpc";

/// Session-related error.
#[derive(Debug, Fail)]
enum SessionError {
    #[fail(display = "invalid input")]
    InvalidInput,
    #[fail(display = "invalid state")]
    InvalidState,
    #[fail(display = "session closed")]
    Closed,
    #[fail(
        display = "mismatched MRENCLAVE (expected: {:?} actual: {:?})",
        expected, actual
    )]
    MismatchedMrEnclave {
        expected: avr::MrEnclave,
        actual: avr::MrEnclave,
    },
}

/// Information about a session.
pub struct SessionInfo {
    pub rak_binding: RAKBinding,
    pub authenticated_avr: avr::AuthenticatedAVR,
}

#[derive(Eq, PartialEq)]
enum State {
    Handshake1,
    Handshake2,
    Transport,
    Closed,
}

/// An encrypted and authenticated RPC session.
pub struct Session {
    session: Option<snow::Session>,
    local_static_pub: Vec<u8>,
    rak: Option<Arc<RAK>>,
    remote_mrenclave: Option<avr::MrEnclave>,
    info: Option<Arc<SessionInfo>>,
    state: State,
    buf: Vec<u8>,
}

impl Session {
    fn new(
        session: snow::Session,
        local_static_pub: Vec<u8>,
        rak: Option<Arc<RAK>>,
        remote_mrenclave: Option<avr::MrEnclave>,
    ) -> Self {
        Self {
            session: Some(session),
            local_static_pub,
            rak,
            remote_mrenclave,
            info: None,
            state: State::Handshake1,
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
    ) -> Fallible<Option<Message>> {
        // Try to get the active protocol session. In case the session is not
        // there, this indicates that there was a protocol error while processing
        // data which means the session is closed.
        let mut session = self.session.take().ok_or(SessionError::Closed)?;

        match self.state {
            State::Handshake1 => {
                if session.is_initiator() {
                    // Initiator only sends in this state.
                    if !data.is_empty() {
                        return Err(SessionError::InvalidInput.into());
                    }

                    // -> e
                    let len = session.write_message(&[], &mut self.buf)?;
                    writer.write_all(&self.buf[..len])?;
                } else {
                    // <- e
                    session.read_message(&data, &mut self.buf)?;

                    // -> e, ee, s, es
                    let len = session.write_message(&self.get_rak_binding(), &mut self.buf)?;
                    writer.write_all(&self.buf[..len])?;
                }

                self.state = State::Handshake2;
                self.session = Some(session);
            }
            State::Handshake2 => {
                if session.is_initiator() {
                    // <- e, ee, s, es
                    let len = session.read_message(&data, &mut self.buf)?;
                    let remote_static = session
                        .get_remote_static()
                        .expect("dh exchange just happened");
                    self.info = self.verify_rak_binding(&self.buf[..len], remote_static)?;

                    // -> s, se
                    let len = session.write_message(&self.get_rak_binding(), &mut self.buf)?;
                    writer.write_all(&self.buf[..len])?;
                } else {
                    // <- s, se
                    let len = session.read_message(&data, &mut self.buf)?;
                    let remote_static = session
                        .get_remote_static()
                        .expect("dh exchange just happened");
                    self.info = self.verify_rak_binding(&self.buf[..len], remote_static)?;
                }

                // Move into transport mode.
                self.session = Some(session.into_transport_mode()?);
                self.state = State::Transport;
            }
            State::Transport => {
                // TODO: Restore session in case of errors.
                let len = session.read_message(&data, &mut self.buf)?;
                let msg = serde_cbor::from_slice(&self.buf[..len])?;

                self.session = Some(session);
                return Ok(Some(msg));
            }
            State::Closed => {
                return Err(SessionError::InvalidState.into());
            }
        }

        Ok(None)
    }

    /// Write message to session.
    ///
    /// The `writer` will be used for protocol message output which should
    /// be transmitted to the remote session counterpart.
    pub fn write_message<W: Write>(&mut self, msg: Message, mut writer: W) -> Fallible<()> {
        if self.state != State::Transport {
            return Err(SessionError::InvalidState.into());
        }

        let session = self.session.as_mut().ok_or(SessionError::Closed)?;

        let msg = serde_cbor::to_vec(&msg)?;
        let len = session.write_message(&msg, &mut self.buf)?;
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

                serde_cbor::to_vec(&rak_binding).unwrap()
            }
            None => vec![],
        }
    }

    fn verify_rak_binding(
        &self,
        rak_binding: &[u8],
        remote_static: &[u8],
    ) -> Fallible<Option<Arc<SessionInfo>>> {
        if rak_binding.is_empty() {
            // If MRENCLAVE verification is required and no RAK binding has been
            // provided, we must abort the session.
            if let Some(ref mr_enclave) = self.remote_mrenclave {
                return Err(SessionError::MismatchedMrEnclave {
                    expected: mr_enclave.clone(),
                    actual: avr::MrEnclave::default(),
                }
                .into());
            }
            return Ok(None);
        }

        let rak_binding: RAKBinding = serde_cbor::from_slice(rak_binding)?;
        let authenticated_avr = avr::verify(&rak_binding.avr)?;

        // Verify MRENCLAVE.
        if let Some(ref mr_enclave) = self.remote_mrenclave {
            if mr_enclave != &authenticated_avr.mr_enclave {
                return Err(SessionError::MismatchedMrEnclave {
                    expected: mr_enclave.clone(),
                    actual: authenticated_avr.mr_enclave,
                }
                .into());
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

    /// Return true if session handshake has completed and the session
    /// is in transport mode.
    pub fn is_connected(&self) -> bool {
        self.state == State::Transport
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
#[derive(Clone, Serialize, Deserialize)]
pub struct RAKBinding {
    pub avr: avr::AVR,
    pub rak_pub: PublicKey,
    pub binding: Signature,
}

/// Session builder.
#[derive(Clone)]
pub struct Builder {
    rak: Option<Arc<RAK>>,
    remote_mrenclave: Option<avr::MrEnclave>,
}

impl Builder {
    /// Create new session builder.
    pub fn new() -> Self {
        Self {
            rak: None,
            remote_mrenclave: None,
        }
    }

    /// Return remote MRENCLAVE if configured in the builder.
    pub fn get_remote_mrenclave(&self) -> &Option<avr::MrEnclave> {
        &self.remote_mrenclave
    }

    /// Enable remote MRENCLAVE verification.
    pub fn remote_mrenclave(mut self, mrenclave: Option<avr::MrEnclave>) -> Self {
        self.remote_mrenclave = mrenclave;
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
        Option<avr::MrEnclave>,
    ) {
        let noise_builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
        let rak = self.rak.take();
        let remote_mrenclave = self.remote_mrenclave.take();
        let keypair = noise_builder.generate_keypair().unwrap();

        (noise_builder, keypair, rak, remote_mrenclave)
    }

    /// Build initiator session.
    pub fn build_initiator(self) -> Session {
        let (builder, keypair, rak, mrenclave) = self.build();
        let session = builder
            .local_private_key(&keypair.private)
            .build_initiator()
            .unwrap();
        Session::new(session, keypair.public, rak, mrenclave)
    }

    /// Build responder session.
    pub fn build_responder(self) -> Session {
        let (builder, keypair, rak, mrenclave) = self.build();
        let session = builder
            .local_private_key(&keypair.private)
            .build_responder()
            .unwrap();
        Session::new(session, keypair.public, rak, mrenclave)
    }
}
