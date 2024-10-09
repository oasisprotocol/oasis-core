//! Session demultiplexer.
use std::{io::Write, sync::Mutex};

use thiserror::Error;
use tokio::sync::OwnedMutexGuard;

use super::{
    session::Builder,
    sessions::{self, MultiplexedSession, Sessions},
    types::{Frame, Message, SessionID},
};
use crate::common::time::insecure_posix_time;

/// Demultiplexer error.
#[derive(Error, Debug)]
pub enum Error {
    #[error("malformed payload: {0}")]
    MalformedPayload(#[from] cbor::DecodeError),
    #[error("malformed request method")]
    MalformedRequestMethod,
    #[error("sessions error: {0}")]
    SessionsError(#[from] sessions::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl Error {
    fn code(&self) -> u32 {
        match self {
            Error::MalformedPayload(_) => 1,
            Error::MalformedRequestMethod => 2,
            Error::SessionsError(_) => 3,
            Error::Other(_) => 4,
        }
    }
}

impl From<Error> for crate::types::Error {
    fn from(e: Error) -> Self {
        Self {
            module: "demux".to_string(),
            code: e.code(),
            message: e.to_string(),
        }
    }
}

/// Session demultiplexer.
pub struct Demux {
    sessions: Mutex<Sessions<Vec<u8>>>,
}

impl Demux {
    /// Create new session demultiplexer.
    pub fn new(
        builder: Builder,
        max_sessions: usize,
        max_sessions_per_peer: usize,
        stale_session_timeout: i64,
    ) -> Self {
        Self {
            sessions: Mutex::new(Sessions::new(
                builder,
                max_sessions,
                max_sessions_per_peer,
                stale_session_timeout,
            )),
        }
    }

    /// Set the session builder to use.
    pub fn set_session_builder(&self, builder: Builder) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.set_builder(builder);
    }

    async fn get_or_create_session(
        &self,
        peer_id: Vec<u8>,
        session_id: SessionID,
    ) -> Result<OwnedMutexGuard<MultiplexedSession<Vec<u8>>>, Error> {
        let session = {
            let mut sessions = self.sessions.lock().unwrap();
            match sessions.get(&peer_id, &session_id) {
                Some(session) => session,
                None => {
                    let now = insecure_posix_time();
                    let _ = sessions.remove_for(&peer_id, now)?;
                    let session = sessions.create_responder(peer_id, session_id);
                    sessions
                        .add(session, now)
                        .expect("there should be space for the new session")
                }
            }
        };

        Ok(session.lock_owned().await)
    }

    /// Process a frame, returning the locked session guard and decoded message.
    ///
    /// Any data that needs to be transmitted back to the peer is written to the passed writer.
    pub async fn process_frame<W: Write>(
        &self,
        peer_id: Vec<u8>,
        data: Vec<u8>,
        writer: W,
    ) -> Result<
        (
            OwnedMutexGuard<MultiplexedSession<Vec<u8>>>,
            Option<Message>,
        ),
        Error,
    > {
        // Decode frame.
        let frame: Frame = cbor::from_slice(&data)?;
        // Get the existing session or create a new one.
        let mut session = self.get_or_create_session(peer_id, frame.session).await?;
        // Process session data.
        match session.process_data(&frame.payload, writer).await {
            Ok(msg) => {
                if let Some(Message::Request(ref req)) = msg {
                    // Make sure that the untrusted_plaintext matches the request's method.
                    if frame.untrusted_plaintext != req.method {
                        return Err(Error::MalformedRequestMethod);
                    }
                }

                Ok((session, msg))
            }
            Err(err) => {
                // In case the session was closed, remove the session.
                if session.is_closed() {
                    let mut sessions = self.sessions.lock().unwrap();
                    sessions.remove(&session);
                }
                Err(Error::Other(err))
            }
        }
    }

    /// Closes the given session.
    ///
    /// Any data that needs to be transmitted back to the peer is written to the passed writer.
    pub fn close<W: Write>(
        &self,
        mut session: OwnedMutexGuard<MultiplexedSession<Vec<u8>>>,
        writer: W,
    ) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(&session);

        session.write_message(Message::Close, writer)?;
        Ok(())
    }

    /// Resets all open sessions.
    pub fn reset(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        let _ = sessions.drain();
    }
}
