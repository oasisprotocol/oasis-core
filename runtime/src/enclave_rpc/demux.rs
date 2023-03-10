//! Session demultiplexer.
use std::{
    collections::HashMap,
    io::Write,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use thiserror::Error;

use super::{
    session::{Builder, Session, SessionInfo},
    types::{Frame, Message, SessionID},
};
use crate::{common::time::insecure_posix_system_time, identity::Identity};

/// Maximum concurrent EnclaveRPC sessions.
const MAX_CONCURRENT_SESSIONS: usize = 100;
/// Sessions without any processed frame for more than STALE_SESSION_TIMEOUT_SECS seconds
/// can be purged.
const STALE_SESSION_TIMEOUT_SECS: u64 = 60;
/// Stale session check will be performed on any new incoming connection with at minimum
/// STALE_SESSIONS_CHECK_TIMEOUT_SECS seconds between checks.
const STALE_SESSIONS_CHECK_TIMEOUT_SECS: u64 = 10;

/// Demultiplexer error.
#[derive(Error, Debug)]
pub enum Error {
    #[error("malformed payload: {0}")]
    MalformedPayload(#[from] cbor::DecodeError),
    #[error("malformed request method")]
    MalformedRequestMethod,
    #[error("max concurrent sessions reached")]
    MaxConcurrentSessions,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl Error {
    fn code(&self) -> u32 {
        match self {
            Error::MalformedPayload(_) => 1,
            Error::MalformedRequestMethod => 2,
            Error::MaxConcurrentSessions => 3,
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

/// A map of session identifiers to session instances.
type SessionMap = HashMap<SessionID, Arc<tokio::sync::Mutex<MultiplexedSession>>>;

/// Session demultiplexer.
pub struct Demux {
    identity: Arc<Identity>,

    sessions: Mutex<SessionMap>,
    last_stale_sessions_purge: Mutex<SystemTime>,
}

/// A multiplexed session.
pub struct MultiplexedSession {
    id: SessionID,
    session: Session,
    last_process_frame_time: SystemTime,
}

impl MultiplexedSession {
    /// Session information.
    pub fn info(&self) -> Option<Arc<SessionInfo>> {
        self.session.session_info()
    }

    /// Process incoming session data.
    pub async fn process_data<W: Write>(
        &mut self,
        data: Vec<u8>,
        writer: W,
    ) -> Result<Option<Message>, Error> {
        let msg = self.session.process_data(data, writer).await?;

        // Update last processed frame time.
        self.last_process_frame_time = insecure_posix_system_time();

        Ok(msg)
    }

    /// Write message to session and generate a response.
    pub fn write_message<W: Write>(&mut self, msg: Message, mut writer: W) -> Result<(), Error> {
        Ok(self.session.write_message(msg, &mut writer)?)
    }
}

impl Demux {
    /// Create new session demultiplexer.
    pub fn new(identity: Arc<Identity>) -> Self {
        Self {
            identity,
            sessions: Default::default(),
            last_stale_sessions_purge: Mutex::new(insecure_posix_system_time()),
        }
    }

    fn purge_stale_sessions(&self, sessions: &mut SessionMap) {
        let now = insecure_posix_system_time();
        if STALE_SESSION_TIMEOUT_SECS == 0 {
            // If 0, sessions should never be considered stale.
            return;
        }

        let mut last_stale_sessions_purge = self.last_stale_sessions_purge.lock().unwrap();

        if now
            .duration_since(*last_stale_sessions_purge)
            .unwrap()
            .as_secs()
            < STALE_SESSIONS_CHECK_TIMEOUT_SECS
        {
            // Skip pruning if already pruned.
            return;
        }

        // Prune sessions.
        sessions.retain(|_, ms| {
            match ms.try_lock() {
                Ok(ms) => {
                    // No locks held, check if we can prune.
                    now.duration_since(ms.last_process_frame_time)
                        .unwrap()
                        .as_secs()
                        < STALE_SESSION_TIMEOUT_SECS
                }
                Err(_) => {
                    // Session is currently in use, skip pruning.
                    true
                }
            }
        });
        *last_stale_sessions_purge = now;
    }

    /// Decode a frame.
    fn decode_frame(&self, data: Vec<u8>) -> Result<Frame, Error> {
        Ok(cbor::from_slice(&data)?)
    }

    /// Fetch an existing session given its identifier or create a new session with the given
    /// identifier, returning the locked session guard.
    fn get_or_create_session(
        &self,
        id: SessionID,
    ) -> Result<Arc<tokio::sync::Mutex<MultiplexedSession>>, Error> {
        let mut sessions = self.sessions.lock().unwrap();

        if let Some(session) = sessions.get(&id) {
            Ok(session.clone())
        } else {
            // Session does not yet exist, first check if any stale sessions should be closed.
            //
            // Don't check if less than STALE_SESSIONS_CHECK_TIMEOUT_SECS seconds since last check.
            self.purge_stale_sessions(&mut sessions);

            // Create a new session.
            if sessions.len() < MAX_CONCURRENT_SESSIONS {
                let session = Builder::default()
                    .quote_policy(self.identity.quote_policy())
                    .local_identity(self.identity.clone())
                    .build_responder();
                let session = Arc::new(tokio::sync::Mutex::new(MultiplexedSession {
                    id,
                    session,
                    last_process_frame_time: insecure_posix_system_time(),
                }));

                sessions.insert(id, session.clone());

                Ok(session)
            } else {
                Err(Error::MaxConcurrentSessions)
            }
        }
    }

    /// Process a frame, returning the locked session guard and decoded message.
    ///
    /// Any data that needs to be transmitted back to the peer is written to the passed writer.
    pub async fn process_frame<W: Write>(
        &self,
        data: Vec<u8>,
        writer: W,
    ) -> Result<
        (
            tokio::sync::OwnedMutexGuard<MultiplexedSession>,
            Option<Message>,
        ),
        Error,
    > {
        // Decode frame.
        let frame = self.decode_frame(data)?;
        // Get the existing session or create a new one.
        let mut session = self
            .get_or_create_session(frame.session)?
            .lock_owned()
            .await;
        // Process session data.
        let result = session.process_data(frame.payload, writer).await;
        match result {
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
                if session.session.is_closed() {
                    let mut sessions = self.sessions.lock().unwrap();
                    sessions.remove(&frame.session);
                }
                Err(err)
            }
        }
    }

    /// Closes the given session.
    ///
    /// Any data that needs to be transmitted back to the peer is written to the passed writer.
    pub fn close<W: Write>(
        &self,
        mut session: tokio::sync::OwnedMutexGuard<MultiplexedSession>,
        writer: W,
    ) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(&session.id);

        session.write_message(Message::Close, writer)?;
        Ok(())
    }

    /// Resets all open sessions.
    pub fn reset(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.clear();
    }
}
