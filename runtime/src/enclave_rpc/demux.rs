//! Session demultiplexer.
use std::{collections::HashMap, io::Write, sync::Arc, time::SystemTime};

use anyhow::Result;
use thiserror::Error;

use super::{
    session::{Builder, Session, SessionInfo},
    types::{Frame, Message, SessionID},
};
use crate::{common::time::insecure_posix_system_time, rak::RAK};

/// Maximum concurrent EnclaveRPC sessions.
const DEFAULT_MAX_CONCURRENT_SESSIONS: usize = 100;
/// Sessions without any processed frame for more than STALE_SESSION_TIMEOUT_SECS seconds
/// can be purged.
const DEFAULT_STALE_SESSION_TIMEOUT_SECS: u64 = 60;
/// Stale session check will be performed on any new incoming connection with at minimum
/// STALE_SESSIONS_CHECK_TIMEOUT_SECS seconds between checks.
const STALE_SESSIONS_CHECK_TIMEOUT_SECS: u64 = 10;

/// Demux error.
#[derive(Error, Debug)]
enum DemuxError {
    #[error("session not found for id {session:?}")]
    SessionNotFound { session: SessionID },
    #[error("max concurrent sessions reached")]
    MaxConcurrentSessions,
}

pub type SessionMessage = (SessionID, Option<Arc<SessionInfo>>, Message, String);

/// Session demultiplexer.
pub struct Demux {
    rak: Arc<RAK>,
    sessions: HashMap<SessionID, EnrichedSession>,
    max_concurrent_sessions: usize,
    stale_session_timeout: u64,
    last_stale_sessions_purge: SystemTime,
}

struct EnrichedSession {
    session: Session,
    last_process_frame_time: SystemTime,
}

impl Demux {
    /// Create new session demultiplexer.
    pub fn new(rak: Arc<RAK>) -> Self {
        Self {
            rak,
            sessions: HashMap::new(),
            max_concurrent_sessions: DEFAULT_MAX_CONCURRENT_SESSIONS,
            stale_session_timeout: DEFAULT_STALE_SESSION_TIMEOUT_SECS,
            last_stale_sessions_purge: insecure_posix_system_time(),
        }
    }

    /// Configures max_concurrent_sessions.
    pub fn set_max_concurrent_sessions(&mut self, max_concurrent_sessions: usize) {
        self.max_concurrent_sessions = max_concurrent_sessions;
    }

    /// Configures stale session timeout.
    /// If 0, sessions are never considered stale.
    pub fn set_stale_session_timeout(&mut self, stale_session_timeout: u64) {
        self.stale_session_timeout = stale_session_timeout;
    }

    fn purge_stale_sessions(&mut self) {
        let now = insecure_posix_system_time();
        let stale_session_timeout = self.stale_session_timeout;

        // If 0, sessions should never be considered stale.
        if stale_session_timeout != 0 {
            self.sessions.retain(|_, val| {
                now.duration_since(val.last_process_frame_time)
                    .unwrap()
                    .as_secs()
                    < stale_session_timeout
            });
        }
        self.last_stale_sessions_purge = now;
    }

    /// Process an incoming frame.
    pub fn process_frame<W: Write>(
        &mut self,
        data: Vec<u8>,
        writer: W,
    ) -> Result<Option<SessionMessage>> {
        let frame: Frame = cbor::from_slice(&data)?;
        let id = frame.session;
        let untrusted_plaintext = frame.untrusted_plaintext.clone();

        if let Some(enriched_session) = self.sessions.get_mut(&id) {
            match enriched_session
                .session
                .process_data(frame.payload, writer)
                .map(|m| {
                    m.map(|msg| {
                        (
                            id,
                            enriched_session.session.session_info(),
                            msg,
                            untrusted_plaintext.clone(),
                        )
                    })
                }) {
                Ok(result) => {
                    enriched_session.last_process_frame_time = insecure_posix_system_time();
                    Ok(result)
                }
                // In case there is an error, drop the session.
                Err(error) => {
                    self.sessions.remove(&id);
                    Err(error)
                }
            }
        } else {
            // Session does not yet exist, first check if any stale sessions
            // should be closed.
            // Don't check if less than STALE_SESSIONS_CHECK_TIMEOUT_SECS seconds
            // since last check.
            let now = insecure_posix_system_time();
            if now
                .duration_since(self.last_stale_sessions_purge)
                .unwrap()
                .as_secs()
                >= STALE_SESSIONS_CHECK_TIMEOUT_SECS
            {
                self.purge_stale_sessions()
            }

            // Create a new session.
            if self.sessions.len() < self.max_concurrent_sessions {
                let mut session = Builder::default()
                    .local_rak(self.rak.clone())
                    .build_responder();
                let result = match session.process_data(frame.payload, writer).map(|m| {
                    m.map(|msg| (id, session.session_info(), msg, untrusted_plaintext.clone()))
                }) {
                    Ok(result) => result,
                    // In case there is an error, drop the session.
                    Err(error) => return Err(error),
                };
                self.sessions.insert(
                    id,
                    EnrichedSession {
                        session,
                        last_process_frame_time: insecure_posix_system_time(),
                    },
                );

                Ok(result)
            } else {
                Err(DemuxError::MaxConcurrentSessions.into())
            }
        }
    }

    /// Write message to session and generate a response.
    pub fn write_message<W: Write>(
        &mut self,
        id: SessionID,
        msg: Message,
        mut writer: W,
    ) -> Result<()> {
        match self.sessions.get_mut(&id) {
            Some(enriched_session) => {
                // Responses don't need framing as they are linked at the
                // runtime IPC protocol.
                enriched_session.session.write_message(msg, &mut writer)?;
                Ok(())
            }
            None => Err(DemuxError::SessionNotFound { session: id }.into()),
        }
    }

    /// Close the session and generate a response.
    pub fn close<W: Write>(&mut self, id: SessionID, mut writer: W) -> Result<()> {
        match self.sessions.remove(&id) {
            Some(mut enriched_session) => {
                // Responses don't need framing as they are linked at the
                // runtime IPC protocol.
                enriched_session
                    .session
                    .write_message(Message::Close, &mut writer)?;
                Ok(())
            }
            None => Err(DemuxError::SessionNotFound { session: id }.into()),
        }
    }
}
