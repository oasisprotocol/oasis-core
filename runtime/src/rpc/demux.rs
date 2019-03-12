//! Session demultiplexer.
use std::{
    collections::{hash_map::Entry, HashMap},
    io::Write,
    sync::Arc,
};

use failure::Fallible;
use serde_cbor;

use super::{
    session::{Builder, Session, SessionInfo},
    types::{Frame, Message, SessionID},
};
use crate::rak::RAK;

/// Demux error.
#[derive(Debug, Fail)]
enum DemuxError {
    #[fail(display = "session not found for id {}", session)]
    SessionNotFound { session: SessionID },
}

pub type SessionMessage = (SessionID, Option<Arc<SessionInfo>>, Message);

/// Session demultiplexer.
pub struct Demux {
    rak: Arc<RAK>,
    sessions: HashMap<SessionID, Session>,
}

impl Demux {
    /// Create new session demultiplexer.
    pub fn new(rak: Arc<RAK>) -> Self {
        Self {
            rak,
            sessions: HashMap::new(),
        }
    }

    /// Process an incoming frame.
    pub fn process_frame<W: Write>(
        &mut self,
        data: Vec<u8>,
        writer: W,
    ) -> Fallible<Option<SessionMessage>> {
        let frame: Frame = serde_cbor::from_slice(&data)?;
        let id = frame.session.clone();

        match self.sessions.entry(frame.session.clone()) {
            Entry::Occupied(mut entry) => {
                // Session already exists, let it process received data.
                let session = entry.get_mut();
                match session
                    .process_data(frame.payload, writer)
                    .map(|m| m.map(|msg| (id, session.session_info(), msg)))
                {
                    Ok(result) => Ok(result),
                    // In case there is an error, drop the session.
                    Err(error) => {
                        entry.remove_entry();
                        Err(error)
                    }
                }
            }
            Entry::Vacant(entry) => {
                // Session does not yet exist, create a new session.
                // TODO: Evaluate DOS potential and provide mitigations.
                let mut session = Builder::new().local_rak(self.rak.clone()).build_responder();
                let result = match session
                    .process_data(frame.payload, writer)
                    .map(|m| m.map(|msg| (id, session.session_info(), msg)))
                {
                    Ok(result) => result,
                    // In case there is an error, drop the session.
                    Err(error) => return Err(error),
                };
                entry.insert(session);

                Ok(result)
            }
        }
    }

    /// Write message to session and generate a response.
    pub fn write_message<W: Write>(
        &mut self,
        id: SessionID,
        msg: Message,
        mut writer: W,
    ) -> Fallible<()> {
        match self.sessions.get_mut(&id) {
            Some(session) => {
                // Responses don't need framing as they are linked at the
                // runtime IPC protocol.
                session.write_message(msg, &mut writer)?;
                Ok(())
            }
            None => Err(DemuxError::SessionNotFound { session: id }.into()),
        }
    }

    /// Close the session and generate a response.
    pub fn close<W: Write>(&mut self, id: SessionID, mut writer: W) -> Fallible<()> {
        match self.sessions.remove(&id) {
            Some(mut session) => {
                // Responses don't need framing as they are linked at the
                // runtime IPC protocol.
                session.write_message(Message::Close, &mut writer)?;
                Ok(())
            }
            None => Err(DemuxError::SessionNotFound { session: id }.into()),
        }
    }
}
