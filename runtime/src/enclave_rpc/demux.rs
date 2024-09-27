//! Session demultiplexer.
use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
    io::Write,
    sync::{Arc, Mutex},
};

use thiserror::Error;
use tokio::sync::OwnedMutexGuard;

use super::{
    session::{Builder, Session, SessionInfo},
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

/// Shared pointer to a multiplexed session.
type SharedSession<PeerID> = Arc<tokio::sync::Mutex<MultiplexedSession<PeerID>>>;

/// Key for use in the by-idle-time index.
type SessionByTimeKey<PeerID> = (i64, PeerID, SessionID);

/// Structure used for session accounting.
struct SessionMeta<PeerID: Clone + Ord + Hash> {
    /// Peer identifier.
    peer_id: PeerID,
    /// Session identifier.
    session_id: SessionID,
    /// Timestamp when the session was last accessed.
    last_access_time: i64,
    /// The shared session pointer that needs to be locked for access.
    inner: SharedSession<PeerID>,
}

impl<PeerID> SessionMeta<PeerID>
where
    PeerID: Clone + Ord + Hash,
{
    /// Key for ordering in the by-idle-time index.
    fn by_time_key(&self) -> SessionByTimeKey<PeerID> {
        (self.last_access_time, self.peer_id.clone(), self.session_id)
    }
}

/// Session indices and management operations.
struct Sessions<PeerID: Clone + Ord + Hash> {
    /// Session builder.
    builder: Builder,
    /// Maximum number of sessions.
    max_sessions: usize,
    /// Maximum number of sessions per peer.
    max_sessions_per_peer: usize,
    /// Stale session timeout (in seconds).
    stale_session_timeout: i64,

    /// A map of sessions for each peer.
    by_peer: HashMap<PeerID, HashMap<SessionID, SessionMeta<PeerID>>>,
    /// A set of all sessions, ordered by idle time.
    by_idle_time: BTreeSet<SessionByTimeKey<PeerID>>,
}

impl<PeerID> Sessions<PeerID>
where
    PeerID: Clone + Ord + Hash,
{
    /// Create a new session management instance.
    fn new(
        builder: Builder,
        max_sessions: usize,
        max_sessions_per_peer: usize,
        stale_session_timeout: i64,
    ) -> Self {
        Self {
            builder,
            max_sessions,
            max_sessions_per_peer,
            stale_session_timeout,
            by_peer: HashMap::new(),
            by_idle_time: BTreeSet::new(),
        }
    }

    /// Create a new multiplexed session.
    fn create_session(
        mut builder: Builder,
        peer_id: PeerID,
        session_id: SessionID,
        now: i64,
    ) -> SessionMeta<PeerID> {
        // If no quote policy is set, use the local one.
        if builder.get_quote_policy().is_none() {
            let policy = builder
                .get_local_identity()
                .as_ref()
                .and_then(|id| id.quote_policy());
            builder = builder.quote_policy(policy);
        }

        SessionMeta {
            inner: Arc::new(tokio::sync::Mutex::new(MultiplexedSession {
                peer_id: peer_id.clone(),
                session_id,
                inner: builder.build_responder(),
            })),
            peer_id,
            session_id,
            last_access_time: now,
        }
    }

    /// Fetch an existing session given its identifier.
    fn get(&mut self, peer_id: &PeerID, session_id: &SessionID) -> Option<SharedSession<PeerID>> {
        // Check if peer exists.
        let sessions = match self.by_peer.get_mut(peer_id) {
            Some(sessions) => sessions,
            None => return None,
        };

        // Check if the session exists. If so, return it.
        let session = match sessions.get_mut(session_id) {
            Some(session) => session,
            None => return None,
        };

        // Remove old idle time.
        self.by_idle_time.remove(&session.by_time_key());

        // Update idle time.
        session.last_access_time = insecure_posix_time();
        self.by_idle_time.insert(session.by_time_key());

        Some(session.inner.clone())
    }

    /// Remove one existing session from the given peer if the peer has reached
    /// the maximum number of sessions or if the total number of sessions exceeds
    /// the global session limit.
    fn remove_from(
        &mut self,
        peer_id: &PeerID,
    ) -> Result<Option<OwnedMutexGuard<MultiplexedSession<PeerID>>>, Error> {
        // Check if peer exists.
        let sessions = match self.by_peer.get_mut(peer_id) {
            Some(sessions) => sessions,
            None => return Ok(None),
        };

        // Check if the peer has max sessions or if no more sessions are available globally.
        // If so, remove the oldest or return an error.
        if sessions.len() < self.max_sessions_per_peer
            && self.by_idle_time.len() < self.max_sessions
        {
            return Ok(None);
        }

        // Force close the oldest idle session.
        let remove_session = sessions
            .iter()
            .min_by_key(|(_, s)| {
                if let Ok(_inner) = s.inner.try_lock() {
                    s.last_access_time
                } else {
                    i64::MAX // Session is currently in use.
                }
            })
            .map(|(_, s)| s.inner.clone())
            .ok_or(Error::MaxConcurrentSessions)?;

        let session = match remove_session.try_lock_owned() {
            Ok(inner) => inner,
            Err(_) => return Err(Error::MaxConcurrentSessions), // All sessions are in use.
        };

        self.remove(&session);

        Ok(Some(session))
    }

    /// Remove one stale session if the total number of sessions exceeds
    /// the global session limit.
    fn remove_one(
        &mut self,
        now: i64,
    ) -> Result<Option<OwnedMutexGuard<MultiplexedSession<PeerID>>>, Error> {
        // Check if there are too many sessions. If so, remove one or return an error.
        if self.by_idle_time.len() < self.max_sessions {
            return Ok(None);
        }

        // Attempt to prune stale sessions, starting with the oldest ones.
        let mut remove_session: Option<OwnedMutexGuard<MultiplexedSession<PeerID>>> = None;

        for (last_process_frame_time, peer_id, session_id) in self.by_idle_time.iter() {
            if now.saturating_sub(*last_process_frame_time) < self.stale_session_timeout {
                // This is the oldest session, all next ones will be more fresh.
                return Err(Error::MaxConcurrentSessions);
            }

            // Fetch session and attempt to lock it.
            if let Some(sessions) = self.by_peer.get(peer_id) {
                if let Some(session) = sessions.get(session_id) {
                    if let Ok(session) = session.inner.clone().try_lock_owned() {
                        remove_session = Some(session);
                        break;
                    }
                }
            }
        }

        // Check if we found a session that can be removed.
        let session = match remove_session {
            Some(session) => session,
            None => return Err(Error::MaxConcurrentSessions), // All stale sessions are in use.
        };

        self.remove(&session);

        Ok(Some(session))
    }

    /// Create a new session if there is an available spot.
    fn create(
        &mut self,
        peer_id: PeerID,
        session_id: SessionID,
        now: i64,
    ) -> Result<SharedSession<PeerID>, Error> {
        if self.by_idle_time.len() >= self.max_sessions {
            return Err(Error::MaxConcurrentSessions);
        }

        let sessions = self.by_peer.entry(peer_id.clone()).or_default();
        if sessions.len() >= self.max_sessions_per_peer {
            return Err(Error::MaxConcurrentSessions);
        }

        let session = Self::create_session(self.builder.clone(), peer_id.clone(), session_id, now);
        let inner = session.inner.clone();
        sessions.insert(session_id, session);
        self.by_idle_time.insert((now, peer_id, session_id));

        Ok(inner)
    }

    /// Remove a session that must be currently owned by the caller.
    fn remove(&mut self, session: &OwnedMutexGuard<MultiplexedSession<PeerID>>) {
        let sessions = self.by_peer.get_mut(&session.peer_id).unwrap();
        let session_meta = sessions.get(&session.session_id).unwrap();
        let key = session_meta.by_time_key();
        sessions.remove(&session.session_id);
        self.by_idle_time.remove(&key);

        // If peer doesn't have any more sessions, remove the peer.
        if sessions.is_empty() {
            self.by_peer.remove(&session.peer_id);
        }
    }

    /// Clear all sessions.
    fn clear(&mut self) {
        self.by_peer.clear();
        self.by_idle_time.clear();
    }

    /// Number of all sessions.
    #[cfg(test)]
    fn session_count(&self) -> usize {
        self.by_idle_time.len()
    }

    /// Number of all peers.
    #[cfg(test)]
    fn peer_count(&self) -> usize {
        self.by_peer.len()
    }
}

/// Session demultiplexer.
pub struct Demux {
    sessions: Mutex<Sessions<Vec<u8>>>,
}

/// A multiplexed session.
pub struct MultiplexedSession<PeerID> {
    /// Peer identifier (needed for resolution when only given the shared pointer).
    peer_id: PeerID,
    /// Session identifier (needed for resolution when only given the shared pointer).
    session_id: SessionID,
    /// The actual session.
    inner: Session,
}

impl<PeerID> MultiplexedSession<PeerID> {
    /// Session information.
    pub fn info(&self) -> Option<Arc<SessionInfo>> {
        self.inner.session_info()
    }

    /// Process incoming session data.
    async fn process_data<W: Write>(
        &mut self,
        data: Vec<u8>,
        writer: W,
    ) -> Result<Option<Message>, Error> {
        Ok(self.inner.process_data(data, writer).await?)
    }

    /// Write message to session and generate a response.
    pub fn write_message<W: Write>(&mut self, msg: Message, mut writer: W) -> Result<(), Error> {
        Ok(self.inner.write_message(msg, &mut writer)?)
    }
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
                    let _ = sessions.remove_from(&peer_id)?;
                    let _ = sessions.remove_one(now)?;
                    sessions.create(peer_id, session_id, now)?
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
        match session.process_data(frame.payload, writer).await {
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
                if session.inner.is_closed() {
                    let mut sessions = self.sessions.lock().unwrap();
                    sessions.remove(&session);
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
        sessions.clear();
    }
}

#[cfg(test)]
mod test {
    use crate::enclave_rpc::{session::Builder, types::SessionID};

    use super::{Error, Sessions};

    fn ids() -> (Vec<Vec<u8>>, Vec<SessionID>) {
        let peer_ids: Vec<Vec<u8>> = (1..8).map(|x| vec![x]).collect();
        let session_ids: Vec<SessionID> = (1..8).map(|_| SessionID::random()).collect();

        (peer_ids, session_ids)
    }

    #[test]
    fn test_create() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 4, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0], 1, 1, true),
            (&peer_ids[0], &session_ids[1], 2, 1, true), // Different session ID.
            (&peer_ids[0], &session_ids[2], 2, 1, false), // Too many sessions per peer.
            (&peer_ids[1], &session_ids[0], 3, 2, true), // Different peer ID.
            (&peer_ids[2], &session_ids[2], 4, 3, true), // Different peer ID and session ID.
            (&peer_ids[3], &session_ids[3], 4, 3, false), // Too many sessions.
        ];

        let now = 0;
        for (peer_id, session_id, num_sessions, num_peers, created) in test_vector {
            let res = sessions.create(peer_id.clone(), session_id.clone(), now);
            match created {
                true => {
                    assert!(res.is_ok(), "session should be created");
                    let s = res.unwrap();
                    let s_owned = s.try_lock().unwrap();
                    assert_eq!(&s_owned.peer_id, peer_id);
                    assert_eq!(&s_owned.session_id, session_id);
                }
                false => {
                    assert!(res.is_err(), "session should not be created");
                    assert!(matches!(res, Err(Error::MaxConcurrentSessions)));
                }
            };
            assert_eq!(sessions.session_count(), num_sessions);
            assert_eq!(sessions.peer_count(), num_peers);
        }
    }

    #[test]
    fn test_get() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 8, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0], true),
            (&peer_ids[0], &session_ids[1], false), // Different peer ID.
            (&peer_ids[1], &session_ids[0], false), // Different session ID.
            (&peer_ids[1], &session_ids[1], false), // Different peer ID and session ID.
        ];

        let now = 0;
        for (peer_id, session_id, create) in test_vector {
            if create {
                let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
            }

            let maybe_s = sessions.get(peer_id, session_id);
            match create {
                true => assert!(maybe_s.is_some(), "session should exist"),
                false => assert!(maybe_s.is_none(), "session should not exist"),
            }
        }
    }

    #[test]
    fn test_remove_from() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 4, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0]),
            (&peer_ids[1], &session_ids[1]),
            (&peer_ids[2], &session_ids[2]),
            (&peer_ids[2], &session_ids[3]), // Max sessions per peer reached.
                                             // Max sessions reached.
        ];

        let mut now = 0;
        for (peer_id, session_id) in test_vector.clone() {
            let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
            now += 1;
        }

        // Removing one session from an unknown peer should have no effect,
        // even if all global session slots are occupied.
        let res = sessions.remove_from(&peer_ids[3]);
        assert!(res.is_ok(), "remove_from should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_none(), "no sessions should be removed");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 3);

        // Removing one session for one of the existing peers should work
        // as it should force evict an old session.
        // Note that each peer has 2 available slots, but globally there are
        // only 4 slots so if global slots are full this should trigger peer
        // session eviction.
        let res = sessions.remove_from(&peer_ids[0]);
        assert!(res.is_ok(), "remove_from should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_some(), "one session should be removed");
        let s_owned = maybe_s_owned.unwrap();
        assert_eq!(&s_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s_owned.session_id, &session_ids[0]);
        assert_eq!(sessions.session_count(), 3);
        assert_eq!(sessions.peer_count(), 2);

        // Removing another session should fail as one global session slot
        // is available.
        for peer_id in vec![&peer_ids[0], &peer_ids[1]] {
            let res = sessions.remove_from(peer_id);
            assert!(res.is_ok(), "remove_from should succeed");
            let maybe_s_owned = res.unwrap();
            assert!(maybe_s_owned.is_none(), "no sessions should be removed");
            assert_eq!(sessions.session_count(), 3);
            assert_eq!(sessions.peer_count(), 2);
        }

        // Removing one session from a peer with max sessions should succeed
        // even if one global slot is available.
        let res = sessions.remove_from(&peer_ids[2]);
        assert!(res.is_ok(), "remove_from should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_some(), "one session should be removed");
        let s_owned = maybe_s_owned.unwrap();
        assert_eq!(&s_owned.peer_id, &peer_ids[2]);
        assert_eq!(&s_owned.session_id, &session_ids[2]);
        assert_eq!(sessions.session_count(), 2);
        assert_eq!(sessions.peer_count(), 2);
    }

    #[test]
    fn test_remove_one() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 4, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0]),
            (&peer_ids[1], &session_ids[1]),
            (&peer_ids[2], &session_ids[2]),
            (&peer_ids[2], &session_ids[3]), // Max sessions reached.
        ];

        let mut now = 0;
        for (peer_id, session_id) in test_vector.clone() {
            let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
            now += 1;
        }

        // Forward time (stale_session_timeout - test_vector.len() - 1).
        now += 60 - 4 - 1;

        // Removing one session should fail as there are none stale sessions.
        let res = sessions.remove_one(now);
        assert!(res.is_err(), "remove_one should fail");
        assert!(matches!(res, Err(Error::MaxConcurrentSessions)));
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 3);

        // Forward time.
        now += 1;

        // Removing one session should succeed as no session slots
        // are available and there is one stale session.
        let res = sessions.remove_one(now);
        assert!(res.is_ok(), "remove_one should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_some(), "one session should be removed");
        let s_owned = maybe_s_owned.unwrap();
        assert_eq!(&s_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s_owned.session_id, &session_ids[0]);
        assert_eq!(sessions.session_count(), 3);
        assert_eq!(sessions.peer_count(), 2);

        // Forward time.
        now += 100;

        // Removing one session should fail even though there are stale sessions
        // because there is one session slot available.
        let res = sessions.remove_one(now);
        assert!(res.is_ok(), "remove_one should succeed");
        let maybe_s_owned = res.unwrap();
        assert!(maybe_s_owned.is_none(), "no sessions should be removed");
        assert_eq!(sessions.session_count(), 3);
        assert_eq!(sessions.peer_count(), 2);
    }

    #[test]
    fn test_remove() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 8, 2, 60);

        let test_vector = vec![
            (&peer_ids[0], &session_ids[0], 3, 2),
            (&peer_ids[1], &session_ids[1], 2, 1),
            (&peer_ids[2], &session_ids[2], 1, 1),
            (&peer_ids[2], &session_ids[3], 0, 0),
        ];

        let now = 0;
        for (peer_id, session_id, _, _) in test_vector.clone() {
            let _ = sessions.create(peer_id.clone(), session_id.clone(), now);
        }

        for (peer_id, session_id, num_sessions, num_peers) in test_vector {
            let maybe_s = sessions.get(peer_id, session_id);
            assert!(maybe_s.is_some(), "session should exist");
            let s = maybe_s.unwrap();
            let s_owned = s.try_lock_owned().unwrap();

            sessions.remove(&s_owned);
            assert_eq!(sessions.session_count(), num_sessions);
            assert_eq!(sessions.peer_count(), num_peers);
        }
    }
}
