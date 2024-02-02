//! Session demultiplexer.
use std::{
    collections::{BTreeSet, HashMap},
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

/// Peer identifier.
type PeerID = Vec<u8>;

/// Shared pointer to a multiplexed session.
type SharedSession = Arc<tokio::sync::Mutex<MultiplexedSession>>;

/// Key for use in the by-idle-time index.
type SessionByTimeKey = (i64, PeerID, SessionID);

/// Structure used for session accounting.
struct SessionMeta {
    /// Peer identifier.
    peer_id: PeerID,
    /// Session identifier.
    session_id: SessionID,
    /// Timestamp when the session was last accessed.
    last_access_time: i64,
    /// The shared session pointer that needs to be locked for access.
    inner: SharedSession,
}

impl SessionMeta {
    /// Key for ordering in the by-idle-time index.
    fn by_time_key(&self) -> SessionByTimeKey {
        (self.last_access_time, self.peer_id.clone(), self.session_id)
    }
}

/// Session indices and management operations.
struct Sessions {
    /// Session builder.
    builder: Builder,
    /// Maximum number of sessions.
    max_sessions: usize,
    /// Maximum number of sessions per peer.
    max_sessions_per_peer: usize,
    /// Stale session timeout (in seconds).
    stale_session_timeout: i64,

    /// A map of sessions for each peer.
    by_peer: HashMap<PeerID, HashMap<SessionID, SessionMeta>>,
    /// A set of all sessions, ordered by idle time.
    by_idle_time: BTreeSet<SessionByTimeKey>,
}

impl Sessions {
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
    ) -> SessionMeta {
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

    /// Fetch an existing session given its identifier or create a new one.
    fn get_or_create(
        &mut self,
        peer_id: PeerID,
        session_id: SessionID,
    ) -> Result<(SharedSession, bool), Error> {
        let now = insecure_posix_time();

        // Check if peer exists.
        if let Some(sessions) = self.by_peer.get_mut(&peer_id) {
            // Check if the session exists. If so, return it.
            if let Some(session) = sessions.get_mut(&session_id) {
                // Remove old idle time.
                self.by_idle_time.remove(&session.by_time_key());
                // Update idle time.
                session.last_access_time = now;
                self.by_idle_time.insert(session.by_time_key());

                return Ok((session.inner.clone(), false));
            }

            // Check if the peer has max sessions or if no more sessions are available globally. If
            // so, remove the oldest or return an error.
            if sessions.len() >= self.max_sessions_per_peer
                || self.by_idle_time.len() >= self.max_sessions
            {
                // Force close the oldest idle session so we can start a new one.
                let inner = sessions
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

                if let Ok(inner) = inner.try_lock_owned() {
                    self.remove(&inner);
                } else {
                    // All sessions are in use.
                    return Err(Error::MaxConcurrentSessions);
                }
            }
        }

        // Check if there are too many sessions. If so, remove one or return an error.
        if self.by_idle_time.len() >= self.max_sessions {
            // Attempt to prune stale sessions, starting with the oldest ones.
            let mut remove_session: Option<OwnedMutexGuard<MultiplexedSession>> = None;
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

            if let Some(session) = remove_session {
                // We found a session that can be removed.
                self.remove(&session);
            } else {
                // All stale sessions are in use.
                return Err(Error::MaxConcurrentSessions);
            }
        }

        // Create a new session.
        let sessions = self.by_peer.entry(peer_id.clone()).or_default();
        let session = Self::create_session(self.builder.clone(), peer_id.clone(), session_id, now);
        let inner = session.inner.clone();
        sessions.insert(session_id, session);
        self.by_idle_time.insert((now, peer_id, session_id));

        Ok((inner, true))
    }

    /// Remove a session that must be currently owned by the caller.
    fn remove(&mut self, session: &OwnedMutexGuard<MultiplexedSession>) {
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
    sessions: Mutex<Sessions>,
}

/// A multiplexed session.
pub struct MultiplexedSession {
    /// Peer identifier (needed for resolution when only given the shared pointer).
    peer_id: PeerID,
    /// Session identifier (needed for resolution when only given the shared pointer).
    session_id: SessionID,
    /// The actual session.
    inner: Session,
}

impl MultiplexedSession {
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
        peer_id: PeerID,
        session_id: SessionID,
    ) -> Result<OwnedMutexGuard<MultiplexedSession>, Error> {
        let (session, _) = {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.get_or_create(peer_id, session_id)?
        };

        Ok(session.lock_owned().await)
    }

    /// Process a frame, returning the locked session guard and decoded message.
    ///
    /// Any data that needs to be transmitted back to the peer is written to the passed writer.
    pub async fn process_frame<W: Write>(
        &self,
        peer_id: PeerID,
        data: Vec<u8>,
        writer: W,
    ) -> Result<(OwnedMutexGuard<MultiplexedSession>, Option<Message>), Error> {
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
        mut session: OwnedMutexGuard<MultiplexedSession>,
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
        let peer_ids: Vec<Vec<u8>> = (1..16).map(|x| vec![x]).collect();
        let session_ids: Vec<SessionID> = (1..16).map(|_| SessionID::random()).collect();

        (peer_ids, session_ids)
    }

    #[test]
    fn test_namespacing() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 16, 4, 60);

        let (s1, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[0])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let s1_owned = s1.try_lock().unwrap();
        assert_eq!(&s1_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s1_owned.session_id, &session_ids[0]);
        drop(s1_owned);
        assert_eq!(sessions.session_count(), 1);
        assert_eq!(sessions.peer_count(), 1);

        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[1])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[2])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[3])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 1);

        // Requesting an existing session for an existing peer should return it.
        let (s1r, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[0])
            .expect("get_or_create should succeed");
        assert!(!created, "session should be reused");
        let s1r_owned = s1r.try_lock().unwrap();
        assert_eq!(&s1r_owned.peer_id, &peer_ids[0]);
        assert_eq!(&s1r_owned.session_id, &session_ids[0]);
        drop(s1r_owned);
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 1);

        // Sessions should be properly namespaced by peer.
        let (s5, created) = sessions
            .get_or_create(peer_ids[1].clone(), session_ids[0])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created due to namespacing");
        let s5_owned = s5.try_lock().unwrap();
        assert_eq!(&s5_owned.peer_id, &peer_ids[1]);
        assert_eq!(&s5_owned.session_id, &session_ids[0]);
        drop(s5_owned);
        assert_eq!(sessions.session_count(), 5);
        assert_eq!(sessions.peer_count(), 2);
    }

    #[test]
    fn test_max_sessions_per_peer() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 16, 4, 60); // Stale timeout is ignored.

        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[0])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");

        // Sleep to make sure the first session is the oldest.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[1])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[2])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[3])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 1);

        // Creating more sessions for the same peer should result in the oldest session being
        // closed.
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[4])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 1);

        // Only the oldest session should be closed.
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[1])
            .expect("get_or_create should succeed");
        assert!(!created, "session should be reused");
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[2])
            .expect("get_or_create should succeed");
        assert!(!created, "session should be reused");
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[3])
            .expect("get_or_create should succeed");
        assert!(!created, "session should be reused");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 1);

        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[0])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 1);
    }

    #[test]
    fn test_max_sessions() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 4, 4, 60);

        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[0])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[1].clone(), session_ids[1])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[2].clone(), session_ids[2])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[3].clone(), session_ids[3])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 4);

        // Creating more sessions for a different peer should fail as no sessions are available and
        // none are stale.
        let res = sessions.get_or_create(peer_ids[4].clone(), session_ids[4]);
        assert!(
            matches!(res, Err(Error::MaxConcurrentSessions)),
            "get_or_create should fail"
        );
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 4);

        // Creating more sessions for one of the existing peers should still work as it should force
        // evict an old session. Note that each peer has 4 available slots, but globally there are
        // only 4 slots so if global slots are full this should still trigger peer session eviction.
        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[5])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 4);
    }

    #[test]
    fn test_max_sessions_prune_stale() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 4, 4, 0); // Stale timeout is zero.

        let (_, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[0])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[1].clone(), session_ids[1])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[2].clone(), session_ids[2])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[3].clone(), session_ids[3])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 4);

        // Creating more sessions for a different peer should succeed as one of the stale sessions
        // should be removed to make room for a new session.
        let (_, created) = sessions
            .get_or_create(peer_ids[4].clone(), session_ids[4])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 4);
    }

    #[test]
    fn test_remove() {
        let (peer_ids, session_ids) = ids();
        let mut sessions = Sessions::new(Builder::default(), 16, 4, 0); // Stale timeout is zero.

        let (s1, created) = sessions
            .get_or_create(peer_ids[0].clone(), session_ids[0])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (s2, created) = sessions
            .get_or_create(peer_ids[1].clone(), session_ids[1])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[1].clone(), session_ids[2])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        let (_, created) = sessions
            .get_or_create(peer_ids[2].clone(), session_ids[3])
            .expect("get_or_create should succeed");
        assert!(created, "new session should be created");
        assert_eq!(sessions.session_count(), 4);
        assert_eq!(sessions.peer_count(), 3);

        let s1r = s1.try_lock_owned().unwrap();
        sessions.remove(&s1r);
        assert_eq!(sessions.session_count(), 3);
        assert_eq!(sessions.peer_count(), 2);

        let s2r = s2.try_lock_owned().unwrap();
        sessions.remove(&s2r);
        assert_eq!(sessions.session_count(), 2);
        assert_eq!(sessions.peer_count(), 2);
    }
}
